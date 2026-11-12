import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { judgeTrivyReport, scanImage, trivyEnv, trivyLog } from "./trivy.mjs";
import { classifyAdvisory, COULD_NOT_RUN, FINDING, INFO, NOT_CHECKED } from "../lib/advisory-classes.mjs";

// Real reports from Trivy 0.74.0, trimmed to the fields the check reads (agent/fixtures/trivy/).
const report = (name) => JSON.parse(readFileSync(new URL(`./fixtures/trivy/${name}`, import.meta.url), "utf8"));
const WARN = (message, fields = "") => ({ level: "WARN", message, fields });
const EOL_UNKNOWN = (family, version) => WARN("This OS version is not on the EOL list", `family="${family}" version="${version}"`);

test("a vulnerability at the severity or above with a fixed version blocks; the rest are counted", () => {
  const r = judgeTrivyReport({ image: "node:18.0.0-alpine", report: report("node-18.0.0-alpine.json") });
  assert.equal(r.couldNotRun.length, 0);
  assert.equal(r.failures.length, 1);
  // 4 in the OS packages and 4 in Node's own npm, CRITICAL first.
  assert.match(r.failures[0], /^trivy \(node:18\.0\.0-alpine\): 8 vulnerabilities at HIGH or above have a fixed version — CRITICAL /);
  assert.match(r.failures[0], /; and 3 more\. Upgrade those packages or the base image\.$/);
  const notBlocking = r.advisories.find((a) => / do not block/.test(a));
  assert.equal(notBlocking, "trivy (node:18.0.0-alpine): 10 more vulnerabilities do not block — 1 at HIGH or above with no fixed version yet, 9 below HIGH.");
  assert.ok(r.advisories.some((a) => /alpine 3\.15\.4 is past its end of service life/.test(a)), "EOSL is said");
});

test("the severity moves the line", () => {
  const critical = judgeTrivyReport({ image: "i", severity: "CRITICAL", report: report("node-18.0.0-alpine.json") });
  assert.match(critical.failures[0], /: 2 vulnerabilities at CRITICAL or above/);
  const low = judgeTrivyReport({ image: "i", severity: "LOW", report: report("node-18.0.0-alpine.json") });
  assert.match(low.failures[0], /: 17 vulnerabilities at LOW or above/);
  assert.ok(low.advisories.some((a) => a === "trivy (i): 1 more vulnerability does not block — 1 at LOW or above with no fixed version yet."));
});

// Kali: Trivy reads it as Debian "kali-rolling", has no advisories for it, and reports 0 of 79
// packages vulnerable. Only its log says it does not know the version.
test("an OS Trivy does not know, with nothing found, is not reported as clean", () => {
  const r = judgeTrivyReport({ image: "kali", report: report("kali-rolling.json"), log: [EOL_UNKNOWN("debian", "kali-rolling")] });
  assert.deepEqual(r.failures, []);
  assert.equal(r.advisories.length, 1, r.advisories.join("\n"));
  assert.match(r.advisories[0], /Trivy does not recognise debian kali-rolling and found no vulnerabilities/);
  assert.equal(classifyAdvisory(r.advisories[0], { trivyImages: ["kali"] }).class, COULD_NOT_RUN);
  // Without the warning, the same report is a clean scan.
  const clean = judgeTrivyReport({ image: "kali", report: report("kali-rolling.json") });
  assert.match(clean.advisories[0], /scanned debian kali-rolling; nothing at HIGH or above has a fixed version/);
});

// Trivy 0.74 says "not on the EOL list" of Alpine 3.24 too, and finds its vulnerabilities.
test("an OS version Trivy does not list, with vulnerabilities found, was scanned", () => {
  const r = judgeTrivyReport({ image: "alpine:latest", report: report("alpine-3.24.json"), log: [EOL_UNKNOWN("alpine", "3.24")] });
  assert.match(r.failures[0], /: 1 vulnerability at HIGH or above has a fixed version — HIGH /);
  assert.ok(!r.advisories.some((a) => /does not recognise/.test(a)));
});

test("an image with nothing to scan says so, and an OS detected and not scanned is not clean", () => {
  const r = judgeTrivyReport({ image: "scratch", report: report("scratch.json") });
  assert.deepEqual(r.failures, []);
  assert.deepEqual(r.advisories, ["trivy (scratch): Trivy 0.74.0 found no OS packages and no language packages in the image, so there was nothing to scan."]);
  const unscanned = judgeTrivyReport({ image: "p", report: { SchemaVersion: 2, Metadata: { OS: { Family: "photon", Name: "5.0" } } } });
  assert.deepEqual(unscanned.advisories, ["trivy (p): Trivy detected photon 5.0 and did not scan its packages, so the OS packages were not checked."]);
});

test("a warning Trivy carried on past is said; the known ones are not repeated", () => {
  const log = [WARN("Using severities from other vendors for some vulnerabilities."), WARN("Failed to analyze file", 'path="x.jar"')];
  const r = judgeTrivyReport({ image: "i", report: report("scratch.json"), log });
  assert.ok(r.advisories.includes('trivy (i): Trivy reported a problem and carried on: Failed to analyze file (path="x.jar").'));
  assert.ok(!r.advisories.some((a) => /other vendors/.test(a)));
});

test("a report in a schema this does not read could not be checked", () => {
  const r = judgeTrivyReport({ image: "i", report: { SchemaVersion: 3 } });
  assert.deepEqual(r.failures, []);
  assert.match(r.couldNotRun[0], /schema version 3, and this version of wolfproof reads version 2/);
});

test("every advisory the check prints has a class factory mode knows", () => {
  const all = [
    ...judgeTrivyReport({ image: "a", report: report("node-18.0.0-alpine.json"), log: [WARN("Failed to analyze file")] }).advisories,
    ...judgeTrivyReport({ image: "b", report: report("kali-rolling.json"), log: [EOL_UNKNOWN("debian", "kali-rolling")] }).advisories,
    ...judgeTrivyReport({ image: "c", report: report("kali-rolling.json") }).advisories,
    ...judgeTrivyReport({ image: "d", report: report("scratch.json") }).advisories,
  ];
  // Factory mode reads the image's name off a line by being told it, not by its brackets.
  const classes = all.map((a) => classifyAdvisory(a, { trivyImages: ["a", "b", "c", "d"] }));
  assert.ok(!classes.some((c) => c.unclassified), JSON.stringify(all));
  assert.deepEqual([...new Set(classes.map((c) => c.class))].sort(), [COULD_NOT_RUN, FINDING, INFO, NOT_CHECKED].sort());
});

test("Trivy's own settings that change what is reported are not passed on", () => {
  const { env, dropped } = trivyEnv({ PATH: "/bin", TRIVY_SEVERITY: "CRITICAL", TRIVY_IGNOREFILE: "x", TRIVY_USERNAME: "u", TRIVY_DB_REPOSITORY: "m" });
  assert.deepEqual(dropped, ["TRIVY_IGNOREFILE", "TRIVY_SEVERITY"]);
  assert.deepEqual(Object.keys(env).sort(), ["PATH", "TRIVY_DB_REPOSITORY", "TRIVY_USERNAME"]);
});

test("the log is read by level, and only WARN and above", () => {
  const log = trivyLog("2026-11-02T16:42:04-07:00\tINFO\tDetected OS\tfamily=\"debian\"\n2026-11-02T16:42:05-07:00\tWARN\tThis OS version is not on the EOL list\tfamily=\"debian\" version=\"kali-rolling\"\n");
  assert.deepEqual(log, [{ level: "WARN", message: "This OS version is not on the EOL list", fields: 'family="debian" version="kali-rolling"' }]);
});

// A stand-in for trivy that records how it was run and writes the report it is given.
function fakeTrivy(t, body) {
  const bin = mkdtempSync(path.join(tmpdir(), "trivy-bin-"));
  t.after(() => rmSync(bin, { recursive: true, force: true }));
  writeFileSync(path.join(bin, "trivy"), `#!/bin/sh\n${body}\n`);
  chmodSync(path.join(bin, "trivy"), 0o755);
  return bin;
}
const fixture = (name) => new URL(`./fixtures/trivy/${name}`, import.meta.url).pathname;

test("the scan runs in an empty directory, reports everything, ignores nothing, and passes on only some settings", (t) => {
  const seen = path.join(mkdtempSync(path.join(tmpdir(), "trivy-seen-")), "seen");
  const bin = fakeTrivy(
    t,
    `{ echo "cwd=$(ls -A . | tr '\\n' ' ')"; echo "args=$*"; echo "sev=$TRIVY_SEVERITY user=$TRIVY_USERNAME"; } > "${seen}"
while [ "$1" != "--output" ]; do shift; done; cp "${fixture("node-18.0.0-alpine.json")}" "$2"`
  );
  const r = scanImage("node:18.0.0-alpine", { env: { PATH: `${bin}:/usr/bin:/bin`, TRIVY_SEVERITY: "CRITICAL", TRIVY_USERNAME: "u" } });
  const out = readFileSync(seen, "utf8");
  assert.match(out, /^cwd=empty\.trivyignore $/m, "nothing but the empty ignore file where it runs");
  assert.match(out, /--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --ignorefile \S+empty\.trivyignore /);
  assert.match(out, /^sev= user=u$/m);
  assert.equal(r.ran, true);
  assert.match(r.failures[0], /: 8 vulnerabilities at HIGH or above/);
  assert.match(r.advisories[0], /^trivy \(node:18\.0\.0-alpine\): TRIVY_SEVERITY is set and not passed to Trivy/);
});

test("trivy missing, a failed scan, and an unreadable report each mean the image was not checked", (t) => {
  const none = scanImage("i", { env: { PATH: mkdtempSync(path.join(tmpdir(), "trivy-empty-")) } });
  assert.equal(none.ran, false);
  assert.deepEqual(none.couldNotRun, ["trivy (i): trivy is not installed, so the image was not scanned."]);

  const failed = fakeTrivy(t, `printf '2026-11-02T16:40:44-07:00\\tFATAL\\tFatal error\\tunable to find the specified image "i"\\n' >&2; exit 1`);
  const f = scanImage("i", { env: { PATH: `${failed}:/usr/bin:/bin` } });
  assert.equal(f.ran, false);
  assert.match(f.couldNotRun[0], /^trivy \(i\): the scan failed, so the image was not checked — Fatal error: unable to find the specified image "i"$/);
  assert.deepEqual(f.failures, []);

  const empty = fakeTrivy(t, "exit 0");
  const e = scanImage("i", { env: { PATH: `${empty}:/usr/bin:/bin` } });
  assert.match(e.couldNotRun[0], /^trivy \(i\): the scan finished without a readable report/);
});

test("WOLFPROOF_TRIVY names the binary, and a missing one is not replaced by the trivy on PATH", (t) => {
  const onPath = fakeTrivy(t, `while [ "$1" != "--output" ]; do shift; done; cp "${fixture("scratch.json")}" "$2"`);
  const r = scanImage("i", { env: { PATH: `${onPath}:/usr/bin:/bin`, WOLFPROOF_TRIVY: "/nonexistent/trivy" } });
  assert.equal(r.ran, false);
  assert.deepEqual(r.couldNotRun, ["trivy (i): /nonexistent/trivy does not exist, so the image was not scanned."]);
  const named = scanImage("i", { env: { PATH: "/usr/bin:/bin", WOLFPROOF_TRIVY: path.join(onPath, "trivy") } });
  assert.equal(named.ran, true);
});
