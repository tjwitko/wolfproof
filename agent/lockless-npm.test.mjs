import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import path from "path";

import { fileURLToPath } from "url";
import { lowestVersion, npmDeclared, lockfileFor, scanWithoutLockfile, scanLockfiles, childSummarizer } from "./lockless-npm.mjs";

// dep-audit's own banding, run as the gate runs it, in a process of its own. dep-audit up to v1.0.2
// deletes the importer's environment as it loads (see childSummarizer), the test runner's variables
// too, and the gate runs whichever version a project hands it.
const DEP_AUDIT = fileURLToPath(import.meta.resolve("@tjwitko/dep-audit-mcp"));
const summarizeFindings = childSummarizer(DEP_AUDIT);

test("the lowest version a range allows, and none for a range that names no version", () => {
  const cases = {
    "^4.17.4": "4.17.4",
    "~1.2": "1.2.0",
    "1.x": "1.0.0",
    "4": "4.0.0",
    ">=1.2.3 <2": "1.2.3",
    ">= 2.1.2 < 3.0.0": "2.1.2",
    "1.2.3 - 2.0.0": "1.2.3",
    "^1.0.0 || ^0.9.1": "0.9.1",
    ">1.2.3": "1.2.4",
    ">1.2": "1.3.0",
    "=3.1.0": "3.1.0",
    "v2.1.0": "2.1.0",
    "2.0.0-beta.3": "2.0.0-beta.3",
    "*": null,
    "": null,
    latest: null,
    "<2.0.0": null,
    "git+https://github.com/a/b.git": null,
    "file:../local": null,
    "workspace:*": null,
    "github:user/repo": null,
  };
  for (const [range, want] of Object.entries(cases)) assert.equal(lowestVersion(range), want, range);
});

test("a manifest's direct dependencies, an alias read as the package it names, peers left out", () => {
  const text = JSON.stringify({
    dependencies: { express: "^4.17.1", lodash4: "npm:lodash@^4.17.4", mine: "file:../mine" },
    devDependencies: { jest: "~29.0", express: "9" },
    peerDependencies: { react: "^18" },
  });
  assert.deepEqual(npmDeclared(text), [
    { name: "express", range: "^4.17.1", version: "4.17.1" },
    { name: "lodash", range: "^4.17.4", version: "4.17.4" },
    { name: "mine", range: "file:../mine", version: null },
    { name: "jest", range: "~29.0", version: "29.0.0" },
  ]);
  assert.equal(npmDeclared("{ not json"), null);
  const lock = lockfileFor([{ name: "@hapi/hoek", version: "8.0.0" }]);
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages["node_modules/@hapi/hoek"], { version: "8.0.0" });
});

// osv-scanner, answering from a table of advisories rather than the network: what it would report
// for each -L lockfile it is given, read from that lockfile.
const ADVISORIES = {
  "lodash@4.17.4": [{ id: "GHSA-jf85-cpcp-j695", score: "9.1", fixed: "4.17.12" }, { id: "GHSA-29mw-wpgm-hmr9", score: "5.3", fixed: "4.17.21" }],
  "@hapi/hoek@8.0.0": [{ id: "GHSA-c429-5p7v-vgjp", score: "8.1", fixed: "8.5.1" }],
};
function fakeOsv(calls = []) {
  return (bin, args) => {
    calls.push(args);
    const locks = args.flatMap((a, i) => (args[i - 1] === "-L" ? [a] : []));
    const results = locks.map((lock) => {
      const packages = Object.entries(JSON.parse(readFileSync(lock, "utf8")).packages)
        .filter(([k]) => k.startsWith("node_modules/"))
        .map(([k, v]) => ({ name: k.slice("node_modules/".length), version: v.version }))
        .filter((p) => ADVISORIES[`${p.name}@${p.version}`])
        .map((p) => {
          const adv = ADVISORIES[`${p.name}@${p.version}`];
          return {
            package: { name: p.name, version: p.version, ecosystem: "npm" },
            vulnerabilities: adv.map((a) => ({ id: a.id, summary: a.id, affected: [{ package: { name: p.name }, ranges: [{ events: [{ introduced: "0" }, { fixed: a.fixed }] }] }] })),
            groups: adv.map((a) => ({ ids: [a.id], max_severity: a.score })),
          };
        });
      return { source: { path: lock, type: "lockfile" }, packages };
    });
    return { status: results.some((r) => r.packages.length) ? 1 : 0, stdout: JSON.stringify({ results }), stderr: "" };
  };
}

test("each package.json is scanned at its lowest versions, in one osv-scanner run, high and above kept", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "lockless-"));
  try {
    mkdirSync(path.join(dir, "web"));
    writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { lodash: "^4.17.4", left: "latest" } }));
    writeFileSync(path.join(dir, "web/package.json"), JSON.stringify({ dependencies: { "@hapi/hoek": "~8.0.0" } }));
    writeFileSync(path.join(dir, "empty.json"), JSON.stringify({ dependencies: { only: "*" } }));
    const calls = [];
    const r = scanWithoutLockfile(dir, ["package.json", "web/package.json", "empty.json"], { summarize: summarizeFindings, run: fakeOsv(calls) });
    assert.equal(calls.length, 1);
    assert.deepEqual(
      r.scanned.map((s) => [s.manifest, s.checked, s.unresolved, s.findings.map((f) => `${f.package}@${f.version}:${f.id}:${f.fixedVersion}`)]),
      [
        ["package.json", 1, ["left@latest"], ["lodash@4.17.4:GHSA-jf85-cpcp-j695:4.17.12"]],
        ["web/package.json", 1, [], ["@hapi/hoek@8.0.0:GHSA-c429-5p7v-vgjp:8.5.1"]],
        ["empty.json", 0, ["only@*"], []],
      ]
    );
    // A scanner that fails is an error, never an empty result.
    const failed = scanWithoutLockfile(dir, ["package.json"], { summarize: summarizeFindings, run: () => ({ status: 127, stdout: "", stderr: "network unreachable" }) });
    assert.match(failed.error, /^osv-scanner did not scan them \(exit 127\): network unreachable$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The pinned dep-audit (v1.0.3 on) no longer clears the environment on import, so the test below
// would pass in-process too. A project can still hand the gate v1.0.2 or older, which does: this
// stand-in deletes every variable but PATH, HOME and SCAN_ROOT as it loads, as those versions did.
test("a dep-audit that clears the environment as it loads clears only its own process's", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "old-dep-audit-"));
  process.env.WOLFPROOF_LOCKLESS_SENTINEL = "kept";
  try {
    const entry = path.join(dir, "index.mjs");
    writeFileSync(
      entry,
      'for (const k of Object.keys(process.env)) if (!["PATH", "HOME", "SCAN_ROOT"].includes(k)) delete process.env[k];\n' +
        'export function summarizeFindings(r) { return [{ id: "banded", left: Object.keys(process.env).sort().join(",") }]; }\n'
    );
    const before = Object.keys(process.env).sort();
    const banded = childSummarizer(entry)({ results: [] });
    // It ran, and cleared its own environment...
    assert.equal(banded[0].id, "banded");
    assert.ok(!banded[0].left.includes("WOLFPROOF_LOCKLESS_SENTINEL"), banded[0].left);
    // ...and not this one.
    assert.deepEqual(Object.keys(process.env).sort(), before);
    assert.equal(process.env.WOLFPROOF_LOCKLESS_SENTINEL, "kept");
  } finally {
    delete process.env.WOLFPROOF_LOCKLESS_SENTINEL;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dep-audit's bands come from a process of its own, and this one keeps its environment", () => {
  process.env.WOLFPROOF_LOCKLESS_SENTINEL = "kept";
  try {
    // Names only: a failing assertion prints both sides, and an environment holds credentials.
    const before = Object.keys(process.env).sort();
    const result = (lock) => ({
      source: { path: lock },
      packages: [{ package: { name: "lodash", version: "4.17.4", ecosystem: "npm" }, vulnerabilities: [{ id: "GHSA-jf85-cpcp-j695", affected: [] }], groups: [{ ids: ["GHSA-jf85-cpcp-j695"], max_severity: "9.1" }] }],
    });
    const calls = [];
    const run = (bin, args, opts) => {
      calls.push(bin);
      return bin === "osv-scanner" ? { status: 1, stdout: JSON.stringify({ results: [result("/a/package-lock.json"), result("/b/package-lock.json")] }), stderr: "" } : spawnSync(bin, args, opts);
    };
    const r = scanLockfiles(["/a/package-lock.json", "/b/package-lock.json"], { summarize: childSummarizer(DEP_AUDIT, { run }), run });
    assert.deepEqual(r.findings.map((f) => f.map((x) => x.id)), [["GHSA-jf85-cpcp-j695"], ["GHSA-jf85-cpcp-j695"]]);
    // One osv-scanner run and one dep-audit process for both lockfiles.
    assert.deepEqual(calls, ["osv-scanner", process.execPath]);
    assert.deepEqual(Object.keys(process.env).sort(), before);

    // A dep-audit that cannot be run is an error, never findings banded some other way.
    const broken = scanLockfiles(["/a/package-lock.json"], { summarize: childSummarizer(path.join(tmpdir(), "no-such-dep-audit.mjs")), run });
    assert.match(broken.error, /^dep-audit's severity bands could not be read \(exit 1\): /);
  } finally {
    delete process.env.WOLFPROOF_LOCKLESS_SENTINEL;
  }
});
