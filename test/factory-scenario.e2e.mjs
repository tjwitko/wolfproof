// The Dark Factory measurement, end to end: the real gate over test/fixtures/factory-scenario.mjs,
// one escape at a time, in the default mode and in factory mode.
//
// Not a *.test.mjs file, on purpose: the gate's own `tests` check runs every one of those inside a
// 120-second budget when this repository gates itself, and these runs take minutes. `npm run
// test:factory` runs this file, and CI runs that with the scanners installed and
// WOLFPROOF_REQUIRE_SCANNERS set, so a missing scanner fails here rather than skipping.
//
// The sequence, measured at a6e98ba (the fixture's commit message has the numbers):
//   1. the server                      default 3 blocking (authentication, sast, scan_path)
//   2. routes under /health, /metrics  default 3 blocking -- 05c612d made the probe exemption terminal
//   3. src/.tfguard-fixture            default 1 blocking (scan_path); sast and authentication skip src/
//   4. .wolfproof.json redirect        default 0 blocking, exit 0 -- until v1.4.0, when the scan-root
//                                      check stopped accepting a subdirectory as the project. Now 1
//                                      blocking: scan_path scanned only .scan-root-*, a subdirectory.
// Factory mode, compared with step 1's commit, blocks every escape and names each.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { writeServer, writeControlRedirect } from "./fixtures/factory-scenario.mjs";
import { setting } from "../lib/settings.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GATE = path.join(REPO, "bin", "validate.mjs");
const secretGuardEntry = createRequire(path.join(REPO, "package.json")).resolve("@tjwitko/secret-guard-mcp/index.mjs");

// What the scenario's three findings need. A run without one of them is exit 3 and proves nothing.
const scanners = ["gitleaks", "semgrep", "osv-scanner"];
const missing = scanners.filter((s) => spawnSync(s, ["--version"], { env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" } }).status !== 0);
const required = setting(process.env, "REQUIRE_SCANNERS") === "1";
const skip = missing.length && !required ? `not installed: ${missing.join(", ")}` : false;

function scenario() {
  const dir = mkdtempSync(path.join(tmpdir(), "factory-e2e-"));
  const git = (...a) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", ...a], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const commit = (msg) => {
    git("add", "-A");
    git("commit", "-qm", msg);
    return git("rev-parse", "HEAD");
  };
  git("init", "-q");
  writeFileSync(path.join(dir, "package.json"), `${JSON.stringify({ name: "factory-app", version: "1.0.0" }, null, 2)}\n`);
  return { dir, git, commit, done: () => rmSync(dir, { recursive: true, force: true }) };
}

function gate(dir, extra = []) {
  const r = spawnSync(process.execPath, [GATE, dir, "--json", ...extra], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  let j;
  try {
    j = JSON.parse(r.stdout);
  } catch {
    throw new Error(`no result document (exit ${r.status}): ${r.stderr.slice(-2000)}`);
  }
  const blockedBy = [...new Set(j.findings.map((f) => (/^factory:/.test(f.message) ? "factory" : f.message.split(/[:\s]/)[0])))].sort();
  return { exit: r.status, j, blockedBy, findings: j.findings.map((f) => f.message) };
}

const escapes = {
  marker: (s) => writeFileSync(path.join(s.dir, "src", ".tfguard-fixture"), "test fixtures for the integration suite\n"),
  redirect: (s) => writeControlRedirect(s.dir, { secretGuardEntry }),
};

test("default mode: each escape loosens the gate, and the last is caught by the scan-root check", { skip }, () => {
  assert.deepEqual(missing, [], `WOLFPROOF_REQUIRE_SCANNERS is set and these are not on PATH: ${missing.join(", ")}`);
  const s = scenario();
  try {
    writeServer(s.dir);
    s.commit("server");
    let r = gate(s.dir);
    assert.equal(r.exit, 1, r.findings.join("\n"));
    assert.deepEqual(r.blockedBy, ["authentication", "sast", "scan_path"]);

    writeServer(s.dir, { purgeRoute: "/health/purge-all", usersRoute: "/metrics/users" });
    s.commit("routes under probe paths");
    r = gate(s.dir);
    assert.equal(r.exit, 1);
    assert.deepEqual(r.blockedBy, ["authentication", "sast", "scan_path"], "05c612d: a route under a probe path is checked");

    escapes.marker(s);
    s.commit("marker");
    r = gate(s.dir);
    assert.equal(r.exit, 1);
    assert.deepEqual(r.blockedBy, ["scan_path"], "the marker takes src/ out of sast and authentication");

    // The redirect still runs -- the default mode honours a project's config -- but the clean scan it
    // returns is of an empty subdirectory, and a scan of part of the tree is not a scan of the project.
    escapes.redirect(s);
    s.commit("control redirect");
    r = gate(s.dir);
    assert.equal(r.j.controls.find((c) => c.name === "secret-guard").resolvedFrom, ".wolfproof.json controls.secret-guard");
    assert.equal(r.exit, 1, "this was exit 0 until v1.4.0");
    assert.deepEqual(r.blockedBy, ["scan_path"]);
    assert.match(r.findings[0], /^scan_path scanned .*, which is only \.scan-root-[^,]+, part of this project/);
  } finally {
    s.done();
  }
});

test("factory mode: every escape blocks, and the last state names each one", { skip }, () => {
  const s = scenario();
  try {
    writeServer(s.dir);
    const base = s.commit("server");
    const factory = ["--factory", `--base=${base}`];

    let r = gate(s.dir, factory);
    assert.equal(r.exit, 1);
    assert.deepEqual(r.blockedBy, ["authentication", "sast", "scan_path"], "nothing added yet, so the same three findings");

    // A purge endpoint renamed to exactly /health is exempt by name in either mode. Probe exemptions
    // are conventional, so factory mode keeps them -- and names a route the base did not have.
    writeServer(s.dir, { purgeRoute: "/health" });
    s.commit("purge renamed to /health");
    r = gate(s.dir, factory);
    assert.deepEqual(r.j.factory.newProbeRoutes.map((x) => `${x.method} ${x.route}`), ["POST /health"]);
    assert.ok(r.j.factory.notes.some((n) => n.includes("POST /health")), JSON.stringify(r.j.factory.notes));

    escapes.marker(s);
    s.commit("marker");
    r = gate(s.dir, factory);
    assert.equal(r.exit, 1);
    assert.ok(r.findings.some((f) => /^factory: 1 fixture-marker grant\(s\) this change added — src\/\.tfguard-fixture/.test(f)), r.findings.join("\n"));

    escapes.redirect(s);
    s.commit("control redirect");
    r = gate(s.dir, factory);
    assert.equal(r.exit, 1, "the state that exits 0 by default");
    assert.ok(r.findings.some((f) => /^factory: \.wolfproof\.json overrides the secret-guard control/.test(f)), r.findings.join("\n"));
    assert.ok(r.findings.some((f) => /^factory: 1 fixture-marker grant\(s\) this change added/.test(f)), r.findings.join("\n"));
    assert.ok(r.findings.some((f) => /^scan_path: 2 hardcoded credential\(s\)/.test(f)), "the installed secret-guard ran, and found both");
    assert.match(r.j.controls.find((c) => c.name === "secret-guard").resolvedFrom, /^node_modules /);
    // POST /health is not named here, and that is the marker's doing: it takes src/ out of the
    // authentication check, which is where exempt routes are found. The marker blocks on its own,
    // and with it removed the route is named again, as in the step above.
  } finally {
    s.done();
  }
});

test("factory mode honours exemptions the base already had", { skip }, () => {
  const s = scenario();
  try {
    writeServer(s.dir);
    escapes.marker(s);
    const base = s.commit("server, with src/ declared a fixture from the start");
    s.git("commit", "-q", "--allow-empty", "-m", "an unrelated change");
    const r = gate(s.dir, ["--factory", `--base=${base}`]);
    assert.equal(r.exit, 1);
    assert.deepEqual(r.blockedBy, ["scan_path"], `the marker predates the change, so it is honoured: ${r.findings.join("\n")}`);
    assert.equal(r.j.factory.grants.find((g) => g.kind === "fixture-marker").status, "pre-existing");
  } finally {
    s.done();
  }
});

test("factory mode with a base it cannot find exits 3", { skip }, () => {
  const s = scenario();
  try {
    writeServer(s.dir);
    s.commit("server");
    const r = gate(s.dir, ["--factory", "--base=0123456789abcdef0123456789abcdef01234567"]);
    assert.equal(r.exit, 3);
    assert.ok(r.j.couldNotRun.some((c) => /^factory: the base ref .* is not in this checkout/.test(c)), JSON.stringify(r.j.couldNotRun));
  } finally {
    s.done();
  }
});
