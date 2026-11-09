// The corpus's finding keys decide what counts as drift, so each factory refusal must land on its own
// key. The ones lib/factory.mjs writes are taken from a real judgement; the ones bin/validate.mjs
// writes are spelled as its templates spell them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { findingId, factoryFindingId, incompleteReasons } from "./corpus-keys.mjs";
import { judgeChange, materializeBase } from "./factory.mjs";

test("default-mode findings are keyed by the check that produced them", () => {
  assert.equal(findingId("check_dependencies: 3 packages with known vulnerabilities"), "check_dependencies");
  assert.equal(findingId("workload identity (terraform/iam.tf): a static key"), "workload identity");
  assert.deepEqual(factoryFindingId("tests: 2 of 9 test(s) FAILED"), { id: "tests", n: 1 }, "not a factory refusal, so keyed as in the default mode");
});

test("each refusal judgeChange writes has its own key, weighted by what it lists", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "corpus-keys-"));
  const git = (...a) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", ...a], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const write = (rel, text) => {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  };
  try {
    git("init", "-q");
    write("samples/.tfguard-fixture", "deliberately broken samples\n");
    write("src/server.js", "module.exports = 1;\n");
    write(".github/workflows/ci.yml", "on: push\n");
    git("add", "-A");
    git("commit", "-qm", "base");
    const sha = git("rev-parse", "HEAD");
    write("app/a.py", "import os  # noqa\nimport sys  # noqa\nimport re  # noqa\n");
    write("samples/new.js", "x");
    write("dist/bundle.js", "y");
    renameSync(path.join(dir, "src/server.js"), path.join(dir, "src/server.test.js"));
    write(".github/workflows/ci.yml", "on: [push]\n");
    git("add", "-A");
    git("commit", "-qm", "change");
    const base = materializeBase(dir, sha);
    let j;
    try {
      j = judgeChange(dir, { sha, baseDir: base.dir });
    } finally {
      base.cleanup();
    }
    const keys = Object.fromEntries(j.failures.map((f) => [factoryFindingId(f).id, factoryFindingId(f).n]));
    assert.deepEqual(
      keys,
      {
        "factory: added noqa": 3,
        "factory: changed-under-exemption": 1,
        "factory: skipped-location": 1,
        "factory: moved-to-unchecked": 1,
        "factory: workflow-change": 1,
      },
      j.failures.join("\n")
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the refusals the gate writes itself have their own keys too", () => {
  const cases = {
    "factory: .wolfproof.json overrides the secret-guard control with \"./tools/x.mjs\". In factory mode": "factory: control override (secret-guard)",
    "factory: the task file task.txt was added by this change — it did not exist at the base (0123456789ab).": "factory: task file added",
    "factory: this change edits the baseline baseline.txt, the requirements it is checked against.": "factory: baseline edited",
    "factory: nothing was checked — authentication: no HTTP routes were identified, so nothing was checked": "factory: nothing checked (authentication)",
    "factory: blocked by the pipeline's policy (sast:sql-string-built) — sast: SQL built from a string": "factory: policy (sast:sql-string-built)",
    "factory: an advisory factory mode cannot classify, so it cannot tell whether it means nothing was checked — x": "factory: unclassified advisory",
    "factory: server.test.js builds an HTTP server, and package.json refers to it from outside the tests — but the authentication check skips files named as tests": "factory: server-in-test",
  };
  for (const [message, id] of Object.entries(cases)) assert.deepEqual(factoryFindingId(message), { id, n: 1 }, message);
});

// The corpus printed "INCOMPLETE … a control could not run" and then only the controls that had not
// run. Twice the three Go fixtures came back that way with every control running: what could not run
// was a check, and nothing named it. Here a Go project's build cannot get its image, as when docker
// cannot be reached, through the real gate.
test("an incomplete run names what could not run, a check as well as a control", () => {
  const d = mkdtempSync(path.join(tmpdir(), "corpus-incomplete-"));
  try {
    const proj = path.join(d, "proj");
    const bin = path.join(d, "bin");
    mkdirSync(proj);
    mkdirSync(bin);
    writeFileSync(path.join(proj, "go.mod"), "module example.com/svc\n\ngo 1.22\n");
    writeFileSync(path.join(proj, "main.go"), "package main\n\nfunc main() {}\n");
    writeFileSync(path.join(bin, "docker"), "#!/bin/sh\necho 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.' >&2\nexit 1\n", { mode: 0o755 });
    const git = (...a) => spawnSync("git", ["-C", proj, "-c", "user.name=t", "-c", "user.email=t@localhost", ...a], { encoding: "utf8" });
    git("init", "-q");
    git("add", "-A");
    git("commit", "-q", "-m", "fixture");
    const cli = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "bin", "validate.mjs");
    const run = spawnSync(process.execPath, [cli, proj, "--json"], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
      timeout: 300_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    const r = JSON.parse(run.stdout);
    assert.equal(r.incomplete, true);
    assert.ok(r.controls.every((c) => c.status === "ran"), "every control ran: the corpus's old reading printed nothing");
    const reasons = incompleteReasons(r);
    assert.ok(reasons.some((w) => /could not obtain golang:1\.22, so the Go build did not run — Cannot connect to the Docker daemon/.test(w)), reasons.join("\n"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("each cause of an incomplete run is a line, and an unexplained one says so", () => {
  const ran = { name: "dep-audit", status: "ran", error: null };
  assert.deepEqual(
    incompleteReasons({
      incomplete: true,
      controls: [ran, { name: "secret-guard", status: "could-not-run", error: "spawn ENOENT" }, { name: "identity-guard", status: "could-not-run", error: null }],
      couldNotRun: ["build_check: docker is not installed or not on PATH"],
      configError: ".wolfproof.json is not valid JSON",
    }),
    ["secret-guard: spawn ENOENT", "identity-guard: never called", "build_check: docker is not installed or not on PATH", "config: .wolfproof.json is not valid JSON"]
  );
  // The document the gate writes when it fails outright carries only an error.
  assert.deepEqual(incompleteReasons({ incomplete: true, error: "the gate itself failed: boom" }), ["the gate itself failed: boom"]);
  assert.deepEqual(incompleteReasons({ incomplete: true, controls: [ran], couldNotRun: [] }), ["the run is marked incomplete and the document gives no reason"]);
  assert.deepEqual(incompleteReasons({ incomplete: false, controls: [ran], couldNotRun: [] }), []);
});
