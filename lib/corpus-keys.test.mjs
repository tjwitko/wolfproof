// The corpus's finding keys decide what counts as drift, so each factory refusal must land on its own
// key. The ones lib/factory.mjs writes are taken from a real judgement; the ones bin/validate.mjs
// writes are spelled as its templates spell them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { findingId, factoryFindingId } from "./corpus-keys.mjs";
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
