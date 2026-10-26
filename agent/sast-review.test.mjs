// Reviewed findings on the injection check (lib/reviewed.mjs, docs/candidate-rules.md #24). Its own
// file so node runs its four Semgrep scans beside the other injection tests rather than after them:
// the suite has to finish inside the gate's own 120-second default for this repository.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { sastFailures } from "./sast.mjs";
import { setting } from "../lib/settings.mjs";

const haveSemgrep = spawnSync("semgrep", ["--version"], { env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" } }).status === 0;
const required = setting(process.env, "REQUIRE_SCANNERS") === "1";
const scanner = (name, fn) =>
  test(name, { skip: !haveSemgrep && !required && "semgrep not installed" }, () => {
    assert.ok(haveSemgrep, "WOLFPROOF_REQUIRE_SCANNERS is set and semgrep is not on PATH");
    fn();
  });

function project(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "sast-"));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}

// Reviewing a finding through a helper (docs/candidate-rules.md #24): the review names the call line
// and the helper's line, not a line number. Lines moving keeps it; changing the helper voids it.
scanner("a review of a helper finding survives lines moving and is voided when the helper changes", () => {
  const helper = "def run_query(db, name):\n    return db.execute(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n";
  const route = "from flask import request\nfrom db import run_query\n\n@app.route('/u')\ndef u():\n    return run_query(db, request.args['n'])\n";
  const dir = project({ "db.py": helper, "routes.py": route });
  try {
    const first = sastFailures(dir);
    const id = first.ids.find((i) => i.startsWith("sast:python-sql-injection--via-helper:routes.py:"));
    assert.ok(id, first.ids.join("\n"));
    const reviews = [{ id, reason: "the table holds fixtures only", source: "test" }];
    const reviewed = sastFailures(dir, { reviews });
    assert.deepEqual([reviewed.failures.length, reviewed.reviewed.map((r) => r.id)], [0, [id]]);

    writeFileSync(path.join(dir, "routes.py"), "# moved down a line\n" + route);
    writeFileSync(path.join(dir, "db.py"), "# and this one too\n" + helper);
    assert.equal(sastFailures(dir, { reviews }).failures.length, 0, "the same lines, moved: still reviewed");

    writeFileSync(path.join(dir, "db.py"), "# and this one too\n" + helper.replace("def run_query(db, name):", "def run_query(db, name, table='u'):"));
    const after = sastFailures(dir, { reviews });
    assert.equal(after.reviewed.length, 0);
    assert.match(after.failures.join("\n"), /routes\.py:7 \(via run_query\(\) at db\.py:2\)/, "a changed helper is a new finding to review");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
