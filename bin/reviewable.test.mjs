// The report prints no finding IDs, so when a blocking finding has one it says where to get it:
// `wolfproof review <project>`. Its own file, because it runs the real CLI twice and the suite has
// to finish inside the gate's own 120-second default for this repository.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "validate.mjs");

function run(args, cwd) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", cwd, timeout: 120_000 });
  return { code: r.status, stdout: r.stdout || "" };
}

function withApp(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "reviewable-"));
  writeFileSync(path.join(dir, "app.js"), "const app = require('express')();\napp.get('/report', report);\napp.get('/export', exportAll);\n");
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a blocking authentication finding points at wolfproof review, with the path as given", () => {
  withApp((dir) => {
    const r = run(["."], dir);
    assert.equal(r.code, 1, r.stdout.slice(-2000));
    const lines = r.stdout.split("\n").filter((l) => l.startsWith("reviewable"));
    assert.deepEqual(lines, [
      "reviewable      : 2 injection or authentication findings above can be marked reviewed once read — wolfproof review . lists their IDs",
    ]);
    // Under the verdict, before the advisories.
    const at = (s) => r.stdout.indexOf(s);
    assert.ok(at("\nBLOCKING        :") < at("\nreviewable      :") && at("\nreviewable      :") < at("\nadvisory        :"), r.stdout);
  });
});

test("the JSON report lists the IDs, and a reviewed route is not among them", () => {
  withApp((dir) => {
    writeFileSync(path.join(dir, ".wolfproof-reviewed.json"), JSON.stringify({ reviewed: [{ id: "authentication:GET /export:app.js", reason: "public export" }] }));
    const doc = JSON.parse(run([dir, "--json"]).stdout);
    assert.deepEqual(doc.reviewable, ["authentication:GET /report:app.js"]);
  });
});
