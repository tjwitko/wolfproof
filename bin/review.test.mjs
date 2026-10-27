// `wolfproof review` and `--reviewed`, through the real entry point (docs/candidate-rules.md #24).
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const CLI = fileURLToPath(new URL("./validate.mjs", import.meta.url));
const wolfproof = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
const APP = "const app = require('express')();\napp.get('/report', report);\n";

function dir() {
  const d = mkdtempSync(path.join(tmpdir(), "review-cli-"));
  writeFileSync(path.join(d, "app.js"), APP);
  return d;
}

test("review lists open routes by ID, writes an entry, replaces it, and marks it reviewed", () => {
  const d = dir();
  try {
    const list = wolfproof("review", d);
    assert.match(list.stdout, /^BLOCKING  authentication:GET \/report:app\.js$/m, list.stdout + list.stderr);
    const w = wolfproof("review", d, "authentication:GET /report:app.js", "--reason", "public report", "--reviewer", "tj");
    assert.equal(w.status, 0, w.stderr);
    assert.match(w.stdout, /^added in .*\.wolfproof-reviewed\.json:/);
    assert.match(w.stdout, /stops applying when the route's method, path or file changes/);
    const again = wolfproof("review", d, "authentication:GET /report:app.js", "--reason=still public", "--expires=2027-01-01");
    assert.match(again.stdout, /^replaced in /);
    const doc = JSON.parse(readFileSync(path.join(d, ".wolfproof-reviewed.json"), "utf8"));
    assert.deepEqual(doc, { reviewed: [{ id: "authentication:GET /report:app.js", reason: "still public", expires: "2027-01-01" }] });
    assert.match(wolfproof("review", d).stdout, /^reviewed  authentication:GET \/report:app\.js$/m);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("review refuses an entry the gate would ignore, and writes nothing", () => {
  const d = dir();
  try {
    for (const args of [
      ["authentication:GET /report:app.js"],
      ["authentication:GET /report:app.js", "--reason", "x", "--expires", "soon"],
      ["*", "--reason", "everything"],
    ]) {
      const r = wolfproof("review", d, ...args);
      assert.equal(r.status, 2, args.join(" "));
      assert.match(r.stderr, /^wolfproof review: this entry /);
    }
    assert.ok(!existsSync(path.join(d, ".wolfproof-reviewed.json")));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("--reviewed is refused inside the project and when it is not JSON, before anything runs", () => {
  const d = dir();
  const outside = mkdtempSync(path.join(tmpdir(), "review-list-"));
  try {
    writeFileSync(path.join(d, "reviewed.json"), JSON.stringify({ reviewed: [] }));
    const inside = wolfproof(d, `--reviewed=${path.join(d, "reviewed.json")}`);
    assert.equal(inside.status, 2);
    assert.match(inside.stderr, /is inside the project, where the code under test could edit it.*\.wolfproof-reviewed\.json/);
    writeFileSync(path.join(outside, "r.json"), "{ nope");
    const bad = wolfproof(d, `--reviewed=${path.join(outside, "r.json")}`);
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /could not be parsed as JSON/);
    assert.equal(wolfproof(d, "--reviewed").status, 2);
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
