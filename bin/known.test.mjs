// `wolfproof known` and `--known`, through the real entry point (docs/candidate-rules.md #36).
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, realpathSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const CLI = fileURLToPath(new URL("./validate.mjs", import.meta.url));
const wolfproof = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
const git = (d, ...args) => spawnSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=t", ...args], { cwd: d, encoding: "utf8" });
const APP = "const app = require('express')();\napp.post('/items', add);\n";

function repo() {
  const d = realpathSync(mkdtempSync(path.join(tmpdir(), "known-cli-")));
  writeFileSync(path.join(d, "app.js"), APP);
  writeFileSync(path.join(d, "empty.js"), "");
  git(d, "init", "-q");
  git(d, "add", "-A");
  git(d, "commit", "-qm", "legacy");
  return d;
}
const commit = (d) => {
  git(d, "add", "-A");
  git(d, "commit", "-qm", "change");
};
const json = (r) => JSON.parse(r.stdout);

test("known snapshots what blocks; the gate then passes, a new finding blocks, and the snapshot only shrinks", () => {
  const d = repo();
  try {
    assert.equal(wolfproof(d).status, 1);
    const made = wolfproof("known", d);
    assert.equal(made.status, 0, made.stdout + made.stderr);
    assert.match(made.stdout, /^wrote 2 findings: 1 authentication, 1 empty files\.$/m);
    const file = path.join(d, ".wolfproof-known.json");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), {
      known: [
        { id: "authentication:POST /items:app.js", where: "POST /items (app.js:2)" },
        { id: "presence:empty:empty.js", where: "empty.js" },
      ],
    });
    commit(d);
    const clean = wolfproof(d, "--json");
    assert.equal(clean.status, 0, clean.stdout);
    assert.equal(json(clean).known.length, 2);
    assert.match(wolfproof(d).stdout, /^known +: 2 findings known from the snapshot \(\.wolfproof-known\.json\), not blocking/m);

    // A route added after the snapshot blocks, and is the one record the snapshot does not hold.
    writeFileSync(path.join(d, "app.js"), `${APP}app.post('/admin/delete', drop);\n`);
    commit(d);
    const fresh = wolfproof(d, "--json");
    assert.equal(fresh.status, 1);
    assert.deepEqual(
      json(fresh).records.filter((r) => !r.known).map((r) => [r.id, r.file, r.line, r.blocking]),
      [["authentication:POST /admin/delete:app.js", "app.js", 3, true]]
    );
    // Running known again does not add it, and leaves the file as it was.
    const before = readFileSync(file, "utf8");
    const again = wolfproof("known", d);
    assert.equal(again.status, 0);
    assert.match(again.stdout, /^unchanged: all 2 entries still match a finding/m);
    assert.match(again.stdout, /^still blocking: 1 finding the snapshot does not hold —/m);
    assert.equal(readFileSync(file, "utf8"), before);

    // Fixing a known finding lets the command remove its entry.
    rmSync(path.join(d, "empty.js"));
    const shrunk = wolfproof("known", d);
    assert.match(shrunk.stdout, /^removed 1 entry matching no finding \(1 empty files\); 1 remain\.$/m);
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")).known.map((e) => e.id), ["authentication:POST /items:app.js"]);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a snapshot kept outside the project applies through --known; inside, or unreadable, it is refused", () => {
  const d = repo();
  const outside = realpathSync(mkdtempSync(path.join(tmpdir(), "known-outside-")));
  try {
    const file = path.join(outside, "known.json");
    const made = wolfproof("known", d, "--file", file);
    assert.equal(made.status, 0, made.stderr);
    assert.match(made.stdout, /Pass it to the gate with --known=/);
    assert.ok(!existsSync(path.join(d, ".wolfproof-known.json")));
    assert.equal(wolfproof(d).status, 1);
    const r = wolfproof(d, `--known=${file}`, "--json");
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual([...new Set(json(r).known.map((k) => k.source))], [`--known ${file}`]);

    writeFileSync(path.join(d, "k.json"), "{}");
    const inside = wolfproof(d, `--known=${path.join(d, "k.json")}`);
    assert.equal(inside.status, 2);
    assert.match(inside.stderr, /is inside the project, where the code under test could edit it.*\.wolfproof-known\.json/);
    writeFileSync(file, "{ nope");
    assert.equal(wolfproof(d, `--known=${file}`).status, 2);
    assert.equal(wolfproof(d, "--known").status, 2);
    assert.equal(wolfproof("known", d, "--file").status, 2);
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

// runKnown against a gate that returns `result`, from a snapshot holding `held` (none: no file).
async function known(held, result, args = []) {
  const { runKnown } = await import("./known.mjs");
  const d = realpathSync(mkdtempSync(path.join(tmpdir(), "known-unit-")));
  const file = path.join(d, ".wolfproof-known.json");
  if (held) writeFileSync(file, JSON.stringify({ known: held }));
  const gate = { runGate: async () => ({ known: [], staleKnown: [], records: [], failures: [], couldNotRun: [], incomplete: false, ...result }), UsageError: Error };
  const write = process.stdout.write;
  let out = "";
  process.stdout.write = (s) => ((out += s), true);
  try {
    const code = await runKnown([d, ...args], { gate });
    return { code, out, doc: existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null };
  } finally {
    process.stdout.write = write;
    rmSync(d, { recursive: true, force: true });
  }
}

test("with part of the gate not run, an existing snapshot loses nothing, and what would have gone is listed", async () => {
  const held = [{ id: "dependencies:npm/lodash:GHSA-jf85-cpcp-j695" }, { id: "presence:empty:gone.js" }];
  const r = await known(held, {
    staleKnown: [{ id: "dependencies:npm/lodash:GHSA-jf85-cpcp-j695" }],
    couldNotRun: ["check_dependencies: dep-audit could not scan"],
    incomplete: true,
  });
  assert.equal(r.code, 3);
  assert.deepEqual(r.doc.known, held);
  assert.match(r.out, /^unchanged: part of the gate could not run \(listed below\), so no entry was removed or added\.$/m);
  assert.match(r.out, /^1 entry matched no finding in this run \(1 dependency vulnerabilities\) and would have been removed:\n  - dependencies:npm\/lodash:GHSA-jf85-cpcp-j695\n/m);
  // The first snapshot still writes what it can, as documented.
  const first = await known(null, { known: [{ id: "presence:empty:a.js", where: "a.js" }], couldNotRun: ["sast: semgrep timed out"], incomplete: true });
  assert.equal(first.code, 3);
  assert.deepEqual(first.doc.known, [{ id: "presence:empty:a.js", where: "a.js" }]);
});
