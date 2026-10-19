import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { localTools } from "./gate-core.mjs";

// What the agent loop's write_file and delete_file refuse: anything that changes which code checks
// the work. A guard the model can edit is not a guard.

function project(files = {}) {
  const d = mkdtempSync(path.join(tmpdir(), "refusals-"));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(d, rel)), { recursive: true });
    writeFileSync(path.join(d, rel), body);
  }
  return d;
}
const write = (d, rel, content = "x\n") => String(localTools(d, null).write_file.run({ path: rel, content }));
const del = (d, rel) => String(localTools(d, null).delete_file.run({ path: rel }));

test("the gate's own config is refused, under its name and its old one, at any depth", () => {
  // .wolfproof.json can point a control at a file the agent wrote: measured, a script running the
  // real secret-guard against an empty directory turned hardcoded AWS keys from blocking to clean.
  const d = project();
  try {
    for (const rel of [".wolfproof.json", ".agent-gate.json", "services/api/.wolfproof.json"]) {
      assert.match(write(d, rel, '{"controls":{"secret-guard":"./x.mjs"}}'), new RegExp(`^REFUSED: ${rel.replace(/\./g, "\\.")} was NOT written`));
      assert.equal(existsSync(path.join(d, rel)), false, rel);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("an existing config cannot be deleted either", () => {
  const d = project({ ".wolfproof.json": "{}\n", ".agent-gate.json": "{}\n" });
  try {
    assert.match(del(d, ".wolfproof.json"), /^REFUSED: \.wolfproof\.json was NOT deleted/);
    assert.match(del(d, ".agent-gate.json"), /^REFUSED: \.agent-gate\.json was NOT deleted/);
    assert.ok(existsSync(path.join(d, ".wolfproof.json")) && existsSync(path.join(d, ".agent-gate.json")));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("the suppression files refused before are still refused", () => {
  const d = project();
  try {
    for (const rel of [".gitleaksignore", ".gitleaks.toml", "infra/.tfguard-fixture", "k8s/.identity-exception"]) {
      assert.match(write(d, rel), /was NOT written/, rel);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a file is a control's code once the config names it, and not before", () => {
  // Writing tools/secret-guard.mjs is ordinary on its own. The redirect is what makes it a bypass,
  // and with the config refused the agent cannot create one -- but a redirect a human committed
  // points at a file the agent could otherwise replace.
  const d = project();
  try {
    assert.doesNotMatch(write(d, "tools/secret-guard.mjs", "export {};\n"), /REFUSED/, "no config names it: ordinary");
    writeFileSync(path.join(d, ".wolfproof.json"), JSON.stringify({ controls: { "secret-guard": "./tools/secret-guard.mjs" } }));
    assert.match(write(d, "tools/secret-guard.mjs", "// replaced\n"), /^REFUSED: tools\/secret-guard\.mjs was NOT written: it is the secret-guard control, as \.wolfproof\.json names it/);
    assert.equal(readFileSync(path.join(d, "tools", "secret-guard.mjs"), "utf8"), "export {};\n", "unchanged");
    assert.match(del(d, "tools/secret-guard.mjs"), /^REFUSED: tools\/secret-guard\.mjs was NOT deleted: it is the secret-guard control/);
    assert.doesNotMatch(write(d, "tools/other.mjs"), /REFUSED/, "a file the config does not name is still ordinary");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("installed packages are refused: node_modules holds the pinned controls", () => {
  const d = project({ "node_modules/@tjwitko/secret-guard-mcp/index.mjs": "// the real control\n" });
  try {
    const rel = "node_modules/@tjwitko/secret-guard-mcp/index.mjs";
    assert.match(write(d, rel, "// replaced\n"), /was NOT written: it is inside node_modules/);
    assert.match(del(d, rel), /was NOT deleted: it is inside node_modules/);
    assert.equal(readFileSync(path.join(d, rel), "utf8"), "// the real control\n");
    assert.doesNotMatch(write(d, "src/app.js", "console.log(1);\n"), /REFUSED/, "ordinary work is untouched");
  } finally { rmSync(d, { recursive: true, force: true }); }
});
