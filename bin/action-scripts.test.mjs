// Every `run:` script in action.yml parses, as the runner receives it.
//
// The renderer is JavaScript inside a single-quoted `node -e '...'`, so one apostrophe in a comment
// ends the quote, and bash then fails with a syntax error after the gate has run: the verdict is
// computed and never reported. Nothing else in the test suite runs these scripts, so this checks
// all of them, not the one comment that broke it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { Script } from "node:vm";
import YAML from "yaml";

const yml = readFileSync(new URL("../action.yml", import.meta.url), "utf8");
const steps = YAML.parse(yml).runs.steps.filter((s) => typeof s.run === "string");

// GitHub replaces each ${{ ... }} expression in a `run:` script with its value as text before the
// shell sees it. A placeholder that is a plain word stands in for any value.
const asReceived = (run) => run.replace(/\$\{\{[^}]*\}\}/g, "EXPR");

test("action.yml has the run steps this test is meant to read", () => {
  assert.ok(steps.length >= 4, `found ${steps.length}`);
  assert.ok(steps.some((s) => s.id === "gate"), "the gate step");
});

for (const s of steps) {
  const name = s.name || s.id;
  const script = asReceived(s.run);

  test(`action.yml step "${name}": bash -n accepts its script`, () => {
    assert.equal(s.shell, "bash");
    const r = spawnSync("bash", ["-n"], { input: script, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
  });

  // A single-quoted bash word cannot contain a quote, so this match is exactly what bash passes to
  // node -e.
  const bodies = [...script.matchAll(/node -e '([^']*)'/g)].map((m) => m[1]);
  if (bodies.length) {
    test(`action.yml step "${name}": each node -e script compiles`, () => {
      for (const b of bodies) assert.doesNotThrow(() => new Script(b), b.slice(0, 80));
    });
  }
}

test("the renderer is one node -e script that reaches the BLOCKING line", () => {
  const gate = asReceived(steps.find((s) => s.id === "gate").run);
  const body = [...gate.matchAll(/node -e '([^']*)'/g)].map((m) => m[1]).find((b) => b.includes("r.controls"));
  assert.ok(body, "the renderer's script");
  assert.ok(body.includes("BLOCKING :") && body.includes("r.advisories"), "the whole renderer is inside the quotes");
});

// Run, not only parsed: the renderer prints the dependency rule's lines as the CLI does.
test("the renderer prints the dependency rule's lines, the same as the CLI", async () => {
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const path = await import("node:path");
  const { dependencyLines } = await import("./validate.mjs");
  const gate = asReceived(steps.find((s) => s.id === "gate").run);
  const body = [...gate.matchAll(/node -e '([^']*)'/g)].map((m) => m[1]).find((b) => b.includes("r.controls"));
  const dependencies = {
    findings: [{ blocking: true }, { blocking: false }],
    notRead: [{ path: "Cargo.toml", ecosystem: "crates.io" }],
  };
  const result = {
    controls: [], validatorsRun: [], findings: [], advisories: [], blocking: 1,
    factory: { base: { ref: "main", sha: "0123456789abcdef" }, grants: [], allowlist: null, policy: null,
      advisories: { blocked: 0, incomplete: 0, dropped: 0 }, dependencies },
  };
  const file = path.join(mkdtempSync(path.join(tmpdir(), "wp-render-")), "result.json");
  writeFileSync(file, JSON.stringify(result));
  const r = spawnSync(process.execPath, ["-e", body, file], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const printed = r.stdout.split("\n").filter((l) => l.startsWith("factory deps")).map((l) => l.replace(/^factory deps\s*:\s/, ""));
  assert.deepEqual(printed, dependencyLines(dependencies));
});
