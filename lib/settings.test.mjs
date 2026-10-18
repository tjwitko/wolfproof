import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { setting } from "./settings.mjs";
import { readConfig, resolveControls, CONFIG_FILE, LEGACY_CONFIG_FILE } from "./resolve-controls.mjs";

// agent-gate became wolfproof in v1.2.0. A setting or a config file under the old name must keep
// working -- a pinned date or a declared control that quietly stops applying on upgrade changes
// what a verdict means with nothing saying so.

test("a setting is read as WOLFPROOF_* first and AGENT_GATE_* second", () => {
  assert.equal(setting({ WOLFPROOF_TODAY: "2026-01-02" }, "TODAY"), "2026-01-02");
  assert.equal(setting({ AGENT_GATE_TODAY: "2026-01-02" }, "TODAY"), "2026-01-02", "the old name still works");
  assert.equal(setting({ WOLFPROOF_TODAY: "2026-01-02", AGENT_GATE_TODAY: "1999-01-01" }, "TODAY"), "2026-01-02", "the new name wins");
  assert.equal(setting({ WOLFPROOF_TODAY: "", AGENT_GATE_TODAY: "1999-01-01" }, "TODAY"), "1999-01-01", "empty is unset");
  assert.equal(setting({}, "TODAY"), undefined);
});

function project(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "settings-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(path.join(dir, name), body);
  return dir;
}

test("the config file is .wolfproof.json, and .agent-gate.json is still read -- with a note", () => {
  const dir = project({ [LEGACY_CONFIG_FILE]: JSON.stringify({ controls: { "dep-audit": "./da.mjs" } }) });
  try {
    const r = readConfig(dir);
    assert.equal(CONFIG_FILE, ".wolfproof.json");
    assert.deepEqual(r.config, { controls: { "dep-audit": "./da.mjs" } }, "the declaration still applies");
    assert.equal(r.file, LEGACY_CONFIG_FILE);
    assert.match(r.note, /Rename it to \.wolfproof\.json/);
    // A declared control is explicit: pointing at nothing is an error, labelled with the file read.
    const da = resolveControls(dir, { config: r.config, configFile: r.file }).find((c) => c.name === "dep-audit");
    assert.equal(da.source, ".agent-gate.json controls.dep-audit");
    assert.match(da.error, /does not exist/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("with both files, .wolfproof.json is read and the old one is named as ignored", () => {
  const dir = project({
    [CONFIG_FILE]: JSON.stringify({ controls: {} }),
    [LEGACY_CONFIG_FILE]: JSON.stringify({ controls: { "dep-audit": "./old.mjs" } }),
  });
  try {
    const r = readConfig(dir);
    assert.deepEqual(r.config, { controls: {} });
    assert.equal(r.file, CONFIG_FILE);
    assert.match(r.note, /\.agent-gate\.json is ignored/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("with only .wolfproof.json, or none, there is nothing to note", () => {
  const only = project({ [CONFIG_FILE]: "{}" });
  const none = project({});
  try {
    assert.equal(readConfig(only).note, null);
    assert.deepEqual(readConfig(none), { config: null, error: null, file: CONFIG_FILE, note: null });
  } finally {
    rmSync(only, { recursive: true, force: true });
    rmSync(none, { recursive: true, force: true });
  }
});

test("a malformed config is still an error, under whichever name was read", () => {
  const dir = project({ [LEGACY_CONFIG_FILE]: "{ not json" });
  try {
    assert.match(readConfig(dir).error, /^\.agent-gate\.json could not be parsed/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
