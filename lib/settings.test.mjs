import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { setting, legacySettingsInUse } from "./settings.mjs";
import { readConfig, resolveControls, CONFIG_FILE, LEGACY_CONFIG_FILE } from "./resolve-controls.mjs";

// agent-gate became wolfproof in v1.2.0, which read the old names too; since v1.3.0 only the new ones
// are read. An old name must not stop applying silently -- a pinned date or a declared control that
// quietly drops out changes what a verdict means with nothing saying so -- so each is reported.

test("a setting is read only as WOLFPROOF_*", () => {
  assert.equal(setting({ WOLFPROOF_TODAY: "2026-01-02" }, "TODAY"), "2026-01-02");
  assert.equal(setting({ AGENT_GATE_TODAY: "2026-01-02" }, "TODAY"), undefined, "the old name is no longer read");
  assert.equal(setting({ WOLFPROOF_TODAY: "" }, "TODAY"), undefined, "empty is unset");
  assert.equal(setting({}, "TODAY"), undefined);
});

test("every AGENT_GATE_* variable still set is named, with what to set instead", () => {
  assert.deepEqual(legacySettingsInUse({ AGENT_GATE_TODAY: "2026-01-02", AGENT_GATE_HOOKS_PATH: "/h", AGENT_GATE_EMPTY: "", PATH: "/bin" }), [
    { name: "AGENT_GATE_HOOKS_PATH", use: "WOLFPROOF_HOOKS_PATH" },
    { name: "AGENT_GATE_TODAY", use: "WOLFPROOF_TODAY" },
  ]);
  assert.deepEqual(legacySettingsInUse({ WOLFPROOF_TODAY: "x" }), []);
});

function project(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "settings-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(path.join(dir, name), body);
  return dir;
}

test("a project with only .agent-gate.json is an error, not a silent fallback", () => {
  const dir = project({ [LEGACY_CONFIG_FILE]: JSON.stringify({ controls: { "dep-audit": "./da.mjs" } }) });
  try {
    const r = readConfig(dir);
    assert.equal(CONFIG_FILE, ".wolfproof.json");
    assert.equal(r.config, null);
    assert.match(r.error, /\.agent-gate\.json is no longer read/);
    assert.match(r.error, /the controls it declares are not applied/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a control declared in .wolfproof.json is labelled with that file", () => {
  const dir = project({ [CONFIG_FILE]: JSON.stringify({ controls: { "dep-audit": "./da.mjs" } }) });
  try {
    const r = readConfig(dir);
    const da = resolveControls(dir, { config: r.config, configFile: r.file }).find((c) => c.name === "dep-audit");
    assert.equal(da.source, ".wolfproof.json controls.dep-audit");
    assert.match(da.error, /does not exist/, "a declared control pointing at nothing is an error");
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

test("a malformed config is an error", () => {
  const dir = project({ [CONFIG_FILE]: "{ not json" });
  try {
    assert.match(readConfig(dir).error, /^\.wolfproof\.json could not be parsed/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
