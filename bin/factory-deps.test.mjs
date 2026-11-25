import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");

// Factory mode's dependency rule through the real CLI, because an exit code is a property of a
// process: a dependency nobody approved is exit 1 and the line says how to approve it, an approval
// in the pipeline's allowlist makes it exit 0, a manifest the rule cannot read is exit 3, and a
// manifest of an ecosystem it does not read is named above the verdict. The default mode does not
// run the rule. The rule itself is tested in lib/factory-deps.test.mjs.

const pkg = (deps) => `${JSON.stringify({ name: "p", version: "1.0.0", dependencies: deps }, null, 2)}\n`;
const lock = (pkgs, deps) => `${JSON.stringify({ name: "p", lockfileVersion: 3, requires: true, packages: { "": { name: "p", version: "1.0.0", dependencies: deps }, ...pkgs } }, null, 2)}\n`;
const entry = (name, version, extra = {}) => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: `sha512-${name}-${version}`, ...extra });

function cli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000, maxBuffer: 1 << 26 });
  let doc = null;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    /* not --json */
  }
  return { code: r.status, stdout: r.stdout || "", doc };
}

/** A repository whose first commit is `base` and second `change`, with the base's sha. */
function repo(base, change) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-deps-")));
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const write = (files) => {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), text);
    }
  };
  git("init", "-q");
  write(base);
  git("add", "-A");
  git("commit", "-qm", "base");
  const sha = git("rev-parse", "HEAD");
  write(change);
  git("add", "-A");
  git("commit", "-qm", "change");
  return { dir, sha, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const BASE = { "package.json": pkg({ "left-pad": "^1.1.0" }), "package-lock.json": lock({ "node_modules/left-pad": entry("left-pad", "1.1.3") }, { "left-pad": "^1.1.0" }), "a.js": "export const a = 1;\n" };
const rule = (doc) => (doc?.findings || []).map((f) => f.message).filter((m) => /^factory: (new dependency|dependency from a new source|install script|a range that takes anything)/.test(m));

test("a new dependency: exit 1 in factory mode with the entry that approves it, exit 0 once approved, the default mode untouched", () => {
  const r = repo(BASE, {
    "package.json": pkg({ "left-pad": "^1.1.0", "is-odd": "^3.0.1" }),
    "package-lock.json": lock(
      { "node_modules/left-pad": entry("left-pad", "1.1.3"), "node_modules/is-odd": entry("is-odd", "3.0.1", { dependencies: { "is-number": "^6.0.0" } }), "node_modules/is-number": entry("is-number", "6.0.0") },
      { "left-pad": "^1.1.0", "is-odd": "^3.0.1" }
    ),
  });
  const allow = path.join(realpathSync(tmpdir()), `factory-deps-allow-${process.pid}.json`);
  try {
    const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
    assert.equal(f.code, 1, JSON.stringify(f.doc?.couldNotRun));
    const [line, ...more] = rule(f.doc);
    assert.equal(more.length, 0, more.join("\n"));
    assert.match(line, /^factory: new dependency — npm package is-odd "\^3\.0\.1" in package\.json \(dependencies\), from the npm registry\. It adds 2 packages to package-lock\.json, none of which runs code when installed\./);
    assert.ok(line.endsWith('{"kind":"new-dependency","ecosystem":"npm","package":"is-odd","reason":"<why a person approved it>"}'), line);
    assert.equal(f.doc.factory.dependencies.findings.length, 1);

    writeFileSync(allow, JSON.stringify({ exemptions: [{ kind: "new-dependency", ecosystem: "npm", package: "is-odd", reason: "read by the platform team" }] }));
    const a = cli([r.dir, "--factory", `--base=${r.sha}`, `--allowlist=${allow}`]);
    assert.equal(a.code, 0, a.stdout);
    assert.match(a.stdout, /^factory deps   : 1 added by this change need approval: 0 blocking, 1 approved by the allowlist$/m);
    assert.match(a.stdout, /^factory grants : 0 predate the change, 1 allowlisted, 0 added by it$/m);

    const d = cli([r.dir, "--json"]);
    assert.equal(d.code, 0);
    assert.deepEqual(rule(d.doc), []);
    assert.equal(d.doc.factory, null, "no factory report in the default mode");
  } finally {
    rmSync(allow, { force: true });
    r.cleanup();
  }
});

test("a manifest the rule cannot read is exit 3 in factory mode, never a pass; the default mode does not read it for this rule", () => {
  const r = repo(BASE, { "tools/package.json": "{ not json\n" });
  try {
    const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
    assert.equal(f.code, 3);
    assert.ok(
      f.doc.couldNotRun.some((c) => /^factory: tools\/package\.json at the head could not be read by the dependency rule — it is not JSON .*Whether this change adds a dependency nobody approved is not known\.$/.test(c)),
      JSON.stringify(f.doc.couldNotRun)
    );
    const d = cli([r.dir, "--json"]);
    assert.ok(!d.doc.couldNotRun.some((c) => /dependency rule/.test(c)), JSON.stringify(d.doc.couldNotRun));
  } finally {
    r.cleanup();
  }
});

test("a manifest of an ecosystem the rule does not read is named above the verdict", () => {
  const r = repo(BASE, { "Cargo.toml": '[package]\nname = "p"\nversion = "0.1.0"\n' });
  try {
    const f = cli([r.dir, "--factory", `--base=${r.sha}`]);
    assert.match(f.stdout, /^factory deps   : not checked by this rule: Cargo\.toml \(crates\.io\)$/m);
    assert.ok(f.stdout.indexOf("factory deps") < f.stdout.indexOf("BLOCKING"), "above the verdict");
  } finally {
    r.cleanup();
  }
});
