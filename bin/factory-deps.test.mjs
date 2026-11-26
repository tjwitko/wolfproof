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

/** A repository whose first commit is `base` and second `change`, with the base's sha. A file given as null is deleted. */
function repo(base, change) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-deps-")));
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const write = (files) => {
    for (const [rel, text] of Object.entries(files)) {
      if (text === null) {
        rmSync(path.join(dir, rel), { force: true });
        continue;
      }
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
    assert.match(line, /^factory: new dependency — npm package is-odd "\^3\.0\.1" in package\.json \(dependencies\), from the npm registry\. It adds 2 packages to package-lock\.json \(with it: is-number 6\.0\.0\), none of which runs code when installed\./);
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

test("a new workspace member passes; a name new to the lockfile that only a version move brings blocks; a lockfile rewritten as version 1 is exit 3", () => {
  const wsPkg = `${JSON.stringify({ name: "p", version: "1.0.0", workspaces: ["packages/*"], dependencies: { "left-pad": "^1.1.0" } }, null, 2)}\n`;
  const member = (name) => `${JSON.stringify({ name, version: "1.0.0" }, null, 2)}\n`;
  const wsLock = (members) =>
    lock(
      { "node_modules/left-pad": entry("left-pad", "1.1.3"), ...Object.fromEntries(members.flatMap((m) => [[`packages/${m}`, { name: m, version: "1.0.0" }], [`node_modules/${m}`, { resolved: `packages/${m}`, link: true }]])) },
      { "left-pad": "^1.1.0" }
    );
  const wsBase = { "package.json": wsPkg, "package-lock.json": wsLock(["x"]), "packages/x/package.json": member("x"), "a.js": "export const a = 1;\n" };
  const cases = [
    ["a new member", wsBase, { "package-lock.json": wsLock(["x", "y"]), "packages/y/package.json": member("y") }, 0],
    [
      "an edge written under a version move",
      BASE,
      {
        "package.json": pkg({ "left-pad": "^1.3.0" }),
        "package-lock.json": lock({ "node_modules/left-pad": entry("left-pad", "1.3.0", { dependencies: { "is-number": "^6.0.0" } }), "node_modules/is-number": entry("is-number", "6.0.0") }, { "left-pad": "^1.3.0" }),
        "a.js": 'import n from "is-number";\nexport const a = n(1);\n',
      },
      1,
    ],
    [
      "version 1",
      BASE,
      { "package.json": pkg({ "left-pad": "^1.3.0" }), "package-lock.json": `${JSON.stringify({ name: "p", lockfileVersion: 1, requires: true, dependencies: { "left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" } } }, null, 2)}\n` },
      3,
    ],
  ];
  for (const [label, b, change, want] of cases) {
    const r = repo(b, change);
    try {
      const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
      assert.equal(f.code, want, `${label}: ${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)}`);
      if (want === 1) assert.match(rule(f.doc).join("\n"), /npm package is-number 6\.0\.0 in package-lock\.json, .*It is new to package-lock\.json, brought in by left-pad 1\.3\.0, which the project had at the base; no manifest declares it\./);
      if (want === 3) assert.ok(f.doc.couldNotRun.some((c) => /^factory: package-lock\.json at the head has lockfileVersion 1, so npm reads it as a lockfile from before npm 7, which records no install scripts/.test(c)), JSON.stringify(f.doc.couldNotRun));
    } finally {
      r.cleanup();
    }
  }
});

test(".npmrc as npm reads it, a setting on neither list, a lockfile npm reads as old, and pip's --trusted-host", () => {
  const moved = (doc) => ({ "package.json": pkg({ "left-pad": "^1.3.0" }), "package-lock.json": `${JSON.stringify(doc, null, 2)}\n` });
  const noVersion = { name: "p", requires: true, packages: { "": { name: "p", version: "1.0.0", dependencies: { "left-pad": "^1.3.0" } }, "node_modules/left-pad": entry("left-pad", "1.3.0") } };
  const cases = [
    ['"registry"= in quotes', BASE, { ".npmrc": '"registry"=https://r.example.invalid/\n' }, 1, /registry=https:\/\/r\.example\.invalid\/ in \.npmrc/],
    ["script-shell=, on neither list", BASE, { ".npmrc": "script-shell=./x.sh\n" }, 1, /which this rule does not know to leave what installs, and from where, as it was/],
    ["strict-ssl=0", BASE, { ".npmrc": "strict-ssl=0\n" }, 0, null],
    ["no lockfileVersion, packages kept", BASE, moved(noVersion), 3, null],
    ["--trusted-host", { "requirements.txt": "idna==3.7\n" }, { "requirements.txt": "--trusted-host pypi.example.invalid\nidna==3.7\n" }, 1, /--trusted-host pypi\.example\.invalid in requirements\.txt/],
  ];
  for (const [label, b, change, want, line] of cases) {
    const r = repo(b, change);
    try {
      const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
      assert.equal(f.code, want, `${label}: ${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)}`);
      if (line) assert.match(rule(f.doc).join("\n"), line, label);
      if (want === 3) assert.ok(f.doc.couldNotRun.some((c) => /^factory: package-lock\.json at the head has no lockfileVersion, so npm reads it as a lockfile from before npm 7/.test(c)), JSON.stringify(f.doc.couldNotRun));
    } finally {
      r.cleanup();
    }
  }
});

test("names that vouch for each other, a first lockfile, a registry taken away, a workspace character class, and an .npmrc key that is a list", () => {
  const A = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": entry("a", "1.0.0") }, { a: "^1.0.0" }), "a.js": "export const a = 1;\n" };
  const corp = (name, version) => ({ version, resolved: `https://npm.corp.example/${name}/-/${name}-${version}.tgz`, integrity: `sha512-${name}-${version}` });
  const py = (deps) => `[project]\nname = "p"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = ${JSON.stringify(deps)}\n`;
  const uvEntry = (n, v, deps = []) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\n${deps.length ? `dependencies = [${deps.map((d) => `{ name = "${d}" }`).join(", ")}]\n` : ""}wheels = [{ url = "https://files.pythonhosted.org/packages/x/${n}-${v}-py3-none-any.whl", hash = "sha256:${n}${v}" }]\n`;
  const uvLock = (...entries) => `version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "idna" }]\n\n[package.metadata]\nrequires-dist = [{ name = "idna", specifier = ">=3.7" }]\n\n${entries.join("\n")}`;
  const ws = (members) => ({
    "package.json": `${JSON.stringify({ name: "p", version: "1.0.0", workspaces: ["packages/[yz]"] })}\n`,
    "package-lock.json": lock(Object.fromEntries(members.flatMap((m) => [[`packages/${m}`, { name: m, version: "1.0.0", ...(m === "z" ? { dependencies: { y: "^1.0.0" } } : {}) }], [`node_modules/${m}`, { resolved: `packages/${m}`, link: true }]])), {}),
    ...Object.fromEntries(members.map((m) => [`packages/${m}/package.json`, `${JSON.stringify({ name: m, version: "1.0.0", ...(m === "z" ? { dependencies: { y: "^1.0.0" } } : {}) })}\n`])),
  });
  const cases = [
    ["x and y depend on each other", A, { "package-lock.json": lock({ "node_modules/a": entry("a", "1.0.2", { dependencies: { x: "1.0.0" } }), "node_modules/x": entry("x", "1.0.0", { dependencies: { y: "1.0.0" } }), "node_modules/y": entry("y", "1.0.0", { dependencies: { x: "1.0.0" } }) }, { a: "^1.0.0" }) }, 1, /npm package x 1\.0\.0 in package-lock\.json, .*brought in by a 1\.0\.2, which the project had at the base; .*With it comes 1 more package new to the lockfile \(y 1\.0\.0\)/],
    ["a first uv.lock", { "pyproject.toml": py(["idna>=3.7"]) }, { "uv.lock": uvLock(uvEntry("idna", "3.7", ["six"]), uvEntry("six", "1.17.0")) }, 1, /PyPI package six 1\.17\.0 in uv\.lock, .*brought in by idna 3\.7, which the project had at the base/],
    [".npmrc registry= taken away", { ...A, ".npmrc": "registry=https://npm.corp.example/\n", "package-lock.json": lock({ "node_modules/a": corp("a", "1.0.0") }, { a: "^1.0.0" }) }, { ".npmrc": null, "package-lock.json": lock({ "node_modules/a": entry("a", "1.0.2") }, { a: "^1.0.0" }) }, 1, /npm packages: registry=https:\/\/npm\.corp\.example\/ in \.npmrc at the base, and the head no longer names it/],
    ["--index-url made --extra-index-url", { "requirements.txt": "--index-url https://pypi.corp.example/simple\nidna==3.7\n" }, { "requirements.txt": "--extra-index-url https://pypi.corp.example/simple\nidna==3.7\n" }, 1, /the head names it only as --extra-index-url/],
    ["a new member under packages/[yz]", ws(["y"]), ws(["y", "z"]), 0, null],
    ["'[1,2,3]'=x in .npmrc", A, { ".npmrc": "'[1,2,3]'=x\n" }, 3, null],
  ];
  for (const [label, b, change, want, line] of cases) {
    const r = repo(b, change);
    try {
      const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
      assert.equal(f.code, want, `${label}: ${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)}`);
      if (line) assert.match(rule(f.doc).join("\n"), line, label);
      // The JSON names every package the finding counts, not only the first few.
      if (label === "x and y depend on each other") assert.deepEqual(f.doc.factory.dependencies.findings.find((x) => x.package === "x").brings.packages.map((p) => `${p.name} ${p.version}`).sort(), ["x 1.0.0", "y 1.0.0"]);
      if (want === 3) {
        assert.ok(f.doc.couldNotRun.some((c) => /^factory: \.npmrc at the head could not be read by the dependency rule — this rule could not read it \(line 1: its key, '\[1,2,3\]', is JSON that is not a string/.test(c)), JSON.stringify(f.doc.couldNotRun));
        assert.doesNotMatch(f.stdout, /TypeError|at npmrcSettings/);
      }
    } finally {
      r.cleanup();
    }
  }
});
