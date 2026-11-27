import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "fs";
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
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "", doc };
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

test("a name moved to the public registry, a registry setting that counts where the tool reads it, and poetry's PyPI source", () => {
  const corp = (name, version) => ({ version, resolved: `https://npm.corp.example/${name}/-/${name.split("/").pop()}-${version}.tgz`, integrity: `sha512-${name}-${version}` });
  const INDEX = "--index-url https://pypi.corp.example/simple";
  const scoped = { "package.json": pkg({ "@corp/lib": "^1.0.0" }), ".npmrc": "@corp:registry=https://npm.corp.example/\n", "package-lock.json": lock({ "node_modules/@corp/lib": corp("@corp/lib", "1.0.0") }, { "@corp/lib": "^1.0.0" }) };
  const gitSpec = "git+https://github.com/corp/lib.git#v1.0.0";
  const member = (name, deps) => `${JSON.stringify({ name, version: "1.0.0", ...(deps ? { dependencies: deps } : {}) })}\n`;
  const ws = (range, extra = {}) => ({
    "package.json": `${JSON.stringify({ name: "p", version: "1.0.0", workspaces: ["packages/*"] })}\n`,
    "packages/y/package.json": member("y"),
    "packages/z/package.json": member("z", { y: range }),
    "package-lock.json": lock({ "packages/y": { name: "y", version: "1.0.0" }, "packages/z": { name: "z", version: "1.0.0", dependencies: { y: range } }, "node_modules/y": { resolved: "packages/y", link: true }, "node_modules/z": { resolved: "packages/z", link: true }, ...extra }, {}),
  });
  const py = (extra) => `[project]\nname = "p"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = ["lib>=1"]\n\n[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n${extra}`;
  const uvLock = (version, index, host) => `version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "lib" }]\n\n[package.metadata]\nrequires-dist = [{ name = "lib" }]\n\n[[package]]\nname = "lib"\nversion = "${version}"\nsource = { registry = "${index}" }\nwheels = [{ url = "${host}/lib-${version}-py3-none-any.whl", hash = "sha256:lib${version}" }]\n`;
  const poetry = `[tool.poetry]\nname = "p"\nversion = "1.0.0"\n\n[tool.poetry.dependencies]\npython = "^3.10"\nidna = "^3.7"\n\n[[tool.poetry.source]]\nname = "PyPI"\npriority = "primary"\n`;
  const poetryLock = `[[package]]\nname = "idna"\nversion = "3.7"\ndescription = ""\noptional = false\npython-versions = ">=3.5"\nfiles = [{ file = "idna-3.7-py3-none-any.whl", hash = "sha256:82fee1fc78add43492d3a1898bfa6d8a904cc97d8427f683ed8e798d07761aa0" }]\n\n[metadata]\nlock-version = "2.0"\npython-versions = "^3.10"\ncontent-hash = "x"\n`;
  const cases = [
    ["a scope's package, its entry moved to registry.npmjs.org", scoped, { "package-lock.json": lock({ "node_modules/@corp/lib": { ...entry("@corp/lib", "1.0.2"), resolved: "https://registry.npmjs.org/@corp/lib/-/lib-1.0.2.tgz" } }, { "@corp/lib": "^1.0.0" }) }, 1, /npm package @corp\/lib "\^1\.0\.0" in package\.json, package-lock\.json, from the npm registry: its source changed \(the base took it from https:\/\/npm\.corp\.example\/@corp\/lib\/-\/lib-1\.0\.0\.tgz\)/],
    ["the same package, a version move at the scope's registry", scoped, { "package-lock.json": lock({ "node_modules/@corp/lib": corp("@corp/lib", "1.0.2") }, { "@corp/lib": "^1.0.0" }) }, 0, null],
    ["uv.lock: the project's index to pypi.org", { "pyproject.toml": py(""), "uv.lock": uvLock("1.0.0", "https://pypi.corp.example/simple", "https://pypi.corp.example/files") }, { "uv.lock": uvLock("1.0.2", "https://pypi.org/simple", "https://files.pythonhosted.org/packages/x") }, 1, /PyPI package lib "1\.0\.2" in uv\.lock, from PyPI: its source changed \(the base took it from the index https:\/\/pypi\.corp\.example\/simple\)/],
    ["git, then a range", { "package.json": pkg({ lib: gitSpec }), "package-lock.json": lock({ "node_modules/lib": { version: "1.0.0", resolved: "git+ssh://git@github.com/corp/lib.git#0123456789abcdef0123456789abcdef01234567" } }, { lib: gitSpec }) }, { "package.json": pkg({ lib: "^1.0.0" }), "package-lock.json": lock({ "node_modules/lib": entry("lib", "1.0.0") }, { lib: "^1.0.0" }) }, 1, /npm package lib "\^1\.0\.0" in package\.json, package-lock\.json, from the npm registry: its source changed \(the base took it from git\+https:\/\/github\.com\/corp\/lib\.git#v1\.0\.0\)/],
    ["a member's range moved past the member's version", ws("^1.0.0"), ws("^2.0.0", { "packages/z/node_modules/y": entry("y", "2.0.0") }), 1, /npm package y "\^2\.0\.0" in packages\/z\/package\.json, package-lock\.json, from the npm registry: its source changed \(the base took it from the project's own packages\/y\)/],
    ["--index-url taken from one of two requirements files", { "requirements.txt": `${INDEX}\nidna==3.7\n`, "requirements-dev.txt": `${INDEX}\npytest==8.0.0\n` }, { "requirements.txt": "idna==3.7\n" }, 1, /--index-url https:\/\/pypi\.corp\.example\/simple in requirements\.txt at the base, and the head no longer names it/],
    ["registry= moved to another directory's .npmrc", { "package.json": pkg({ "left-pad": "^1.3.0" }), ".npmrc": "registry=https://npm.corp.example/\n", "package-lock.json": lock({ "node_modules/left-pad": entry("left-pad", "1.2.0") }, { "left-pad": "^1.2.0" }) }, { ".npmrc": null, "tools/.npmrc": "registry=https://npm.corp.example/\n", "package-lock.json": lock({ "node_modules/left-pad": entry("left-pad", "1.3.0") }, { "left-pad": "^1.2.0" }) }, 1, /registry=https:\/\/npm\.corp\.example\/ in \.npmrc at the base, and the head no longer names it/],
    // The other file is not Python: with a .py file the gate also runs ruff, which a machine may not have.
    ["poetry's PyPI source with no url, and a change to another file", { "pyproject.toml": poetry, "poetry.lock": poetryLock, "notes.txt": "one\n" }, { "notes.txt": "two\n" }, 0, null],
  ];
  for (const [label, b, change, want, line] of cases) {
    const r = repo(b, change);
    try {
      const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
      assert.equal(f.code, want, `${label}: ${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)} ${JSON.stringify((f.doc?.findings || []).map((x) => x.message.slice(0, 120)))}`);
      if (line) assert.match(rule(f.doc).join("\n"), line, label);
      if (want === 1) assert.ok(rule(f.doc).every((m) => /^factory: dependency from a new source/.test(m)), `${label}: ${JSON.stringify(rule(f.doc))}`);
    } finally {
      r.cleanup();
    }
  }
});

test("another package's file on a registry the project names, in a lockfile and in a manifest; a uv workspace's member reads the root's index", () => {
  const MIRROR = "https://mirror.corp.example/npm/";
  const at = (name, version, file = `${name}-${version}.tgz`, dir = name) => ({ version, resolved: `${MIRROR}${dir}/-/${file}`, integrity: `sha512-${file}` });
  const mirrored = (spec, e) => ({ ".npmrc": `registry=${MIRROR}\n`, "package.json": pkg({ "left-pad": spec }), "package-lock.json": lock({ "node_modules/left-pad": e }, { "left-pad": spec }) });
  const root = `[project]\nname = "p"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = ["idna>=3"]\n\n[tool.uv.workspace]\nmembers = ["libs/*"]\n\n[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\ndefault = true\n`;
  const proj = (name, deps = "[]", extra = "") => `[project]\nname = "${name}"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = ${deps}\n${extra}`;
  const uvLock = (edge) =>
    `version = 1\nrequires-python = ">=3.10"\n\n[manifest]\nmembers = ["m", "o", "p"]\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "idna" }]\n\n[package.metadata]\nrequires-dist = [{ name = "idna", specifier = ">=3" }]\n\n` +
    `[[package]]\nname = "m"\nversion = "1.0.0"\nsource = { virtual = "libs/m" }\n${edge ? 'dependencies = [{ name = "o" }]\n\n[package.metadata]\nrequires-dist = [{ name = "o", virtual = "libs/o" }]\n' : ""}\n[[package]]\nname = "o"\nversion = "1.0.0"\nsource = { virtual = "libs/o" }\n\n` +
    `[[package]]\nname = "idna"\nversion = "3.7"\nsource = { registry = "https://pypi.corp.example/simple" }\nwheels = [{ url = "https://pypi.corp.example/files/idna-3.7-py3-none-any.whl", hash = "sha256:idna37" }]\n`;
  const ws = { "pyproject.toml": root, "libs/m/pyproject.toml": proj("m"), "libs/o/pyproject.toml": proj("o"), "uv.lock": uvLock(false), "notes.txt": "one\n" };
  const cases = [
    ["a lockfile entry at another package's file on the registry .npmrc names", mirrored("^1.1.0", at("left-pad", "1.1.0")), { "package-lock.json": lock({ "node_modules/left-pad": { ...at("is-odd", "3.0.1"), version: "1.1.3" } }, { "left-pad": "^1.1.0" }) }, 1, /npm package left-pad "1\.1\.3" in package-lock\.json, from https:\/\/mirror\.corp\.example\/npm\/is-odd\/-\/is-odd-3\.0\.1\.tgz: the lockfile takes left-pad 1\.1\.3 from a file of the registry's that is not that package's/],
    ["a version move to the package's own file there", mirrored("^1.1.0", at("left-pad", "1.1.0")), { "package-lock.json": lock({ "node_modules/left-pad": at("left-pad", "1.1.3") }, { "left-pad": "^1.1.0" }) }, 0, null],
    ["a manifest's range made the URL of another package's file there", mirrored("^1.1.0", at("left-pad", "1.1.0")), mirrored(`${MIRROR}is-odd/-/is-odd-3.0.1.tgz`, { ...at("is-odd", "3.0.1") }), 1, /npm package left-pad "https:\/\/mirror\.corp\.example\/npm\/is-odd\/-\/is-odd-3\.0\.1\.tgz" in package\.json, package-lock\.json, .*package\.json takes left-pad from a file of the registry's that is not that package's/],
    ["a uv workspace's member starts to depend on another member", ws, { "libs/m/pyproject.toml": proj("m", '["o"]', "\n[tool.uv.sources]\no = { workspace = true }\n"), "uv.lock": uvLock(true) }, 0, null],
    ["the same workspace, another file edited", ws, { "notes.txt": "two\n" }, 0, null],
  ];
  for (const [label, b, change, want, line] of cases) {
    const r = repo(b, change);
    try {
      const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
      assert.equal(f.code, want, `${label}: ${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)} ${JSON.stringify((f.doc?.findings || []).map((x) => x.message.slice(0, 120)))}`);
      if (line) assert.match(rule(f.doc).join("\n"), line, label);
      if (want === 1) assert.ok(rule(f.doc).every((m) => /^factory: dependency from a new source/.test(m)), `${label}: ${JSON.stringify(rule(f.doc))}`);
    } finally {
      r.cleanup();
    }
  }
});

test("the reviewer's cases: an entry's path, a linked manifest, a password in a URL, a URL that is not one, ./local, a skipped directory, and a file that is another package's", () => {
  // A made-up word in the place a password or token has in a URL: the test is that it is not printed.
  const MARK = "zq7-made-up-0123456789";
  const withPassword = (host, rest) => `https://${["user", MARK].join(":")}@${host}${rest}`;
  const outside = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-deps-outside-")));
  const allowFile = path.join(outside, "allowlist.json");
  const REQ = { "api/requirements.txt": "idna==3.7\n", "web/requirements.txt": "idna==3.7\n", "notes.txt": "one\n" };
  const six = "idna==3.7\nsix==1.17.0\n";
  const forSix = (p) => ({ kind: "new-dependency", ecosystem: "PyPI", package: "six", path: p, reason: `for ${p}` });
  const ONE = { "requirements.txt": "idna==3.7\n", "notes.txt": "one\n" };
  const GH = "https://npm.pkg.github.com/";
  const gh = (at, version) => ({ version, resolved: `${GH}download/${at}/${version}/0123456789abcdef0123456789abcdef01234567`, integrity: `sha512-${at}-${version}` });
  const scoped = (e) => ({ ".npmrc": `@corp:registry=${GH}\n`, "package.json": pkg({ "@corp/lib": "^1.0.0" }), "package-lock.json": lock({ "node_modules/@corp/lib": e }, { "@corp/lib": "^1.0.0" }), "a.js": "export const a = 1;\n" });
  const CORP = "https://pypi.corp.example/simple";
  const py = `[project]\nname = "p"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = ["lib"]\n\n[[tool.uv.index]]\nname = "corp"\nurl = "${CORP}"\ndefault = true\n`;
  const uv = (v, file) => ({ "pyproject.toml": py, "notes.txt": "one\n", "uv.lock": `version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "lib" }]\n\n[package.metadata]\nrequires-dist = [{ name = "lib" }]\n\n[[package]]\nname = "lib"\nversion = "${v}"\nsource = { registry = "${CORP}" }\nwheels = [{ url = "https://pypi.corp.example/files/${file}", hash = "sha256:${file}" }]\n` });
  const member = { "package.json": pkg({}), "package-lock.json": lock({}, {}), "local/package.json": `${JSON.stringify({ name: "local", version: "1.0.0" })}\n`, "local/index.js": "export const l = 1;\n" };
  const run = (base, change, { allow, after } = {}) => {
    const r = repo(base, change);
    try {
      if (after) after(r.dir);
      if (allow) writeFileSync(allowFile, JSON.stringify({ exemptions: allow }));
      return cli([r.dir, "--json", "--factory", `--base=${r.sha}`, ...(allow ? [`--allowlist=${allowFile}`] : [])]);
    } finally {
      r.cleanup();
    }
  };
  const said = (f) => `${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)} ${JSON.stringify((f.doc?.findings || []).map((x) => x.message.slice(0, 120)))} ${f.stderr.slice(0, 300)}`;
  try {
    // An entry for api approves api's manifest and not web's, whichever is read first.
    const both = { "api/requirements.txt": six, "web/requirements.txt": six };
    for (const p of ["api", "web"]) {
      const f = run(REQ, both, { allow: [forSix(p)] });
      assert.equal(f.code, 1, `an entry for ${p}: ${said(f)}`);
      assert.match(rule(f.doc).join("\n"), /^factory: new dependency — PyPI package six "six==1\.17\.0" in api\/requirements\.txt, web\/requirements\.txt \(requirements\)/);
    }
    const each = run(REQ, both, { allow: [forSix("api"), forSix("web")] });
    assert.equal(each.code, 0, said(each));
    assert.deepEqual(each.doc.factory.dependencies.findings.map((x) => x.approvedBy), ["for api; for web"]);

    // A manifest that is a link is not opened, and what it points at is not printed.
    writeFileSync(path.join(outside, "elsewhere.txt"), `TOKEN=${MARK}\n`);
    const linked = run(ONE, { "notes.txt": "two\n" }, { after: (dir) => { rmSync(path.join(dir, "requirements.txt")); symlinkSync(path.join(outside, "elsewhere.txt"), path.join(dir, "requirements.txt")); spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-qam", "link"]); } });
    assert.equal(linked.code, 3, said(linked));
    assert.match(linked.doc.couldNotRun.join("\n"), /factory: requirements\.txt at the head could not be read by the dependency rule — it is a symbolic link, which this rule does not follow\./);
    assert.ok(!(linked.stdout + linked.stderr).includes(MARK), "the file outside the project is not printed");

    // A password in an index URL is in no line, and the entry the line writes out approves the finding.
    const cred = { "requirements.txt": `--index-url ${withPassword("pypi.corp.example", "/simple")}\nidna==3.7\n` };
    const shown = run(ONE, cred);
    assert.equal(shown.code, 1, said(shown));
    const [line] = rule(shown.doc);
    assert.match(line, /^factory: dependency from a new source — PyPI packages: index-url https:\/\/pypi\.corp\.example\/simple in requirements\.txt, from https:\/\/pypi\.corp\.example\/simple: /);
    assert.ok(!(shown.stdout + shown.stderr).includes(MARK), "the password is not printed");
    const copied = JSON.parse(line.slice(line.lastIndexOf('{"kind"')));
    assert.deepEqual(copied, { kind: "dependency-source", ecosystem: "PyPI", source: "https://pypi.corp.example/simple", reason: "<why a person approved it>" });
    const approved = run(ONE, cred, { allow: [{ ...copied, reason: "the platform team's index" }] });
    assert.deepEqual(rule(approved.doc), [], said(approved));
    assert.deepEqual(approved.doc.factory.dependencies.findings.map((x) => x.blocking === true), [false]);

    // A URL that cannot be decoded or parsed: exit 3 that names the file, from a gate that did not fall over.
    for (const u of ["https://registry.npmjs.org/left-pad/-/%zz", "https://"]) {
      const f = run(BASE, { "package-lock.json": lock({ "node_modules/left-pad": { version: "1.1.4", resolved: u, integrity: "sha512-x" } }, { "left-pad": "^1.1.0" }) });
      assert.equal(f.code, 3, `${u}: ${said(f)}`);
      assert.ok(f.doc && !f.doc.error, `${u}: a result, not a gate that failed: ${f.stderr.slice(0, 200)}`);
      assert.ok(f.doc.couldNotRun.some((c) => c.includes(`factory: package-lock.json at the head could not be read by the dependency rule — it gives a URL this rule cannot read as one: ${u}.`)), said(f));
      assert.doesNotMatch(f.stderr, /the gate itself failed|\n\s+at /);
    }
    const entry = run(BASE, { "a.js": "export const a = 2;\n" }, { allow: [{ kind: "dependency-source", ecosystem: "npm", package: "left-pad", source: "https://", reason: "x" }] });
    assert.equal(entry.code, 3, said(entry));
    assert.match(entry.doc.couldNotRun.join("\n"), /factory: the allowlist's entry \{"kind":"dependency-source","ecosystem":"npm","package":"left-pad","source":"https:\/\/"\} names a source that starts as a URL and cannot be read as one\./);

    // ./local is the directory, as npm reads it.
    const local = run(member, { "package.json": pkg({ local: "./local" }), "package-lock.json": lock({ "node_modules/local": { resolved: "local", link: true }, local: { name: "local", version: "1.0.0" } }, { local: "./local" }) });
    assert.deepEqual(rule(local.doc), [], said(local));
    assert.equal(local.code, 0, said(local));

    // A manifest written under a directory the walks skip is blocked by the check on such writes;
    // once a person approves the place, this rule still names the file as one it did not read.
    const skipped = run(ONE, { "build/requirements.txt": "six==1.17.0\n" });
    assert.equal(skipped.code, 1, said(skipped));
    assert.match(skipped.doc.findings.map((x) => x.message).join("\n"), /factory: 1 file\(s\) this change wrote under build, where every source check skips build\/ — build\/requirements\.txt\./);
    const placed = run(ONE, { "build/requirements.txt": "six==1.17.0\n" }, { allow: [{ kind: "skipped-location", path: "build", reason: "generated by the release job" }] });
    assert.equal(placed.code, 0, said(placed));
    assert.deepEqual(placed.doc.factory.dependencies.notRead, [{ path: "build/requirements.txt", ecosystem: "under build/, a directory this rule does not read" }]);

    // Another package's file: on a registry whose paths have no /-/, and on a Python index.
    const cases = [
      ["a scoped entry at another package's path on GitHub's registry", scoped(gh("@corp/lib", "1.0.0")), { "package-lock.json": lock({ "node_modules/@corp/lib": gh("@other/evil", "1.0.2") }, { "@corp/lib": "^1.0.0" }) }, 1, /npm package @corp\/lib "1\.0\.2" in package-lock\.json, from https:\/\/npm\.pkg\.github\.com\/download\/@other\/evil\/1\.0\.2\/0123456789abcdef0123456789abcdef01234567: the lockfile takes @corp\/lib 1\.0\.2 from a file of the registry's that is not that package's/],
      ["a version move to its own path there", scoped(gh("@corp/lib", "1.0.0")), { "package-lock.json": lock({ "node_modules/@corp/lib": gh("@corp/lib", "1.0.2") }, { "@corp/lib": "^1.0.0" }) }, 0, null],
      ["a uv.lock entry whose wheel is another package's, on the project's index", uv("1.0.0", "lib-1.0.0-py3-none-any.whl"), uv("1.0.2", "other-1.0.2-py3-none-any.whl"), 1, /PyPI package lib "1\.0\.2" in uv\.lock, from https:\/\/pypi\.corp\.example\/files\/other-1\.0\.2-py3-none-any\.whl: the lockfile takes lib 1\.0\.2 from a file of the registry's that is not that package's/],
      ["a version move to its own wheel there", uv("1.0.0", "lib-1.0.0-py3-none-any.whl"), uv("1.0.2", "lib-1.0.2-py3-none-any.whl"), 0, null],
      // A package.json under the root's lockfile that is not a member of its workspace: nothing pins its ranges.
      ["a nested manifest's range made *, under a lockfile that does not cover it", { ...BASE, "tools/package.json": pkg({ "is-odd": "^3.0.1" }) }, { "tools/package.json": pkg({ "is-odd": "*" }) }, 1, /^factory: a range that takes anything — npm package is-odd "\*" in tools\/package\.json \(dependencies\), and no lockfile pins what installs/],
      ["the same manifest edited, its range left alone", { ...BASE, "tools/package.json": pkg({ "is-odd": "^3.0.1" }) }, { "tools/package.json": pkg({ "is-odd": "^3.0.1" }).replace('"version"', '"description": "tools",\n  "version"') }, 0, null],
    ];
    for (const [label, b, change, want, expected] of cases) {
      const f = run(b, change);
      assert.equal(f.code, want, `${label}: ${said(f)}`);
      if (expected) assert.match(rule(f.doc).join("\n"), expected, label);
    }
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});

test("the seventh review's cases: two entries of one name and version, a lockfile the change adds, a linked path, a plain git scheme, a ref that is a branch's name", () => {
  const outside = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-deps-outside7-")));
  const py = `[project]\nname = "p"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = ["six"]\n`;
  const top = `version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "six" }]\n\n[package.metadata]\nrequires-dist = [{ name = "six" }]\n`;
  const six = `\n[[package]]\nname = "six"\nversion = "1.17.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "https://files.pythonhosted.org/packages/b7/six-1.17.0-py2.py3-none-any.whl", hash = "sha256:six1170" }]\n`;
  const gitSix = `\n[[package]]\nname = "six"\nversion = "1.17.0"\nsource = { git = "https://github.com/evil/six?rev=abc#0123456789abcdef0123456789abcdef01234567" }\n`;
  const pipLock = (def, dev) => `${JSON.stringify({ _meta: { sources: [{ name: "pypi", url: "https://pypi.org/simple", verify_ssl: true }] }, default: def, develop: dev }, null, 2)}\n`;
  const pinned = { six: { version: "==1.17.0" } };
  const tools = (range) => pkg({ "is-odd": range });
  const SHA = "0123456789abcdef0123456789abcdef01234567";
  const cases = [
    ["uv.lock gains a git entry for six 1.17.0, written before the registry's entry", { "pyproject.toml": py, "uv.lock": top + six, "notes.txt": "one\n" }, { "uv.lock": top + gitSix + six }, 1, /PyPI package six "1\.17\.0" in uv\.lock, from https:\/\/github\.com\/evil\/six/],
    ["Pipfile.lock: default's six moves to git, develop keeps the registry's", { Pipfile: '[packages]\nsix = "==1.17.0"\n', "Pipfile.lock": pipLock(pinned, pinned), "notes.txt": "one\n" }, { "Pipfile.lock": pipLock({ six: { git: "https://github.com/evil/six", ref: "abc" } }, pinned) }, 1, /PyPI package six "" in Pipfile\.lock, from https:\/\/github\.com\/evil\/six/],
    ["a nested manifest's range made *, and the change adds a yarn.lock that holds a comment", { ...BASE, "tools/package.json": tools("^3.0.1") }, { "tools/package.json": tools("*"), "tools/yarn.lock": "# yarn lockfile v1\n" }, 1, /a range that takes anything — npm package is-odd "\*" in tools\/package\.json/],
    ["a manifest no lockfile covers: a git dependency moved from https to git://, the same tag", { ...BASE, "tools/package.json": pkg({ lib: "git+https://github.com/corp/lib.git#v1.2.3" }) }, { "tools/package.json": pkg({ lib: "git://github.com/corp/lib.git#v1.2.3" }) }, 1, /dependency from a new source — npm package lib "git:\/\/github\.com\/corp\/lib\.git#v1\.2\.3" in tools\/package\.json/],
    ["the same, from a commit to #v2", { ...BASE, "tools/package.json": pkg({ lib: `git+https://github.com/corp/lib.git#${SHA}` }) }, { "tools/package.json": pkg({ lib: "git+https://github.com/corp/lib.git#v2" }) }, 1, /a range that takes anything — npm package lib "git\+https:\/\/github\.com\/corp\/lib\.git#v2" in tools\/package\.json/],
    ["the same, from a commit to #v1.2.3", { ...BASE, "tools/package.json": pkg({ lib: `git+https://github.com/corp/lib.git#${SHA}` }) }, { "tools/package.json": pkg({ lib: "git+https://github.com/corp/lib.git#v1.2.3" }) }, 0, null],
    ["package.json gains x: file:pkgs/x, and pkgs/x is a link to a directory outside the project", BASE, { "package.json": pkg({ "left-pad": "^1.1.0", x: "file:pkgs/x" }), "package-lock.json": lock({ "node_modules/left-pad": entry("left-pad", "1.1.3"), "node_modules/x": { resolved: "pkgs/x", link: true } }, { "left-pad": "^1.1.0", x: "file:pkgs/x" }) }, 1, /npm package x "file:pkgs\/x" in package\.json.*through pkgs\/x, a symbolic link out of what this gate reads/, (dir) => {
      mkdirSync(path.join(outside, "x"), { recursive: true });
      writeFileSync(path.join(outside, "x", "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
      mkdirSync(path.join(dir, "pkgs"), { recursive: true });
      symlinkSync(path.join(outside, "x"), path.join(dir, "pkgs", "x"));
    }],
  ];
  try {
    for (const [label, b, change, want, line, link] of cases) {
      const r = repo(b, change);
      try {
        if (link) {
          link(r.dir);
          const git = (...a) => spawnSync("git", ["-C", r.dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" });
          git("add", "-A");
          git("commit", "-qm", "link");
        }
        const f = cli([r.dir, "--json", "--factory", `--base=${r.sha}`]);
        assert.equal(f.code, want, `${label}: ${JSON.stringify(rule(f.doc))} ${JSON.stringify(f.doc?.couldNotRun)} ${JSON.stringify((f.doc?.findings || []).map((x) => x.message.slice(0, 120)))}`);
        if (line) assert.match(rule(f.doc).join("\n"), line, label);
      } finally {
        r.cleanup();
      }
    }
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});
