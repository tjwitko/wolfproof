import test from "node:test";
import assert from "node:assert/strict";

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { approvingEntry, canonicalGit, canonicalSource, findingLine, inventory, judgeDependencies, markerDirs, normalName, npmSpec, parseGoMod, parseRequirements, pyFileNamed, registryFileMatches, treeOf, withoutCredentials, workspaceMatches } from "./factory-deps.mjs";
import { allowlisted, dependencyTree, GRANT_KINDS, judgeDependencyChange, parseAllowlist } from "./factory.mjs";

// Factory mode's dependency rule (lib/factory-deps.mjs), on trees held in memory: what blocks, what
// passes, what the approver is told, and that what it cannot read is could-not-run. The CLI's half
// is bin/factory-deps.test.mjs.

const tree = (files) => treeOf(Object.keys(files), (r) => files[r] ?? null, markerDirs(Object.keys(files)));
const judge = (base, head, exemptions = []) =>
  judgeDependencies(inventory(tree(head)), inventory(tree(base)), {
    changed: Object.keys(head).map((p) => ({ path: p })),
    allowlist: parseAllowlist({ exemptions }).entries,
  });
const blocking = (r) => r.findings.filter((f) => !f.approvedBy).map((f) => `${f.kind}:${f.package}`).sort();

const pkg = (deps, extra = {}) => JSON.stringify({ name: "p", version: "1.0.0", dependencies: deps, ...extra });
const lock = (pkgs, root = {}) => JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "p", ...root }, ...pkgs } });
const reg = (n, v, extra = {}) => ({ version: v, resolved: `https://registry.npmjs.org/${n}/-/${n.split("/").pop()}-${v}.tgz`, integrity: `sha512-${n}-${v}`, ...extra });
const base = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0") }) };

test("a version move of a dependency the project had passes, and so do the packages it brings that the base had", () => {
  const had = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { b: "^1" } }), "node_modules/b": reg("b", "1.0.0") }) };
  const r = judge(had, {
    "package.json": pkg({ a: "^1.1.0" }),
    "package-lock.json": lock({ "node_modules/a": reg("a", "1.1.0", { dependencies: { b: "^2" } }), "node_modules/b": reg("b", "2.0.0") }),
  });
  assert.deepEqual(blocking(r), []);
  assert.deepEqual(r.errors, []);
});

test("removing a dependency passes", () => {
  assert.deepEqual(blocking(judge(base, { "package.json": pkg({}), "package-lock.json": lock({}) })), []);
});

test("a new direct dependency blocks, and the line carries what a person approves from", () => {
  const r = judge(base, {
    "package.json": pkg({ a: "^1.0.0", x: "^3.0.0" }),
    "package-lock.json": lock({
      "node_modules/a": reg("a", "1.0.0"),
      "node_modules/x": reg("x", "3.0.0", { dependencies: { y: "^1", s: "^1" } }),
      "node_modules/y": reg("y", "1.0.0"),
      "node_modules/s": reg("s", "1.0.0", { hasInstallScript: true }),
    }),
  });
  assert.deepEqual(blocking(r), ["install-script:s", "new-dependency:x"]);
  const line = findingLine(r.findings.find((f) => f.kind === "new-dependency"));
  for (const part of ['npm package x "^3.0.0"', "in package.json (dependencies)", "from the npm registry", "It adds 3 packages to package-lock.json", "1 of them runs code when installed (s)"]) {
    assert.ok(line.includes(part), `${part} in: ${line}`);
  }
  assert.ok(line.endsWith('{"kind":"new-dependency","ecosystem":"npm","package":"x","reason":"<why a person approved it>"}'), line);
  assert.match(findingLine(r.findings.find((f) => f.kind === "install-script")), /brought in by x/);
});

test("a new dependency the lockfile already held says it adds nothing", () => {
  const r = judge({ ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { y: "^1" } }), "node_modules/y": reg("y", "1.0.0") }) }, {
    "package.json": pkg({ a: "^1.0.0", y: "^1.0.0" }),
    "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { y: "^1" } }), "node_modules/y": reg("y", "1.0.0") }),
  });
  assert.deepEqual(blocking(r), ["new-dependency:y"]);
  assert.match(findingLine(r.findings[0]), /It adds no package to package-lock\.json, which already held it/);
});

test("with no lockfile, what a new dependency brings is said to be unknown", () => {
  const r = judge({ "package.json": pkg({}) }, { "package.json": pkg({ x: "^1.0.0" }) });
  assert.deepEqual(blocking(r), ["new-dependency:x"]);
  assert.match(findingLine(r.findings[0]), /There is no lockfile, so which packages it brings, and whether any runs code when it is installed, is not known/);
});

test("an npm alias installs the package it names: on an existing name it is a new dependency", () => {
  const r = judge(base, { "package.json": pkg({ a: "npm:other-package@1" }), "package-lock.json": lock({ "node_modules/a": { ...reg("other-package", "1.0.0"), name: "other-package" } }) });
  assert.deepEqual(blocking(r), ["new-dependency:other-package"]);
  assert.match(findingLine(r.findings[0]), /declared as a/);
});

test("a lockfile-only change: an entry nothing declares or brings in, and an entry edited in place", () => {
  assert.deepEqual(blocking(judge(base, { ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/evil": reg("evil", "1.0.0") }) })), ["new-dependency:evil"]);
  // Declaring it in the lockfile's own record of the project does not make it reachable: an install starts from package.json.
  assert.deepEqual(blocking(judge(base, { ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/evil": reg("evil", "1.0.0") }, { dependencies: { a: "^1", evil: "1" } }) })), ["new-dependency:evil"]);
  for (const [label, edit] of [
    ["resolved moved", { resolved: "https://npm.elsewhere.example/a-1.0.0.tgz" }],
    ["integrity changed", { integrity: "sha512-something-else" }],
    ["a dependency added", { dependencies: { evil: "1" } }],
  ]) {
    const r = judge(base, { ...base, "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.0"), ...edit } }) });
    assert.ok(blocking(r).includes("dependency-source:a"), `${label}: ${blocking(r)}`);
  }
  const moved = judge(base, { ...base, "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.0"), resolved: "https://npm.elsewhere.example/a-1.0.0.tgz" } }) });
  assert.match(findingLine(moved.findings[0]), /from https:\/\/npm\.elsewhere\.example\/a-1\.0\.0\.tgz/);
});

test("a lockfile entry that takes another package's file from the registry blocks", () => {
  // The registry serves every package, so an entry pointed at another package's tarball is from the
  // registry and installs that package's code under this name.
  const r = judge(base, { "package.json": pkg({ a: "^1.0.1" }), "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.1"), resolved: "https://registry.npmjs.org/other/-/other-9.9.9.tgz" } }) });
  assert.deepEqual(blocking(r), ["dependency-source:a"]);
  assert.match(findingLine(r.findings[0]), /from a file of the registry's that is not that package's/);
  const scoped = judge(base, { ...base, "package.json": pkg({ a: "^1.0.0", "@s/b": "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/@s/b": reg("@s/b", "1.0.0") }) });
  assert.deepEqual(blocking(scoped), ["new-dependency:@s/b"], "a scoped package's own tarball");
  const uv = (url) => `[[package]]\nname = "p"\nversion = "0"\nsource = { editable = "." }\n\n[[package]]\nname = "x"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "${url}", hash = "sha256:aaa" }]\n`;
  const py = { "pyproject.toml": '[project]\nname = "p"\ndependencies = ["x>=1"]\n', "uv.lock": uv("https://files.pythonhosted.org/packages/x-1.0-py3-none-any.whl") };
  assert.deepEqual(blocking(judge(py, { ...py, "uv.lock": uv("https://files.pythonhosted.org/packages/other-1.0-py3-none-any.whl") })), ["dependency-source:x"]);
});

test("hasInstallScript removed from a lockfile entry by hand blocks as an entry edited in place", () => {
  // Measured on npm 11.17.0 with a local package whose postinstall writes a file: with the flag
  // removed, npm ci, npm install and npm rebuild all left the script unrun. So the flag is what npm
  // runs by, and removing it is an edit npm would not make, not a way to run the script unseen.
  const withScript = { ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { hasInstallScript: true }) }) };
  const r = judge(withScript, base);
  assert.deepEqual(blocking(r), ["dependency-source:a"]);
  assert.match(findingLine(r.findings[0]), /its install-script flag \(removed\) changed while the version did not/);
});

test("install scripts: a new package with one, direct or brought in, and one whose base versions had none", () => {
  const scripted = (v) => ({ ...base, "package-lock.json": lock({ "node_modules/a": reg("a", v, { hasInstallScript: true }) }), "package.json": pkg({ a: `^${v}` }) });
  assert.deepEqual(blocking(judge(base, scripted("1.1.0"))), ["install-script:a"], "a version move that brings a script");
  assert.deepEqual(blocking(judge(scripted("1.0.0"), scripted("1.1.0"))), [], "a script the base's version already ran");
});

test("a range that takes anything, added or changed, with no lockfile", () => {
  for (const spec of ["*", "", "latest", "next", "x", ">=0", "1 || *", "github:someone/x#main", "github:someone/x"]) {
    const r = judge({ "package.json": pkg({ x: "1.0.0" }) }, { "package.json": pkg({ x: spec }) });
    assert.ok(blocking(r).includes("unpinned-range:x"), `${JSON.stringify(spec)}: ${blocking(r)}`);
  }
  for (const spec of ["^1.0.0", "1.x", "github:someone/x#v1.2.0", "github:someone/x#3f2a9c1"]) {
    const r = judge({ "package.json": pkg({ x: "1.0.0" }) }, { "package.json": pkg({ x: spec }) });
    assert.ok(!blocking(r).includes("unpinned-range:x"), `${JSON.stringify(spec)}: ${blocking(r)}`);
  }
  // A lockfile pins what installs; a range already there is not this change's.
  assert.deepEqual(blocking(judge(base, { "package.json": pkg({ a: "*" }), "package-lock.json": base["package-lock.json"] })), []);
  assert.deepEqual(blocking(judge({ "package.json": pkg({ x: "*" }) }, { "package.json": pkg({ x: "*" }), "a.js": "" })), []);
});

test("sources: a new dependency from git, an existing one moved to git, and a control's tag moving", () => {
  assert.deepEqual(blocking(judge(base, { ...base, "package.json": pkg({ a: "^1.0.0", x: "git+https://github.com/someone/x.git#v1.0.0" }) })), ["dependency-source:x", "new-dependency:x"]);
  assert.deepEqual(blocking(judge(base, { ...base, "package.json": pkg({ a: "git+https://github.com/someone/a.git#v1.0.0" }) })), ["dependency-source:a"]);
  assert.deepEqual(blocking(judge(base, { ...base, "package.json": pkg({ a: "https://files.example/a-1.0.0.tgz" }) })), ["dependency-source:a"]);
  assert.deepEqual(blocking(judge(base, { ...base, "package.json": pkg({ a: "file:../outside/a" }) })), ["dependency-source:a"]);
  assert.deepEqual(blocking(judge(base, { ...base, "package.json": pkg({ a: "^1.0.0", own: "file:./libs/own" }) })), [], "a path inside the project is its own code");
  const pin = (tag, sha) => ({
    "package.json": pkg({ c: `git+https://github.com/tjwitko/c.git#${tag}` }),
    "package-lock.json": lock({ "node_modules/c": { version: tag.slice(1), resolved: `git+ssh://git@github.com/tjwitko/c.git#${sha}` } }),
  });
  assert.deepEqual(blocking(judge(pin("v1.0.4", "aaaaaaa"), pin("v1.0.5", "bbbbbbb"))), [], "wolfproof's own control pins move from tag to tag");
});

test("registries and indexes the project's files name", () => {
  const cases = [
    [base, { ...base, ".npmrc": "registry=https://npm.elsewhere.example/\n" }, "dependency-source:null"],
    [base, { ...base, ".npmrc": "@corp:registry=https://npm.elsewhere.example/\n" }, "dependency-source:@corp"],
    [{ "requirements.txt": "requests==2.32.0\n" }, { "requirements.txt": "--index-url https://pypi.elsewhere.example/simple\nrequests==2.32.0\n" }, "dependency-source:null"],
    [{ "requirements.txt": "requests==2.32.0\n" }, { "requirements.txt": "--extra-index-url https://pypi.elsewhere.example/simple\nrequests==2.32.0\n" }, "dependency-source:null"],
    [{ "pyproject.toml": '[project]\nname="p"\ndependencies=["requests"]\n' }, { "pyproject.toml": '[project]\nname="p"\ndependencies=["requests"]\n[[tool.uv.index]]\nname="x"\nurl="https://pypi.elsewhere.example/simple"\n' }, "dependency-source:null"],
    [{ "pyproject.toml": '[tool.poetry.dependencies]\npython="^3.11"\nrequests="^2"\n' }, { "pyproject.toml": '[tool.poetry.dependencies]\npython="^3.11"\nrequests="^2"\n[[tool.poetry.source]]\nname="x"\nurl="https://pypi.elsewhere.example/simple"\n' }, "dependency-source:null"],
  ];
  for (const [b, h, want] of cases) assert.deepEqual(blocking(judge(b, h)), [want], JSON.stringify(h).slice(0, 160));
  // One the base already named is honoured, and so is what the lockfile takes from it.
  const corp = { ".npmrc": "registry=https://npm.corp.example/\n", "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.0"), resolved: "https://npm.corp.example/a/-/a-1.0.0.tgz" } }) };
  assert.deepEqual(blocking(judge(corp, { ...corp, "package.json": pkg({ a: "^1.0.0", b: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.0"), resolved: "https://npm.corp.example/a/-/a-1.0.0.tgz" }, "node_modules/b": { ...reg("b", "1.0.0"), resolved: "https://npm.corp.example/b/-/b-1.0.0.tgz" } }) })), ["new-dependency:b"]);
});

test("Python: requirements, -r includes, pyproject, poetry, Pipfile, names folded as PyPI folds them", () => {
  assert.deepEqual(blocking(judge({ "requirements.txt": "-r base.in\n", "base.in": "requests==2.32.0\n" }, { "requirements.txt": "-r base.in\n", "base.in": "requests==2.32.0\nnewpkg==1.0\n" })), ["new-dependency:newpkg"]);
  assert.deepEqual(blocking(judge({ "requirements.txt": "Foo_Bar==1.0\n" }, { "requirements.txt": "foo-bar==1.1\n" })), []);
  assert.deepEqual(blocking(judge({ "requirements.txt": "flask==3.0\n" }, { "pyproject.toml": '[project]\nname="p"\ndependencies=["Flask>=3"]\n' })), [], "a dependency moved from one manifest to another");
  assert.deepEqual(blocking(judge({ "pyproject.toml": '[project]\nname="p"\n' }, { "pyproject.toml": '[project]\nname="p"\ndependencies=["x @ git+https://github.com/someone/x.git@main"]\n' })), ["dependency-source:x", "new-dependency:x", "unpinned-range:x"]);
  assert.deepEqual(blocking(judge({ Pipfile: "[packages]\n" }, { Pipfile: '[packages]\nrequests = "*"\n' })), ["new-dependency:requests", "unpinned-range:requests"]);
  assert.deepEqual(blocking(judge({ Pipfile: "[packages]\n", "Pipfile.lock": "{}" }, { Pipfile: '[packages]\nrequests = "*"\n', "Pipfile.lock": '{"default":{"requests":{"version":"==2.32.0"}}}' })), ["new-dependency:requests"], "a lockfile pins what installs");
  assert.deepEqual(blocking(judge({ "pyproject.toml": "[build-system]\nrequires=[]\n" }, { "pyproject.toml": '[build-system]\nrequires=["setuptools>=61", "cython>=3"]\n' })), ["new-dependency:cython", "new-dependency:setuptools"], "what the build installs counts");
  assert.deepEqual(blocking(judge({ "pyproject.toml": '[project]\nname="p"\ndynamic=["dependencies"]\n[tool.setuptools.dynamic]\ndependencies={file=["deps.txt"]}\n', "deps.txt": "" }, { "pyproject.toml": '[project]\nname="p"\ndynamic=["dependencies"]\n[tool.setuptools.dynamic]\ndependencies={file=["deps.txt"]}\n', "deps.txt": "evil==1.0\n" })), ["new-dependency:evil"], "a file setuptools reads dependencies from");
});

test("Python lockfiles: what a new dependency brings, and a package that is built from source", () => {
  const uv = (pkgs) => pkgs.map(([n, v, { deps = [], wheel = true } = {}]) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\nsdist = { url = "https://files.pythonhosted.org/${n}-${v}.tar.gz" }\n${wheel ? `wheels = [{ url = "https://files.pythonhosted.org/${n}-${v}-py3-none-any.whl" }]\n` : ""}dependencies = [${deps.map((d) => `{ name = "${d}" }`).join(", ")}]\n`).join("\n");
  const proj = (deps) => `[project]\nname = "p"\ndependencies = [${deps.map((d) => `"${d}"`).join(", ")}]\n`;
  const r = judge({ "pyproject.toml": proj([]), "uv.lock": uv([["p", "0"]]) }, { "pyproject.toml": proj(["x>=1"]), "uv.lock": uv([["p", "0"], ["x", "1.0", { deps: ["y"] }], ["y", "2.0", { wheel: false }]]) });
  assert.deepEqual(blocking(r), ["install-script:y", "new-dependency:x"]);
  assert.match(findingLine(r.findings.find((f) => f.kind === "new-dependency")), /It adds 2 packages to uv\.lock \(with it: y 2\.0\), and 1 of them is built from source when installed, which runs its own code \(y\)/);
});

test("Python lockfiles edited in place: a file from outside the registry, a hash changed; a wheel added is a re-lock", () => {
  const proj = "[project]\nname = \"p\"\ndependencies = [\"x>=1\"]\n";
  const uv = (files) => `[[package]]\nname = "p"\nversion = "0"\nsource = { editable = "." }\n\n[[package]]\nname = "x"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [${files.map(([u, h]) => `{ url = "${u}", hash = "${h}" }`).join(", ")}]\n`;
  const w = (host, h = "sha256:aaa", file = "x-1.0-py3-none-any.whl") => [`https://${host}/packages/${file}`, h];
  const base = { "pyproject.toml": proj, "uv.lock": uv([w("files.pythonhosted.org")]) };
  assert.deepEqual(blocking(judge(base, { ...base, "uv.lock": uv([w("files.elsewhere.example")]) })), ["dependency-source:x"], "a wheel from another host");
  assert.deepEqual(blocking(judge(base, { ...base, "uv.lock": uv([w("files.pythonhosted.org", "sha256:bbb")]) })), ["dependency-source:x"], "the same file, another hash");
  assert.deepEqual(blocking(judge(base, { ...base, "uv.lock": uv([w("files.pythonhosted.org"), w("files.pythonhosted.org", "sha256:ccc", "x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl")]) })), [], "a wheel added for another platform");
  const poetry = (h) => `[[package]]\nname = "x"\nversion = "1.0"\nfiles = [{ file = "x-1.0-py3-none-any.whl", hash = "${h}" }]\n`;
  const pb = { "pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.11\"\nx = \"^1\"\n", "poetry.lock": poetry("sha256:aaa") };
  assert.deepEqual(blocking(judge(pb, { ...pb, "poetry.lock": poetry("sha256:bbb") })), ["dependency-source:x"]);
});

test("Go: a new module, a new replace, an indirect one the code imports, and the project's own modules", () => {
  const mod = (extra = "") => `module example.com/p\n\ngo 1.22\n\nrequire github.com/a/b v1.0.0\n${extra}`;
  const gob = { "go.mod": mod(), "go.sum": "github.com/a/b v1.0.0 h1:x=\n" };
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require github.com/new/x v1.0.0\n"), "go.sum": "github.com/a/b v1.0.0 h1:x=\ngithub.com/new/x v1.0.0 h1:y=\n" })), ["new-dependency:github.com/new/x"]);
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("\nreplace github.com/a/b => github.com/elsewhere/b v1.0.0\n") })), ["dependency-source:github.com/a/b"]);
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("\nreplace github.com/a/b => ./third_party/b\n") })), []);
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require github.com/new/x v1.0.0 // indirect\n"), "main.go": 'package main\n\nimport (\n\t"fmt"\n\tx "github.com/new/x/sub"\n)\n' })), ["new-dependency:github.com/new/x"]);
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require github.com/new/x v1.0.0 // indirect\n") })), [], "brought in by another module");
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require github.com/a/b v1.2.0\n").replace("require github.com/a/b v1.0.0\n", "") })), [], "a version move");
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require example.com/p/lib v0.0.0\n\nreplace example.com/p/lib => ./lib\n"), "lib/go.mod": "module example.com/p/lib\n\ngo 1.22\n" })), [], "a module of the project's own, replaced with its directory");
});

test("where a dependency is declared: a fixture's manifest is not the project's, and a move hides nothing", () => {
  const fixture = { "fixtures/x/.tfguard-fixture": "reason: a sample", "fixtures/x/package.json": pkg({ lodash: "4.17.4" }) };
  assert.deepEqual(blocking(judge({ ...base, ...fixture }, { ...base, ...fixture, "package.json": pkg({ a: "^1.0.0", lodash: "4.17.4" }) })), ["new-dependency:lodash"]);
  const moved = { "app/package.json": base["package.json"], "app/package-lock.json": base["package-lock.json"] };
  assert.deepEqual(blocking(judge(base, moved)), []);
  assert.deepEqual(blocking(judge(moved, base)), []);
  assert.deepEqual(blocking(judge(base, { ...moved, "app/package.json": pkg({ a: "^1.0.0", x: "^1.0.0" }) })), ["new-dependency:x"]);
  assert.deepEqual(blocking(judge(moved, { ...base, "package.json": pkg({ a: "^1.0.0", x: "^1.0.0" }) })), ["new-dependency:x"]);
  const links = { "packages/m": { name: "m" }, "packages/n": { name: "n" }, "node_modules/m": { resolved: "packages/m", link: true }, "node_modules/n": { resolved: "packages/n", link: true } };
  const ws = (m) => ({ "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), ...links }), "package.json": pkg({ a: "^1.0.0" }, { workspaces: ["packages/*"] }), "packages/m/package.json": JSON.stringify({ name: "m", dependencies: m }), "packages/n/package.json": JSON.stringify({ name: "n" }) });
  assert.deepEqual(blocking(judge(ws({}), ws({ x: "^1.0.0" }))), ["new-dependency:x"], "a workspace member");
  assert.deepEqual(blocking(judge(ws({}), ws({ n: "^1.0.0" }))), [], "a member depending on another member");
  assert.deepEqual(blocking(judge(base, { ...base, "tools/package.json": pkg({ x: "^1.0.0" }) })), ["new-dependency:x"], "a nested manifest");
});

test("a manifest or lockfile that cannot be read, at either end, is an error and never a pass", () => {
  for (const [label, b, h, side] of [
    ["package.json at the head", base, { ...base, "package.json": "{" }, "the head"],
    ["package-lock.json at the base", { ...base, "package-lock.json": "{" }, base, "the base"],
    ["pyproject.toml at the head", {}, { "pyproject.toml": "[project\n" }, "the head"],
    ["a requirements option", {}, { "requirements.txt": "--something-new x\n" }, "the head"],
    ["a requirement", {}, { "requirements.txt": "requests 2.0\n" }, "the head"],
    ["an include outside the project", {}, { "requirements.txt": "-r ../other.txt\n" }, "the head"],
    ["an include that is not there", {}, { "requirements.txt": "-r gone.txt\n" }, "the head"],
    ["go.mod", {}, { "go.mod": "module x\nfrobnicate y\n" }, "the head"],
    ["a file that cannot be opened", {}, { "package.json": null }, "the head"],
  ]) {
    const r = judge(b, h);
    assert.equal(r.errors.length, 1, `${label}: ${JSON.stringify(r.errors)}`);
    assert.equal(r.errors[0].side, side, label);
  }
});

test("an edited manifest of an ecosystem the rule does not read is named", () => {
  const r = judge(base, { ...base, "Cargo.toml": '[dependencies]\nserde = "1"\n', "web/yarn.lock": "", "setup.py": "" });
  assert.deepEqual(r.notRead.map((n) => `${n.path} (${n.ecosystem})`), ["Cargo.toml (crates.io)", "web/yarn.lock (npm, a file this rule does not read)", "setup.py (PyPI, a file this rule does not read)"]);
});

test("approval: each kind its own entry, by ecosystem and exact name, never by '*'", () => {
  const head = { "package.json": pkg({ a: "^1.0.0", x: "git+https://github.com/someone/x.git#v1.0.0" }), "package-lock.json": base["package-lock.json"] };
  const name = { kind: "new-dependency", ecosystem: "npm", package: "x", reason: "read by the platform team" };
  const src = (s) => ({ kind: "dependency-source", ecosystem: "npm", package: "x", source: s, reason: "our fork" });
  assert.deepEqual(blocking(judge(base, head, [name])), ["dependency-source:x"], "a name does not approve its source");
  assert.deepEqual(blocking(judge(base, head, [name, src("git+https://github.com/someone/x.git")])), []);
  assert.deepEqual(blocking(judge(base, head, [name, src("github:someone/x")])), [], "the same repository written another way");
  assert.deepEqual(blocking(judge(base, head, [name, src("git+https://github.com/other/x.git")])), ["dependency-source:x"], "another fork");
  assert.deepEqual(blocking(judge(base, head, [{ kind: "*", path: ".", reason: "everything" }])), ["dependency-source:x", "new-dependency:x"]);
  assert.deepEqual(blocking(judge({ "requirements.txt": "" }, { "requirements.txt": "yaml==1.0\n" }, [{ kind: "new-dependency", ecosystem: "npm", package: "yaml", reason: "r" }])), ["new-dependency:yaml"], "npm's yaml is not PyPI's");
  assert.deepEqual(blocking(judge({ "requirements.txt": "" }, { "requirements.txt": "Foo-Bar==1.0\n" }, [{ kind: "new-dependency", ecosystem: "pypi", package: "foo_bar", reason: "r" }])), []);
  const web = { "web/package.json": pkg({ z: "^1.0.0" }) };
  assert.deepEqual(blocking(judge({}, web, [{ kind: "new-dependency", ecosystem: "npm", package: "z", path: "api", reason: "r" }])), ["new-dependency:z"], "an entry narrowed to another directory");
  assert.deepEqual(blocking(judge({}, web, [{ kind: "new-dependency", ecosystem: "npm", package: "z", path: "web/package.json", reason: "r" }])), []);
  const approved = judge(base, head, [name]).findings.find((f) => f.kind === "new-dependency");
  assert.equal(approved.approvedBy, "read by the platform team");
});

test("the allowlist reads the four kinds by name and refuses entries that do not name one package", () => {
  for (const k of ["new-dependency", "dependency-source", "install-script", "unpinned-range"]) assert.ok(k in GRANT_KINDS, k);
  const { entries, ignored } = parseAllowlist({
    exemptions: [
      { kind: "new-dependency", ecosystem: "npm", package: "yaml", reason: "ok" },
      { kind: "new-dependency", ecosystem: "npm", package: "yaml*", reason: "a pattern" },
      { kind: "new-dependency", ecosystem: "cargo", package: "serde", reason: "not read" },
      { kind: "new-dependency", ecosystem: "npm", reason: "no package" },
      { kind: "dependency-source", ecosystem: "npm", package: "x", reason: "no source" },
      { kind: "install-script", ecosystem: "npm", package: "esbuild" },
    ],
  });
  assert.equal(entries.length, 1);
  assert.deepEqual(ignored.map((i) => i.why), [
    "names a pattern; an entry names one package exactly",
    'names no ecosystem this rule reads (ecosystem is "cargo"; it must be one of npm, PyPI, Go)',
    "names no package",
    "is a dependency-source entry with no source",
    "gives no reason",
  ]);
  // A dependency entry approves no grant of another kind, at any path.
  assert.equal(allowlisted({ kind: "new-dependency", path: "package.json" }, entries), null);
});

test("parsers: npm specs, git locations, requirements lines, go.mod", () => {
  assert.deepEqual(npmSpec("npm:@scope/real@^2", "package.json", "alias").real, "@scope/real");
  assert.equal(npmSpec("github:u/r#v1.0.0", "package.json", "r").anything, false);
  assert.equal(npmSpec("u/r", "package.json", "r").anything, true, "no ref is the default branch");
  for (const s of ["git+ssh://git@github.com/U/r.git#abc", "git+https://github.com/U/r.git", "github:U/r", "U/r", "git@github.com:U/r.git"]) assert.equal(canonicalGit(s), "github.com/U/r", s);
  assert.equal(normalName("PyPI", "Foo__Bar.baz"), "foo-bar-baz");
  assert.equal(normalName("npm", "Foo"), "Foo");
  const r = parseRequirements("# c\nflask[async]>=3 ; python_version >= '3.9'  # why\nrequests==2.32.0 \\\n  --hash=sha256:abc\n-e ./local\ngit+https://github.com/u/pkg.git@v1#egg=pkg\n", "requirements.txt");
  assert.deepEqual(r.deps.map((d) => [d.name, d.source.type, d.anything]), [["flask", "registry", false], ["requests", "registry", false], ["local", "path", false], ["pkg", "git", false]]);
  const g = parseGoMod('module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v0.1.0 // indirect\n)\n\nreplace github.com/a/b v1.0.0 => ../b\ntool golang.org/x/tools/cmd/stringer\n');
  assert.deepEqual(g.requires.map((x) => [x.path, x.indirect]), [["github.com/a/b", false], ["github.com/c/d", true]]);
  assert.deepEqual(g.replaces.map((x) => [x.path, x.to]), [["github.com/a/b", "../b"]]);
  assert.deepEqual(g.tools, ["golang.org/x/tools/cmd/stringer"]);
});

// ---------------------------------------------------------------------------------------------
// From the review of 94d2f76. Each case below was exit 0 in factory mode, or a false block.

const member = (name, extra = {}) => JSON.stringify({ name, version: "1.0.0", ...extra });
const wsLock = (members, pkgs = {}) =>
  lock(
    {
      ...Object.fromEntries(members.flatMap((m) => [[`packages/${m}`, { name: m, version: "1.0.0" }], [`node_modules/${m}`, { resolved: `packages/${m}`, link: true }]])),
      ...pkgs,
    },
    { workspaces: ["packages/*"] }
  );
const wsTree = (members, { pkgs = {}, deps = {} } = {}) => ({
  "package.json": pkg({}, { workspaces: ["packages/*"] }),
  "package-lock.json": wsLock(members, pkgs),
  ...Object.fromEntries(members.map((m) => [`packages/${m}/package.json`, member(m, deps[m] ? { dependencies: deps[m] } : {})])),
});

test("a workspace member is the project's own code: one that existed at the base, and a new one", () => {
  assert.deepEqual(blocking(judge(wsTree(["x"]), wsTree(["x", "y"]))), [], "a new member with no dependencies");
  assert.deepEqual(blocking(judge(wsTree(["x"]), wsTree(["x"], { deps: { x: {} } }))), [], "an existing member, edited");
  assert.deepEqual(blocking(judge(wsTree([]), wsTree(["x", "y"], { deps: { y: { x: "^1.0.0" } } }))), [], "a new member depending on another, linked in the lockfile");
  const outside = { ...wsTree(["x"]), "package-lock.json": wsLock(["x"], { "node_modules/z": { resolved: "../elsewhere/z", link: true } }) };
  assert.ok(blocking(judge(wsTree(["x"]), outside)).includes("dependency-source:z"), "a link to a path outside the project is not");
});

test("a name new to the lockfiles that no manifest declares, and that no new package brings in, is a new dependency", () => {
  // The lockfile is the change's to write: an edge from a version move, or from the lockfile's own
  // record of the project, brings in any name. Whether the code imports it does not matter.
  const head = {
    "package.json": pkg({ a: "^1.0.1" }),
    "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.1", { dependencies: { evil: "^1.0.1" } }), "node_modules/evil": reg("evil", "1.0.1", { dependencies: { "evil-dep": "^1" } }), "node_modules/evil-dep": reg("evil-dep", "1.0.0", { hasInstallScript: true }) }),
  };
  const r = judge(base, head);
  assert.deepEqual(blocking(r).filter((f) => f.startsWith("new-dependency")), ["new-dependency:evil"], "evil-dep comes with evil, which is new");
  assert.match(findingLine(r.findings.find((f) => f.package === "evil")), /It is new to package-lock\.json, brought in by a 1\.0\.1, which the project had at the base; no manifest declares it\. .* With it comes 1 more package new to the lockfile \(evil-dep 1\.0\.0\), and evil-dep runs code when installed\./);
  for (const code of ['import*as e from"evil"', 'import{x}from"evil"', 'import"evil"', 'export*from"evil"', 'const r = /\\/\\//; require("evil")', 'createRequire(import.meta.url)("evil")', 'require(require.resolve("evil"))', 'require("ev" + "il")']) {
    assert.deepEqual(blocking(judge(base, { ...head, "bin/run": `#!/usr/bin/env node\n${code}\n` })).filter((f) => f.startsWith("new-dependency")), ["new-dependency:evil"], code);
  }
  const fromRoot = { ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/evil": reg("evil", "1.0.1") }, { dependencies: { a: "^1.0.0", evil: "^1" } }) };
  assert.deepEqual(blocking(judge(base, fromRoot)), ["new-dependency:evil"], "brought in only by the lockfile's own record of the project");
  // An override chooses a version of a name; it does not declare one.
  assert.deepEqual(blocking(judge(base, { ...head, "package.json": pkg({ a: "^1.0.1" }, { overrides: { evil: "1.0.1" } }) })).filter((f) => f.startsWith("new-dependency")), ["new-dependency:evil"], "named only in overrides");
  // A version move that brings no new name passes; a new dependency's own packages are its finding's.
  assert.deepEqual(blocking(judge(base, { "package.json": pkg({ a: "^1.0.1" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.1") }) })), []);
  const added = judge(base, { "package.json": pkg({ a: "^1.0.0", n: "^1" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/n": reg("n", "1.0.0", { dependencies: { m: "^1" } }), "node_modules/m": reg("m", "1.0.0") }) });
  assert.deepEqual(blocking(added), ["new-dependency:n"]);
  assert.equal(added.findings[0].brings.count, 2);
  // A first lockfile: a declared at the base is not new, so b, which the project never had, is.
  assert.deepEqual(blocking(judge({ "package.json": pkg({ a: "^1.0.0" }) }, { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { b: "^1" } }), "node_modules/b": reg("b", "1.0.0") }) })), ["new-dependency:b"]);

  // uv.lock and poetry.lock record edges as npm's does.
  const uvp = (deps) => `[project]\nname = "p"\nversion = "1"\ndependencies = ${deps}\n`;
  const uvPkg = (n, v, deps = []) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\n${deps.length ? `dependencies = [${deps.map((d) => `{ name = "${d}" }`).join(", ")}]\n` : ""}wheels = [{ url = "https://files.pythonhosted.org/packages/x/${n}-${v}-py3-none-any.whl", hash = "sha256:${n}${v}" }]\n`;
  const uvLock = (...ps) => `version = 1\n\n[[package]]\nname = "p"\nversion = "1"\nsource = { virtual = "." }\ndependencies = [{ name = "idna" }]\n\n${ps.join("\n")}`;
  const uvBase = { "pyproject.toml": uvp('["idna==3.7"]'), "uv.lock": uvLock(uvPkg("idna", "3.7")) };
  assert.deepEqual(blocking(judge(uvBase, { ...uvBase, "uv.lock": uvLock(uvPkg("idna", "3.7", ["six"]), uvPkg("six", "1.17.0")) })), ["new-dependency:six"], "uv.lock");
  assert.deepEqual(blocking(judge(uvBase, { "pyproject.toml": uvp('["idna==3.8"]'), "uv.lock": uvLock(uvPkg("idna", "3.8")) })), [], "a uv version move");
  const poetry = (ps) => ps.map(([n, v, deps = []]) => `[[package]]\nname = "${n}"\nversion = "${v}"\nfiles = [{ file = "${n}-${v}-py3-none-any.whl", hash = "sha256:${n}" }]\n${deps.length ? `[package.dependencies]\n${deps.map((d) => `${d} = "*"`).join("\n")}\n` : ""}`).join("\n");
  const ppBase = { "pyproject.toml": '[tool.poetry.dependencies]\nidna = "3.7"\n', "poetry.lock": poetry([["idna", "3.7"]]) };
  assert.deepEqual(blocking(judge(ppBase, { ...ppBase, "poetry.lock": poetry([["idna", "3.7", ["six"]], ["six", "1.17.0"]]) })), ["new-dependency:six"], "poetry.lock");
  // Pipfile.lock records no edges: a new name passes only with a new declared one beside it.
  const pf = (names) => JSON.stringify({ _meta: { sources: [] }, default: Object.fromEntries(names.map(([n, v]) => [n, { version: `==${v}` }])), develop: {} });
  const pfBase = { Pipfile: '[packages]\nidna = "*"\n', "Pipfile.lock": pf([["idna", "3.7"]]) };
  const lone = judge(pfBase, { ...pfBase, "Pipfile.lock": pf([["idna", "3.7"], ["six", "1.17.0"]]) });
  assert.deepEqual(blocking(lone), ["new-dependency:six"], "Pipfile.lock, nothing new declared");
  assert.match(findingLine(lone.findings[0]), /Pipfile\.lock does not record which package brings which/);
  assert.deepEqual(blocking(judge(pfBase, { Pipfile: '[packages]\nidna = "*"\nrequests = "==2.32.0"\n', "Pipfile.lock": pf([["idna", "3.7"], ["requests", "2.32.0"], ["urllib3", "2.2.0"]]) })), ["new-dependency:requests"], "Pipfile.lock, beside a new declared one");
});

test("a lockfile entry that installs another package under an existing name blocks", () => {
  const swapped = { ...base, "package-lock.json": lock({ "node_modules/a": { ...reg("evil", "1.0.1"), name: "evil" } }) };
  const r = judge(base, swapped);
  assert.deepEqual(blocking(r), ["new-dependency:evil"]);
  assert.match(findingLine(r.findings[0]), /installed as a/);
  // An alias a dependency itself declares is how npm writes one: @isaacs/cliui's string-width-cjs.
  const viaParent = {
    "package.json": pkg({ a: "^1.0.0" }),
    "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { "w-cjs": "npm:w@^4" } }), "node_modules/w-cjs": { ...reg("w", "4.0.0"), name: "w" } }),
  };
  assert.deepEqual(blocking(judge(viaParent, viaParent)), []);
  const withBase = { ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { "w-cjs": "npm:w@^4" } }), "node_modules/w-cjs": { ...reg("w", "4.0.0"), name: "w" } }) };
  assert.deepEqual(blocking(judge(withBase, { ...withBase, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { "w-cjs": "npm:w@^4" } }), "node_modules/w-cjs": { ...reg("w", "4.1.0"), name: "w" } }) })), [], "a version move of an alias a dependency declares");
});

test("a lockfile whose format records no install scripts, where the change added or moved packages, cannot be judged", () => {
  const v1 = (deps) => JSON.stringify({ name: "p", lockfileVersion: 1, requires: true, dependencies: deps });
  const head = { "package.json": pkg({ a: "^1.0.1" }), "package-lock.json": v1({ a: { version: "1.0.1", resolved: "https://registry.npmjs.org/a/-/a-1.0.1.tgz", requires: { s: "^1" } }, s: { version: "1.0.0", resolved: "https://registry.npmjs.org/s/-/s-1.0.0.tgz" } }) };
  const r = judge(base, head);
  assert.equal(r.errors.length, 1, JSON.stringify(r.errors));
  assert.deepEqual(blocking(r), [], "the new name s is in the exit-3 line, and a lockfile this old may record no edges");
  assert.match(r.errors[0].text, /package-lock\.json at the head has lockfileVersion 1, so npm reads it as a lockfile from before npm 7, which records no install scripts \(the base's has lockfileVersion 3, so this change rewrote it in the older format\)\. The change adds or moves 2 packages in it \(a 1\.0\.1, s 1\.0\.0\)/);
  // Rewritten in the old format with nothing new in it is still reported.
  const same = judge(base, { ...base, "package-lock.json": v1({ a: { version: "1.0.0", resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz" } }) });
  assert.equal(same.errors.length, 1);
  assert.match(same.errors[0].text, /rewrote it in the older format\)\. Whether this change adds/);
  // Unchanged, or only removals: nothing new to judge.
  const v1base = { "package.json": pkg({ a: "^1.0.1" }), "package-lock.json": head["package-lock.json"] };
  assert.deepEqual(judge(v1base, v1base).errors, []);
  assert.deepEqual(judge(v1base, { ...v1base, "package-lock.json": v1({ a: { version: "1.0.1" } }) }).errors, []);
});

test("a name is the project's own only where the tool resolves it locally", () => {
  // npm: a member named like a registry package, at a version the range does not take.
  const npmBase = wsTree(["is-number", "y"]);
  const npmHead = wsTree(["is-number", "y"], { deps: { y: { "is-number": "^6.0.0" } }, pkgs: { "packages/y/node_modules/is-number": reg("is-number", "6.0.0") } });
  // It is a new dependency, and a name that was the project's own code now comes from the registry.
  assert.deepEqual(blocking(judge(npmBase, npmHead)), ["dependency-source:is-number", "new-dependency:is-number"]);
  assert.deepEqual(blocking(judge(npmBase, wsTree(["is-number", "y"], { deps: { y: { "is-number": "^1.0.0" } } }))), [], "linked in the lockfile");
  assert.deepEqual(blocking(judge(npmBase, { ...npmBase, "packages/y/package.json": member("y", { dependencies: { "is-number": "workspace:*" } }) })), [], "a workspace: range");
  // Python: the project's name, or a nested pyproject's, required from another manifest.
  const py = (name) => `[project]\nname = "${name}"\nversion = "1"\n`;
  assert.deepEqual(blocking(judge({ "pyproject.toml": py("p"), "requirements.txt": "" }, { "pyproject.toml": py("six"), "requirements.txt": "six==1.16.0\n" })), ["new-dependency:six"], "the project renamed");
  assert.deepEqual(
    blocking(judge({ "pyproject.toml": '[project]\nname = "p"\ndependencies = []\n', "tools/pyproject.toml": py("six") }, { "pyproject.toml": '[project]\nname = "p"\ndependencies = ["six==1.16.0"]\n', "tools/pyproject.toml": py("six") })),
    ["new-dependency:six"],
    "a nested pyproject"
  );
  assert.deepEqual(blocking(judge({ "pyproject.toml": py("p") }, { "pyproject.toml": '[project]\nname = "p"\nversion = "1"\n[project.optional-dependencies]\nall = ["p[extra]"]\n' })), [], "the project's own extras");
  const uvWs = (deps) => `[project]\nname = "p"\ndependencies = ${deps}\n[tool.uv.workspace]\nmembers = ["tools"]\n[tool.uv.sources]\nsix = { workspace = true }\n`;
  // A uv source is the project's own where uv.lock covers the manifest and holds the name locally.
  const wsLockUv = 'version = 1\n\n[[package]]\nname = "p"\nversion = "1"\nsource = { virtual = "." }\ndependencies = [{ name = "six" }]\n\n[[package]]\nname = "six"\nversion = "1"\nsource = { editable = "tools" }\n';
  assert.deepEqual(blocking(judge({ "pyproject.toml": uvWs("[]"), "tools/pyproject.toml": py("six") }, { "pyproject.toml": uvWs('["six"]'), "tools/pyproject.toml": py("six"), "uv.lock": wsLockUv })), [], "a uv workspace member, in uv.lock");
  // Go: a nested go.mod named like the module, with nothing pointing the require at it.
  const mod = (extra) => `module example.com/p\n\ngo 1.22\n${extra}`;
  const gb = { "go.mod": mod(""), "tools/go.mod": "module github.com/pkg/errors\n\ngo 1.22\n" };
  const req = "\nrequire github.com/pkg/errors v0.9.1\n";
  assert.deepEqual(blocking(judge(gb, { ...gb, "go.mod": mod(req), "main.go": 'package main\nimport _ "github.com/pkg/errors"\n' })), ["new-dependency:github.com/pkg/errors"]);
  assert.deepEqual(blocking(judge(gb, { ...gb, "go.mod": mod(`${req}replace github.com/pkg/errors => ./tools\n`) })), [], "replaced with the nested module");
  assert.deepEqual(blocking(judge(gb, { ...gb, "go.mod": mod(req), "go.work": "go 1.22\n\nuse (\n\t.\n\t./tools\n)\n" })), [], "used by go.work");
});

test("places a dependency is declared, in tools the rule reads", () => {
  const p = (extra) => `[project]\nname = "p"\nversion = "1"\ndependencies = ["six==1.16.0"]\n${extra}`;
  const b = { "pyproject.toml": p(""), "uv.lock": 'version = 1\n\n[[package]]\nname = "p"\nversion = "1"\nsource = { editable = "." }\n' };
  for (const [extra, want] of [
    ['[tool.uv]\ndev-dependencies = ["evil>=1"]\n', ["new-dependency:evil"]],
    ['[tool.uv]\noverride-dependencies = ["six @ https://files.elsewhere.example/six-1.16.0-py3-none-any.whl"]\n', ["dependency-source:six"]],
    ['[tool.uv]\nconstraint-dependencies = ["six @ git+https://github.com/someone/six@v1.16.0"]\n', ["dependency-source:six"]],
    ['[tool.uv]\nbuild-constraint-dependencies = ["setuptools @ https://files.elsewhere.example/setuptools-70.tar.gz"]\n', ["dependency-source:setuptools"]],
    ['[tool.uv.extra-build-dependencies]\nsix = ["evil>=1"]\n', ["new-dependency:evil"]],
    ['[tool.uv.pip]\nindex-url = "https://pypi.elsewhere.example/simple"\n', ["dependency-source:null"]],
    ['[tool.pdm.resolution.overrides]\nsix = "https://files.elsewhere.example/six-1.16.0.tar.gz"\n', ["dependency-source:six"]],
    ['[tool.poetry.requires-plugins]\nevil = ">=1"\n', ["new-dependency:evil"]],
    ['[tool.hatch.envs.default]\ndependencies = ["evil>=1"]\n', ["new-dependency:evil"]],
    ['[tool.hatch.envs.test]\nextra-dependencies = ["evil>=1"]\n', ["new-dependency:evil"]],
    ['[tool.hatch.build.hooks.custom]\ndependencies = ["evil>=1"]\n', ["new-dependency:evil"]],
    ['[tool.hatch.build.targets.wheel.hooks.custom]\ndependencies = ["evil>=1"]\n', ["new-dependency:evil"]],
  ]) {
    assert.deepEqual(blocking(judge(b, { ...b, "pyproject.toml": p(extra) })), want, extra);
  }
  assert.deepEqual(blocking(judge({ "hatch.toml": "" }, { "hatch.toml": '[envs.default]\ndependencies = ["evil>=1"]\n' })), ["new-dependency:evil"], "hatch.toml");
  assert.deepEqual(blocking(judge(b, { ...b, "pyproject.toml": p('[tool.hatch.envs.default]\ndependencies = ["own @ {root:uri}/libs/own"]\n') })), [], "a hatch path in the project");
  // Go: a tool line makes a module marked indirect the project's, and an import path written with an escape is the plain one.
  const mod = (extra = "") => `module example.com/p\n\ngo 1.24\n\nrequire github.com/a/b v1.0.0\n${extra}`;
  const gob = { "go.mod": mod(), "go.sum": "github.com/a/b v1.0.0 h1:x=\n" };
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require github.com/new/x v1.0.0 // indirect\n\ntool github.com/new/x/cmd/x\n") })), ["new-dependency:github.com/new/x"]);
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require github.com/pkg/errors v0.9.1 // indirect\n"), "main.go": 'package main\n\nimport _ "github.com/pkg/\\x65rrors"\n' })), ["new-dependency:github.com/pkg/errors"]);
});

test(".npmrc settings that change where packages come from", () => {
  for (const line of ["proxy=http://proxy.elsewhere.example:8080", "https-proxy=http://proxy.elsewhere.example:8080", "http-proxy=http://proxy.elsewhere.example:8080", "strict-ssl=false", "cafile=./certs/ca.pem", "ca=-----BEGIN CERTIFICATE-----", "replace-registry-host=never"]) {
    const r = judge(base, { ...base, ".npmrc": `${line}\n` });
    assert.deepEqual(blocking(r), ["dependency-source:null"], line);
  }
  assert.deepEqual(blocking(judge(base, { ...base, ".npmrc": "strict-ssl=true\nsave-exact=true\n" })), [], "settings that do not");
  const proxied = judge(base, { ...base, ".npmrc": "proxy=http://proxy.corp.example:8080\n" }, [{ kind: "dependency-source", ecosystem: "npm", source: "proxy=http://proxy.corp.example:8080", reason: "the corporate proxy" }]);
  assert.deepEqual(blocking(proxied), [], "approved by the entry the finding writes out");
  assert.equal(proxied.findings.length, 1);
  const had = { ...base, ".npmrc": "proxy=http://proxy.corp.example:8080\n" };
  assert.deepEqual(blocking(judge(had, had)), [], "one the base had");
});

test(".npmrc is read as npm reads it: a key in quotes or with [] is the plain key", () => {
  for (const line of ['"registry"=https://r.example.invalid/', "'registry'=https://r.example.invalid/", "registry[]=https://r.example.invalid/"]) {
    const r = judge(base, { ...base, ".npmrc": `${line}\n` });
    assert.deepEqual(blocking(r), ["dependency-source:null"], line);
    assert.equal(r.findings[0].sourceShown, "https://r.example.invalid/", `${line}: read as the registry`);
    assert.match(findingLine(r.findings[0]), /a registry or index the base did not name/, line);
  }
  for (const line of ['"proxy"="http://p.example.invalid:8080"', '"strict-ssl"=false', "strict-ssl = false ; a comment"]) {
    const r = judge(base, { ...base, ".npmrc": `${line}\n` });
    assert.deepEqual(blocking(r), ["dependency-source:null"], line);
    assert.match(findingLine(r.findings[0]), /changes where packages come from, or which server the tool trusts/, line);
  }
  assert.deepEqual(blocking(judge(base, { ...base, ".npmrc": '"@corp:registry"=https://r.example.invalid/\n' })), ["dependency-source:@corp"], "a scope's registry in quotes");
  // npm still checks the certificate for any value but false.
  for (const line of ["strict-ssl=0", "strict-ssl=null", "strict-ssl", "# registry=https://r.example.invalid/", "[section]\nregistry=https://r.example.invalid/"]) {
    assert.deepEqual(blocking(judge(base, { ...base, ".npmrc": `${line}\n` })), [], line);
  }
  const r = judge(base, { ...base, ".npmrc": "registry=https://r.example.invalid/ # ours\n" });
  assert.equal(r.findings[0].sourceShown, "https://r.example.invalid/", "an inline comment is not part of the value");
});

test(".npmrc: a setting the base did not have that is on neither list blocks; a harmless one passes", () => {
  for (const line of ["script-shell=./x.sh", "node-options=--require ./x.js", "package-lock=false", "${X?}registry=https://r.example.invalid/", "allow-git=all", "ignore-scripts=false", "git=./bin/git", "//r.example.invalid/:registry=https://r.example.invalid/", "something-new=1"]) {
    const r = judge(base, { ...base, ".npmrc": `${line}\n` });
    assert.deepEqual(blocking(r), ["dependency-source:null"], line);
    assert.match(findingLine(r.findings[0]), /a setting the base did not have, which this rule does not know to leave what installs, and from where, as it was|changes where packages come from/, line);
  }
  const harmless = "save-exact=true\nfund=false\naudit=false\nengine-strict=true\nignore-scripts=true\nmin-release-age=7\nallow-git=none\nauto-install-peers=true\nshamefully-hoist=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nloglevel=warn\n";
  assert.deepEqual(blocking(judge(base, { ...base, ".npmrc": harmless })), [], "harmless settings");
  const had = { ...base, ".npmrc": "script-shell=/bin/bash\n" };
  assert.deepEqual(blocking(judge(had, had)), [], "one the base had");
  assert.deepEqual(blocking(judge(had, { ...base, ".npmrc": "script-shell=./x.sh\n" })), ["dependency-source:null"], "one the base had, with another value");
});

test("npm reads a lockfile as old unless its lockfileVersion is 2 or more, whatever sections it has", () => {
  const moved = (version) => {
    const doc = { lockfileVersion: version, packages: { "": { name: "p" }, "node_modules/a": reg("a", "1.0.1", { hasInstallScript: false }) } };
    if (version === undefined) delete doc.lockfileVersion;
    return { "package.json": pkg({ a: "^1.0.1" }), "package-lock.json": JSON.stringify(doc) };
  };
  for (const v of [undefined, 0, 1, 1.5, null, "1", true]) {
    const r = judge(base, moved(v));
    assert.equal(r.errors.length, 1, `lockfileVersion ${JSON.stringify(v)}`);
    assert.match(r.errors[0].text, /so npm reads it as a lockfile from before npm 7, which records no install scripts \(the base's has lockfileVersion 3, so this change rewrote it in the older format\)\. The change adds or moves 1 package in it \(a 1\.0\.1\)/);
  }
  for (const v of [2, 3, "3"]) assert.deepEqual(judge(base, moved(v)).errors, [], `lockfileVersion ${JSON.stringify(v)}`);
  const noPackages = judge(base, { "package.json": pkg({ a: "^1.0.1" }), "package-lock.json": JSON.stringify({ lockfileVersion: 3, dependencies: { a: { version: "1.0.1" } } }) });
  assert.match(noPackages.errors[0]?.text || "", /has lockfileVersion 3 and no packages section, so npm reads it as a lockfile from before npm 7/);
});

test("uv's settings: dependency-metadata, uv.toml read as [tool.uv] is, and a setting on neither list", () => {
  const p = (extra = "") => `[project]\nname = "p"\nversion = "1"\ndependencies = ["idna==3.7"]\n${extra}`;
  const b = { "pyproject.toml": p() };
  // dependency-metadata stands in for what a package declares: the names in it are dependencies.
  const meta = '\n[[tool.uv.dependency-metadata]]\nname = "idna"\nversion = "3.7"\nrequires-dist = ["six"]\n';
  assert.ok(blocking(judge(b, { "pyproject.toml": p(meta) })).includes("new-dependency:six"), "in pyproject.toml");
  assert.ok(blocking(judge(b, { ...b, "uv.toml": '[[dependency-metadata]]\nname = "idna"\nrequires-dist = ["six==1.17.0"]\n' })).includes("new-dependency:six"), "in uv.toml");
  assert.ok(blocking(judge(b, { ...b, "uv.toml": '[[pip.dependency-metadata]]\nname = "idna"\nrequires-dist = ["six==1.17.0"]\n' })).includes("new-dependency:six"), "for uv pip");
  // uv.toml's overrides and constraints, which uv pip compile applies.
  for (const k of ["override-dependencies", "constraint-dependencies", "build-constraint-dependencies"]) {
    assert.deepEqual(blocking(judge(b, { ...b, "uv.toml": `${k} = ["idna @ https://elsewhere.example.invalid/idna-3.7.tar.gz"]\n` })), ["dependency-source:idna"], k);
  }
  // Settings that change whom uv trusts or where it fetches from, in either file.
  for (const [file, text] of [
    ["pyproject.toml", p('[tool.uv]\nallow-insecure-host = ["self-signed.example.invalid"]\n')],
    ["uv.toml", 'allow-insecure-host = ["self-signed.example.invalid"]\n'],
    ["uv.toml", 'index-strategy = "unsafe-best-match"\n'],
    ["uv.toml", '[pip]\nkeyring-provider = "subprocess"\n'],
    ["uv.toml", 'https-proxy = "http://p.example.invalid:8080"\n'],
    ["uv.toml", 'cache-dir = ".cache/uv"\n'],
    ["uv.toml", "a-key-uv-adds-next-year = true\n"],
    ["pyproject.toml", p('[tool.uv.pip]\nno-binary = [":all:"]\n')],
  ]) {
    const r = judge(b, { ...b, [file]: text });
    assert.deepEqual(blocking(r), ["dependency-source:null"], `${file}: ${text}`);
    const known = /allow-insecure-host|index-strategy|keyring-provider|https-proxy/.test(text);
    assert.match(findingLine(r.findings[0]), known ? /changes where packages come from, or which server the tool trusts/ : /which this rule does not know to leave what installs/, `${file}: ${text}`);
  }
  const harmless = 'resolution = "lowest-direct"\nprerelease = "allow"\nindex-strategy = "first-index"\ncompile-bytecode = true\nexclude-newer = "2026-01-01T00:00:00Z"\nno-build = false\n[pip]\ngenerate-hashes = true\nuniversal = true\n';
  assert.deepEqual(blocking(judge(b, { ...b, "uv.toml": harmless })), [], "harmless settings");
  assert.deepEqual(blocking(judge(b, { "pyproject.toml": p('[tool.uv]\npackage = false\ndefault-groups = ["dev"]\n') })), [], "harmless in [tool.uv]");
  // pip: --trusted-host takes anything a host serves, over http or with any certificate.
  const req = { "requirements.txt": "idna==3.7\n" };
  assert.deepEqual(blocking(judge(req, { "requirements.txt": "--trusted-host pypi.example.invalid\nidna==3.7\n" })), ["dependency-source:null"], "--trusted-host");
});

test("a name is the project's own only where the tool resolves it locally: uv sources, go.work, npm lockfiles", () => {
  // Python: a uv source, with no uv.lock that covers the manifest and holds the name locally.
  const py = (deps, extra = "") => `[project]\nname = "p"\nversion = "1"\ndependencies = ${deps}\n${extra}`;
  const pb = { "pyproject.toml": py("[]"), "libs/six/pyproject.toml": '[project]\nname = "six"\nversion = "1"\n' };
  for (const src of ['six = { path = "libs/six" }', "six = { workspace = true }"]) {
    const head = { ...pb, "pyproject.toml": py('["six"]', `[tool.uv.sources]\n${src}\n`) };
    assert.ok(blocking(judge(pb, head)).includes("new-dependency:six"), src);
    assert.match(findingLine(judge(pb, head).findings.find((f) => f.kind === "new-dependency")), /from PyPI \(tool\.uv\.sources names/);
  }
  const uvLock = 'version = 1\n\n[[package]]\nname = "p"\nversion = "1"\nsource = { virtual = "." }\ndependencies = [{ name = "six" }]\n\n[[package]]\nname = "six"\nversion = "1"\nsource = { directory = "libs/six" }\n';
  assert.deepEqual(blocking(judge(pb, { ...pb, "pyproject.toml": py('["six"]', '[tool.uv.sources]\nsix = { path = "libs/six" }\n'), "uv.lock": uvLock })), [], "uv.lock holds it from the directory");
  const otherRoot = uvLock.replace('source = { virtual = "." }', 'source = { virtual = "elsewhere" }');
  assert.ok(blocking(judge(pb, { ...pb, "pyproject.toml": py('["six"]', '[tool.uv.sources]\nsix = { path = "libs/six" }\n'), "uv.lock": otherRoot })).includes("new-dependency:six"), "a uv.lock that does not cover the manifest");

  // Go: a go.work's replace applies only to the modules it uses.
  const mod = (extra = "") => `module example.com/p\n\ngo 1.22\n${extra}`;
  const gb = { "go.mod": mod(), "tools/e/go.mod": "module github.com/pkg/errors\n\ngo 1.22\n" };
  const gh = { ...gb, "go.mod": mod("\nrequire github.com/pkg/errors v0.9.1\n"), "main.go": 'package main\n\nimport _ "github.com/pkg/errors"\n' };
  assert.deepEqual(blocking(judge(gb, { ...gh, "tools/go.work": "go 1.22\n\nreplace github.com/pkg/errors => ./e\n" })), ["new-dependency:github.com/pkg/errors"], "tools/go.work does not cover the root module");
  assert.deepEqual(blocking(judge(gb, { ...gh, "go.work": "go 1.22\n\nuse .\n\nreplace github.com/pkg/errors => ./tools/e\n" })), [], "a go.work at the root that uses it");
  assert.deepEqual(blocking(judge(gb, { ...gh, "go.work": "go 1.22\n\nuse ./tools/e\n\nreplace github.com/pkg/errors => ./tools/e\n" })), ["new-dependency:github.com/pkg/errors"], "a go.work that does not use the root module");

  // npm: a lockfile covers its root and the members its root package.json names, and nothing else.
  const tools = { name: "tools", version: "1.0.0", dependencies: { "is-number": "^7.0.0" } };
  const linked = (ws) => ({
    "package.json": pkg({ a: "^1.0.0" }, ws ? { workspaces: ["tools"] } : {}),
    "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), tools, "node_modules/tools": { resolved: "tools", link: true }, "node_modules/is-number": { resolved: "tools/vendor/is-number", link: true }, "tools/vendor/is-number": { name: "is-number", version: "7.0.0" } }),
    "tools/package.json": JSON.stringify(tools),
    "tools/vendor/is-number/package.json": JSON.stringify({ name: "is-number", version: "7.0.0" }),
  });
  assert.deepEqual(blocking(judge(base, linked(false))), ["new-dependency:is-number"], "tools/ is not a workspace member");
  assert.match(findingLine(judge(base, linked(false)).findings[0]), /No package-lock\.json covers this manifest/);
  assert.deepEqual(blocking(judge({ ...base, "package.json": pkg({ a: "^1.0.0" }, { workspaces: ["tools"] }) }, linked(true))), [], "a member, linked into the project");

  // Two lockfiles in one directory: npm follows npm-shrinkwrap.json, whichever is listed first.
  const both = (order) => {
    const files = {
      "package.json": pkg({ a: "^1.0.0", evil: "^1.0.0" }),
      "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/evil": { resolved: "vendor/evil", link: true }, "vendor/evil": { name: "evil", version: "1.0.0" } }),
      "npm-shrinkwrap.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/evil": reg("evil", "1.0.0") }),
      "vendor/evil/package.json": JSON.stringify({ name: "evil", version: "1.0.0" }),
    };
    return Object.fromEntries(order.map((k) => [k, files[k]]).concat(Object.entries(files).filter(([k]) => !order.includes(k))));
  };
  const swBase = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0") }), "npm-shrinkwrap.json": lock({ "node_modules/a": reg("a", "1.0.0") }) };
  for (const order of [["package-lock.json", "npm-shrinkwrap.json"], ["npm-shrinkwrap.json", "package-lock.json"]]) {
    assert.deepEqual(blocking(judge(swBase, both(order))), ["new-dependency:evil"], order.join(" before "));
  }
});

// The lockfiles of the three formats that record edges, for the tests below: `entries` is
// [name, version, [names it depends on]], and `root` what the lockfile's own record of the project
// depends on (npm and uv.lock keep one; poetry.lock does not).
const uvp = (deps, extra = "") => `[project]\nname = "p"\nversion = "1"\ndependencies = ${JSON.stringify(deps)}\n${extra}`;
const uvEntry = (n, v, deps = []) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\n${deps.length ? `dependencies = [${deps.map((d) => `{ name = "${d}" }`).join(", ")}]\n` : ""}wheels = [{ url = "https://files.pythonhosted.org/packages/x/${n}-${v}-py3-none-any.whl", hash = "sha256:${n}${v}" }]\n`;
const FORMATS = {
  npm: {
    manifest: (names) => ({ "package.json": pkg(Object.fromEntries(names.map((n) => [n, "^1.0.0"]))) }),
    lock: (entries, root) => ({ "package-lock.json": lock(Object.fromEntries(entries.map(([n, v, deps]) => [`node_modules/${n}`, reg(n, v, deps.length ? { dependencies: Object.fromEntries(deps.map((d) => [d, "^1"])) } : {})])), { dependencies: Object.fromEntries(root.map((d) => [d, "^1"])) }) }),
  },
  "uv.lock": {
    manifest: (names) => ({ "pyproject.toml": uvp(names) }),
    lock: (entries, root) => ({ "uv.lock": `version = 1\n\n[[package]]\nname = "p"\nversion = "1"\nsource = { virtual = "." }\n${root.length ? `dependencies = [${root.map((d) => `{ name = "${d}" }`).join(", ")}]\n` : ""}\n${entries.map(([n, v, deps]) => uvEntry(n, v, deps)).join("\n")}` }),
  },
  "poetry.lock": {
    manifest: (names) => ({ "pyproject.toml": `[tool.poetry.dependencies]\npython = "^3.10"\n${names.map((n) => `${n} = "*"`).join("\n")}\n` }),
    lock: (entries) => ({ "poetry.lock": entries.map(([n, v, deps]) => `[[package]]\nname = "${n}"\nversion = "${v}"\nfiles = [{ file = "${n}-${v}-py3-none-any.whl", hash = "sha256:${n}${v}" }]\n${deps.length ? `[package.dependencies]\n${deps.map((d) => `${d} = "*"`).join("\n")}\n` : ""}`).join("\n") }),
  },
};
const newNames = (r) => r.findings.filter((f) => f.kind === "new-dependency").flatMap((f) => [f.package, ...(f.brings?.packages || []).map((p) => p.name)]);

test("names new to the project vouch for nothing: a new name that depends on itself, two that depend on each other", () => {
  for (const [format, F] of Object.entries(FORMATS)) {
    const base = { ...F.manifest(["a"]), ...F.lock([["a", "1.0.0", []]], ["a"]) };
    const self = judge(base, { ...base, ...F.lock([["a", "1.0.2", ["x"]], ["x", "1.0.0", ["x"]]], ["a"]) });
    assert.deepEqual(blocking(self), ["new-dependency:x"], `${format}: x depends on itself`);
    const pair = judge(base, { ...base, ...F.lock([["a", "1.0.2", ["x"]], ["x", "1.0.0", ["y"]], ["y", "1.0.0", ["x"]]], ["a"]) });
    assert.deepEqual(blocking(pair), ["new-dependency:x"], `${format}: x and y depend on each other`);
    assert.deepEqual(pair.findings[0].brings.packages.map((p) => `${p.name} ${p.version}`).sort(), ["x 1.0.0", "y 1.0.0"], format);
    assert.match(findingLine(pair.findings[0]), /brought in by a 1\.0\.2, which the project had at the base; .*With it comes 1 more package new to the lockfile \(y 1\.0\.0\)/, format);
    // A cycle that nothing the project had brings in at all.
    const alone = judge(base, { ...base, ...F.lock([["a", "1.0.0", []], ["x", "1.0.0", ["y"]], ["y", "1.0.0", ["x"]]], ["a"]) });
    assert.deepEqual(newNames(alone).sort().filter((n, i, all) => all.indexOf(n) === i), ["x", "y"], `${format}: a cycle on its own`);
  }
});

test("a new dependency excuses what comes with it, and not what a package the project had brings in beside it", () => {
  for (const [format, F] of Object.entries(FORMATS)) {
    const base = { ...F.manifest(["a"]), ...F.lock([["a", "1.0.0", []]], ["a"]) };
    // n is new and brings y, and through y, z. It also depends on a, which the project had; in the
    // same change a moves and its entry gains x.
    const r = judge(base, { ...F.manifest(["a", "n"]), ...F.lock([["n", "1.0.0", ["a", "y"]], ["y", "1.0.0", ["z"]], ["z", "1.0.0", []], ["a", "1.0.2", ["x"]], ["x", "1.0.0", []]], ["a", "n"]) });
    assert.deepEqual(blocking(r), ["new-dependency:n", "new-dependency:x"], format);
    assert.match(findingLine(r.findings.find((f) => f.package === "x")), /brought in by a 1\.0\.2, which the project had at the base/, format);
    assert.deepEqual(r.findings.find((f) => f.package === "n").brings.packages.map((p) => p.name).sort(), ["a", "n", "x", "y", "z"], `${format}: n's finding lists all the lockfile gains with it`);
  }
});

test("what comes with a new dependency through a nested copy of another new one is counted; a nested copy a package the project had brings is not", () => {
  // express and body-parser are both new. express keeps its own body-parser, which brings its own raw-body.
  const r = judge(base, {
    "package.json": pkg({ a: "^1.0.0", express: "^4.0.0", "body-parser": "^1.20.2" }),
    "package-lock.json": lock({
      "node_modules/a": reg("a", "1.0.0"),
      "node_modules/express": reg("express", "4.18.2", { dependencies: { "body-parser": "1.20.1" } }),
      "node_modules/express/node_modules/body-parser": reg("body-parser", "1.20.1", { dependencies: { "raw-body": "2.5.1" } }),
      "node_modules/express/node_modules/raw-body": reg("raw-body", "2.5.1"),
      "node_modules/body-parser": reg("body-parser", "1.20.2", { dependencies: { "raw-body": "2.5.2" } }),
      "node_modules/raw-body": reg("raw-body", "2.5.2"),
    }),
  });
  assert.deepEqual(blocking(r), ["new-dependency:body-parser", "new-dependency:express"]);
  assert.ok(r.findings.find((f) => f.package === "express").brings.packages.some((p) => p.name === "raw-body" && p.version === "2.5.1"));
  // n is new, and a, which the project had, now keeps an older n of its own that brings x.
  const nested = judge(base, {
    "package.json": pkg({ a: "^1.0.0", n: "^1.0.0" }),
    "package-lock.json": lock({ "node_modules/n": reg("n", "1.0.0"), "node_modules/a": reg("a", "1.0.2", { dependencies: { n: "^0.9.0" } }), "node_modules/a/node_modules/n": reg("n", "0.9.0", { dependencies: { x: "^1" } }), "node_modules/a/node_modules/x": reg("x", "1.0.0") }),
  });
  assert.deepEqual(blocking(nested), ["new-dependency:n", "new-dependency:x"]);
  assert.match(findingLine(nested.findings.find((f) => f.package === "x")), /It is new to package-lock\.json, brought in by n 0\.9\.0; no manifest declares it\./);
});

test("every name new to the project that no manifest declares is named in a finding or counted in one, over random lock graphs", () => {
  // xorshift, seeded, so a failure gives the same graph again.
  let seed = 0x2545f491;
  const rnd = (n) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const pick = (list, p) => list.filter(() => rnd(100) < p);
  const NAMES = ["a", "b", "c", "d", "e", "f", "g", "h"];
  let checked = 0;
  let cycles = 0;
  for (const [format, F] of Object.entries(FORMATS)) {
    for (let run = 0; run < 400; run++) {
      const baseDecl = ["a", ...pick(NAMES.slice(1), 20)];
      const baseLocked = rnd(4) === 0 ? [] : [...new Set(["a", ...pick(NAMES, 30)])];
      const headDecl = [...new Set([...pick(baseDecl, 80), ...pick(NAMES, 15)])];
      const headLocked = [...new Set([...pick(headDecl, 90), ...pick(NAMES, 50)])];
      const edges = (from, among) => [...new Set(pick(among, 30).concat(rnd(8) === 0 ? [from] : []))];
      const baseEntries = baseLocked.map((n) => [n, "1.0.0", edges(n, baseLocked)]);
      const headEntries = headLocked.map((n) => [n, rnd(3) ? "1.0.0" : "1.0.1", edges(n, headLocked)]);
      if (headEntries.some(([n, , d]) => d.includes(n))) cycles++;
      const b = { ...F.manifest(baseDecl), ...(baseLocked.length ? F.lock(baseEntries, pick(baseLocked, 50)) : {}) };
      const h = { ...F.manifest(headDecl), ...F.lock(headEntries, pick(headLocked, 50)) };
      const r = judge(b, h);
      assert.deepEqual(r.errors, [], `${format} run ${run}`);
      const covered = new Set(newNames(r));
      for (const n of headLocked) {
        if (headDecl.includes(n) || baseDecl.includes(n) || baseLocked.includes(n)) continue;
        checked++;
        assert.ok(covered.has(n), `${format} run ${run}: ${n} is new to the project, and no finding names or counts it\nbase ${JSON.stringify(b)}\nhead ${JSON.stringify(h)}\n${r.findings.map(findingLine).join("\n")}`);
      }
    }
  }
  assert.ok(checked > 1000 && cycles > 100, `${checked} names checked, ${cycles} graphs with an entry depending on itself`);
});

test("new means new to the project: what a first lockfile brings with a name the base declared, and Pipfile.lock beside a name the base declared", () => {
  for (const [format, F] of Object.entries(FORMATS)) {
    const declared = F.manifest(["idna"]);
    const r = judge(declared, { ...declared, ...F.lock([["idna", "3.7", ["six"]], ["six", "1.17.0", []]], ["idna"]) });
    assert.deepEqual(blocking(r), ["new-dependency:six"], `${format}: a first lockfile`);
    assert.match(findingLine(r.findings[0]), /brought in by idna 3\.7, which the project had at the base/, format);
    // The same lockfile with a new declared dependency that brings six: six is counted in its finding.
    const withNew = judge(declared, { ...F.manifest(["idna", "req"]), ...F.lock([["idna", "3.7", []], ["req", "2.0.0", ["six"]], ["six", "1.17.0", []]], ["idna", "req"]) });
    assert.deepEqual(blocking(withNew), ["new-dependency:req"], format);
    assert.deepEqual(withNew.findings[0].brings.packages.map((p) => p.name).sort(), ["req", "six"], format);
    // A name the base declared and the head no longer does was the project's: it is not new.
    const dropped = judge(F.manifest(["idna", "six"]), { ...declared, ...F.lock([["idna", "3.7", ["six"]], ["six", "1.17.0", []]], ["idna"]) });
    assert.deepEqual(blocking(dropped), [], `${format}: six was declared at the base`);
  }
  // A name the base only overrode was never the project's.
  const overrode = { "package.json": pkg({ a: "^1.0.0" }, { overrides: { evil: "1.0.1" } }) };
  assert.deepEqual(blocking(judge(overrode, { ...overrode, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { evil: "^1" } }), "node_modules/evil": reg("evil", "1.0.1") }) })), ["new-dependency:evil"], "named only in the base's overrides");
  const pf = (names) => JSON.stringify({ _meta: { sources: [] }, default: Object.fromEntries(names.map(([n, v]) => [n, { version: `==${v}` }])), develop: {} });
  const pfBase = { Pipfile: '[packages]\nidna = "*"\nrequests = "*"\n', "Pipfile.lock": pf([["idna", "3.7"]]) };
  const r = judge(pfBase, { ...pfBase, "Pipfile.lock": pf([["idna", "3.7"], ["requests", "2.32.3"], ["six", "1.17.0"]]) });
  assert.deepEqual(blocking(r), ["new-dependency:six"], "requests was declared at the base, so it brings nothing in unapproved");
  assert.match(findingLine(r.findings[0]), /this change declares no new dependency beside it/);
  // A new declared name beside it lists what is new to Pipfile.lock in its own finding.
  const beside = judge(pfBase, { Pipfile: '[packages]\nidna = "*"\nrequests = "*"\nflask = "*"\n', "Pipfile.lock": pf([["idna", "3.7"], ["flask", "3.0.0"], ["six", "1.17.0"]]) });
  assert.deepEqual(blocking(beside), ["new-dependency:flask"]);
  assert.deepEqual(beside.findings[0].brings.packages, [{ name: "six", version: "1.17.0" }]);
  assert.match(findingLine(beside.findings[0]), /New to Pipfile\.lock with this change, and declared by no manifest: six 1\.17\.0\. Approving this dependency approves them as what it brings\./);
});

test("a registry or index the base named, taken away or given a weaker role, is dependency-source", () => {
  const corp = (n, v) => ({ version: v, resolved: `https://npm.corp.example/${n}/-/${n.split("/").pop()}-${v}.tgz`, integrity: `sha512-${n}-${v}` });
  const npmBase = { ".npmrc": "registry=https://npm.corp.example/\n", "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": corp("a", "1.0.0") }) };
  const gone = judge(npmBase, { ".npmrc": null, "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.2") }) });
  assert.deepEqual(blocking(gone), ["dependency-source:null"]);
  assert.match(findingLine(gone.findings[0]), /npm packages: registry=https:\/\/npm\.corp\.example\/ in \.npmrc at the base, and the head no longer names it: what the base took from it can come from the public npm registry instead/);
  assert.equal(gone.findings[0].sourceShown, "no longer registry=https://npm.corp.example/");
  const scoped = { ".npmrc": "@corp:registry=https://npm.corp.example/\n", "package.json": pkg({ "@corp/lib": "^1.0.0" }), "package-lock.json": lock({ "node_modules/@corp/lib": corp("@corp/lib", "1.0.0") }) };
  assert.deepEqual(blocking(judge(scoped, { ...scoped, ".npmrc": null })), ["dependency-source:@corp"], "a scope's registry");
  assert.deepEqual(blocking(judge(npmBase, { ...npmBase, ".npmrc": "@corp:registry=https://npm.corp.example/\n" })), ["dependency-source:@corp", "dependency-source:null"], "every name's registry made one scope's");
  assert.deepEqual(blocking(judge({ ...npmBase, ".npmrc": "registry=https://registry.npmjs.org/\n" }, { ...npmBase, ".npmrc": null })), [], "the public registry, named and then not");
  // Approving the registry as a source does not approve taking it away; the entry the line gives does.
  const asSource = [{ kind: "dependency-source", ecosystem: "npm", source: "https://npm.corp.example/", reason: "ours" }];
  assert.deepEqual(blocking(judge(npmBase, { ...npmBase, ".npmrc": null }, asSource)), ["dependency-source:null"]);
  assert.deepEqual(blocking(judge(npmBase, { ...npmBase, ".npmrc": null }, [{ kind: "dependency-source", ecosystem: "npm", source: "no longer registry=https://npm.corp.example/", reason: "moved to the public registry" }])), []);

  const req = (lines) => ({ "requirements.txt": `${lines.join("\n")}\nidna==3.7\n` });
  const idx = "https://pypi.corp.example/simple";
  for (const [label, b, h, want] of [
    ["--index-url removed", [`--index-url ${idx}`], [], ["dependency-source:null"]],
    ["--index-url made --extra-index-url", [`--index-url ${idx}`], [`--extra-index-url ${idx}`], ["dependency-source:null"]],
    ["--no-index removed beside --find-links", ["--no-index", "--find-links ./wheels"], ["--find-links ./wheels"], ["dependency-source:null"]],
    ["--extra-index-url removed", [`--extra-index-url ${idx}`], [], ["dependency-source:null"]],
    ["--extra-index-url made --index-url", [`--extra-index-url ${idx}`], [`--index-url ${idx}`], []],
    ["-i written for --index-url", [`--index-url ${idx}`], [`-i ${idx}`], []],
    ["unchanged", ["--no-index", `--index-url ${idx}`], ["--no-index", `--index-url ${idx}`], []],
  ]) {
    assert.deepEqual(blocking(judge(req(b), req(h))), want, label);
  }
  assert.match(findingLine(judge(req(["--no-index", "--find-links /"]), req(["--find-links /"])).findings[0]), /--no-index in requirements\.txt at the base, and the head no longer names it: what the base took from its own files and indexes can come from PyPI instead/);
  assert.match(findingLine(judge(req([`--index-url ${idx}`]), req([`--extra-index-url ${idx}`])).findings[0]), /--index-url https:\/\/pypi\.corp\.example\/simple in requirements\.txt at the base, and the head names it only as --extra-index-url: what the base took from it can come from PyPI instead/);

  const uv = (index) => ({ "pyproject.toml": uvp(["idna>=3.7"], index === null ? "" : `[[tool.uv.index]]\nname = "corp"\nurl = "${idx}"\n${index}`) });
  for (const [label, b, h, want, line] of [
    ["default = true taken off", "default = true\n", "", ["dependency-source:null"], /\(default = true\) in pyproject\.toml at the base, and the head names it only as an index with neither default nor explicit: what the base took from it can come from PyPI/],
    ["explicit = true taken off", "explicit = true\n", "", ["dependency-source:null"], /\(explicit = true\) .* which names come from it and which from PyPI is no longer what the base said/],
    ["the index removed", "default = true\n", null, ["dependency-source:null"], /the head no longer names it/],
    ["default = true given", "", "default = true\n", [], null],
  ]) {
    const r = judge(uv(b), uv(h));
    assert.deepEqual(blocking(r), want, label);
    if (line) assert.match(findingLine(r.findings[0]), line, label);
  }
  const poetry = (priority) => ({ "pyproject.toml": `[tool.poetry.dependencies]\nidna = "3.7"\n\n[[tool.poetry.source]]\nname = "corp"\nurl = "${idx}"\n${priority ? `priority = "${priority}"\n` : ""}` });
  assert.deepEqual(blocking(judge(poetry("primary"), poetry("supplemental"))), ["dependency-source:null"], "a primary poetry source made supplemental");
  assert.deepEqual(blocking(judge(poetry(null), poetry("primary"))), [], "primary is poetry's default");
});

test("a new dependency's finding names what comes with it, in the JSON and the line", () => {
  const head = {
    "package.json": pkg({ a: "^1.0.0", yaml: "^2.0.0" }),
    "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/yaml": reg("yaml", "2.0.0", { dependencies: { q1: "^1", q2: "^1", q3: "^1", q4: "^1", q5: "^1", q6: "^1", q7: "^1" } }), ...Object.fromEntries([1, 2, 3, 4, 5, 6, 7].map((i) => [`node_modules/q${i}`, reg(`q${i}`, "1.0.0")])) }),
  };
  const r = judge(base, head);
  assert.deepEqual(blocking(r), ["new-dependency:yaml"]);
  assert.deepEqual(r.findings[0].brings.packages.map((p) => `${p.name}@${p.version}`).sort(), ["q1@1.0.0", "q2@1.0.0", "q3@1.0.0", "q4@1.0.0", "q5@1.0.0", "q6@1.0.0", "q7@1.0.0", "yaml@2.0.0"]);
  assert.match(findingLine(r.findings[0]), /It adds 8 packages to package-lock\.json \(with it: (?:q\d 1\.0\.0, ){5}q\d 1\.0\.0, \+1 more\), none of which runs code when installed\./);
});

test("workspace patterns are read as npm's minimatch reads them: character classes, braces, dots; an extglob makes no member", () => {
  for (const [p, dir, want] of [
    ["packages/[yz]", "packages/z", true],
    ["packages/[yz]", "packages/x", false],
    ["packages/[!y]", "packages/z", true],
    ["packages/[^y]", "packages/y", false],
    ["packages/[a-c]*", "packages/beta", true],
    ["packages/[[:digit:]]*", "packages/7x", true],
    ["packages/[[:alpha:]]", "packages/7", false],
    ["packages/[.]x", "packages/.x", true],
    ["packages/*", "packages/.x", false],
    ["packages/v{1..3}", "packages/v2", true],
    ["{apps,libs}/*", "libs/q", true],
    ["packages/**", "packages/a/b", true],
    ["packages//*", "packages/a", true],
    ["packages/[]", "packages/a", false],
    ["packages/x[z-a]", "packages/xz-a]", false],
    ["packages/x[z-a]", "packages/x", false],
    ["packages/+(y|z)", "packages/y", null],
    ["packages/!(x)", "packages/y", null],
  ]) {
    assert.equal(workspaceMatches(p, dir), want, `${p} ${dir}`);
  }
  const ws = (pattern, members) => ({
    "package.json": pkg({}, { workspaces: [pattern] }),
    "package-lock.json": lock(Object.fromEntries(members.flatMap((m) => [[`packages/${m}`, { name: m, version: "1.0.0", ...(m === "z" ? { dependencies: { y: "^1.0.0" } } : {}) }], [`node_modules/${m}`, { resolved: `packages/${m}`, link: true }]])), { workspaces: [pattern] }),
    ...Object.fromEntries(members.map((m) => [`packages/${m}/package.json`, member(m, m === "z" ? { dependencies: { y: "^1.0.0" } } : {})])),
  });
  assert.deepEqual(blocking(judge(ws("packages/[yz]", ["y"]), ws("packages/[yz]", ["y", "z"]))), [], "a new member under a character class");
  assert.deepEqual(blocking(judge(ws("packages/+(y|z)", ["y"]), ws("packages/+(y|z)", ["y", "z"]))), ["dependency-source:y", "new-dependency:y"], "an extglob is not read, and blocks");
});

test("an .npmrc key that is JSON other than a string is could-not-run, naming the file", () => {
  const r = judge(base, { ...base, ".npmrc": "registry=https://registry.npmjs.org/\n'[1,2,3]'=x\n" });
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0].path, ".npmrc");
  assert.match(r.errors[0].why, /line 2: its key, '\[1,2,3\]', is JSON that is not a string/);
});

// ---------------------------------------------------------------------------------------------
// Where a name comes from: one comparison, and the public registry is a place like any other.

const CORP_NPM = "https://npm.corp.example/";
const CORP_PY = "https://pypi.corp.example/simple";
const corpPkg = (n, v, extra = {}) => ({ version: v, resolved: `${CORP_NPM}${n}/-/${n.split("/").pop()}-${v}.tgz`, integrity: `sha512-${n}-${v}`, ...extra });
const sources = (r, name) => r.findings.filter((f) => f.kind === "dependency-source" && f.package === name && !f.approvedBy);
const pyproj = (deps, extra = "") => `[project]\nname = "p"\nversion = "1.0.0"\ndependencies = ${deps}\n${extra}`;
const uvIndex = (extra = "") => `\n[[tool.uv.index]]\nname = "corp"\nurl = "${CORP_PY}"\n${extra}`;
const uvLocked = (name, version, source) => `version = 1\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "${name}" }]\n\n[[package]]\nname = "${name}"\nversion = "${version}"\nsource = ${source}\n`;
const poetryProj = (deps, src = "") => `[tool.poetry]\nname = "p"\nversion = "1.0.0"\n\n[tool.poetry.dependencies]\npython = "^3.10"\n${deps}\n${src}`;
const poetrySource = (priority, name = "corp", url = CORP_PY) => `\n[[tool.poetry.source]]\nname = "${name}"\n${url ? `url = "${url}"\n` : ""}priority = "${priority}"\n`;
const poetryLocked = (name, version, src = "") => `[[package]]\nname = "${name}"\nversion = "${version}"\nfiles = [{ file = "${name}-${version}-py3-none-any.whl", hash = "sha256:${name}${version}" }]\n${src}`;
const GIT_SHA = "0123456789abcdef0123456789abcdef01234567";

test("a name the project had that moves to the public registry is dependency-source: the lockfile's entry, with no setting touched", () => {
  // npm: a scope's package, its entry moved from the scope's registry to registry.npmjs.org, which
  // npm reads as the registry every name has, and not the scope's.
  const npmBase = { ".npmrc": `@corp:registry=${CORP_NPM}\n`, "package.json": pkg({ "@corp/lib": "^1.0.0" }), "package-lock.json": lock({ "node_modules/@corp/lib": corpPkg("@corp/lib", "1.0.0") }) };
  const npm = judge(npmBase, { ...npmBase, "package-lock.json": lock({ "node_modules/@corp/lib": reg("@corp/lib", "1.0.2") }) });
  assert.deepEqual(blocking(npm), ["dependency-source:@corp/lib"]);
  assert.match(findingLine(npm.findings[0]), /npm package @corp\/lib "\^1\.0\.0" in package\.json, package-lock\.json, from the npm registry: its source changed \(the base took it from https:\/\/npm\.corp\.example\/@corp\/lib\/-\/lib-1\.0\.0\.tgz\)\. .*Take it from where the base took it, or have the pipeline's allowlist approve this source: \{"kind":"dependency-source","ecosystem":"npm","package":"@corp\/lib","source":"https:\/\/registry\.npmjs\.org\/"/);
  assert.deepEqual(blocking(judge(npmBase, { ...npmBase, "package-lock.json": lock({ "node_modules/@corp/lib": corpPkg("@corp/lib", "1.0.2") }) })), [], "a version move at the scope's registry");
  // The entry the line gives approves it, and an entry for another source does not.
  const moved = { ...npmBase, "package-lock.json": lock({ "node_modules/@corp/lib": reg("@corp/lib", "1.0.2") }) };
  assert.deepEqual(blocking(judge(npmBase, moved, [{ kind: "dependency-source", ecosystem: "npm", package: "@corp/lib", source: "https://registry.npmjs.org/", reason: "published there now" }])), []);
  assert.deepEqual(blocking(judge(npmBase, moved, [{ kind: "dependency-source", ecosystem: "npm", package: "@corp/lib", source: CORP_NPM, reason: "the scope's registry" }])), ["dependency-source:@corp/lib"]);
  // With no `resolved`, npm asks the scope's registry for the name: the same place.
  assert.deepEqual(blocking(judge(npmBase, { ...npmBase, "package-lock.json": lock({ "node_modules/@corp/lib": { version: "1.0.2", integrity: "sha512-x" } }) })), [], "no resolved: the scope's registry");
  // A first lockfile that resolves the scope's package on registry.npmjs.org.
  const noLock = { ".npmrc": npmBase[".npmrc"], "package.json": npmBase["package.json"] };
  assert.deepEqual(blocking(judge(noLock, { ...noLock, "package-lock.json": lock({ "node_modules/@corp/lib": reg("@corp/lib", "1.0.0") }) })), ["dependency-source:@corp/lib"], "a first lockfile");
  assert.deepEqual(blocking(judge(noLock, { ...noLock, "package-lock.json": lock({ "node_modules/@corp/lib": corpPkg("@corp/lib", "1.0.0") }) })), [], "a first lockfile, from the scope's registry");
  // registry.yarnpkg.com is the public registry under another name.
  assert.deepEqual(blocking(judge(base, { ...base, "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.2"), resolved: "https://registry.yarnpkg.com/a/-/a-1.0.2.tgz" } }) })), [], "yarnpkg and npmjs are one place");

  // The same file over plain http is not the registry: npm before 7 fetches it as it is written.
  const http = judge(base, { ...base, "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.0"), resolved: "http://registry.npmjs.org/a/-/a-1.0.0.tgz" } }) });
  assert.deepEqual(blocking(http), ["dependency-source:a"]);
  assert.match(findingLine(http.findings[0]), /from http:\/\/registry\.npmjs\.org\/a\/-\/a-1\.0\.0\.tgz: its source changed \(the base took it from the npm registry\)/);
  const wasHttp = { ...base, "package-lock.json": lock({ "node_modules/a": { ...reg("a", "1.0.0"), resolved: "http://registry.npmjs.org/a/-/a-1.0.0.tgz" } }) };
  assert.deepEqual(blocking(judge(wasHttp, { ...base, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.2") }) })), [], "off plain http, to the registry");
  assert.deepEqual(blocking(judge(wasHttp, wasHttp)), [], "plain http, as the base had it");

  // uv.lock: a package moves from the project's index to pypi.org.
  const uvBase = { "pyproject.toml": pyproj('["lib>=1"]', uvIndex()), "uv.lock": uvLocked("lib", "1.0.0", `{ registry = "${CORP_PY}" }`) };
  const uv = judge(uvBase, { ...uvBase, "uv.lock": uvLocked("lib", "1.0.2", '{ registry = "https://pypi.org/simple" }') });
  assert.deepEqual(blocking(uv), ["dependency-source:lib"]);
  assert.match(findingLine(uv.findings[0]), /PyPI package lib "1\.0\.2" in uv\.lock, from PyPI: its source changed \(the base took it from the index https:\/\/pypi\.corp\.example\/simple\)/);
  assert.deepEqual(blocking(judge(uvBase, { ...uvBase, "uv.lock": uvLocked("lib", "1.0.2", `{ registry = "${CORP_PY}" }`) })), [], "a version move at the project's index");
  // And the other way: from PyPI to an index the project names is a change of place too.
  assert.deepEqual(blocking(judge({ ...uvBase, "uv.lock": uvLocked("lib", "1.0.0", '{ registry = "https://pypi.org/simple" }') }, uvBase)), ["dependency-source:lib"], "PyPI to the project's index");

  // poetry.lock: an entry loses its [package.source].
  const legacy = `\n[package.source]\ntype = "legacy"\nurl = "${CORP_PY}"\nreference = "corp"\n`;
  const poBase = { "pyproject.toml": poetryProj('lib = { version = "^1.0", source = "corp" }', poetrySource("explicit")), "poetry.lock": poetryLocked("lib", "1.0.0", legacy) };
  const po = judge(poBase, { ...poBase, "poetry.lock": poetryLocked("lib", "1.0.2") });
  assert.deepEqual(blocking(po), ["dependency-source:lib"]);
  assert.match(findingLine(po.findings[0]), /in poetry\.lock, from PyPI: its source changed/);
  assert.deepEqual(blocking(judge({ "poetry.lock": poBase["poetry.lock"] }, { "poetry.lock": poetryLocked("lib", "1.0.2") })), ["dependency-source:lib"], "the lockfile alone");
  assert.deepEqual(blocking(judge(poBase, { ...poBase, "poetry.lock": poetryLocked("lib", "1.0.2", legacy) })), [], "a version move with its source kept");

  // Pipfile.lock: an entry's index changes.
  const pipLock = (index) => JSON.stringify({ _meta: { sources: [{ name: "pypi", url: "https://pypi.org/simple" }, { name: "corp", url: CORP_PY }] }, default: { lib: { version: "==1.0.0", index } }, develop: {} });
  const pipfile = `[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n\n[[source]]\nname = "corp"\nurl = "${CORP_PY}"\n\n[packages]\nlib = { version = "*", index = "corp" }\n`;
  assert.deepEqual(blocking(judge({ Pipfile: pipfile, "Pipfile.lock": pipLock("corp") }, { Pipfile: pipfile, "Pipfile.lock": pipLock("pypi") })), ["dependency-source:lib"], "Pipfile.lock");
  // An entry that named PyPI and now names no index comes from the Pipfile's only source, which is not PyPI.
  const corpOnly = `[[source]]\nname = "corp"\nurl = "${CORP_PY}"\n\n[packages]\nlib = "*"\n`;
  const noIndex = JSON.stringify({ _meta: { sources: [{ name: "corp", url: CORP_PY }] }, default: { lib: { version: "==1.0.0" } }, develop: {} });
  assert.deepEqual(blocking(judge({ Pipfile: corpOnly, "Pipfile.lock": pipLock("pypi") }, { Pipfile: corpOnly, "Pipfile.lock": noIndex })), ["dependency-source:lib"], "Pipfile.lock, the index no longer named");
  assert.deepEqual(blocking(judge({ Pipfile: corpOnly, "Pipfile.lock": noIndex }, { Pipfile: corpOnly, "Pipfile.lock": pipLock("corp") })), [], "Pipfile.lock, the Pipfile's only source named");
});

test("a name the project had that moves to the public registry is dependency-source: the manifest's declaration", () => {
  const gitLib = { version: "1.0.0", resolved: `git+ssh://git@github.com/corp/lib.git#${GIT_SHA}` };
  // npm: git, then a range.
  const gitBase = { "package.json": pkg({ lib: "git+https://github.com/corp/lib.git#v1.0.0" }), "package-lock.json": lock({ "node_modules/lib": gitLib }) };
  const git = judge(gitBase, { "package.json": pkg({ lib: "^1.0.0" }), "package-lock.json": lock({ "node_modules/lib": reg("lib", "1.0.0") }) });
  assert.deepEqual(blocking(git), ["dependency-source:lib"]);
  assert.match(findingLine(git.findings[0]), /from the npm registry: its source changed \(the base took it from git\+https:\/\/github\.com\/corp\/lib\.git#v1\.0\.0\)/);
  assert.deepEqual(blocking(judge({ "package.json": gitBase["package.json"] }, { "package.json": pkg({ lib: "^1.0.0" }) })), ["dependency-source:lib"], "git to a range, no lockfile");
  assert.deepEqual(blocking(judge(gitBase, { "package.json": pkg({ lib: "git+https://github.com/corp/lib.git#v1.0.1" }), "package-lock.json": lock({ "node_modules/lib": { ...gitLib, version: "1.0.1" } }) })), [], "a ref moved in the same repository");
  // npm: the project's own directory, then a range.
  const fileBase = { "package.json": pkg({ lib: "file:./vendor/lib" }), "vendor/lib/package.json": '{"name":"lib","version":"1.0.0"}', "package-lock.json": lock({ "node_modules/lib": { resolved: "vendor/lib", link: true }, "vendor/lib": { version: "1.0.0" } }) };
  const file = judge(fileBase, { ...fileBase, "package.json": pkg({ lib: "^1.0.0" }), "package-lock.json": lock({ "node_modules/lib": reg("lib", "1.0.0") }) });
  assert.deepEqual(blocking(file), ["dependency-source:lib"]);
  assert.match(findingLine(file.findings[0]), /the base took it from the project's own vendor\/lib/);
  // The other way, to the project's own code, passes: that code is in the change, and the gate reads it.
  assert.deepEqual(blocking(judge({ "package.json": pkg({ lib: "^1.0.0" }), "package-lock.json": lock({ "node_modules/lib": reg("lib", "1.0.0") }) }, fileBase)), [], "to the project's own code");
  // npm: a member's range on another member moved past that member's version, so the registry's copy is nested under it.
  const wsFiles = (range, extra = {}) => ({
    "package.json": pkg({}, { workspaces: ["packages/*"] }),
    "packages/y/package.json": '{"name":"y","version":"1.0.0"}',
    "packages/z/package.json": JSON.stringify({ name: "z", version: "1.0.0", dependencies: { y: range } }),
    "package-lock.json": lock({ "packages/y": { name: "y", version: "1.0.0" }, "packages/z": { name: "z", version: "1.0.0", dependencies: { y: range } }, "node_modules/y": { resolved: "packages/y", link: true }, "node_modules/z": { resolved: "packages/z", link: true }, ...extra }, { workspaces: ["packages/*"] }),
  });
  const member = judge(wsFiles("^1.0.0"), wsFiles("^2.0.0", { "packages/z/node_modules/y": reg("y", "2.0.0") }));
  assert.deepEqual(blocking(member), ["dependency-source:y"]);
  assert.match(findingLine(member.findings[0]), /npm package y "\^2\.0\.0" in packages\/z\/package\.json, package-lock\.json, from the npm registry: its source changed \(the base took it from the project's own packages\/y\)/);
  // npm: workspaces narrowed, so a member's name becomes the registry's package.
  const narrowed = { ...wsFiles("^1.0.0"), "package.json": pkg({}, { workspaces: ["packages/z"] }), "package-lock.json": lock({ "packages/z": { name: "z", version: "1.0.0", dependencies: { y: "^1.0.0" } }, "node_modules/z": { resolved: "packages/z", link: true }, "node_modules/y": reg("y", "1.0.0") }, { workspaces: ["packages/z"] }) };
  assert.deepEqual(blocking(judge(wsFiles("^1.0.0"), narrowed)), ["dependency-source:y"], "workspaces narrowed");

  // pip and pyproject.toml: a direct reference, then a version.
  assert.deepEqual(blocking(judge({ "requirements.txt": "lib @ git+https://github.com/corp/lib.git@v1.0.0\n" }, { "requirements.txt": "lib==1.0\n" })), ["dependency-source:lib"], "requirements");
  assert.deepEqual(blocking(judge({ "pyproject.toml": pyproj('["lib @ git+https://github.com/corp/lib.git@v1.0.0"]') }, { "pyproject.toml": pyproj('["lib==1.0"]') })), ["dependency-source:lib"], "pyproject.toml");
  assert.deepEqual(blocking(judge({ "requirements.txt": "lib @ git+https://github.com/corp/lib.git@v1.0.0\n" }, { "requirements.txt": "lib @ git+https://github.com/corp/lib.git@v1.0.1\n" })), [], "a ref moved");
  // uv: a source taken away, an index pin, git or a path; or narrowed by a marker.
  const explicit = uvIndex("explicit = true\n");
  const uvSrc = (src) => ({ "pyproject.toml": pyproj('["lib>=1"]', `${src ? `\n[tool.uv.sources]\nlib = ${src}\n` : ""}${explicit}`), "vendor/lib/pyproject.toml": '[project]\nname = "lib"\nversion = "1.0.0"\n' });
  for (const [src, from] of [['{ index = "corp" }', /the index corp/], ['{ git = "https://github.com/corp/lib", tag = "v1.0.0" }', /https:\/\/github\.com\/corp\/lib/], ['{ path = "vendor/lib" }', /the project's own vendor\/lib/]]) {
    const r = judge(uvSrc(src), uvSrc(null));
    assert.deepEqual(blocking(r), ["dependency-source:lib"], src);
    assert.match(findingLine(r.findings[0]), /in pyproject\.toml, from PyPI: its source changed/, src);
    assert.match(findingLine(r.findings[0]), from, src);
    assert.deepEqual(blocking(judge(uvSrc(src), uvSrc(src))), [], `${src}, kept`);
  }
  assert.deepEqual(blocking(judge(uvSrc('{ index = "corp" }'), uvSrc(`{ index = "corp", marker = "sys_platform == 'win32'" }`))), ["dependency-source:lib"], "a source given a marker covers part of what installs");
  // Every source of a list is read, not the last alone.
  assert.deepEqual(blocking(judge(uvSrc(null), uvSrc(`[{ git = "https://github.com/elsewhere/lib", tag = "v1.0.0", marker = "sys_platform == 'win32'" }, { index = "corp", marker = "sys_platform != 'win32'" }]`))), ["dependency-source:lib", "dependency-source:lib"], "each source of a list");
  // poetry: source = or git = taken away.
  const po = (dep, extra = {}) => ({ "pyproject.toml": poetryProj(dep, poetrySource("explicit")), ...extra });
  assert.deepEqual(blocking(judge(po('lib = { version = "^1.0", source = "corp" }'), po('lib = "^1.0"'))), ["dependency-source:lib"], "poetry source =");
  assert.deepEqual(blocking(judge(po('lib = { git = "https://github.com/corp/lib.git", tag = "v1.0.0" }'), po('lib = "^1.0"'))), ["dependency-source:lib"], "poetry git =");
  assert.deepEqual(blocking(judge(po('lib = { version = "^1.0", source = "corp" }'), po('lib = { version = "^1.1", source = "corp" }'))), [], "poetry, the source kept");
});

test("an override or a replace line that said where a name comes from, taken away, is dependency-source", () => {
  const gitLib = { version: "1.0.0", resolved: `git+ssh://git@github.com/corp/lib.git#${GIT_SHA}` };
  const over = { overrides: { lib: "git+https://github.com/corp/lib.git#v1.0.0" } };
  const a = (extra = {}) => reg("a", "1.0.0", { dependencies: { lib: "^1.0.0" }, ...extra });
  const baseO = { "package.json": pkg({ a: "^1.0.0" }, over), "package-lock.json": lock({ "node_modules/a": a(), "node_modules/lib": gitLib }) };
  const gone = judge(baseO, { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": a(), "node_modules/lib": reg("lib", "1.0.0") }) });
  assert.deepEqual(blocking(gone), ["dependency-source:lib"]);
  assert.match(findingLine(gone.findings[0]), /npm package lib in package\.json, package-lock\.json, from the npm registry: an override in package\.json at the base took it from git\+https:\/\/github\.com\/corp\/lib\.git#v1\.0\.0, and the head has none\./);
  // No lockfile: nothing shows whether the name is still installed, so the override's removal is the finding.
  const bare = judge({ "package.json": baseO["package.json"] }, { "package.json": pkg({ a: "^1.0.0" }) });
  assert.deepEqual(blocking(bare), ["dependency-source:lib"]);
  assert.match(findingLine(bare.findings[0]), /no lockfile at the head shows whether it is still installed/);
  // The lockfile shows the name gone with the override: nothing is taken from anywhere.
  assert.deepEqual(blocking(judge(baseO, { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.1") }) })), [], "the name is gone");
  // The override kept, or dropped while the lockfile still takes the name from the same repository.
  assert.deepEqual(blocking(judge(baseO, baseO)), []);
  assert.deepEqual(blocking(judge(baseO, { ...baseO, "package.json": pkg({ a: "^1.0.0" }) })), [], "still from the same repository");

  // uv: a workspace root's sources are every member's, so one for a name only a member declares says where that name comes from.
  const wsRoot = (src) => pyproj("[]", `\n[tool.uv.workspace]\nmembers = ["packages/*"]\n${src ? `\n[tool.uv.sources]\nlib = ${src}\n` : ""}${uvIndex("explicit = true\n")}`);
  const uvWs = (src) => ({ "pyproject.toml": wsRoot(src), "packages/m/pyproject.toml": '[project]\nname = "m"\nversion = "1.0.0"\ndependencies = ["lib>=1"]\n' });
  const rootGone = judge(uvWs('{ index = "corp" }'), uvWs(null));
  assert.deepEqual(blocking(rootGone), ["dependency-source:lib"]);
  assert.match(findingLine(rootGone.findings[0]), /PyPI package lib in pyproject\.toml, from PyPI: a uv source in pyproject\.toml at the base took it from the index corp, and the head has none\./);
  assert.deepEqual(blocking(judge(uvWs(null), uvWs('{ git = "https://github.com/elsewhere/lib", tag = "v1.0.0" }'))), ["dependency-source:lib"], "a root source added for a member's dependency");
  assert.deepEqual(blocking(judge(uvWs('{ index = "corp" }'), uvWs('{ index = "corp" }'))), [], "a root source kept");

  // Go: a replace line removed, so the module comes from its own path again.
  const mod = (replace) => `module example.com/p\n\ngo 1.22\n\nrequire github.com/corp/lib v1.0.0\n${replace ? `\nreplace github.com/corp/lib => ${replace}\n` : ""}`;
  const go = judge({ "go.mod": mod("github.com/fork/lib v1.0.1") }, { "go.mod": mod(null) });
  assert.deepEqual(blocking(go), ["dependency-source:github.com/corp/lib"]);
  assert.match(findingLine(go.findings[0]), /Go package github\.com\/corp\/lib "v1\.0\.0" in go\.mod, from its own path, through the Go module proxy: its source changed \(the base took it from github\.com\/fork\/lib v1\.0\.1\)/);
  assert.deepEqual(blocking(judge({ "go.mod": mod("./vendor/lib") }, { "go.mod": mod(null) })), ["dependency-source:github.com/corp/lib"], "a local replace removed");
  assert.deepEqual(blocking(judge({ "go.mod": mod("github.com/fork/lib v1.0.1") }, { "go.mod": mod("github.com/fork/lib v1.0.2") })), [], "the replacement's version moved");
  // A module a go.work uses is the project's own; with the go.work gone it comes from its own path.
  const work = { "go.work": "go 1.22\n\nuse (\n\t.\n\t./lib\n)\n", "go.mod": "module example.com/p\n\ngo 1.22\n\nrequire example.com/lib v0.0.0\n", "lib/go.mod": "module example.com/lib\n\ngo 1.22\n" };
  assert.deepEqual(blocking(judge(work, work)), []);
  assert.deepEqual(blocking(judge(work, { ...work, "go.work": null })), ["dependency-source:example.com/lib"], "a go.work that made a module the project's own, removed");
  // A replace line for a module no require line names, with go.sum to say whether the module is still used.
  const pin = (replace) => `module example.com/p\n\ngo 1.22\n${replace ? `\nreplace github.com/deep/lib => ${replace}\n` : ""}`;
  const sum = (m) => `${m} v1.0.0 h1:aaaa=\n${m} v1.0.0/go.mod h1:bbbb=\n`;
  assert.deepEqual(blocking(judge({ "go.mod": pin("github.com/fork/lib v1.0.1"), "go.sum": sum("github.com/fork/lib") }, { "go.mod": pin(null), "go.sum": sum("github.com/deep/lib") })), ["dependency-source:github.com/deep/lib"], "a pin removed, the module still in go.sum");
  assert.deepEqual(blocking(judge({ "go.mod": pin("github.com/fork/lib v1.0.1"), "go.sum": sum("github.com/fork/lib") }, { "go.mod": pin(null), "go.sum": sum("github.com/other/x") })), [], "a pin removed, the module gone from go.sum");
});

// One way a tree records `lib`, and the kinds of place it can record: each kind is [the files, the
// place it is, by hand]. The property is checked over every pair of kinds of every form.
const PLACE_FORMS = {
  "npm, package.json alone": (v) => {
    const f = (spec, extra = {}) => ({ "package.json": pkg({ a: "^1.0.0", lib: spec }), ...extra });
    return { name: "lib", kinds: { registry: [f(`^${v}`), "registry"], git: [f(`git+https://github.com/corp/lib.git#v${v}`), "git corp"], "another git": [f(`github:fork/lib#v${v}`), "git fork"], url: [f(`https://files.corp.example/lib/lib-${v}.tgz`), "url"], own: [f("file:./vendor/lib", { "vendor/lib/package.json": '{"name":"lib","version":"1.0.0"}' }), "own"] } };
  },
  "npm, with a lockfile": (v) => {
    const n = "@corp/lib";
    const f = (spec, entry, extra = {}) => ({ ".npmrc": `@corp:registry=${CORP_NPM}\n`, "package.json": pkg({ a: "^1.0.0", [n]: spec }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), [`node_modules/${n}`]: entry, ...extra }) });
    return {
      name: n,
      kinds: {
        "the public registry": [f(`^${v}`, reg(n, v)), "npmjs"],
        "the scope's registry": [f(`^${v}`, corpPkg(n, v)), "corp"],
        "no resolved": [f(`^${v}`, { version: v, integrity: `sha512-${n}-${v}` }), "corp"],
        git: [f(`git+https://github.com/corp/lib.git#v${v}`, { version: v, resolved: `git+ssh://git@github.com/corp/lib.git#${GIT_SHA}` }), "git"],
        url: [f(`https://files.corp.example/lib/lib-${v}.tgz`, { version: v, resolved: `https://files.corp.example/lib/lib-${v}.tgz`, integrity: `sha512-u-${v}` }), "url"],
        own: [f("file:./vendor/lib", { resolved: "vendor/lib", link: true }, { "vendor/lib": { version: "1.0.0" } }), "own"],
      },
    };
  },
  "npm, an override": (v) => {
    const f = (over, entry) => ({ "package.json": pkg({ a: "^1.0.0" }, over ? { overrides: { lib: over } } : {}), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { lib: "^1.0.0" } }), "node_modules/lib": entry }) });
    return { name: "lib", kinds: { none: [f(null, reg("lib", v)), "registry"], "a version": [f(v, reg("lib", v)), "registry"], git: [f(`git+https://github.com/corp/lib.git#v${v}`, { version: v, resolved: `git+ssh://git@github.com/corp/lib.git#${GIT_SHA}` }), "git corp"], "another git": [f(`github:fork/lib#v${v}`, { version: v, resolved: `git+ssh://git@github.com/fork/lib.git#${GIT_SHA}` }), "git fork"] } };
  },
  "requirements.txt": (v) => {
    const f = (line, extra = {}) => ({ "requirements.txt": `six==1.16.0\n${line}\n`, "requirements-corp.txt": `--index-url ${CORP_PY}\nidna==3.7\n`, ...extra });
    return { name: "lib", kinds: { PyPI: [f(`lib==${v}`), "pypi"], git: [f(`lib @ git+https://github.com/corp/lib.git@v${v}`), "git"], url: [f(`lib @ https://files.corp.example/lib/lib-${v}.tar.gz`), "url"], "a file with its own index": [f("", { "requirements-corp.txt": `--index-url ${CORP_PY}\nidna==3.7\nlib==${v}\n` }), "corp"], own: [f("./vendor/lib", { "vendor/lib/pyproject.toml": '[project]\nname = "lib"\nversion = "1.0.0"\n' }), "own"] } };
  },
  "pyproject.toml, uv sources": (v) => {
    const f = (dep, src, extra = {}) => ({ "pyproject.toml": pyproj(`["six>=1", "${dep}"]`, `${src ? `\n[tool.uv.sources]\nlib = ${src}\n` : ""}${uvIndex("explicit = true\n")}`), ...extra });
    return { name: "lib", kinds: { PyPI: [f(`lib>=${v}`, null), "pypi"], "an index pin": [f(`lib>=${v}`, '{ index = "corp" }'), "corp"], git: [f(`lib>=${v}`, `{ git = "https://github.com/corp/lib", tag = "v${v}" }`), "git"], "a direct reference": [f(`lib @ git+https://github.com/corp/lib@v${v}`, null), "git"], url: [f(`lib>=${v}`, `{ url = "https://files.corp.example/lib/lib-${v}.tar.gz" }`), "url"], own: [f(`lib>=${v}`, '{ path = "vendor/lib" }', { "vendor/lib/pyproject.toml": '[project]\nname = "lib"\nversion = "1.0.0"\n' }), "own"] } };
  },
  "uv.lock": (v) => {
    const f = (source) => ({ "pyproject.toml": pyproj('["lib>=1"]', uvIndex()), "uv.lock": uvLocked("lib", v, source) });
    return { name: "lib", kinds: { PyPI: [f('{ registry = "https://pypi.org/simple" }'), "pypi"], "the project's index": [f(`{ registry = "${CORP_PY}" }`), "corp"], git: [f(`{ git = "https://github.com/corp/lib?tag=v${v}#${GIT_SHA}" }`), "git"], url: [f(`{ url = "https://files.corp.example/lib/lib-${v}.tar.gz" }`), "url"], own: [f('{ directory = "vendor/lib" }'), "own"] } };
  },
  "poetry, pyproject.toml and poetry.lock": (v) => {
    const f = (dep, src) => ({ "pyproject.toml": poetryProj(`lib = ${dep}`, poetrySource("explicit")), "poetry.lock": poetryLocked("lib", v, src) });
    const s = (type, url, more = "") => `\n[package.source]\ntype = "${type}"\nurl = "${url}"\n${more}`;
    return { name: "lib", kinds: { PyPI: [f(`"^${v}"`, ""), "pypi"], "a source": [f(`{ version = "^${v}", source = "corp" }`, s("legacy", CORP_PY, 'reference = "corp"\n')), "corp"], git: [f(`{ git = "https://github.com/corp/lib.git", tag = "v${v}" }`, s("git", "https://github.com/corp/lib.git", `reference = "v${v}"\nresolved_reference = "${GIT_SHA}"\n`)), "git"], url: [f(`{ url = "https://files.corp.example/lib/lib-${v}.tar.gz" }`, s("url", `https://files.corp.example/lib/lib-${v}.tar.gz`)), "url"], own: [f('{ path = "vendor/lib" }', s("directory", "vendor/lib")), "own"] } };
  },
  "Pipfile and Pipfile.lock": (v) => {
    const meta = { sources: [{ name: "pypi", url: "https://pypi.org/simple" }, { name: "corp", url: CORP_PY }] };
    const f = (dep, entry) => ({ Pipfile: `[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n\n[[source]]\nname = "corp"\nurl = "${CORP_PY}"\n\n[packages]\nlib = ${dep}\n`, "Pipfile.lock": JSON.stringify({ _meta: meta, default: { lib: entry }, develop: {} }) });
    return { name: "lib", kinds: { PyPI: [f(`{ version = "==${v}", index = "pypi" }`, { version: `==${v}`, index: "pypi" }), "pypi"], "the other index": [f(`{ version = "==${v}", index = "corp" }`, { version: `==${v}`, index: "corp" }), "corp"], git: [f(`{ git = "https://github.com/corp/lib.git", ref = "v${v}" }`, { git: "https://github.com/corp/lib.git", ref: GIT_SHA }), "git"], own: [f('{ path = "./vendor/lib" }', { path: "./vendor/lib" }), "own"] } };
  },
  "go.mod": (v) => {
    const f = (replace) => ({ "go.mod": `module example.com/p\n\ngo 1.22\n\nrequire github.com/corp/lib v${v}\n${replace ? `\nreplace github.com/corp/lib => ${replace}\n` : ""}` });
    return { name: "github.com/corp/lib", kinds: { "its own path": [f(null), "proxy"], "a fork": [f(`github.com/fork/lib v${v}`), "fork"], "another fork": [f(`github.com/elsewhere/lib v${v}`), "elsewhere"], own: [f("./vendor/lib"), "own"] } };
  },
};

test("for every name the project had, the head takes it from where the base took it or has a dependency-source finding for it, over every pair of source kinds", () => {
  let pairs = 0;
  let moved = 0;
  for (const [form, make] of Object.entries(PLACE_FORMS)) {
    for (const [v1, v2] of [["1.0.0", "1.0.0"], ["1.0.0", "1.0.2"], ["1.2.0", "2.0.0"]]) {
      const [b, h] = [make(v1), make(v2)];
      for (const [k1, [baseFiles, was]] of Object.entries(b.kinds)) {
        for (const [k2, [headFiles, now]] of Object.entries(h.kinds)) {
          const r = judge(baseFiles, headFiles);
          const at = `${form}: ${k1} ${v1} -> ${k2} ${v2}`;
          assert.deepEqual(r.errors, [], at);
          const found = sources(r, b.name);
          pairs++;
          // The same place, or the project's own code, which is in the change and read by the gate: no finding.
          if (was === now || now === "own") assert.deepEqual(found.map((f) => findingLine(f)), [], at);
          else {
            moved++;
            assert.ok(found.length >= 1, `${at}: no dependency-source finding for ${b.name}`);
            assert.ok(found.every((f) => f.moved || /new source/.test(findingLine(f))), at);
          }
        }
      }
    }
  }
  assert.deepEqual([pairs, moved], [660, 414], "pairs, and those of them that are a move");
});

test("a registry or index setting counts where the tool reads it, and a file that hides another's settings takes them away", () => {
  const idx = `--index-url ${CORP_PY}`;
  // pip: each requirements file is read with the options it and the files it includes give.
  const two = judge({ "requirements.txt": `${idx}\nlib==1.0\n`, "requirements-dev.txt": `${idx}\ntool==1.0\n` }, { "requirements.txt": "lib==1.0\n", "requirements-dev.txt": `${idx}\ntool==1.0\n` });
  assert.deepEqual(blocking(two), ["dependency-source:null"]);
  assert.match(findingLine(two.findings[0]), /--index-url https:\/\/pypi\.corp\.example\/simple in requirements\.txt at the base, and the head no longer names it/);
  assert.deepEqual(blocking(judge({ "requirements.txt": `${idx}\nlib==1.0\n` }, { "requirements.txt": "lib==1.0\n", "tools/requirements.txt": `${idx}\n` })), ["dependency-source:null"], "moved to another file");
  assert.deepEqual(blocking(judge({ "requirements.txt": `${idx}\nlib==1.0\n` }, { "requirements.txt": "-r base.txt\n", "base.txt": `${idx}\nlib==1.0\n` })), [], "moved to a file it includes");
  assert.deepEqual(blocking(judge({ "requirements.txt": "-r base.txt\nlib==1.0\n", "base.txt": `${idx}\n` }, { "requirements.txt": "lib==1.0\n", "base.txt": `${idx}\n` })), ["dependency-source:null"], "the include that gave it taken away");
  // An index the base named for another file is new to this one.
  assert.deepEqual(blocking(judge({ "requirements.txt": "lib==1.0\n", "requirements-dev.txt": `${idx}\ntool==1.0\n` }, { "requirements.txt": `--extra-index-url ${CORP_PY}\nlib==1.0\n`, "requirements-dev.txt": `${idx}\ntool==1.0\n` })), ["dependency-source:null"], "named for one file, added to another");
  // A name moved to a file that reads another index has moved; to a file that reads the same, it has not.
  const split = (a, b) => ({ "requirements.txt": a, "requirements-dev.txt": b });
  assert.deepEqual(blocking(judge(split(`${idx}\nlib==1.0\nsix==1.16.0\n`, "tool==1.0\n"), split(`${idx}\nsix==1.16.0\n`, "tool==1.0\nlib==1.0\n"))), ["dependency-source:lib"], "a name moved to a file with no index of its own");
  assert.deepEqual(blocking(judge(split("lib==1.0\nsix==1.16.0\n", "tool==1.0\n"), split("six==1.16.0\n", "tool==1.0\nlib==1.0\n"))), [], "a name moved between files that read the same index");
  assert.deepEqual(blocking(judge({ "requirements.txt": "lib==1.0\n" }, { "pyproject.toml": pyproj('["lib==1.0"]') })), [], "requirements.txt to pyproject.toml, both from PyPI");
  // pip takes the best version from any index it is given, so with two there is no one place: a
  // first lockfile's entry is a finding whichever of them it names.
  const twoIdx = { "requirements.txt": `--extra-index-url ${CORP_PY}\nlib==1.0\n` };
  for (const index of [CORP_PY, "https://pypi.org/simple"]) assert.deepEqual(blocking(judge(twoIdx, { ...twoIdx, "uv.lock": uvLocked("lib", "1.0", `{ registry = "${index}" }`) })), ["dependency-source:lib"], `a first lockfile from ${index}, where pip read two indexes`);
  assert.deepEqual(blocking(judge({ "requirements.txt": `${idx}\nlib==1.0\n` }, { "requirements.txt": `${idx}\nlib==1.0\n`, "uv.lock": uvLocked("lib", "1.0", `{ registry = "${CORP_PY}" }`) })), [], "a first lockfile from the one index pip read");
  // Two --index-url lines are two candidates, in either order.
  assert.deepEqual(blocking(judge({ "requirements.txt": `${idx}\n--index-url https://pypi.org/simple\nlib==1.0\n` }, { "requirements.txt": `--index-url https://pypi.org/simple\n${idx}\nlib==1.0\n` })), [], "two --index-url lines in another order");
  assert.deepEqual(blocking(judge({ "requirements.txt": `${idx}\n--index-url https://pypi.org/simple\nlib==1.0\n` }, { "requirements.txt": "--index-url https://pypi.org/simple\nlib==1.0\n" })), ["dependency-source:null"], "one of two --index-url lines taken away");
  const twoMain = { "requirements.txt": `${idx}\n--index-url https://pypi.org/simple\nlib==1.0\n` };
  assert.deepEqual(blocking(judge(twoMain, { ...twoMain, "uv.lock": uvLocked("lib", "1.0", '{ registry = "https://pypi.org/simple" }') })), ["dependency-source:lib"], "with two --index-url lines there is no one place either");
  // The public default named where it already served is no change.
  assert.deepEqual(blocking(judge({ "requirements.txt": "lib==1.0\n" }, { "requirements.txt": "--index-url https://pypi.org/simple\nlib==1.0\n" })), [], "PyPI named");
  assert.deepEqual(blocking(judge({ "requirements.txt": `${idx}\nlib==1.0\n` }, { "requirements.txt": `${idx}\n--extra-index-url https://pypi.org/simple\nlib==1.0\n` })), ["dependency-source:null"], "PyPI named beside an index that had replaced it");

  // npm: the .npmrc of the directory npm runs in.
  const npmBase = { ".npmrc": `registry=${CORP_NPM}\n`, "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0") }) };
  const movedRc = judge(npmBase, { ...npmBase, ".npmrc": null, "tools/.npmrc": `registry=${CORP_NPM}\n`, "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.2") }) });
  assert.deepEqual(blocking(movedRc), ["dependency-source:null"]);
  assert.match(findingLine(movedRc.findings[0]), /registry=https:\/\/npm\.corp\.example\/ in \.npmrc at the base, and the head no longer names it/);
  assert.deepEqual(blocking(judge({ ...npmBase, "tools/.npmrc": `registry=${CORP_NPM}\n`, "tools/package.json": pkg({}) }, { ...npmBase, ".npmrc": null, "tools/.npmrc": `registry=${CORP_NPM}\n`, "tools/package.json": pkg({}) })), ["dependency-source:null"], "still named for another directory");
  // A setting taken away explains the names it moved, and no other: one that changed its own source in the same change has its finding.
  const both = judge({ ".npmrc": `registry=${CORP_NPM}\n`, "package.json": pkg({ a: "^1.0.0", lib: "git+https://github.com/corp/lib.git#v1.0.0" }) }, { "package.json": pkg({ a: "^1.0.0", lib: "^1.0.0" }) });
  assert.deepEqual(blocking(both), ["dependency-source:lib", "dependency-source:null"]);
  const lockedCorp = { ".npmrc": `registry=${CORP_NPM}\n`, "package.json": pkg({ a: "^1.0.0", lib: "git+https://github.com/corp/lib.git#v1.0.0" }), "package-lock.json": lock({ "node_modules/a": corpPkg("a", "1.0.0"), "node_modules/lib": { version: "1.0.0", resolved: `git+ssh://git@github.com/corp/lib.git#${GIT_SHA}` } }) };
  assert.deepEqual(blocking(judge(lockedCorp, { "package.json": pkg({ a: "^1.0.0", lib: "^1.0.0" }) })), ["dependency-source:lib", "dependency-source:null"], "the lockfile gone too: a is explained by the registry taken away, lib is not");
  // A scope that was given the public registry, where every other name's registry is a private one: taken away, the scope's names move to that one.
  const carved = { ".npmrc": `registry=${CORP_NPM}\n@pub:registry=https://registry.npmjs.org/\n`, "package.json": pkg({ "@pub/x": "^1.0.0" }) };
  const uncarved = judge(carved, { ...carved, ".npmrc": `registry=${CORP_NPM}\n` });
  assert.deepEqual(blocking(uncarved), ["dependency-source:@pub"]);
  assert.match(findingLine(uncarved.findings[0]), /@pub:registry=https:\/\/registry\.npmjs\.org\/ in \.npmrc at the base, and the head no longer names it: what the base took from the public npm registry under this scope comes from https:\/\/npm\.corp\.example\/ instead/);
  assert.deepEqual(blocking(judge({ ".npmrc": "@pub:registry=https://registry.npmjs.org/\n", "package.json": pkg({ "@pub/x": "^1.0.0" }) }, { "package.json": pkg({ "@pub/x": "^1.0.0" }) })), [], "a scope's public registry named and then not, where every name's is the public one");
  assert.deepEqual(blocking(judge({ ...carved, ".npmrc": `registry=${CORP_NPM}\n` }, carved)), ["dependency-source:@pub"], "the public registry named for a scope the base's settings kept it out of");
  // npm reads the last line that sets a key: two lines in another order are another registry.
  const twoLines = (a, b) => ({ ".npmrc": `registry=https://${a}.corp.example/\nregistry=https://${b}.corp.example/\n`, "package.json": pkg({ a: "^1.0.0" }) });
  assert.deepEqual(blocking(judge(twoLines("one", "two"), twoLines("two", "one"))), ["dependency-source:null", "dependency-source:null"], "registry= lines in another order");
  assert.deepEqual(blocking(judge(twoLines("one", "two"), twoLines("one", "two"))), []);
  // A setting the base had for one directory is new to another.
  assert.deepEqual(blocking(judge({ ...npmBase, "tools/.npmrc": "proxy=http://proxy.corp.example:8080\n" }, { ...npmBase, ".npmrc": `registry=${CORP_NPM}\nproxy=http://proxy.corp.example:8080\n`, "tools/.npmrc": "proxy=http://proxy.corp.example:8080\n" })), ["dependency-source:null"], "a setting added where the base did not have it");

  // uv: the nearest directory up with a uv.toml or a [tool.uv] table, and a uv.toml hides the table beside it.
  const withIndex = pyproj('["lib>=1"]', uvIndex("default = true\n"));
  const hidden = judge({ "pyproject.toml": withIndex }, { "pyproject.toml": withIndex, "uv.toml": "" });
  assert.deepEqual(blocking(hidden), ["dependency-source:null"]);
  assert.match(findingLine(hidden.findings[0]), /tool\.uv\.index https:\/\/pypi\.corp\.example\/simple \(default = true\) in pyproject\.toml at the base, and the head reads uv\.toml in its place, which does not name it/);
  const tomlIndex = `[[index]]\nname = "corp"\nurl = "${CORP_PY}"\ndefault = true\n`;
  assert.deepEqual(blocking(judge({ "pyproject.toml": pyproj('["lib>=1"]'), "uv.toml": tomlIndex }, { "pyproject.toml": withIndex, "uv.toml": "" })), ["dependency-source:null"], "moved from uv.toml into the table it hides");
  assert.deepEqual(blocking(judge({ "pyproject.toml": withIndex }, { "pyproject.toml": pyproj('["lib>=1"]'), "uv.toml": tomlIndex })), [], "moved into uv.toml, which is read");
  const member = (extra = "") => `[project]\nname = "m"\nversion = "1.0.0"\ndependencies = ["lib>=1"]\n${extra}`;
  const wsRoot = (extra) => pyproj('["lib>=1"]', `\n[tool.uv.workspace]\nmembers = ["packages/*"]\n${extra}`);
  assert.deepEqual(blocking(judge({ "pyproject.toml": wsRoot(uvIndex("default = true\n")), "packages/m/pyproject.toml": member() }, { "pyproject.toml": wsRoot(""), "packages/m/pyproject.toml": member(uvIndex("default = true\n")) })), ["dependency-source:null"], "moved from the workspace root to a member");
  // A directory with no settings of its own reads its parent's, until it is given a table of its own.
  const sub = (extra = "") => ({ "uv.toml": tomlIndex, "sub/pyproject.toml": member(extra) });
  assert.deepEqual(blocking(judge(sub(), sub("\n[tool.uv]\nmanaged = true\n"))), ["dependency-source:null"], "a [tool.uv] table that hides the parent's uv.toml");
  assert.deepEqual(blocking(judge(sub(), sub("\n[tool.ruff]\nline-length = 100\n"))), [], "another tool's table hides nothing");
  // An index in a table no tool reads is not an index; read again, it is.
  assert.deepEqual(blocking(judge({ "pyproject.toml": pyproj('["lib>=1"]'), "uv.toml": "" }, { "pyproject.toml": pyproj('["lib>=1"]', uvIndex()), "uv.toml": "" })), [], "added where uv.toml hides it");
  assert.deepEqual(blocking(judge({ "pyproject.toml": pyproj('["lib>=1"]', uvIndex()), "uv.toml": "" }, { "pyproject.toml": pyproj('["lib>=1"]', uvIndex()) })), ["dependency-source:null"], "the uv.toml that hid it removed");
  // uv's no-index = true keeps every index out, as pip's --no-index does.
  const noIdx = (on) => ({ "pyproject.toml": pyproj('["lib>=1"]', `\n[tool.uv]\n${on ? "no-index = true\n" : ""}find-links = ["./wheels"]\n`) });
  const opened = judge(noIdx(true), noIdx(false));
  assert.deepEqual(blocking(opened), ["dependency-source:null"]);
  assert.match(findingLine(opened.findings[0]), /tool\.uv\.no-index = true in pyproject\.toml at the base, and the head no longer names it: what the base took from its own files and indexes can come from PyPI instead/);
  assert.deepEqual(blocking(judge(noIdx(false), noIdx(true))), [], "no-index given");
  // uv takes a name from the first index that has it.
  const two2 = (a, b) => pyproj('["lib>=1"]', `\n[[tool.uv.index]]\nurl = "https://${a}.corp.example/simple"\n\n[[tool.uv.index]]\nurl = "https://${b}.corp.example/simple"\n`);
  const order = judge({ "pyproject.toml": two2("one", "two") }, { "pyproject.toml": two2("two", "one") });
  assert.deepEqual(blocking(order), ["dependency-source:null"]);
  assert.match(findingLine(order.findings[0]), /the head lists them in the order https:\/\/two\.corp\.example\/simple\/, https:\/\/one\.corp\.example\/simple\//);
  const pipSources = (...names) => ({ Pipfile: `${names.map((n) => `[[source]]\nname = "${n}"\nurl = "https://${n}.corp.example/simple"\n`).join("\n")}\n[packages]\nlib = "*"\n` });
  assert.deepEqual(blocking(judge(pipSources("one", "two"), pipSources("two", "one"))), ["dependency-source:null"], "a Pipfile's sources in another order");
  assert.deepEqual(blocking(judge(pipSources("one", "two"), pipSources("one", "two"))), []);
});

test("poetry's PyPI source, named with no url, is read as PyPI and is not could-not-run", () => {
  const withPyPI = (priority) => ({ "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource(priority, "PyPI", null)), "p.py": "x = 1\n" });
  const same = judge(withPyPI("primary"), { ...withPyPI("primary"), "p.py": "x = 2\n" });
  assert.deepEqual(same.errors, []);
  assert.deepEqual(blocking(same), []);
  assert.deepEqual(judge(withPyPI("primary"), withPyPI("primary")).errors, [], "in any case of the name");
  assert.deepEqual(judge({ "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource("supplemental", "pypi", null)) }, { "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource("supplemental", "pypi", null)) }).errors, []);
  // Another source with no url is still not read.
  assert.match(judge(base, { ...base, "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource("primary", "corp", null)) }).errors[0].why, /tool\.poetry\.source holds an entry with no url/);
  // Added where a private source was primary, it brings PyPI back in.
  const priv = { "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource("primary")) };
  const back = judge(priv, { "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource("primary") + poetrySource("primary", "PyPI", null)) });
  assert.deepEqual(blocking(back), ["dependency-source:null"]);
  assert.match(findingLine(back.findings[0]), /tool\.poetry\.source https:\/\/pypi\.org\/simple\/ in pyproject\.toml, from https:\/\/pypi\.org\/simple\/: the base's settings kept the public default out of the names this file serves, and this names it again\. .*Leave it out, as the base did/);
  // Where PyPI already served, naming it changes nothing; and taking the private primary away is its own finding.
  assert.deepEqual(blocking(judge({ "pyproject.toml": poetryProj('lib = "^1.0"') }, { "pyproject.toml": poetryProj('lib = "^1.0"', poetrySource("primary", "PyPI", null)) })), [], "named where it already served");
  assert.deepEqual(blocking(judge(priv, { "pyproject.toml": poetryProj('lib = "^1.0"') })), ["dependency-source:null"], "the private primary source taken away");
});

test("a file of a registry the project names has to be the package's own: a lockfile's resolved, and a URL a manifest gives", () => {
  const MIRROR = "https://mirror.corp.example/npm/";
  const at = (root, name, version, file = `${name.split("/").pop()}-${version}.tgz`) => ({ version, resolved: `${root}${name}/-/${file}`, integrity: `sha512-${name}-${version}` });
  // One registry for every name, named in .npmrc: the entry for left-pad pointed at is-odd's file.
  const mirrored = (e) => ({ ".npmrc": `registry=${MIRROR}\n`, "package.json": pkg({ "left-pad": "^1.1.0" }), "package-lock.json": lock({ "node_modules/left-pad": e }) });
  const other = judge(mirrored(at(MIRROR, "left-pad", "1.1.0")), mirrored({ ...at(MIRROR, "is-odd", "3.0.1"), version: "1.1.3" }));
  assert.deepEqual(blocking(other), ["dependency-source:left-pad"]);
  assert.match(findingLine(other.findings[0]), /npm package left-pad "1\.1\.3" in package-lock\.json, from https:\/\/mirror\.corp\.example\/npm\/is-odd\/-\/is-odd-3\.0\.1\.tgz: the lockfile takes left-pad 1\.1\.3 from a file of the registry's that is not that package's/);
  assert.deepEqual(blocking(judge(mirrored(at(MIRROR, "left-pad", "1.1.0")), mirrored(at(MIRROR, "left-pad", "1.1.3")))), [], "a version move to the package's own file");
  assert.deepEqual(blocking(judge(mirrored(at(MIRROR, "left-pad", "1.1.0")), mirrored({ ...at(MIRROR, "left-pad", "1.1.0"), version: "1.1.3", integrity: "sha512-moved" }))), ["dependency-source:left-pad"], "another version's file of the same package");
  // A scope's registry, and scoped names: the name is what is before /-/.
  const scoped = (e) => ({ ".npmrc": `@corp:registry=${CORP_NPM}\n`, "package.json": pkg({ "@corp/lib": "^1.0.0" }), "package-lock.json": lock({ "node_modules/@corp/lib": e }) });
  const lib = (v, file) => ({ ...at(CORP_NPM, "@corp/lib", v, file), version: v });
  assert.deepEqual(blocking(judge(scoped(lib("1.0.0")), scoped({ ...at(CORP_NPM, "@corp/other", "9.9.9"), version: "1.0.2" }))), ["dependency-source:@corp/lib"], "another package of the scope");
  assert.deepEqual(blocking(judge(scoped(lib("1.0.0")), scoped({ ...at(CORP_NPM, "lib", "1.0.2"), version: "1.0.2" }))), ["dependency-source:@corp/lib"], "the unscoped package of the same last name");
  assert.deepEqual(blocking(judge(scoped(lib("1.0.0")), scoped(lib("1.0.2")))), [], "the scoped package's own file");
  assert.deepEqual(blocking(judge(scoped(lib("1.0.0", "@corp/lib-1.0.0.tgz")), scoped(lib("1.0.2", "@corp/lib-1.0.2.tgz")))), [], "a registry that repeats the scope in the file's path");
  assert.deepEqual(blocking(judge(scoped({ version: "1.0.0", resolved: `${CORP_NPM}@corp%2flib/-/lib-1.0.0.tgz` }), scoped({ version: "1.0.2", resolved: `${CORP_NPM}@corp%2flib/-/lib-1.0.2.tgz` }))), [], "the scope's slash written %2f");
  // A registry that lays its files out another way is not blocked for it.
  assert.deepEqual(blocking(judge(scoped({ version: "1.0.0", resolved: `${CORP_NPM}download/@corp/lib/1.0.0/aaaa` }), scoped({ version: "1.0.2", resolved: `${CORP_NPM}download/@corp/lib/1.0.2/bbbb` }))), [], "no /-/ in the path");
  // A URL a manifest gives: under a registry the project names it is that registry, so it has to be the name's own file.
  const asked = (spec, rc = `registry=${MIRROR}\n`, e = null) => ({ ...(rc ? { ".npmrc": rc } : {}), "package.json": pkg({ a: spec }), ...(e ? { "package-lock.json": lock({ "node_modules/a": e }) } : {}) });
  const url = judge(asked("^1.0.0", undefined, at(MIRROR, "a", "1.0.0")), asked(`${MIRROR}b/-/b-2.0.0.tgz`, undefined, { ...at(MIRROR, "b", "2.0.0") }));
  assert.deepEqual(blocking(url), ["dependency-source:a"]);
  assert.deepEqual(url.findings[0].manifests, ["package.json", "package-lock.json"]);
  assert.match(findingLine(url.findings[0]), /package\.json takes a from a file of the registry's that is not that package's/);
  assert.deepEqual(blocking(judge(asked("^1.0.0"), asked(`${MIRROR}b/-/b-2.0.0.tgz`))), ["dependency-source:a"], "with no lockfile");
  assert.deepEqual(blocking(judge(asked("^1.0.0", null), asked("https://registry.npmjs.org/b/-/b-2.0.0.tgz", null))), ["dependency-source:a"], "on the public registry, with no lockfile");
  assert.deepEqual(blocking(judge(asked("^1.0.0", null), asked("https://registry.npmjs.org/@x/a/-/a-2.0.0.tgz", null))), ["dependency-source:a"], "a scoped package of the same last name");
  assert.deepEqual(blocking(judge(asked("^1.0.0", null), asked("https://registry.npmjs.org/a/-/b-2.0.0.tgz", null))), ["dependency-source:a"], "a file under the name that is not named for it");
  assert.deepEqual(blocking(judge(asked("^1.0.0", undefined, at(MIRROR, "a", "1.0.0")), asked(`${MIRROR}a/-/a-1.0.2.tgz`, undefined, at(MIRROR, "a", "1.0.2")))), [], "the name's own file, from the registry the base took it from");
  // One the base already had is not this change's.
  const had = asked("https://registry.npmjs.org/b/-/b-2.0.0.tgz", null);
  assert.deepEqual(blocking(judge(had, { ...had, "notes.txt": "x" })), [], "the same URL at the base");
});

test("a uv workspace's member reads the root's indexes and settings; a nested project that is not a member reads its own", () => {
  const corp = uvIndex("default = true\n");
  const other = `\n[[tool.uv.index]]\nname = "other"\nurl = "https://other.example/simple"\ndefault = true\n`;
  const root = (extra = corp, ws = 'members = ["libs/*"]') => pyproj('["lib>=1"]', `\n[tool.uv.workspace]\n${ws}\n${extra}`);
  const proj = (name, deps = "[]", extra = "") => `[project]\nname = "${name}"\nversion = "1.0.0"\ndependencies = ${deps}\n${extra}`;
  const lockOf = (edge) => `version = 1\n\n[manifest]\nmembers = ["m", "o", "p"]\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "lib" }]\n\n[[package]]\nname = "m"\nversion = "1.0.0"\nsource = { virtual = "libs/m" }\n${edge ? 'dependencies = [{ name = "o" }]\n' : ""}\n[[package]]\nname = "o"\nversion = "1.0.0"\nsource = { virtual = "libs/o" }\n\n[[package]]\nname = "lib"\nversion = "1.0.0"\nsource = { registry = "${CORP_PY}" }\n`;
  const ws = (m, { rootText = root(), files = {} } = {}) => ({ "pyproject.toml": rootText, "libs/m/pyproject.toml": m, "libs/o/pyproject.toml": proj("o"), ...files });
  // A member that starts to depend on another member: its file gains a [tool.uv] table, and uv still reads the root's index for it.
  const edge = judge(ws(proj("m"), { files: { "uv.lock": lockOf(false) } }), ws(proj("m", '["o"]', "\n[tool.uv.sources]\no = { workspace = true }\n"), { files: { "uv.lock": lockOf(true) } }));
  assert.deepEqual(edge.errors, []);
  assert.deepEqual(blocking(edge), []);
  assert.deepEqual(blocking(judge(ws(proj("m", '["lib>=1"]')), ws(proj("m", '["lib>=1"]', "\n[tool.uv]\nmanaged = true\n")))), [], "a [tool.uv] table of the member's own");
  assert.deepEqual(blocking(judge(ws(proj("m", '["lib>=1"]')), ws(proj("m", '["lib>=1"]'), { files: { "libs/m/uv.toml": "" } }))), [], "a uv.toml of the member's own");
  // What the root reads is what the member reads: taken away at the root, or hidden there, it is taken away.
  const moved = judge(ws(proj("m", '["lib>=1"]')), ws(proj("m", '["lib>=1"]', corp), { rootText: root("") }));
  assert.deepEqual(blocking(moved), ["dependency-source:null"]);
  assert.match(findingLine(moved.findings[0]), /tool\.uv\.index https:\/\/pypi\.corp\.example\/simple \(default = true\) in pyproject\.toml at the base, and the head no longer names it/);
  assert.deepEqual(blocking(judge(ws(proj("m", '["lib>=1"]')), ws(proj("m", '["lib>=1"]'), { files: { "uv.toml": "" } }))), ["dependency-source:null"], "a uv.toml beside the root hides its table from the member too");
  // An index the member's own table names is not what uv reads there. The table is still judged
  // for what it names and no longer names, as the directory read alone would take its names from it.
  const own = judge(ws(proj("m", '["lib>=1"]')), ws(proj("m", '["lib>=1"]', other)));
  assert.deepEqual(blocking(own), ["dependency-source:null"]);
  assert.match(findingLine(own.findings[0]), /tool\.uv\.index https:\/\/other\.example\/simple in libs\/m\/pyproject\.toml, from https:\/\/other\.example\/simple: a registry or index the base did not name/);
  const gone = judge(ws(proj("m", '["lib>=1"]', `\n[tool.uv]\nmanaged = true\n${other}`)), ws(proj("m", '["lib>=1"]', "\n[tool.uv]\nmanaged = true\n")));
  assert.deepEqual(blocking(gone), ["dependency-source:null"], "taken from the member's own table");
  assert.match(findingLine(gone.findings[0]), /tool\.uv\.index https:\/\/other\.example\/simple \(default = true\) in libs\/m\/pyproject\.toml at the base, and the head no longer names it/);
  assert.deepEqual(blocking(judge(ws(proj("m", '["lib>=1"]', other)), ws(proj("m", '["lib>=1"]', other), { files: { "notes.txt": "x" } }))), [], "left as it was");
  // A directory the root does not name, or excludes, is not a member: its own table is what uv reads.
  const nested = (extra) => ({ "pyproject.toml": root(), "tools/n/pyproject.toml": proj("n", '["lib>=1"]', extra) });
  const alone = judge(nested(""), nested("\n[tool.uv]\nmanaged = true\n"));
  assert.deepEqual(blocking(alone), ["dependency-source:null"]);
  assert.match(findingLine(alone.findings[0]), /the head reads tools\/n\/pyproject\.toml in its place, which does not name it/);
  const excluded = 'members = ["libs/*"]\nexclude = ["libs/m"]';
  assert.deepEqual(blocking(judge(ws(proj("m", '["lib>=1"]'), { rootText: root(corp, excluded) }), ws(proj("m", '["lib>=1"]', "\n[tool.uv]\nmanaged = true\n"), { rootText: root(corp, excluded) }))), ["dependency-source:null"], "a directory the root excludes");
  // uv run in a project that sits under another project stops its search for a workspace there,
  // whatever a root further up names: such a directory reads its own table.
  const under = (extra) => ({ "pyproject.toml": root(corp, 'members = ["libs/*", "libs/*/sub"]'), "libs/x/pyproject.toml": proj("x"), "libs/x/sub/pyproject.toml": proj("sub", '["lib>=1"]', extra) });
  assert.deepEqual(blocking(judge(under(""), under("\n[tool.uv]\nmanaged = true\n"))), ["dependency-source:null"], "a project under a project");
  // Taken out of the workspace, the member reads its own table from then on.
  assert.deepEqual(blocking(judge(ws(proj("m", '["lib>=1"]', other)), ws(proj("m", '["lib>=1"]', other), { rootText: root(corp, excluded) }))), ["dependency-source:null", "dependency-source:null"], "a member with an index of its own, excluded");
  // uv's globs: a character class and ** name members; * does not cross a directory.
  for (const [pattern, dir, member] of [["libs/[lm]", "libs/m", true], ["libs/[!m]", "libs/m", false], ["**/m", "libs/m", true], ["**/m", "libs/deep/m", true], ["**", "libs/deep/m", true], ["./libs/m/", "libs/m", true], ["libs/?", "libs/m", true], ["*", "libs/m", false]]) {
    const t = (extra) => ({ "pyproject.toml": root(corp, `members = ["${pattern}"]`), [`${dir}/pyproject.toml`]: proj("m", '["lib>=1"]', extra) });
    assert.deepEqual(blocking(judge(t(""), t("\n[tool.uv]\nmanaged = true\n"))), member ? [] : ["dependency-source:null"], `members = ["${pattern}"] and ${dir}`);
  }
});

// The sixth review: the reviewer's inline comments on the pull request, each run as a case.

test("an allowlist entry narrowed to a path approves the manifests under it and no other, whichever file is read first", () => {
  const had = { "api/requirements.txt": "idna==3.7\n", "web/requirements.txt": "idna==3.7\n" };
  const both = { "api/requirements.txt": "idna==3.7\nsix==1.17.0\n", "web/requirements.txt": "idna==3.7\nsix==1.17.0\n" };
  const entry = (p, reason = `for ${p}`) => ({ kind: "new-dependency", ecosystem: "PyPI", package: "six", ...(p ? { path: p } : {}), reason });
  for (const p of ["api", "web"]) {
    const r = judge(had, both, [entry(p)]);
    assert.deepEqual(blocking(r), ["new-dependency:six"], `an entry for ${p}, and both directories gain the name`);
    assert.deepEqual(r.findings[0].manifests, ["api/requirements.txt", "web/requirements.txt"]);
    assert.equal(r.findings[0].approvedBy, undefined);
  }
  assert.deepEqual(blocking(judge(had, { ...had, "web/requirements.txt": both["web/requirements.txt"] }, [entry("api")])), ["new-dependency:six"], "the other directory alone");
  assert.deepEqual(blocking(judge(had, { ...had, "api/requirements.txt": both["api/requirements.txt"] }, [entry("api")])), [], "its own directory alone");
  assert.deepEqual(blocking(judge(had, { ...had, "api2/requirements.txt": "six==1.17.0\n" }, [entry("api")])), ["new-dependency:six"], "a directory whose name only starts the same");
  // Each manifest under some entry's path: approved, and the finding carries each entry's reason.
  const two = judge(had, both, [entry("web"), entry("api")]);
  assert.deepEqual(blocking(two), []);
  assert.equal(two.findings[0].approvedBy, "for api; for web");
  assert.equal(judge(had, both, [entry(null, "anywhere")]).findings[0].approvedBy, "anywhere");
  assert.equal(judge(had, both, [entry("api"), entry("web/requirements.txt", "that file")]).findings[0].approvedBy, "for api; that file");
  // npm reads the other way round: the same holds.
  const npmHad = { "web/package.json": pkg({}), "api/package.json": pkg({}) };
  const npmBoth = { "web/package.json": pkg({ z: "^1.0.0" }), "api/package.json": pkg({ z: "^1.0.0" }) };
  assert.deepEqual(blocking(judge(npmHad, npmBoth, [{ kind: "new-dependency", ecosystem: "npm", package: "z", path: "web", reason: "x" }])), ["new-dependency:z"]);
});

test("a manifest or lockfile that is a symbolic link is not opened: it is could-not-run, and what it points at is not printed", () => {
  const WORD = ["only-in-the", "outside-file"].join("-");
  const top = realpathSync(mkdtempSync(path.join(tmpdir(), "deps-link-")));
  try {
    const root = path.join(top, "proj");
    mkdirSync(path.join(root, "real"), { recursive: true });
    writeFileSync(path.join(top, "outside.txt"), `${WORD}==1.0\nTOKEN=${WORD}\n`);
    writeFileSync(path.join(root, "real", "requirements.txt"), "idna==3.7\n");
    writeFileSync(path.join(root, "notes.txt"), "x\n");
    for (const name of ["requirements.txt", "package.json", "pyproject.toml", "package-lock.json", ".npmrc"]) symlinkSync(path.join(top, "outside.txt"), path.join(root, name));
    symlinkSync(path.join("real", "requirements.txt"), path.join(root, "requirements-dev.txt"));
    symlinkSync("real", path.join(root, "linked"));
    // In a repository, as the head is: git lists a link as a file.
    for (const args of [["init", "-q"], ["add", "-A"]]) assert.equal(spawnSync("git", ["-C", root, ...args], { encoding: "utf8" }).status, 0);
    const t = dependencyTree(root);
    assert.ok(["requirements.txt", "package.json", "requirements-dev.txt"].every((f) => t.files.includes(f)), "the links are in the tree");
    const files = ["requirements.txt", "package.json", "pyproject.toml", "package-lock.json", ".npmrc", "requirements-dev.txt", "real/requirements.txt", "linked/requirements.txt"];
    const inv = inventory(treeOf(files, t.read));
    assert.deepEqual(inv.decl.map((d) => `${d.manifest}:${d.name}`), ["real/requirements.txt:idna"]);
    assert.deepEqual(
      inv.errors.map((e) => `${e.path}: ${e.why}`).sort(),
      [...files.filter((f) => !/^(?:real|linked)\//.test(f)).map((f) => `${f}: it is a symbolic link, which this rule does not follow`), "linked/requirements.txt: linked is a symbolic link, which this rule does not follow"].sort()
    );
    const r = judgeDependencyChange(root, path.join(root, "real"), {});
    assert.ok(r.couldNotRun.length >= 1, "could-not-run");
    assert.match(r.couldNotRun.join("\n"), /factory: requirements-dev\.txt at the head could not be read by the dependency rule — it is a symbolic link, which this rule does not follow\./);
    assert.ok(!JSON.stringify([inv.errors, inv.decl, r]).includes(WORD), "nothing of the file outside the project");
    // Should the rule itself throw, that is could-not-run with a line of its own, and not a gate that fell over.
    const fell = judgeDependencyChange(root, path.join(root, "real"), { allowlist: 5 });
    assert.deepEqual([fell.failures, fell.grants], [[], []]);
    assert.match(fell.couldNotRun.join("\n"), /^factory: the dependency rule could not judge this change — .+\. Whether it adds a dependency nobody approved is not known\.$/);
  } finally {
    rmSync(top, { recursive: true, force: true });
  }
  // A tree that says why it did not read a file is believed, and the file is not "declares nothing".
  const linked = judgeDependencies(inventory(treeOf(["package.json"], () => ({ unread: "it is a symbolic link, which this rule does not follow" }))), inventory(tree({ "package.json": pkg({}) })));
  assert.deepEqual(linked.errors.map((e) => `${e.path} at ${e.side}: ${e.why}`), ["package.json at the head: it is a symbolic link, which this rule does not follow"]);
});

test("nothing the rule prints carries a URL's user, password or token, and an entry copied from its output still approves", () => {
  // A made-up word in the place a password or token has in a URL: the test is that it is not printed.
  const MARK = "zq7-made-up-0123456789";
  const at = (scheme, host, rest = "", user = "user") => `${scheme}://${[user, MARK].join(":")}@${host}${rest}`;
  const token = (host, rest) => `git+https://${MARK}@${host}${rest}`;
  const npmHad = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0") }) };
  const cases = [
    ["--index-url in a requirements file", { "requirements.txt": "idna==3.7\n" }, { "requirements.txt": `--index-url ${at("https", "pypi.corp.example", "/simple")}\nidna==3.7\n` }, /index-url https:\/\/pypi\.corp\.example\/simple in requirements\.txt, from https:\/\/pypi\.corp\.example\/simple:/],
    ["registry= in .npmrc", npmHad, { ...npmHad, ".npmrc": `registry=${at("https", "npm.corp.example", "/")}\n` }, /registry=https:\/\/npm\.corp\.example\/ in \.npmrc, from https:\/\/npm\.corp\.example\/:/],
    ["proxy= in .npmrc", npmHad, { ...npmHad, ".npmrc": `proxy=${at("http", "proxy.corp.example:3128")}\n` }, /proxy=http:\/\/proxy\.corp\.example:3128 in \.npmrc/],
    ["a git URL with a token in package.json", { "package.json": pkg({}) }, { "package.json": pkg({ lib: token("github.com", "/corp/lib.git#v1.0.0") }) }, /npm package lib "git\+https:\/\/github\.com\/corp\/lib\.git#v1\.0\.0" in package\.json/],
    ["a tarball URL with a query in package.json", { "package.json": pkg({}) }, { "package.json": pkg({ lib: `${at("https", "files.corp.example", "/lib-1.0.0.tgz")}?sig=${MARK}` }) }, /npm package lib "https:\/\/files\.corp\.example\/lib-1\.0\.0\.tgz" in package\.json/],
    ["a direct reference in a requirements file", { "requirements.txt": "idna==3.7\n" }, { "requirements.txt": `idna==3.7\nlib @ ${token("github.com", "/corp/lib.git@v1.0.0")}\n` }, /PyPI package lib "lib @ git\+https:\/\/github\.com\/corp\/lib\.git@v1\.0\.0" in requirements\.txt/],
    ["a uv index in pyproject.toml", { "pyproject.toml": pyproj('["lib>=1"]') }, { "pyproject.toml": pyproj('["lib>=1"]', `\n[[tool.uv.index]]\nname = "corp"\nurl = "${at("https", "pypi.corp.example", "/simple")}"\n`) }, /tool\.uv\.index https:\/\/pypi\.corp\.example\/simple in pyproject\.toml/],
    ["a lockfile entry's resolved", npmHad, { ...npmHad, "package-lock.json": lock({ "node_modules/a": { version: "1.0.2", resolved: at("https", "npm.corp.example", "/a/-/a-1.0.2.tgz"), integrity: "sha512-a" } }) }, /npm package a "\^1\.0\.0" in package\.json, package-lock\.json, from https:\/\/npm\.corp\.example\/a\/-\/a-1\.0\.2\.tgz:/],
    ["an .npmrc setting named for a secret, on neither list", npmHad, { ...npmHad, ".npmrc": `//npm.corp.example/:_authtoken=${MARK}\n` }, /\/\/npm\.corp\.example\/:_authtoken=<a value this rule does not print, sha256 [0-9a-f]{8}> in \.npmrc/],
  ];
  for (const [label, b, h, shown] of cases) {
    const r = judge(b, h);
    assert.ok(blocking(r).length >= 1, `${label}: a finding`);
    const lines = r.findings.map(findingLine);
    assert.match(lines.join("\n"), shown, label);
    assert.ok(!JSON.stringify([r, lines]).includes(MARK), `${label}: the password is in what the rule returns: ${lines.join("\n").slice(0, 300)}`);
    // Each entry the lines write out, given back as the allowlist, approves its finding.
    const again = judge(b, h, r.findings.map((f) => ({ ...approvingEntry(f), reason: "copied from the blocking line" })));
    assert.deepEqual(blocking(again), [], `${label}: the entries copied from the output approve it`);
  }
  // An entry written with the credentials in it is the same place.
  assert.deepEqual(blocking(judge(cases[0][1], cases[0][2], [{ kind: "dependency-source", ecosystem: "PyPI", source: at("https", "pypi.corp.example", "/simple"), reason: "x" }])), []);
  // What it could not read is quoted with the same parts left out, and a file that is not JSON is not quoted at all.
  const bad = judge({ "requirements.txt": "idna==3.7\n" }, { "requirements.txt": `idna==3.7\nlib from ${at("https", "files.corp.example", "/lib.whl")}\n`, "package.json": `{ "token": "${MARK}", }`, "uv.toml": `index-url = ${at("https", "pypi.corp.example", "/simple-with-a-long-path-so-the-cut-falls-inside")}\n` });
  assert.equal(bad.errors.length, 3);
  assert.ok(!JSON.stringify(bad).includes(MARK) && !JSON.stringify(bad).includes(MARK.slice(0, 6)), JSON.stringify(bad.errors));
  assert.equal(bad.errors.find((e) => e.path === "requirements.txt").why, "line 2: a requirement this rule does not read: lib from https://files.corp.example/lib.whl");
  assert.match(bad.errors.find((e) => e.path === "package.json").why, /^it is not JSON(?: \(at position \d+(?: \(line \d+ column \d+\))?\))?$/);
  // Whatever else it quotes from a file it could not read: a file a requirements file includes by
  // URL, a requirement in a pyproject.toml, and the reason a tree gives for not reading a file.
  const files = {
    "requirements.txt": `-r ${at("https", "files.corp.example", "/requirements.txt")}\n`,
    "pyproject.toml": pyproj(`["lib from ${at("https", "files.corp.example", `/${"long-path-".repeat(8)}lib.whl`)}"]`),
    "package.json": { unread: `the server at ${at("https", "files.corp.example", "/package.json")} did not answer` },
  };
  const quoted = judgeDependencies(inventory(treeOf(Object.keys(files), (r) => files[r])), inventory(tree({ "notes.txt": "x" })));
  assert.deepEqual(quoted.errors.map((e) => `${e.path}: ${e.why}`).sort(), [
    "package.json: the server at https://files.corp.example/package.json did not answer",
    "pyproject.toml: project.dependencies holds a requirement this rule does not read: lib from https://files.corp.example/long-path-long-path-long-path-long-path-long",
    "requirements.txt: it includes https://files.corp.example/requirements.txt, which is outside the project",
  ]);
  assert.ok(!JSON.stringify(quoted).includes(MARK) && !JSON.stringify(quoted).includes(MARK.slice(0, 6)), JSON.stringify(quoted.errors));
  // A setting whose value changes is still a change, though the value is not printed.
  const tok = (v) => ({ ...npmHad, ".npmrc": `//npm.corp.example/:_authtoken=${v}\n` });
  assert.deepEqual(blocking(judge(tok("one"), tok("two"))), ["dependency-source:null"]);
  assert.deepEqual(blocking(judge(tok("one"), { ...tok("one"), "notes.txt": "x" })), []);
  // The words themselves: an ssh URL keeps its user and loses a password; a ref after a path stays.
  assert.equal(withoutCredentials("git+ssh://git@github.com/corp/lib.git#abc"), "git+ssh://git@github.com/corp/lib.git#abc");
  assert.equal(withoutCredentials(at("git+ssh", "github.com", "/corp/lib.git", "git")), "git+ssh://git@github.com/corp/lib.git");
  assert.equal(withoutCredentials("git+https://github.com/corp/lib.git@v1.0.0#egg=lib"), "git+https://github.com/corp/lib.git@v1.0.0#egg=lib");
  assert.equal(withoutCredentials(`${at("https", "host", "/x", "a@b")}?k=${MARK}#frag`), "https://host/x#frag");
  assert.equal(withoutCredentials("git@github.com:corp/lib.git"), "git@github.com:corp/lib.git");
});

test("a URL that cannot be parsed, or whose path cannot be decoded, is could-not-run for the file that gives it, and never a crash", () => {
  const had = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0") }) };
  const resolved = (u) => ({ ...had, "package-lock.json": lock({ "node_modules/a": { version: "1.0.2", resolved: u, integrity: "sha512-a" } }) });
  for (const u of ["https://registry.npmjs.org/a/-/%zz", "https://", "https://npm.corp.example:port/a/-/a-1.0.2.tgz", "http://[::1/a.tgz"]) {
    const r = judge(had, resolved(u));
    assert.deepEqual(r.errors.map((e) => `${e.path} at ${e.side}: ${e.why}`), [`package-lock.json at the head: it gives a URL this rule cannot read as one: ${u}`], u);
  }
  assert.deepEqual(judge(had, { ...had, "package.json": pkg({ a: "^1.0.0", b: "https://" }) }).errors.map((e) => e.path), ["package.json"]);
  assert.deepEqual(judge(had, { ...had, "requirements.txt": "lib @ https://\n" }).errors.map((e) => e.path), ["requirements.txt"]);
  const uvLock = (url) => `version = 1\n\n[[package]]\nname = "lib"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "${url}", hash = "sha256:x" }]\n`;
  assert.deepEqual(judge({ "uv.lock": uvLock("https://files.pythonhosted.org/packages/lib-1.0.0-py3-none-any.whl") }, { "uv.lock": uvLock("https://files.pythonhosted.org/packages/%zz") }).errors.map((e) => `${e.path}: ${e.why}`), ["uv.lock: it gives a URL this rule cannot read as one: https://files.pythonhosted.org/packages/%zz"]);
  // A uv.lock registry that is a directory and not a URL is read as it is written.
  const local = `version = 1\n\n[[package]]\nname = "lib"\nversion = "1.0.0"\nsource = { registry = "../wheels" }\nwheels = [{ url = "https://files.pythonhosted.org/packages/lib-1.0.0-py3-none-any.whl", hash = "sha256:x" }]\n`;
  assert.deepEqual(judge({ "uv.lock": local }, { "uv.lock": local, "notes.txt": "x" }).errors, []);
  // The same where the project names that directory as an index, and the files come from another host.
  const dirIndex = { "pyproject.toml": pyproj('["lib"]', `\n[[tool.uv.index]]\nname = "wheels"\nurl = "../wheels"\n`), "uv.lock": local };
  const off = judge(dirIndex, { ...dirIndex, "uv.lock": local.replace("https://files.pythonhosted.org/packages/", "https://elsewhere.example/files/") });
  assert.deepEqual(off.errors, []);
  assert.deepEqual(blocking(off), ["dependency-source:lib"]);
  // An index's URL is compared as it is written (pip fills in ${...}); one this cannot parse is a finding like any other new index.
  const odd = judge({ "requirements.txt": "idna==3.7\n" }, { "requirements.txt": "--index-url https://\nidna==3.7\n" });
  assert.deepEqual(odd.errors, []);
  assert.deepEqual(blocking(odd), ["dependency-source:null"]);
  assert.equal(canonicalSource("npm", "https://"), "url:https://");
  assert.equal(registryFileMatches("npm", "https://registry.npmjs.org/a/-/%zz", "a", "1.0.0"), false);
  // An allowlist entry whose source starts as a URL and is not one: the run says so, by the entry.
  const moved = { "package.json": pkg({ a: "git+https://github.com/corp/a.git#v1.0.2" }), "package-lock.json": lock({ "node_modules/a": { version: "1.0.2", resolved: "git+ssh://git@github.com/corp/a.git#0123456789abcdef0123456789abcdef01234567" } }) };
  const entry = { kind: "dependency-source", ecosystem: "npm", package: "a", source: "https://", reason: "x" };
  for (const head of [moved, { ...had, "notes.txt": "x" }]) {
    const r = judge(had, head, [entry]);
    assert.equal(r.errors.length, 1);
    assert.match(r.errors[0].text, /^factory: the allowlist's entry \{"kind":"dependency-source","ecosystem":"npm","package":"a","source":"https:\/\/"\} names a source that starts as a URL and cannot be read as one\./);
  }
  assert.deepEqual(blocking(judge(had, moved, [entry])), ["dependency-source:a"]);
});

test("an npm spec that starts with a dot is a path, as npm reads it, and not GitHub's shorthand", () => {
  assert.equal(npmSpec("./local", "package.json", "local").source.id, "path:local");
  assert.equal(npmSpec("./local", "packages/a/package.json", "local").source.id, "path:packages/a/local");
  assert.equal(npmSpec(".hidden/x", "package.json", "x").source.id, "path:.hidden/x");
  assert.deepEqual([npmSpec("../sibling", "package.json", "s").source.type, npmSpec("../sibling", "package.json", "s").source.own], ["path", false]);
  assert.equal(npmSpec("user/repo#v1.0.0", "package.json", "r").source.id, "git:github.com/user/repo");
  assert.equal(npmSpec("user/.github", "package.json", "r").source.id, "git:github.com/user/.github");
  assert.equal(canonicalSource("npm", "./local"), "path:./local");
  assert.equal(canonicalSource("npm", "../sibling"), "path:../sibling");
  assert.equal(canonicalSource("npm", "user/repo"), "git:github.com/user/repo");
  assert.equal(canonicalGit("./local"), "./local");
  const had = { "package.json": pkg({}), "local/package.json": JSON.stringify({ name: "local", version: "1.0.0" }) };
  assert.deepEqual(blocking(judge(had, { ...had, "package.json": pkg({ local: "./local" }) })), [], "a directory in the project");
  assert.deepEqual(blocking(judge(had, { ...had, "package.json": pkg({ local: "file:./local" }) })), [], "the same, written file:");
  assert.deepEqual(blocking(judge(had, { ...had, "package.json": pkg({ s: "../sibling" }) })), ["dependency-source:s", "new-dependency:s"], "a directory outside the project");
  assert.deepEqual(blocking(judge(had, { ...had, "package.json": pkg({ r: "user/repo" }) })), ["dependency-source:r", "new-dependency:r", "unpinned-range:r"], "the shorthand is still git");
});

test("a Go module the base held only as // indirect is a new dependency when the project starts to use it", () => {
  const mod = (...req) => `module example.com/app\n\ngo 1.22\n\nrequire github.com/a/b v1.0.0\n${req.map((r) => `require ${r}\n`).join("")}`;
  const code = (...imports) => `package id\n\nimport (\n${imports.map((i) => `\t"${i}"\n`).join("")})\n`;
  const X = "github.com/new/x v1.0.0";
  const B = { "go.mod": mod(), "go.sum": "github.com/a/b v1.0.0 h1:x=\n", "id/id.go": code("github.com/a/b") };
  const held = { ...B, "go.mod": mod(`${X} // indirect`) };
  assert.deepEqual(blocking(judge(B, held)), [], "change 1: marked indirect, and nothing uses it");
  const direct = judge(held, { ...held, "go.mod": mod(X), "id/id.go": code("github.com/a/b", "github.com/new/x") });
  assert.deepEqual(blocking(direct), ["new-dependency:github.com/new/x"], "change 2: imported, and listed as direct");
  assert.match(findingLine(direct.findings[0]), /The base's go\.mod held it only as `\/\/ indirect`, for another module, and nothing of the base's imported it; now the project uses it itself, and in factory mode a dependency needs a person's approval\./);
  const marked = judge(held, { ...held, "id/id.go": code("github.com/a/b", "github.com/new/x/sub") });
  assert.deepEqual(blocking(marked), ["new-dependency:github.com/new/x"], "imported, go.mod left as it was");
  assert.match(findingLine(marked.findings[0]), /It is marked `\/\/ indirect`, and the project's code imports it\. The base's go\.mod held it only as `\/\/ indirect`/);
  assert.deepEqual(blocking(judge(held, { ...held, "go.mod": mod(X) })), ["new-dependency:github.com/new/x"], "listed as direct, with nothing importing it yet");
  assert.deepEqual(blocking(judge(held, { ...held, "go.mod": `${mod(`${X} // indirect`)}\ntool github.com/new/x/cmd/gen\n` })), ["new-dependency:github.com/new/x"], "run by a tool line");
  assert.deepEqual(blocking(judge(held, { ...held, "go.mod": mod(`${X} // indirect`), "id/id.go": code("github.com/a/b", "github.com/new/x") }, [{ kind: "new-dependency", ecosystem: "Go", package: "github.com/new/x", reason: "x" }])), [], "approved like any new dependency");
  // What the base used already is not new: a go.mod that was not tidy, a direct line, a tool line.
  const untidy = { ...held, "id/id.go": code("github.com/a/b", "github.com/new/x") };
  assert.deepEqual(blocking(judge(untidy, { ...untidy, "go.mod": mod(X) })), [], "the base imported it under the marker");
  assert.deepEqual(blocking(judge({ ...held, "go.mod": mod(X) }, { ...held, "go.mod": mod(X), "id/id.go": code("github.com/new/x") })), [], "the base listed it as direct");
  const tooled = { ...held, "go.mod": `${mod(`${X} // indirect`)}\ntool github.com/new/x/cmd/gen\n` };
  assert.deepEqual(blocking(judge(tooled, { ...tooled, "id/id.go": code("github.com/new/x") })), [], "a tool line of the base's ran it");
  assert.deepEqual(blocking(judge(held, { ...held, "go.mod": mod("github.com/new/x v1.1.0 // indirect") })), [], "a version move of a module nothing uses");
  // An import belongs to the longest module path that holds it: the base importing x/v2 did not use x.
  const v2 = { ...B, "go.mod": mod(`${X} // indirect`, "github.com/new/x/v2 v2.0.0"), "id/id.go": code("github.com/new/x/v2/sub") };
  assert.deepEqual(blocking(judge(v2, { ...v2, "id/id.go": code("github.com/new/x/v2/sub", "github.com/new/x") })), ["new-dependency:github.com/new/x"]);
  // A Go file that is not read leaves what the project imports unknown.
  const unread = judgeDependencies(inventory(treeOf(Object.keys(held).concat("id/more.go"), (r) => (r === "id/more.go" ? { unread: "it is a symbolic link, which this rule does not follow" } : held[r]))), inventory(tree(held)));
  assert.deepEqual(unread.errors.map((e) => `${e.path} at ${e.side}: ${e.why}`), ["id/more.go at the head: it is a symbolic link, which this rule does not follow, so the modules it imports are not known"]);
});

test("a manifest the change writes under a directory this rule skips is named as not checked", () => {
  const had = { "requirements.txt": "idna==3.7\n" };
  const names = (head) => judge(had, head).notRead.map((n) => `${n.path} (${n.ecosystem})`);
  assert.deepEqual(names({ ...had, "build/requirements.txt": "six==1.17.0\n" }), ["build/requirements.txt (under build/, a directory this rule does not read)"]);
  assert.deepEqual(names({ ...had, "sub/dist/package.json": pkg({ z: "1.0.0" }), "venv/Cargo.toml": "", "dist/notes.txt": "x" }), ["sub/dist/package.json (under dist/, a directory this rule does not read)", "venv/Cargo.toml (under venv/, a directory this rule does not read)"]);
  assert.deepEqual(names({ ...had, "samples/bad/.tfguard-fixture": "why\n", "samples/bad/package.json": pkg({ z: "1.0.0" }) }), ["samples/bad/package.json (under samples/bad, a declared fixture, which this rule does not read)"]);
  assert.deepEqual(names({ ...had, "deploy/requirements.txt": "six==1.17.0\n", "Cargo.toml": "" }), ["Cargo.toml (crates.io)"]);
  assert.deepEqual(blocking(judge(had, { ...had, "build/requirements.txt": "six==1.17.0\n" })), [], "and it is not read");
});

test("under a registry the project names whose paths have no /-/, the package's name is in the path segment for segment", () => {
  const GH = "https://npm.pkg.github.com/";
  const at = (name, version) => ({ version, resolved: `${GH}download/${name}/${version}/0123456789abcdef0123456789abcdef01234567`, integrity: `sha512-${name}-${version}` });
  const proj = (e, key = "@corp/lib", npmrc = `@corp:registry=${GH}\n`) => ({ ".npmrc": npmrc, "package.json": pkg({ [key]: "^1.0.0" }), "package-lock.json": lock({ [`node_modules/${key}`]: e }) });
  const moved = judge(proj(at("@corp/lib", "1.0.0")), proj({ ...at("@other/evil", "1.0.2") }));
  assert.deepEqual(blocking(moved), ["dependency-source:@corp/lib"]);
  assert.match(findingLine(moved.findings[0]), /the lockfile takes @corp\/lib 1\.0\.2 from a file of the registry's that is not that package's/);
  assert.deepEqual(blocking(judge(proj(at("@corp/lib", "1.0.0")), proj(at("@corp/lib", "1.0.2")))), [], "a version move to its own path");
  assert.deepEqual(blocking(judge(proj(at("@corp/lib", "1.0.0")), proj(at("@corp/other", "1.0.2")))), ["dependency-source:@corp/lib"], "another package of the scope");
  assert.deepEqual(blocking(judge(proj(at("@corp/lib", "1.0.0")), proj(at("@other/lib", "1.0.2")))), ["dependency-source:@corp/lib"], "another scope's package of the same last name");
  assert.deepEqual(blocking(judge(proj(at("@corp/lib", "1.0.0")), proj(at("@corp/lib-extra", "1.0.2")))), ["dependency-source:@corp/lib"], "a name that only starts the same");
  assert.deepEqual(blocking(judge(proj(at("@corp/lib", "1.0.0")), proj({ ...at("@corp/lib", "1.0.2"), resolved: `${GH}download/@corp%2flib/1.0.2/0123` }))), [], "the scope's slash written %2f");
  const all = `registry=${GH}\n`;
  assert.deepEqual(blocking(judge(proj(at("lib", "1.0.0"), "lib", all), proj(at("lib", "1.0.2"), "lib", all))), [], "an unscoped name's own path");
  assert.deepEqual(blocking(judge(proj(at("lib", "1.0.0"), "lib", all), proj(at("@other/lib", "1.0.2"), "lib", all))), ["dependency-source:lib"], "an unscoped name is not a scoped package's last part");
  assert.deepEqual(blocking(judge(proj(at("lib", "1.0.0"), "lib", all), proj(at("evil", "1.0.2"), "lib", all))), ["dependency-source:lib"]);
  assert.equal(registryFileMatches("npm", `${GH}download/@corp/lib/1.0.2/0123`, "@corp/lib", "1.0.2", [GH]), true);
  assert.equal(registryFileMatches("npm", `${GH}download/@corp/lib/1.0.2/0123`, "@corp/lib", "1.0.2", []), null, "a registry the project does not name is not judged");
  // A URL a manifest gives there is checked the same way.
  const url = (u) => ({ ".npmrc": all, "package.json": pkg({ lib: u }) });
  assert.deepEqual(blocking(judge(url("^1.0.0"), url(`${GH}download/evil/1.0.2/0123`))), ["dependency-source:lib"]);
});

test("a Python lockfile entry from an index lists files named for the package, on whatever host", () => {
  const uv = (v, file, index = CORP_PY, host = "https://pypi.corp.example/files") => `version = 1\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\ndependencies = [{ name = "my-lib" }]\n\n[[package]]\nname = "my-lib"\nversion = "${v}"\nsource = { registry = "${index}" }\nwheels = [{ url = "${host}/${file}", hash = "sha256:${file}" }]\n`;
  const proj = (lockText) => ({ "pyproject.toml": pyproj('["my-lib"]', uvIndex("default = true\n")), "uv.lock": lockText });
  const had = proj(uv("1.0.0", "my_lib-1.0.0-py3-none-any.whl"));
  const other = judge(had, proj(uv("1.0.2", "other-1.0.2-py3-none-any.whl")));
  assert.deepEqual(blocking(other), ["dependency-source:my-lib"]);
  assert.match(findingLine(other.findings[0]), /PyPI package my-lib "1\.0\.2" in uv\.lock, from https:\/\/pypi\.corp\.example\/files\/other-1\.0\.2-py3-none-any\.whl: the lockfile takes my-lib 1\.0\.2 from a file of the registry's that is not that package's/);
  for (const file of ["my_lib-1.0.2-py3-none-any.whl", "My.Lib-1.0.2.tar.gz", "my-lib-1.0.2.tar.gz", "my_lib-1.0.2%2Bcorp-py3-none-any.whl"]) assert.deepEqual(blocking(judge(had, proj(uv("1.0.2", file)))), [], file);
  for (const file of ["my_lib_extra-1.0.2-py3-none-any.whl", "my-1.0.2.tar.gz", "lib-1.0.2.tar.gz", "download"]) assert.deepEqual(blocking(judge(had, proj(uv("1.0.2", file)))), ["dependency-source:my-lib"], file);
  // poetry.lock lists its files by name.
  const poetry = `[tool.poetry]\nname = "p"\nversion = "1.0.0"\n\n[tool.poetry.dependencies]\npython = "^3.10"\nmy-lib = { version = "^1.0", source = "corp" }\n\n[[tool.poetry.source]]\nname = "corp"\nurl = "${CORP_PY}"\npriority = "primary"\n`;
  const po = (v, ...files) => ({ "pyproject.toml": poetry, "poetry.lock": `[[package]]\nname = "my-lib"\nversion = "${v}"\ndescription = ""\noptional = false\npython-versions = "*"\nfiles = [${files.map((f) => `{ file = "${f}", hash = "sha256:${f}" }`).join(", ")}]\n\n[package.source]\ntype = "legacy"\nurl = "${CORP_PY}"\nreference = "corp"\n\n[metadata]\nlock-version = "2.0"\npython-versions = "^3.10"\ncontent-hash = "x"\n` });
  assert.deepEqual(blocking(judge(po("1.0.0", "my_lib-1.0.0-py3-none-any.whl"), po("1.0.2", "my_lib-1.0.2-py3-none-any.whl", "other-1.0.2.tar.gz"))), ["dependency-source:my-lib"]);
  assert.deepEqual(blocking(judge(po("1.0.0", "my_lib-1.0.0-py3-none-any.whl"), po("1.0.2", "my_lib-1.0.2-py3-none-any.whl", "my-lib-1.0.2.tar.gz"))), []);
  assert.equal(pyFileNamed("zope.interface-6.0-cp311-cp311-manylinux_2_5_x86_64.whl", "zope-interface"), true);
  assert.equal(pyFileNamed("py-3dmol-1.0.tar.gz", "py-3dmol"), true, "a name with a hyphen and a digit after it");
  assert.equal(pyFileNamed("lib-extra-1.0.tar.gz", "lib"), false, "what follows the name starts as a version does");
  assert.equal(pyFileNamed("https://host/files/a_b-1!2.0.tar.gz?x=1#sha256=abc", "a.b"), true);
  assert.equal(pyFileNamed("https://host/files/a%5Fb-1.0.tar.gz", "a-b"), true, "an escape in the name is read");
  assert.equal(pyFileNamed("https://host/files/lib-1.0.2%2F..%2Fother-1.0.2-py3-none-any.whl", "lib"), false, "an escaped slash is not a file's name");
});

// The reviewer's comments on 37b92ba.

test("a range that takes anything is pinned only by a lockfile that covers its manifest and holds the name", () => {
  const root = { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0") }) };
  const tools = (range) => ({ ...root, "tools/package.json": pkg({ x: range }) });
  // A package.json under a lockfile that is not its workspace's member: nothing pins it.
  const nested = judge(tools("^1.0.0"), tools("*"));
  assert.deepEqual(blocking(nested), ["unpinned-range:x"]);
  assert.deepEqual(nested.findings[0].manifests, ["tools/package.json"]);
  assert.deepEqual(blocking(judge(tools("^1.0.0"), { ...tools("^1.0.0"), "notes.txt": "x" })), [], "left as it was");
  assert.deepEqual(blocking(judge(tools("*"), { ...tools("*"), "notes.txt": "x" })), [], "a range the base had");
  // The root's own range, which its lockfile holds, is pinned; so is a member's that the lockfile links.
  assert.deepEqual(blocking(judge(root, { ...root, "package.json": pkg({ a: "*" }) })), []);
  const ws = (range) => ({ "package.json": pkg({}, { workspaces: ["packages/*"] }), "packages/m/package.json": JSON.stringify({ name: "m", version: "1.0.0", dependencies: { a: range } }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0"), "node_modules/m": { resolved: "packages/m", link: true }, "packages/m": { name: "m", version: "1.0.0", dependencies: { a: range } } }) });
  assert.deepEqual(blocking(judge(ws("^1.0.0"), ws("*"))), [], "a workspace member the lockfile covers");
  // A lockfile that covers the manifest and does not hold the name pins nothing for it.
  const own = (deps, entries) => ({ "package.json": pkg(deps), "package-lock.json": lock(entries) });
  assert.deepEqual(blocking(judge(own({ a: "^1.0.0" }, { "node_modules/a": reg("a", "1.0.0") }), own({ a: "^1.0.0", b: "*" }, { "node_modules/a": reg("a", "1.0.0") }))), ["new-dependency:b", "unpinned-range:b"]);
  // A lockfile this rule does not read is taken to cover what is under it, as before.
  const yarn = (range) => ({ "package.json": pkg({}), "yarn.lock": "# yarn lockfile v1\n", "tools/package.json": pkg({ x: range }) });
  assert.deepEqual(blocking(judge(yarn("^1.0.0"), yarn("*"))), []);
  // Python: a lockfile above that does not hold the name; one that does.
  const py = (deps) => `[project]\nname = "t"\nversion = "1.0.0"\ndependencies = ${deps}\n`;
  const uv = (...names) => `version = 1\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\n${names.map((n) => `\n[[package]]\nname = "${n}"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\n`).join("")}`;
  const pyTools = (deps, ...held) => ({ "pyproject.toml": pyproj("[]"), "uv.lock": uv(...held), "tools/pyproject.toml": py(deps) });
  assert.deepEqual(blocking(judge(pyTools('["x>=1"]'), pyTools('["x"]'))), ["unpinned-range:x"]);
  assert.deepEqual(blocking(judge(pyTools('["x>=1"]', "X"), pyTools('["x"]', "X"))), [], "held by the lockfile above, the name folded");
  assert.deepEqual(blocking(judge({ Pipfile: "[packages]\n", "Pipfile.lock": "{}" }, { Pipfile: '[packages]\nrequests = "*"\n', "Pipfile.lock": "{}" })), ["new-dependency:requests", "unpinned-range:requests"], "a lockfile that does not hold it");
  const pdm = (deps) => ({ "pyproject.toml": py(deps), "pdm.lock": "" });
  assert.deepEqual(blocking(judge(pdm('["x>=1"]'), pdm('["x"]'))), [], "a lockfile this rule does not read");
});

test("an allowlist entry's ecosystem is one of the three, and not a word every object has", () => {
  for (const ecosystem of ["constructor", "__proto__", "hasOwnProperty", "crates.io", ""]) {
    const { entries, ignored } = parseAllowlist({ exemptions: [{ kind: "new-dependency", ecosystem, package: "x", reason: "r" }] });
    assert.deepEqual(entries, [], ecosystem);
    assert.match(ignored[0].why, /^names no ecosystem this rule reads/, ecosystem);
  }
  assert.deepEqual(parseAllowlist({ exemptions: [{ kind: "new-dependency", ecosystem: "pypi", package: "x", reason: "r" }] }).entries.map((e) => e.ecosystem), ["PyPI"]);
});

// The reviewer's comments on 9f179a0.

test("a setting moved under a key named __proto__ is taken away, and a word every object has is a setting like any other", () => {
  const py = (uv) => pyproj('["lib>=1"]', `\n[tool.uv]\n${uv}\n`);
  const moved = judge({ "pyproject.toml": py(`index-url = "${CORP_PY}"`) }, { "pyproject.toml": py(`__proto__ = { index-url = "${CORP_PY}" }`) });
  assert.deepEqual(moved.errors, []);
  assert.deepEqual(moved.findings.map((f) => f.spec).sort(), [`tool.uv.__proto__={"index-url":"${CORP_PY}"}`, `tool.uv.index-url ${CORP_PY}`]);
  assert.ok(moved.findings.some((f) => f.removed), "the index the base named is gone");
  const table = judge({ "pyproject.toml": py(`[[tool.uv.index]]\nurl = "${CORP_PY}"\ndefault = true`) }, { "pyproject.toml": py(`[tool.uv.__proto__]\nindex = [{ url = "${CORP_PY}", default = true }]`) });
  assert.ok(table.findings.some((f) => f.removed) && table.errors.length === 0, JSON.stringify(table.findings.map((f) => f.spec)));
  // The same words as settings, as a dependency's name, as an index's name and as a poetry priority.
  const npm = { "package.json": pkg({}) };
  for (const key of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
    const r = judge(npm, { ...npm, ".npmrc": `${key}=x\n` });
    assert.deepEqual([r.errors, r.findings.map((f) => f.spec)], [[], [`${key}=x`]], key);
    const u = judge({ "pyproject.toml": py("") }, { "pyproject.toml": py(""), "uv.toml": `${key} = 1\n` });
    assert.deepEqual([u.errors, u.findings.map((f) => f.spec)], [[], [`${key}=1`]], key);
  }
  assert.deepEqual(blocking(judge({ "pyproject.toml": '[tool.poetry]\nname = "p"\n[tool.poetry.dependencies]\na = "1.0"\n' }, { "pyproject.toml": '[tool.poetry]\nname = "p"\n[tool.poetry.dependencies]\na = "1.0"\n__proto__ = "1.0"\n' })), ["new-dependency:__proto__"]);
  assert.deepEqual(blocking(judge(npm, { "package.json": '{"name":"p","version":"1.0.0","dependencies":{"__proto__":"1.0.0"}}' })), ["new-dependency:__proto__"]);
  const named = judge({ "pyproject.toml": py("") }, { "pyproject.toml": py(`[[tool.uv.index]]\nname = "constructor"\nurl = "${CORP_PY}"\nexplicit = true\n\n[tool.uv.sources]\nlib = { index = "constructor" }`) });
  assert.deepEqual([named.errors, blocking(named)], [[], ["dependency-source:lib", "dependency-source:null"]]);
  assert.match(findingLine(named.findings.find((f) => f.package === "lib")), /in pyproject\.toml, from the index constructor: its source changed/);
  const poetry = (prio) => `[tool.poetry]\nname = "p"\n[tool.poetry.dependencies]\na = "1.0"\n\n[[tool.poetry.source]]\nname = "corp"\nurl = "${CORP_PY}"\npriority = "${prio}"\n`;
  const prio = judge({ "pyproject.toml": poetry("primary") }, { "pyproject.toml": poetry("constructor") });
  assert.deepEqual(prio.errors, []);
  assert.match(prio.findings.map(findingLine).join("\n"), /at the base, and the head names it only as priority = "constructor":/);
});
