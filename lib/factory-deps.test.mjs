import test from "node:test";
import assert from "node:assert/strict";

import { canonicalGit, findingLine, inventory, judgeDependencies, markerDirs, normalName, npmSpec, parseGoMod, parseRequirements, treeOf } from "./factory-deps.mjs";
import { allowlisted, GRANT_KINDS, parseAllowlist } from "./factory.mjs";

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
  assert.deepEqual(blocking(judge({ Pipfile: "[packages]\n", "Pipfile.lock": "{}" }, { Pipfile: '[packages]\nrequests = "*"\n', "Pipfile.lock": "{}" })), ["new-dependency:requests"], "a lockfile pins what installs");
  assert.deepEqual(blocking(judge({ "pyproject.toml": "[build-system]\nrequires=[]\n" }, { "pyproject.toml": '[build-system]\nrequires=["setuptools>=61", "cython>=3"]\n' })), ["new-dependency:cython", "new-dependency:setuptools"], "what the build installs counts");
  assert.deepEqual(blocking(judge({ "pyproject.toml": '[project]\nname="p"\ndynamic=["dependencies"]\n[tool.setuptools.dynamic]\ndependencies={file=["deps.txt"]}\n', "deps.txt": "" }, { "pyproject.toml": '[project]\nname="p"\ndynamic=["dependencies"]\n[tool.setuptools.dynamic]\ndependencies={file=["deps.txt"]}\n', "deps.txt": "evil==1.0\n" })), ["new-dependency:evil"], "a file setuptools reads dependencies from");
});

test("Python lockfiles: what a new dependency brings, and a package that is built from source", () => {
  const uv = (pkgs) => pkgs.map(([n, v, { deps = [], wheel = true } = {}]) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\nsdist = { url = "https://files.pythonhosted.org/${n}-${v}.tar.gz" }\n${wheel ? `wheels = [{ url = "https://files.pythonhosted.org/${n}-${v}-py3-none-any.whl" }]\n` : ""}dependencies = [${deps.map((d) => `{ name = "${d}" }`).join(", ")}]\n`).join("\n");
  const proj = (deps) => `[project]\nname = "p"\ndependencies = [${deps.map((d) => `"${d}"`).join(", ")}]\n`;
  const r = judge({ "pyproject.toml": proj([]), "uv.lock": uv([["p", "0"]]) }, { "pyproject.toml": proj(["x>=1"]), "uv.lock": uv([["p", "0"], ["x", "1.0", { deps: ["y"] }], ["y", "2.0", { wheel: false }]]) });
  assert.deepEqual(blocking(r), ["install-script:y", "new-dependency:x"]);
  assert.match(findingLine(r.findings.find((f) => f.kind === "new-dependency")), /It adds 2 packages to uv\.lock, and 1 of them is built from source when installed, which runs its own code \(y\)/);
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
  assert.match(findingLine(r.findings.find((f) => f.package === "evil")), /It is new to package-lock\.json, brought in by a 1\.0\.1, which the base's lockfiles already held; no manifest declares it\. .* With it come 1 more package new to the lockfile, and evil-dep runs code when installed\./);
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
  // A first lockfile: every name is new, and each is brought in by one that is new too.
  assert.deepEqual(blocking(judge({ "package.json": pkg({ a: "^1.0.0" }) }, { "package.json": pkg({ a: "^1.0.0" }), "package-lock.json": lock({ "node_modules/a": reg("a", "1.0.0", { dependencies: { b: "^1" } }), "node_modules/b": reg("b", "1.0.0") }) })), []);

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
  assert.deepEqual(blocking(judge(npmBase, npmHead)), ["new-dependency:is-number"]);
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
