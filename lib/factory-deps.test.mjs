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

test("a version move of a dependency the project had passes, and so do the packages it brings", () => {
  const r = judge(base, {
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
  assert.deepEqual(blocking(judge(gob, { ...gob, "go.mod": mod("require example.com/p/lib v0.0.0\n"), "lib/go.mod": "module example.com/p/lib\n\ngo 1.22\n" })), [], "a module of the project's own");
});

test("where a dependency is declared: a fixture's manifest is not the project's, and a move hides nothing", () => {
  const fixture = { "fixtures/x/.tfguard-fixture": "reason: a sample", "fixtures/x/package.json": pkg({ lodash: "4.17.4" }) };
  assert.deepEqual(blocking(judge({ ...base, ...fixture }, { ...base, ...fixture, "package.json": pkg({ a: "^1.0.0", lodash: "4.17.4" }) })), ["new-dependency:lodash"]);
  const moved = { "app/package.json": base["package.json"], "app/package-lock.json": base["package-lock.json"] };
  assert.deepEqual(blocking(judge(base, moved)), []);
  assert.deepEqual(blocking(judge(moved, base)), []);
  assert.deepEqual(blocking(judge(base, { ...moved, "app/package.json": pkg({ a: "^1.0.0", x: "^1.0.0" }) })), ["new-dependency:x"]);
  assert.deepEqual(blocking(judge(moved, { ...base, "package.json": pkg({ a: "^1.0.0", x: "^1.0.0" }) })), ["new-dependency:x"]);
  const ws = (m) => ({ ...base, "package.json": pkg({ a: "^1.0.0" }, { workspaces: ["packages/*"] }), "packages/m/package.json": JSON.stringify({ name: "m", dependencies: m }), "packages/n/package.json": JSON.stringify({ name: "n" }) });
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
