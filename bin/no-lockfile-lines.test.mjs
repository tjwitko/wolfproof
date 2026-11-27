// The no-lockfile check through the real CLI: what its line prints, and which manifests it reaches.
//
// Measured on v1.19.1, in both modes: a package.json with no lockfile and a git dependency whose URL
// carried a token printed the token, in the line that lists the specs it could not give a lowest
// version; and tools/package.json or tools/pyproject.toml, declaring dependencies with no lockfile of
// its own and not a member of the root's workspace, was exit 0 with nothing said about it, because
// the root's lockfile was taken to cover it. The same manifest at the root of a project with no
// lockfile was exit 1. No case here needs the network: none has a dependency with a lowest version.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const CLI = fileURLToPath(new URL("./validate.mjs", import.meta.url));
const J = (o) => `${JSON.stringify(o, null, 2)}\n`;

function run(files, { factory = false } = {}) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "no-lockfile-lines-")));
  const git = (...a) => spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" });
  try {
    git("init", "-q", "-b", "main");
    writeFileSync(path.join(dir, "a.js"), "export const a = 1;\n");
    git("add", "-A");
    git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD").stdout.trim();
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), text);
    }
    git("add", "-A");
    git("commit", "-qm", "change");
    const r = spawnSync(process.execPath, [CLI, dir, "--json", ...(factory ? ["--factory", `--base=${base}`] : [])], { encoding: "utf8", timeout: 300_000, maxBuffer: 1 << 26 });
    let doc = null;
    try {
      doc = JSON.parse(r.stdout);
    } catch {
      /* the assertions say what came instead */
    }
    return { code: r.status, out: `${r.stdout}${r.stderr}`, doc, lines: (doc?.findings || []).map((f) => f.message).filter((m) => m.startsWith("check_dependencies")) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A word in the place a token has: the test is that it is not printed.
const MARK = "zq7madeup0123456789abcdef";

test("the line that lists a package.json's specs with no lowest version prints no user, password, token or query of a URL", () => {
  for (const factory of [false, true]) {
    for (const spec of [`git+https://${MARK}@github.com/corp/lib.git#v1.0.0`, `git+https://${["user", MARK].join(":")}@github.com/corp/lib.git#v1.0.0`, `https://files.corp.example/lib-1.0.0.tgz?token=${MARK}`]) {
      const r = run({ "package.json": J({ name: "p", version: "1.0.0", dependencies: { lib: spec } }) }, { factory });
      const mode = factory ? "factory" : "default";
      assert.equal(r.code, 1, `${mode} ${spec}: ${r.out.slice(0, 400)}`);
      assert.ok(!r.out.includes(MARK), `${mode}: the token is printed: ${r.lines.join(" / ").slice(0, 400)}`);
      assert.match(r.lines.join("\n"), /package\.json \(0 checked; 1 have no lowest version and were not: lib@(?:git\+https:\/\/github\.com\/corp\/lib\.git#v1\.0\.0|https:\/\/files\.corp\.example\/lib-1\.0\.0\.tgz)\)/, mode);
    }
  }
});

test("a nested manifest that no lockfile covers is reported as one at the root is, unless it is a member of the root's workspace", () => {
  const git = { lib: "git+https://github.com/corp/lib.git#v1.0.0" };
  const root = (extra = {}) => ({ "package.json": J({ name: "p", version: "1.0.0", dependencies: { lib: git.lib }, ...extra }), "package-lock.json": J({ name: "p", lockfileVersion: 3, requires: true, packages: { "": { name: "p", version: "1.0.0", dependencies: git }, "node_modules/lib": { version: "1.0.0", resolved: "git+ssh://git@github.com/corp/lib.git#0123456789abcdef0123456789abcdef01234567" } } }) });
  const tools = J({ name: "tools", version: "1.0.0", private: true, dependencies: git });
  const nested = run({ ...root(), "tools/package.json": tools });
  assert.equal(nested.code, 1, nested.out.slice(0, 400));
  assert.match(nested.lines.join("\n"), /^check_dependencies: 1 package\.json file\(s\) declare dependencies and have no lockfile[^\n]*\n {2}- tools\/package\.json \(0 checked; 1 have no lowest version/m);
  // A member of the root's workspace is covered by its lockfile, as before.
  const member = run({ ...root({ workspaces: ["tools"] }), "tools/package.json": tools });
  assert.deepEqual(member.lines.filter((m) => /tools\/package\.json/.test(m)), [], member.lines.join(" / "));
  // Python: a pyproject.toml under a root uv.lock that does not name it as a member.
  const PROJ = '[project]\nname = "t"\nversion = "1.0.0"\ndependencies = ["idna==3.7"]\n';
  const uvRoot = (ws = "") => `[project]\nname = "p"\nversion = "1.0.0"\nrequires-python = ">=3.10"\ndependencies = []\n${ws}`;
  const uvLock = 'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "p"\nversion = "1.0.0"\nsource = { virtual = "." }\n';
  const py = run({ "pyproject.toml": uvRoot(), "uv.lock": uvLock, "tools/pyproject.toml": PROJ });
  assert.equal(py.code, 1, py.out.slice(0, 400));
  assert.match(py.lines.join("\n"), /no scanner read[^\n]*\n {2}- tools\/pyproject\.toml \(PyPI\)/);
  const pyMember = run({ "pyproject.toml": uvRoot('\n[tool.uv.workspace]\nmembers = ["tools"]\n'), "uv.lock": uvLock, "tools/pyproject.toml": PROJ });
  assert.deepEqual(pyMember.lines.filter((m) => /tools\/pyproject\.toml/.test(m)), [], pyMember.lines.join(" / "));
});
