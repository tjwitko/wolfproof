// The gate leaves no Python bytecode in the project it judges (agent/python-bytecode.mjs).
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readdirSync, rmSync, realpathSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { bytecodeOutsideProject } from "./python-bytecode.mjs";
import { runSuites } from "./test-execution.mjs";

const HAS_PYTHON = spawnSync("python3", ["--version"], { encoding: "utf8" }).status === 0;

function project(files, fn) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "pyc-")));
  for (const [rel, contents] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), contents);
  }
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Every __pycache__ directory under `dir`, relative to it.
function pycaches(dir, rel = "") {
  return readdirSync(path.join(dir, rel), { withFileTypes: true }).flatMap((e) =>
    !e.isDirectory() ? [] : e.name === "__pycache__" ? [path.join(rel, e.name)] : pycaches(dir, path.join(rel, e.name))
  );
}

// The variables that decide where bytecode goes, cleared for the length of `fn`: this machine, or a
// CI runner, may set either, and the test has to show what the gate does when neither is set.
function withoutPythonEnv(fn) {
  const saved = {};
  for (const k of ["PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX"]) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
  }
}

test("the prefix is a directory that exists for the run and is gone after it", () => {
  let seen = null;
  const out = bytecodeOutsideProject((extra) => {
    seen = extra.PYTHONPYCACHEPREFIX;
    assert.ok(existsSync(seen), "there for the run");
    return "result";
  }, {});
  assert.equal(out, "result");
  assert.ok(seen && !existsSync(seen), "removed afterwards");
  // Removed when the run throws, too.
  assert.throws(() => bytecodeOutsideProject((extra) => { seen = extra.PYTHONPYCACHEPREFIX; throw new Error("x"); }, {}), /x/);
  assert.ok(!existsSync(seen));
});

test("a prefix the environment already sets is left alone", () => {
  assert.deepEqual(bytecodeOutsideProject((extra) => extra, { PYTHONPYCACHEPREFIX: "/somewhere/else" }), {});
});

test("py_compile run with the prefix writes nothing beside the source", { skip: HAS_PYTHON ? false : "python3 is not installed here" }, () => {
  project({ "calc.py": "def add(a, b):\n    return a + b\n", "pkg/mod.py": "X = 1\n" }, (dir) => {
    const files = [path.join(dir, "calc.py"), path.join(dir, "pkg", "mod.py")];
    const compile = (extra) => spawnSync("python3", ["-m", "py_compile", ...files], { encoding: "utf8", env: { ...process.env, ...extra } });
    withoutPythonEnv(() => {
      const r = bytecodeOutsideProject(compile);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(pycaches(dir), []);
      // A syntax error is still reported, by the same message.
      writeFileSync(path.join(dir, "calc.py"), "def add(a, b:\n");
      const bad = bytecodeOutsideProject(compile);
      assert.notEqual(bad.status, 0);
      assert.match(bad.stderr, /SyntaxError/);
      assert.deepEqual(pycaches(dir), []);
      // The control: without it, this is where py_compile writes. What the gate used to leave.
      writeFileSync(path.join(dir, "calc.py"), "def add(a, b):\n    return a + b\n");
      assert.equal(compile({}).status, 0);
      assert.deepEqual(pycaches(dir).sort(), ["__pycache__", path.join("pkg", "__pycache__")]);
    });
  });
});

// `python3 -m pytest` runs the module named pytest that Python finds first, and the project's own
// directory is first on its path. A stand-in there imports the code under test, as pytest does,
// and prints pytest's summary line, so this runs the same on a machine without pytest.
const STAND_IN = [
  "import sys",
  'if "--version" in sys.argv:',
  '    print("pytest 0.0.0")',
  "    sys.exit(0)",
  "import calc",
  "assert calc.add(1, 1) == 2",
  'print("1 passed in 0.01s")',
  "",
].join("\n");

test("a Python suite run by the test check leaves no __pycache__ in the project", { skip: HAS_PYTHON ? false : "python3 is not installed here" }, () => {
  const files = { "calc.py": "def add(a, b):\n    return a + b\n", "test_calc.py": "from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n" };
  withoutPythonEnv(() => {
    project({ ...files, "pytest.py": STAND_IN }, (dir) => {
      const [r] = runSuites(dir, { timeoutMs: 60_000 });
      assert.equal(r.ran, true, JSON.stringify(r));
      assert.deepEqual(r.counts, { passed: 1, failed: 0, total: 1 });
      assert.deepEqual(pycaches(dir), []);
      // The control: the same command as the gate used to run it writes into the project.
      spawnSync("python3", ["-m", "pytest", "-q"], { cwd: dir, encoding: "utf8" });
      assert.deepEqual(pycaches(dir), ["__pycache__"]);
    });
    // The real pytest, where it is installed: it writes its own rewritten copy of each test module.
    const real = spawnSync("python3", ["-m", "pytest", "--version"], { cwd: tmpdir(), encoding: "utf8" }).status === 0;
    if (real) {
      project(files, (dir) => {
        const [r] = runSuites(dir, { timeoutMs: 60_000 });
        assert.equal(r.ran, true, JSON.stringify(r));
        assert.deepEqual(pycaches(dir), []);
      });
    }
  });
});
