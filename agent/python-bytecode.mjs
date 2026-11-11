// Where Python's bytecode goes when the gate itself runs Python over a project.
//
// Python writes a compiled copy of every module it compiles or imports into __pycache__/ beside the
// source. Two of the gate's own steps do that to the project being judged: the build check's
// `python3 -m py_compile`, and pytest in the test check, which imports the project and writes its
// own rewritten copy of each test module. The gate then left files in the project it had just
// judged, and factory mode read them on the next run as files the change wrote where no source
// check looks: the second run of a clean one-file project blocked on its own first run.
//
// Two ways out, because one does not cover both steps:
//   - PYTHONDONTWRITEBYTECODE stops an import writing bytecode, pytest honours it for its rewritten
//     modules, and a process the suite starts inherits it. It is what a container image commonly
//     sets, so a suite is unlikely to mind. That is NO_BYTECODE, for pytest and the version probes.
//   - py_compile ignores that variable: writing bytecode is its whole job. PYTHONPYCACHEPREFIX
//     (Python 3.8 and later) sends what it writes to a directory of the caller's choosing. That is
//     bytecodeOutsideProject. On an older Python the variable is not read and py_compile writes
//     beside the source, as before.
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

/** Environment for a Python the gate starts that imports from the project: it writes no bytecode. */
export const NO_BYTECODE = Object.freeze({ PYTHONDONTWRITEBYTECODE: "1" });

/**
 * Calls `run(extraEnv)` and returns what it returns. `extraEnv` points Python's bytecode cache at a
 * temporary directory that is removed afterwards. Empty when the caller's environment already sets
 * the prefix (the bytecode is already going somewhere other than the project), and when no temporary
 * directory can be made: the step still runs, as it did before this existed.
 */
export function bytecodeOutsideProject(run, env = process.env) {
  if (env.PYTHONPYCACHEPREFIX) return run({});
  let dir = null;
  try {
    dir = mkdtempSync(path.join(tmpdir(), "wolfproof-pyc-"));
  } catch {
    /* no temporary directory: Python writes beside the source, as it would have */
  }
  try {
    return run(dir ? { PYTHONPYCACHEPREFIX: dir } : {});
  } finally {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
}
