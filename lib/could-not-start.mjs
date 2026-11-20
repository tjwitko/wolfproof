// Failing closed before the command is loaded.
//
// bin/validate.mjs installs each command's crash handler in its own top-level code, and a module's
// own code runs only after everything it imports has been found, read and run. Anything that went
// wrong before that had no handler, so Node ended the process with its default exit 1, which is the
// gate's "blocked": a verdict on a project nothing had looked at. Measured on c54b4a9, in node:20
// and node:22 containers:
//
//   - a copy of the package whose dependencies are not installed, every command, both versions:
//     exit 1, with Node's "Cannot find package" and nothing of the gate's;
//   - under Node 20, which reads a module graph across turns of the event loop, an exception
//     thrown from a timer 0, 5, 20 or 50 ms after start: exit 1. The handler was in place 82 to
//     151 ms after start, and 505 to 786 ms on a fifth of a CPU, which is how a test that threw at
//     200 ms failed once on a slow runner (run 44657815324, node 20 only). Under Node 22 the same
//     timers were caught by the command's handler: nothing ran between the start and the CLI's code.
//
// So bin/validate.mjs installs this first, imports the rest after it, and takes it away when the
// command's own handler is in place. This file imports nothing but Node's own modules, so that it
// cannot itself be what fails to load.
//
// What is left, under Node 20 only: the time Node takes to read bin/validate.mjs and this file
// before any line of either has run, 8 to 11 ms in the same container and 10 to 94 ms on a fifth
// of a CPU. A timer set by a module preloaded with --import can still fire in it (thrown at 0, 5
// and 20 ms: exit 1; at 50 ms: exit 3), and nothing in this package runs early enough to stop that.
//
// The output is written synchronously and the process ended at once. Nothing else has been written
// by then, the text is far smaller than a pipe's buffer, and what failed to start may be in no state
// to wait for a stream.

import { writeSync } from "fs";

const COMMANDS = new Set(["init", "review", "known"]);

/**
 * What to print and the code to end with, for a failure before the command named in `argv` was
 * under way. Returned, so it can be tested without ending a process.
 *
 * Each command keeps its own contract: 3 for the gate, `known` and `review`, where it means "did not
 * finish and this is no verdict", and 70 for `init`, whose 1 means "left a file alone" and whose 3
 * means nothing. In --json mode the gate still gets its one document, as it does from a crash.
 */
export function couldNotStart(err, argv) {
  const command = COMMANDS.has(argv[2]) ? argv[2] : null;
  const reason = (err && err.message) || String(err);
  const stack = (err && err.stack) || reason;
  if (command === "init") {
    return { code: 70, stdout: "", stderr: `wolfproof init: setup could not start: ${stack}\nExit 70: it failed before it began. Nothing was written.\n` };
  }
  if (command) {
    return { code: 3, stdout: "", stderr: `wolfproof ${command}: the command could not start, or failed where it has no handler of its own: ${stack}\nExit 3: it did not finish.\n` };
  }
  return {
    code: 3,
    stdout: argv.includes("--json") ? `${JSON.stringify({ exitCode: 3, incomplete: true, error: `the gate could not start: ${reason}` })}\n` : "",
    stderr: `wolfproof: the gate could not start: ${stack}\nThis is not a verdict on the project. Exit 3: the gate could not run.\n`,
  };
}

function write(fd, text) {
  // A pipe nobody reads any more, or one that is full: the exit code is still owed.
  try {
    writeSync(fd, text);
  } catch {
    /* nothing to write to */
  }
}

/** Reports `err` as a failure to start and ends the process. Does not return. */
export function endNotStarted(err, { argv = process.argv, exit = (code) => process.exit(code), out = write } = {}) {
  const r = couldNotStart(err, argv);
  if (r.stdout) out(1, r.stdout);
  out(2, r.stderr);
  exit(r.code);
}

let installed = null;

/**
 * From here until `standDown`, an uncaught exception or an unhandled rejection is a failure to
 * start. Called once, first thing, by the CLI when it is the program being run; a library that
 * imports the gate gets no handlers.
 */
export function failClosedUntilStarted() {
  if (installed) return;
  installed = function couldNotStartHandler(err) {
    endNotStarted(err);
  };
  process.on("uncaughtException", installed);
  process.on("unhandledRejection", installed);
}

/** The command's own handler is in place, or the command is about to run with its own: this one goes. */
export function standDown() {
  if (!installed) return;
  process.off("uncaughtException", installed);
  process.off("unhandledRejection", installed);
  installed = null;
}
