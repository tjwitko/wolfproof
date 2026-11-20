// Ending the process after its output has left it.
//
// `process.stdout.write(text); process.exit(code)` loses output. A write to a pipe is asynchronous
// on POSIX (Node's process documentation, "A note on process I/O"): write() hands the kernel what
// the pipe has room for and queues the rest, and process.exit() ends the process with the queue
// unsent. Measured on 54d6808 on macOS: a factory run whose --json document was 417,136 bytes gave
// a reader on a pipe 65,536 of them, the size of the pipe's buffer, and the exit code said the run
// had finished. Measured on Linux too (node:22): write 70,000 bytes, exit, and the reader gets
// 65,536. To a file a write is synchronous, which is why a redirect, and the Action, which
// redirects, never showed it. A document cut short is not a document: a consumer that parses it
// gets a SyntaxError, and one that only reads the exit code never learns it was cut.
//
// So nothing here calls process.exit after a write. Every exit that follows output goes through
// exitWhenWritten, which ends the process when both streams have handed everything over.

let ending = null;
// The flushes the exit is still waiting for, and what ends the process when there are none left.
let pending = 0;
let finish = () => {};

/** One more flush for the exit to wait for. Returns what to call when it has happened. */
function hold() {
  pending++;
  let done = false;
  return () => {
    if (done) return;
    done = true;
    if (--pending === 0) finish();
  };
}

/** Whether exitWhenWritten has been called: the process is on its way out, and stdout has had all it will get. */
export const exiting = () => ending !== null;

/** The code the process will end with, or null while nothing has asked it to end. */
export const exitCodeChosen = () => ending;

/**
 * Ends the process with `code` once everything already written to stdout and stderr has been
 * flushed. Returns a promise that never settles, so `await exitWhenWritten(code)` does not go on.
 *
 * The first call decides the code. A later one, from a crash handler that fires while the first is
 * still flushing or the other way round, changes nothing: a code once chosen is not replaced.
 *
 * A reader that has gone away (EPIPE) counts as flushed. There is nobody to write to, and the exit
 * code is still owed.
 */
export function exitWhenWritten(code, { streams = [process.stdout, process.stderr], exit = (c) => process.exit(c) } = {}) {
  const never = new Promise(() => {});
  if (ending !== null) return never;
  ending = code;
  finish = () => exit(code);
  // Held until every stream has its own, so that one whose callback runs at once does not end it.
  const all = hold();
  for (const s of streams) {
    const flushed = hold();
    try {
      s.on("error", flushed);
      // Writes are delivered in order, so this callback runs after everything queued before it.
      s.write("", flushed);
    } catch {
      flushed();
    }
  }
  all();
  return never;
}

/**
 * Writes `text` to stderr after the exit has begun, and has the exit wait for it as it waits for
 * what was written before. For a failure that arrives while the process is on its way out: the
 * code already chosen stands and stdout gets nothing more, but the failure is still said. Written
 * with a plain write after exitWhenWritten, it could be cut off like any other.
 *
 * Before the exit has begun it is an ordinary write.
 *
 * No time limit here or in exitWhenWritten, on purpose. A reader that keeps the pipe open and stops
 * reading makes the process wait, as any program waits on a full pipe, and ending after a while
 * would bring back the document cut short. A caller that cannot wait sets its own limit.
 */
export function writeBeforeExit(text, stream = process.stderr) {
  if (ending === null) {
    stream.write(text);
    return;
  }
  const flushed = hold();
  try {
    stream.write(text, flushed);
  } catch {
    flushed();
  }
}
