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

/** Whether exitWhenWritten has been called: the process is on its way out and must print no more. */
export const exiting = () => ending !== null;

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
  let left = streams.length;
  const one = () => {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      if (--left === 0) exit(code);
    };
  };
  if (!left) exit(code);
  for (const s of streams) {
    const flushed = one();
    try {
      s.on("error", flushed);
      // Writes are delivered in order, so this callback runs after everything queued before it.
      s.write("", flushed);
    } catch {
      flushed();
    }
  }
  return never;
}
