import test from "node:test";
import assert from "node:assert/strict";
import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawn, spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");
const HELPER = pathToFileURL(path.resolve(__dirname, "../lib/exit-when-written.mjs")).href;

// The result was written and then process.exit was called. A write to a pipe is asynchronous on
// POSIX, so the process ended with most of a large document unsent. Measured on 54d6808 on macOS: a
// 417,136-byte --json document reached a reader on a pipe as 65,536 bytes, the pipe's buffer, and
// did not parse; redirected to a file it was whole. Exit 1 both times. The same cut on Linux
// (node:22), with a plain write of 70,000 bytes followed by process.exit. These run the real CLI and
// read its stdout through a pipe, which is how spawnSync, a shell's $(...) and `| jq` read it.

const PIPE = 65536;

function project(files) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "json-pipe-")));
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q", "-b", "main");
  writeFileSync(path.join(dir, "a.js"), "export const a = 1;\n");
  writeFileSync(path.join(dir, ".gitignore"), "node_modules/\n.claude/\n");
  git("add", "-A");
  git("commit", "-qm", "base");
  const base = git("rev-parse", "HEAD");
  // Text files an agent directory holds and git does not track: each is one entry in the report,
  // and no scanner reads them, so the run is as fast as an empty project's.
  mkdirSync(path.join(dir, ".claude/hooks/deps"), { recursive: true });
  for (let i = 0; i < files; i++) writeFileSync(path.join(dir, ".claude/hooks/deps", `dependency-file-number-${String(i).padStart(5, "0")}.txt`), "x\n");
  return { dir, base, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("a --json document larger than a pipe's buffer arrives whole through a pipe, and is the one a file gets", () => {
  const p = project(1500);
  try {
    const args = [CLI, p.dir, "--json", "--factory", `--base=${p.base}`];
    const piped = spawnSync(process.execPath, args, { encoding: "utf8", maxBuffer: 1 << 28, timeout: 120_000 });
    assert.equal(piped.status, 1, piped.stderr.slice(-2000));
    let doc;
    assert.doesNotThrow(() => (doc = JSON.parse(piped.stdout)), `${Buffer.byteLength(piped.stdout)} bytes arrived, and they do not parse`);
    assert.ok(Buffer.byteLength(piped.stdout) > 2 * PIPE, `the document is ${Buffer.byteLength(piped.stdout)} bytes, too small to test this`);
    assert.equal(doc.exitCode, 1);
    assert.equal(doc.factory.agentFileChanges.length, 1500);
    assert.ok(piped.stdout.endsWith("}\n"), "it ends where a document ends");

    // Beside the project and not in it, so the second run judges the same tree.
    const file = `${p.dir}.out.json`;
    const fd = openSync(file, "w");
    const filed = spawnSync(process.execPath, args, { stdio: ["ignore", fd, "pipe"], timeout: 120_000 });
    closeSync(fd);
    const whole = JSON.parse(readFileSync(file, "utf8"));
    rmSync(file);
    assert.equal(filed.status, 1);
    assert.deepEqual(doc.factory.agentFileChanges, whole.factory.agentFileChanges, "a pipe and a file get the same list");
    assert.deepEqual(doc.failures, whole.failures);
  } finally {
    p.done();
  }
});

// Everything a process wrote before it asked to end, on both streams, whatever the exit code. A
// megabyte each way: the crash report and the narration go to stderr, which is a pipe as often.
function child(body) {
  return spawnSync(process.execPath, ["--input-type=module", "-e", `import { exitWhenWritten, exiting } from ${JSON.stringify(HELPER)};\n${body}`], {
    encoding: "utf8",
    maxBuffer: 1 << 28,
    timeout: 60_000,
  });
}

test("exitWhenWritten: a megabyte on each stream arrives whole, with the exit code asked for", () => {
  for (const code of [0, 1, 2, 3]) {
    const r = child(`
      process.stdout.write("o".repeat(1 << 20) + "\\nend of stdout\\n");
      process.stderr.write("e".repeat(1 << 20) + "\\nend of stderr\\n");
      await exitWhenWritten(${code});
      process.stdout.write("this is after the exit and must not run\\n");
    `);
    assert.equal(r.status, code, r.stderr.slice(-500));
    assert.equal(r.stdout.length, (1 << 20) + 15);
    assert.ok(r.stdout.endsWith("\nend of stdout\n"));
    assert.equal(r.stderr.length, (1 << 20) + 15);
    assert.ok(r.stderr.endsWith("\nend of stderr\n"));
  }
});

test("exitWhenWritten: the first code asked for is the one the process ends with, and a timer left running does not hold it open", () => {
  // Exit 3 and exit 1 never become each other: a crash while a verdict is being written does not
  // replace it, and a verdict does not replace a crash's 3.
  for (const [first, second] of [[3, 1], [1, 3], [0, 3]]) {
    const r = child(`
      setInterval(() => {}, 1000);
      process.stdout.write("x".repeat(300000));
      exitWhenWritten(${first});
      if (!exiting()) throw new Error("exiting() is false after the exit was asked for");
      exitWhenWritten(${second});
    `);
    assert.equal(r.status, first, r.stderr.slice(-500));
    assert.equal(r.stdout.length, 300000);
  }
});

test("exitWhenWritten: a reader that has gone away does not hold the process open or change its code", async () => {
  // `wolfproof ... | head -1`: the reader takes a line and closes. The exit code is still owed.
  for (const code of [1, 3]) {
    const c = spawn(process.execPath, ["--input-type=module", "-e", `import { exitWhenWritten } from ${JSON.stringify(HELPER)}; process.stdout.write("y".repeat(1 << 22)); await exitWhenWritten(${code});`], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let err = "";
    c.stderr.on("data", (d) => (err += d));
    c.stdout.once("data", () => c.stdout.destroy());
    const ended = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        c.kill("SIGKILL");
        resolve("still running after 20 s");
      }, 20_000);
      c.on("exit", (status) => {
        clearTimeout(timer);
        resolve(status);
      });
    });
    assert.equal(ended, code, err.slice(-500));
  }
});

// A failure that arrives after the exit has begun. It was dropped whole: measured on c54b4a9, an
// exception delivered while a clean verdict was being flushed left exit 0 and nothing on stderr,
// and `wolfproof known`, whose handler had no such guard, printed "Exit 3: it did not finish" and
// exited 0. The code already chosen stands and stdout gets no second document, but the failure is
// said, and the exit waits for it to be written.

test("writeBeforeExit: what is written after the exit has begun arrives whole, and the code is still the first one", () => {
  for (const code of [0, 1, 3]) {
    // Little on stdout, so that without the wait both streams are flushed at once and the late megabyte is cut.
    const r = child(`
      const { writeBeforeExit, exitCodeChosen } = await import(${JSON.stringify(HELPER)});
      if (exitCodeChosen() !== null) throw new Error("a code is chosen before anything asked to end");
      writeBeforeExit("before the exit, an ordinary write\\n");
      process.stdout.write("the document\\n");
      exitWhenWritten(${code});
      writeBeforeExit("L".repeat(1 << 20) + "\\nlate, and the code is " + exitCodeChosen() + "\\n");
      exitWhenWritten(2);
    `);
    assert.equal(r.status, code, r.stderr.slice(-300));
    assert.equal(r.stdout, "the document\n");
    assert.ok(r.stderr.startsWith("before the exit, an ordinary write\n"));
    assert.ok(r.stderr.endsWith(`\nlate, and the code is ${code}\n`), `${r.stderr.length} bytes of stderr arrived, ending ${JSON.stringify(r.stderr.slice(-40))}`);
    assert.equal(r.stderr.length, 35 + (1 << 20) + 25);
  }
});

// Delivered at the one moment that is certain to be after the exit began and before anything was
// flushed: inside exitWhenWritten's own empty write to stdout. Handed to the handlers as Node hands
// one over, so no timer has to land in a window.
const LATE = `data:text/javascript,${encodeURIComponent(`
  const write = process.stdout.write.bind(process.stdout);
  let once = false;
  process.stdout.write = (chunk, ...rest) => {
    if (chunk === "" && !once) {
      once = true;
      process.emit("uncaughtException", new Error("injected late"), "uncaughtException");
    }
    return write(chunk, ...rest);
  };
`)}`;
const late = (args) => spawnSync(process.execPath, ["--import", LATE, CLI, ...args], { encoding: "utf8", maxBuffer: 1 << 28, timeout: 120_000 });

test("a failure after the gate has begun to exit is said on stderr, with the first exit code and one document", () => {
  const clean = project(0);
  const blocked = project(3);
  try {
    const cases = [
      [0, [clean.dir, "--json"]],
      [1, [blocked.dir, "--json", "--factory", `--base=${blocked.base}`]],
    ];
    for (const [code, args] of cases) {
      const r = late(args);
      assert.equal(r.status, code, `exit ${r.status}; stderr: ${r.stderr.slice(-600)}`);
      let doc;
      assert.doesNotThrow(() => (doc = JSON.parse(r.stdout)), "stdout is one document");
      assert.equal(doc.exitCode, code);
      assert.ok(!doc.incomplete, "and it is the verdict, not a crash document");
      assert.match(r.stderr, /^wolfproof: something failed after the exit had begun: Error: injected late$/m);
      assert.match(r.stderr, new RegExp(`^The exit code already chosen, ${code}, stands, and nothing more is written to stdout\\.$`, "m"));
      assert.doesNotMatch(r.stderr, /Exit 3/, "it does not claim a code the process does not end with");
    }
    // Without --json the verdict is text, and there is still one of it.
    const text = late([clean.dir]);
    assert.equal(text.status, 0, text.stderr.slice(-600));
    assert.match(text.stderr, /^wolfproof: something failed after the exit had begun: Error: injected late$/m);
    assert.doesNotMatch(text.stdout, /injected late|the gate itself failed/);
  } finally {
    clean.done();
    blocked.done();
  }
});

test("wolfproof known says the same of a failure after it has begun to exit, and does not claim exit 3", () => {
  const p = project(0);
  try {
    const plain = spawnSync(process.execPath, [CLI, "known", p.dir], { encoding: "utf8", timeout: 120_000 });
    const r = late(["known", p.dir]);
    assert.equal(r.status, plain.status, `exit ${r.status} with the failure, ${plain.status} without; stderr: ${r.stderr.slice(-600)}`);
    assert.notEqual(r.status, null);
    assert.match(r.stderr, /^wolfproof known: something failed after the exit had begun: Error: injected late$/m);
    assert.match(r.stderr, new RegExp(`^The exit code already chosen, ${plain.status}, stands`, "m"));
    assert.doesNotMatch(r.stderr, /Exit 3: it did not finish/);
  } finally {
    p.done();
  }
});
