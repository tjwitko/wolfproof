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
