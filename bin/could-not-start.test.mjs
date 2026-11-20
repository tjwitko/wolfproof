import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { builtinModules } from "module";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

import { couldNotStart, endNotStarted } from "../lib/could-not-start.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const CLI = path.resolve(__dirname, "validate.mjs");

// A failure before the command was loaded had no handler, and Node's exit 1 is this gate's
// "blocked". Measured on c54b4a9: a copy of the package without its dependencies exited 1 from
// every command, and under Node 20 so did an exception from a timer in the first 50 ms. These run
// the real CLI, because an exit code is a property of a process.

function scratch() {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "could-not-start-")));
  mkdirSync(path.join(dir, "proj"));
  writeFileSync(path.join(dir, "proj", "a.js"), "export const a = 1;\n");
  return dir;
}

const run = (file, args, node = []) => {
  const r = spawnSync(process.execPath, [...node, file, ...args], { encoding: "utf8", timeout: 120_000 });
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
};

// Each command, with the code its own contract gives a run that did not happen.
const COMMANDS = [
  { name: "the gate", args: (p) => [p], code: 3, says: /^wolfproof: the gate could not start: / },
  { name: "known", args: (p) => ["known", p], code: 3, says: /^wolfproof known: the command could not start, or failed where it has no handler of its own: / },
  { name: "review", args: (p) => ["review", p], code: 3, says: /^wolfproof review: the command could not start, or failed where it has no handler of its own: / },
  { name: "init", args: (p) => ["init", p], code: 70, says: /^wolfproof init: setup could not start: / },
];

test("a package whose dependencies are not installed exits 3 from every command, 70 from init, and says why", () => {
  const d = scratch();
  try {
    // This package's own files and none of what they depend on.
    const pkg = path.join(d, "pkg");
    mkdirSync(pkg);
    for (const part of ["bin", "lib", "agent", "package.json"]) cpSync(path.join(ROOT, part), path.join(pkg, part), { recursive: true });
    const copy = path.join(pkg, "bin", "validate.mjs");
    for (const c of COMMANDS) {
      const r = run(copy, c.args(path.join(d, "proj")));
      assert.equal(r.code, c.code, `${c.name}: exit ${r.code}; stderr: ${r.stderr.slice(0, 300)}`);
      assert.match(r.stderr, c.says, c.name);
      assert.match(r.stderr, /Cannot find package/, `${c.name} names what would not load`);
      assert.equal(r.stdout, "", `${c.name} writes nothing to stdout`);
    }
    // In --json mode the gate still writes its one document, as it does from a crash.
    const j = run(copy, [path.join(d, "proj"), "--json"]);
    assert.equal(j.code, 3, j.stderr.slice(0, 300));
    const doc = JSON.parse(j.stdout);
    assert.equal(doc.exitCode, 3);
    assert.equal(doc.incomplete, true);
    assert.match(doc.error, /^the gate could not start: Cannot find package/);
    // Even asking which version it is.
    assert.equal(run(copy, ["--version"]).code, 3);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// Thrown the moment the first handler is in place and before anything else of the package is
// loaded: from a microtask queued when that handler is registered. No timer, so nothing depends on
// how fast the machine is.
const EARLY = `data:text/javascript,${encodeURIComponent(`
  const on = process.on.bind(process);
  process.on = (event, listener) => {
    const r = on(event, listener);
    if (event === "uncaughtException" && listener.name === "couldNotStartHandler") queueMicrotask(() => { throw new Error("injected early"); });
    return r;
  };
`)}`;

test("an exception before the command is loaded is that command's could-not-run, not Node's exit 1", () => {
  const d = scratch();
  try {
    for (const c of COMMANDS) {
      const r = run(CLI, c.args(path.join(d, "proj")), ["--import", EARLY]);
      assert.equal(r.code, c.code, `${c.name}: exit ${r.code}; stderr: ${r.stderr.slice(0, 300)}`);
      assert.match(r.stderr, c.says, c.name);
      assert.match(r.stderr, /Error: injected early/, c.name);
    }
    const j = run(CLI, [path.join(d, "proj"), "--json"], ["--import", EARLY]);
    assert.equal(j.code, 3, j.stderr.slice(0, 300));
    assert.deepEqual(JSON.parse(j.stdout), { exitCode: 3, incomplete: true, error: "the gate could not start: injected early" });
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("couldNotStart: each command's code and words, and one JSON document only for the gate", () => {
  const err = new Error("no such thing");
  const gate = couldNotStart(err, ["node", "wolfproof", "proj", "--json"]);
  assert.equal(gate.code, 3);
  assert.deepEqual(JSON.parse(gate.stdout), { exitCode: 3, incomplete: true, error: "the gate could not start: no such thing" });
  assert.match(gate.stderr, /This is not a verdict on the project\. Exit 3: the gate could not run\.\n$/);
  assert.equal(couldNotStart(err, ["node", "wolfproof", "proj"]).stdout, "");
  for (const command of ["known", "review"]) {
    const r = couldNotStart(err, ["node", "wolfproof", command, "proj", "--json"]);
    assert.equal(r.code, 3, command);
    assert.equal(r.stdout, "", `${command} has no JSON document`);
    assert.match(r.stderr, /Exit 3: it did not finish\.\n$/);
  }
  const init = couldNotStart(err, ["node", "wolfproof", "init", "proj"]);
  assert.equal(init.code, 70, "init's own code for failed: its 1 means a file was left alone, and its 3 means nothing");
  assert.match(init.stderr, /Exit 70: /);
  // Something that is not an Error.
  assert.match(couldNotStart("just a string", ["node", "wolfproof"]).stderr, /could not start: just a string\n/);
  // It ends the process with that code, through whatever it is given to end it with.
  let ended = null;
  const wrote = [];
  endNotStarted(err, { argv: ["node", "wolfproof", "proj", "--json"], exit: (code) => (ended = code), out: (fd, text) => wrote.push([fd, text]) });
  assert.equal(ended, 3);
  assert.deepEqual(wrote.map(([fd]) => fd), [1, 2], "the document to stdout, the report to stderr");
});

test("imported as a library, the gate installs no handler of its own", () => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `const m = await import(${JSON.stringify(pathToFileURL(CLI).href)}); console.log(typeof m.runGate, process.listenerCount("uncaughtException"), process.listenerCount("unhandledRejection"));`], { encoding: "utf8", timeout: 60_000 });
  assert.equal(r.stdout.trim(), "function 0 0", r.stderr.slice(0, 300));
});

// What makes the handler early: nothing of this package that can fail to load is imported before
// it. One `import ... from "../lib/x.mjs"` added at the top of the CLI would put the whole of that
// module's graph ahead of it again, and nothing else would notice.
test("the CLI's static imports are Node's own modules and files that import nothing else", () => {
  const builtin = (s) => builtinModules.includes(s.replace(/^node:/, ""));
  const staticImports = (file) => [...readFileSync(file, "utf8").matchAll(/^import\s[^;]*?from\s+"([^"]+)";|^import\s+"([^"]+)";/gm)].map((m) => m[1] || m[2]);
  const own = staticImports(CLI).filter((s) => !builtin(s));
  assert.deepEqual(own.sort(), ["../lib/advisory-classes.mjs", "../lib/could-not-start.mjs", "../lib/exit-when-written.mjs"]);
  for (const s of own) {
    const inner = staticImports(path.resolve(__dirname, s));
    assert.deepEqual(inner.filter((x) => !builtin(x)), [], `${s} imports only Node's own modules`);
  }
});
