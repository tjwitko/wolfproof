import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { codeqlEnv, copyProject, createFailure, judgeCodeqlRuns, scanSource } from "./codeql.mjs";
import { classifyAdvisory, COULD_NOT_RUN, FINDING, INFO, NOT_CHECKED } from "../lib/advisory-classes.mjs";

// Real SARIF from CodeQL 2.27.3's code-scanning suites, trimmed to the fields the check reads
// (agent/fixtures/codeql/). The project: an Express app running request data through exec and into
// a response, one with `// codeql[js/command-line-injection]` above it, a Flask query built with %,
// a workflow echoing an issue comment, one unparseable .js and .py file, and a Go module that does
// not compile.
const sarif = (name) => JSON.parse(readFileSync(new URL(`./fixtures/codeql/${name}.sarif.json`, import.meta.url), "utf8"));
const runs = (...names) => names.map((n) => ({ language: n.startsWith("go") ? "go" : n, sarif: sarif(n) }));

test("error-level results block, one line per rule; the rest are advisories", () => {
  const r = judgeCodeqlRuns({ runs: runs("javascript", "python", "actions") });
  assert.deepEqual(r.couldNotRun, []);
  assert.deepEqual(r.failures, [
    "codeql (javascript): js/command-line-injection — Uncontrolled command line: src/app.js:5, src/app.js:9. See CodeQL's help for js/command-line-injection.",
    "codeql (javascript): js/reflected-xss — Reflected cross-site scripting: src/app.js:11. See CodeQL's help for js/reflected-xss.",
    "codeql (javascript): js/unnecessary-use-of-cat — Unnecessary use of `cat` process: src/app.js:9. See CodeQL's help for js/unnecessary-use-of-cat.",
    "codeql (python): py/sql-injection — SQL query built from user-controlled sources: src/a.py:7. See CodeQL's help for py/sql-injection.",
    "codeql (actions): actions/code-injection/critical — Code injection: .github/workflows/ci.yml:6. See CodeQL's help for actions/code-injection/critical.",
  ]);
  assert.ok(r.advisories.includes("codeql (javascript): Missing rate limiting (js/missing-rate-limiting, warning, not blocking): src/app.js:4, src/app.js:7."));
  assert.equal(r.blockingIds.length, 6);
  assert.equal(r.ids.length, 9);
  // Nothing says "nothing at error level" beside six blocking results.
  assert.ok(!r.advisories.some((a) => /nothing at error level/.test(a)));
});

// The comment sits above line 9 and line 9 still blocks: the CLI does not apply it, and if a result
// ever carries a suppression it is counted anyway.
test("a suppression comment in the code does not clear a result", () => {
  const r = judgeCodeqlRuns({ runs: runs("javascript") });
  assert.ok(r.failures[0].includes("src/app.js:9"));
  const s = sarif("javascript");
  s.runs[0].results.find((x) => x.ruleId === "js/reflected-xss").suppressions = [{ kind: "inSource" }];
  const r2 = judgeCodeqlRuns({ runs: [{ language: "javascript", sarif: s }] });
  assert.ok(r2.failures.some((f) => /js\/reflected-xss/.test(f)), "still blocks");
  assert.ok(r2.advisories.includes("codeql: 1 result(s) carry a suppression from the code itself and were counted anyway; a review (wolfproof review) is how a finding is accepted."));
});

test("files CodeQL could not extract are named, by location or, for Go, from the message", () => {
  const r = judgeCodeqlRuns({ runs: runs("javascript", "python", "go-unbuildable") });
  assert.ok(r.advisories.includes("codeql (javascript): 1 file(s) could not be fully extracted, so parts of them were not analysed — src/broken.js."));
  assert.ok(r.advisories.includes("codeql (python): 1 file(s) could not be fully extracted, so parts of them were not analysed — src/broken.py."));
  assert.ok(r.advisories.includes("codeql (go): 1 file(s) could not be fully extracted, so parts of them were not analysed — main.go."));
  // Each language's file count is its own, though every SARIF repeats the others' baselines.
  assert.deepEqual(r.files, { javascript: 3, python: 3, go: 2 });
});

test("with nothing at error level, the run says what was analysed", () => {
  const r = judgeCodeqlRuns({ runs: runs("go-unbuildable") });
  assert.deepEqual(r.failures, []);
  assert.ok(r.advisories.includes("codeql: CodeQL 2.27.3 analysed Go (2 files) with the code-scanning suite; nothing at error level."));
});

test("a review takes one result out of the verdict and lists it; IDs follow the line, not its number", () => {
  const lines = { "src/app.js": ["", "", "", "", '  exec("ls " + req.query.dir, (e, out) => res.send(out));'] };
  const lineOf = (f, n) => lines[f]?.[n - 1] ?? "";
  const first = judgeCodeqlRuns({ runs: runs("javascript"), lineOf });
  const id = first.blockingIds.find((i) => i.startsWith("codeql:js/command-line-injection:src/app.js:"));
  assert.match(id, /^codeql:js\/command-line-injection:src\/app\.js:[0-9a-f]{8}$/);
  const r = judgeCodeqlRuns({ runs: runs("javascript"), lineOf, reviews: [{ id, reason: "dir is an enum", source: "test" }] });
  assert.equal(r.reviewed.length, 1);
  assert.equal(r.reviewed[0].where, "src/app.js:5");
  assert.ok(r.failures[0].endsWith("src/app.js:9. See CodeQL's help for js/command-line-injection."), r.failures[0]);
  assert.ok(!r.blockingIds.includes(id));
});

test("SARIF without a results list is could-not-run for that language only", () => {
  const r = judgeCodeqlRuns({ runs: [{ language: "ruby", sarif: { runs: [{}] } }, ...runs("python")] });
  assert.deepEqual(r.couldNotRun, ["codeql (ruby): the SARIF has no results list, so Ruby was not checked."]);
  assert.equal(r.failures.length, 1);
});

test("CODEQL_, LGTM_ and SEMMLE_ variables are not passed on", () => {
  const { env, dropped } = codeqlEnv({ PATH: "/bin", CODEQL_EXTRACTOR_PYTHON_EXTRACT_STDLIB: "1", LGTM_INDEX_FILTERS: "exclude:**", SEMMLE_X: "1", GOFLAGS: "-mod=mod" });
  assert.deepEqual(env, { PATH: "/bin", GOFLAGS: "-mod=mod" });
  assert.deepEqual(dropped, ["CODEQL_EXTRACTOR_PYTHON_EXTRACT_STDLIB", "LGTM_INDEX_FILTERS", "SEMMLE_X"]);
});

test("the copy is the gate's walk: no skipped directories, no declared fixtures, no symbolic links", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-codeql-copy-"));
  const dest = path.join(dir, "out");
  try {
    const p = path.join(dir, "p");
    for (const d of ["src", "node_modules/x", "fix", ".github/workflows", "app"]) mkdirSync(path.join(p, d), { recursive: true });
    writeFileSync(path.join(p, "src/a.ts"), "export {}\n");
    writeFileSync(path.join(p, "node_modules/x/i.js"), "x\n");
    writeFileSync(path.join(p, "fix/.tfguard-fixture"), "deliberately vulnerable\n");
    writeFileSync(path.join(p, "fix/bad.py"), "x\n");
    writeFileSync(path.join(p, ".github/workflows/ci.yml"), "on: push\n");
    writeFileSync(path.join(p, "app/Main.kt"), "fun main() {}\n");
    writeFileSync(path.join(p, "app/Lib.java"), "class Lib {}\n");
    writeFileSync(path.join(p, "index.php"), "<?php\n");
    symlinkSync("/etc", path.join(p, "src/etc"));
    const r = copyProject(p, dest);
    assert.deepEqual(r.languages, { javascript: "none", java: "autobuild", actions: "none" });
    assert.deepEqual(r.unsupported, ["PHP"]);
    assert.ok(existsSync(path.join(dest, "src/a.ts")));
    assert.ok(existsSync(path.join(dest, "index.php")), "every file is copied, for a build");
    assert.ok(!existsSync(path.join(dest, "node_modules")));
    assert.ok(!existsSync(path.join(dest, "fix/bad.py")));
    assert.ok(!existsSync(path.join(dest, "src/etc")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Java alone is extracted without a build", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-codeql-copy-"));
  try {
    mkdirSync(path.join(dir, "p"));
    writeFileSync(path.join(dir, "p/A.java"), "class A {}\n");
    writeFileSync(path.join(dir, "p/m.go"), "package m\n");
    assert.deepEqual(copyProject(path.join(dir, "p"), path.join(dir, "out")).languages, { java: "none", go: "autobuild" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The runner, against stand-ins for codeql: what reaches the verdict when CodeQL cannot run.
function fakeCodeql(dir, body) {
  const bin = path.join(dir, "codeql");
  writeFileSync(bin, `#!/bin/sh\n${body}\n`);
  chmodSync(bin, 0o755);
  return bin;
}

function project(dir) {
  const p = path.join(dir, "p");
  mkdirSync(p);
  writeFileSync(path.join(p, "a.py"), "print(1)\n");
  return p;
}

test("codeql that is not there makes the run incomplete", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-codeql-"));
  try {
    const r = scanSource(project(dir), { env: { PATH: process.env.PATH, WOLFPROOF_CODEQL: path.join(dir, "nope") } });
    assert.deepEqual(r.couldNotRun, [`codeql: ${path.join(dir, "nope")} does not exist, so the source was not analysed.`]);
    assert.deepEqual(r.ran, []);
    assert.equal(r.ids, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a CLI without the bundle's query suites is could-not-run, not clean", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-codeql-"));
  try {
    const dist = path.join(dir, "dist");
    mkdirSync(dist);
    const bin = fakeCodeql(dir, `echo '{"version":"2.27.3","unpackedLocation":"${dist}"}'`);
    const r = scanSource(project(dir), { env: { PATH: process.env.PATH, WOLFPROOF_CODEQL: bin } });
    assert.equal(r.couldNotRun.length, 1);
    assert.match(r.couldNotRun[0], /^codeql \(python\): the code-scanning suite for python is not in .*, so Python was not analysed\. Install the CodeQL bundle, not the CLI alone\.$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an extraction that fails is could-not-run for that language, with CodeQL's reason", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-codeql-"));
  try {
    const dist = path.join(dir, "dist");
    mkdirSync(path.join(dist, "qlpacks/codeql/python-queries/1.0.0/codeql-suites"), { recursive: true });
    writeFileSync(path.join(dist, "qlpacks/codeql/python-queries/1.0.0/codeql-suites/python-code-scanning.qls"), "");
    const bin = fakeCodeql(
      dir,
      `case "$1" in version) echo '{"version":"2.27.3","unpackedLocation":"${dist}"}' ;; database) echo "A fatal error occurred: no python" >&2; exit 32 ;; esac`
    );
    const r = scanSource(project(dir), { env: { PATH: process.env.PATH, WOLFPROOF_CODEQL: bin, CODEQL_RAM: "1" } });
    assert.deepEqual(r.couldNotRun, ["codeql (python): CodeQL could not extract the Python source, so it was not analysed — A fatal error occurred: no python"]);
    assert.ok(r.advisories.includes("codeql: CODEQL_RAM is set and not passed to CodeQL, because it can change what is extracted."));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// What CodeQL 2.27.3 printed for a Kotlin file with no build around it.
test("a failed build is reported by the build's own error, not by the exit status", () => {
  const text = [
    "[2026-11-03 10:00:35] [build-stderr] ERROR: Could not detect a suitable build command for the source checkout.",
    "[2026-11-03 10:00:35] [ERROR] Spawned process exited abnormally (code 1; tried to run: [/c/tools/osx64/preload_tracer, /c/java/tools/autobuild.sh])",
    "A fatal error occurred: Exit status 1 from command: [/c/java/tools/autobuild.sh]",
  ].join("\n");
  assert.equal(createFailure(text), "ERROR: Could not detect a suitable build command for the source checkout.");
  assert.equal(createFailure("A fatal error occurred: no python"), "A fatal error occurred: no python");
});

test("Swift off macOS is could-not-run", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-codeql-"));
  try {
    const p = path.join(dir, "p");
    mkdirSync(p);
    writeFileSync(path.join(p, "App.swift"), "print(1)\n");
    const bin = fakeCodeql(dir, `echo '{"version":"2.27.3","unpackedLocation":"${dir}"}'`);
    const r = scanSource(p, { env: { PATH: process.env.PATH, WOLFPROOF_CODEQL: bin }, platform: "linux" });
    assert.deepEqual(r.couldNotRun, ["codeql (swift): CodeQL analyses Swift only on macOS, so the Swift source was not analysed."]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("every advisory the check writes has a class", () => {
  const all = judgeCodeqlRuns({ runs: runs("javascript", "python", "actions", "go-unbuildable") }).advisories;
  const s = sarif("go-unbuildable");
  s.runs[0].invocations[0].toolExecutionNotifications.push({ descriptor: { id: "go/autobuilder/build-command-failed" }, level: "error", message: { text: "The build command failed." } });
  all.push(...judgeCodeqlRuns({ runs: [{ language: "go", sarif: s }] }).advisories);
  all.push(
    "codeql: CODEQL_RAM is set and not passed to CodeQL, because it can change what is extracted.",
    "codeql: PHP source is not analysed — CodeQL does not support it. The sast check still reads it.",
    "codeql: not checked — nothing here is in a language CodeQL analyses.",
    "codeql: 1 result(s) carry a suppression from the code itself and were counted anyway; a review (wolfproof review) is how a finding is accepted."
  );
  const want = {
    "Missing rate limiting": FINDING,
    "could not be fully extracted": NOT_CHECKED,
    "reported a problem and carried on": COULD_NOT_RUN,
    "nothing at error level": INFO,
    "not passed to CodeQL": INFO,
    "does not support": INFO,
    "nothing here is in a language": INFO,
    "carry a suppression": INFO,
  };
  for (const [phrase, cls] of Object.entries(want)) {
    const a = all.find((x) => x.includes(phrase));
    assert.ok(a, `an advisory with "${phrase}"`);
    assert.equal(classifyAdvisory(a, {}).class, cls, a);
  }
  for (const a of all) assert.ok(!classifyAdvisory(a, {}).unclassified, a);
});
