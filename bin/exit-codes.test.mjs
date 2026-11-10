import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

import { failClosed } from "./validate.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");

// The contract: 0 clean, 1 blocked having run in full, 2 usage, 3 part of the gate could not run.
//
// Every bad input used to exit 1. A missing project directory, a project that was a file, a task
// file that did not exist, a task file that was a directory: each crashed, and Node exits 1 on an
// uncaught exception, which is this gate's "blocked". In CI the Action then printed "blocked — ?
// blocking finding(s). The gate ran in full; these are real." A mistyped path, reported as a
// verdict on the project.
//
// These run the real CLI, because an exit code is a property of a process.

function scratch() {
  const dir = mkdtempSync(path.join(tmpdir(), "exitcodes-"));
  mkdirSync(path.join(dir, "proj"));
  writeFileSync(path.join(dir, "a-file.txt"), "x\n");
  return dir;
}

function cli(args, env = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 120_000,
  });
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "", timedOut: r.error?.code === "ETIMEDOUT" };
}

const noStack = (s) => !/Unhandled 'error' event|\n\s+at .+:\d+:\d+/.test(s);

for (const [label, args] of [
  ["a project directory that does not exist", (d) => [path.join(d, "missing")]],
  ["a project that is a file", (d) => [path.join(d, "a-file.txt")]],
  ["a task file that does not exist", (d) => [path.join(d, "proj"), path.join(d, "missing.txt")]],
  ["a task file that is a directory", (d) => [path.join(d, "proj"), d]],
]) {
  test(`${label} is a usage error, exit 2, said plainly`, () => {
    const d = scratch();
    try {
      const r = cli(args(d));
      assert.equal(r.code, 2, `exit ${r.code}; stderr: ${r.stderr.slice(0, 300)}`);
      assert.ok(noStack(r.stderr), "a sentence, not a stack trace");
      assert.match(r.stderr, /wolfproof:/);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
}

test("a usage error in --json mode still writes one JSON document", () => {
  // The Action and the corpus parse stdout. An empty or non-JSON stdout made the Action's count fall
  // back to "?" and its renderer fail, so the first thing a reader saw was not the reason.
  const d = scratch();
  try {
    const r = cli([path.join(d, "missing"), "--json"]);
    assert.equal(r.code, 2);
    const doc = JSON.parse(r.stdout);
    assert.equal(doc.exitCode, 2);
    assert.match(doc.error, /does not exist/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a control that dies on startup is could-not-run, exit 3, and fast", () => {
  // It used to wait ten minutes per request for a process that had already exited, then register
  // the control with no tools. Pointed at a script that throws on load, it must come back quickly
  // and say which control and why.
  const d = scratch();
  const broken = path.join(d, "broken-control.mjs");
  writeFileSync(broken, 'throw new Error("this control cannot start");\n');
  try {
    const started = Date.now();
    const r = cli([path.join(d, "proj")], { SECRETGUARD_SERVER: broken });
    const took = Date.now() - started;
    assert.ok(!r.timedOut, "came back rather than waiting on a dead process");
    assert.ok(took < 60_000, `took ${took}ms`);
    assert.equal(r.code, 3, `exit ${r.code}; stdout: ${r.stdout.slice(-400)}`);
    assert.match(r.stdout, /secret-guard/);
    assert.match(r.stdout, /exited|could not be started/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// The last resort. Anything not foreseen above must not become exit 1.
test("an unexpected failure is exit 3, not exit 1", () => {
  const r = failClosed(new Error("something nobody planned for"), { json: false, wroteResult: false });
  assert.equal(r.code, 3);
  assert.match(r.stderr, /not a verdict on the project/);
  assert.equal(r.stdout, "");
});

test("an unexpected failure in --json mode writes a document saying so", () => {
  const r = failClosed(new Error("boom"), { json: true, wroteResult: false });
  assert.equal(r.code, 3);
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.exitCode, 3);
  assert.equal(doc.incomplete, true);
  assert.match(doc.error, /boom/);
});

test("a failure after the result was written does not write a second document", () => {
  // Two JSON documents on stdout is as unparseable as none.
  const r = failClosed(new Error("late"), { json: true, wroteResult: true });
  assert.equal(r.stdout, "");
  assert.equal(r.code, 3);
});

// --- what --version and the report say the gate ran with -------------------------------------

test("--help is not a usage error, and lists --version", () => {
  const r = cli(["--help"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /wolfproof --version/);
  assert.match(r.stdout, /exit 0 nothing blocking, 1 blocking findings, 2 usage, 3/);
});

test("--version lists every scanner, and says which are not found", () => {
  // Only node's directory on PATH: the scanners are absent, and must be listed as absent.
  const r = cli(["--version"], { PATH: path.dirname(process.execPath) });
  assert.equal(r.code, 0);
  const tools = r.stdout.slice(r.stdout.indexOf("tools on PATH"));
  for (const name of ["gitleaks", "osv-scanner", "terraform", "checkov", "semgrep", "ruff", "go", "pytest"]) {
    assert.match(tools, new RegExp(`^  ${name} +(not found|\\d[\\w.]*)$`, "m"), name);
  }
  assert.match(tools, /^  semgrep +not found$/m);
  assert.match(r.stdout, /^  secret-guard /m, "the controls are still there");
});

test("the JSON report records when it ran and with which tools", () => {
  const d = scratch();
  try {
    const before = Date.now();
    const r = cli([path.join(d, "proj"), "--json"], { WOLFPROOF_TODAY: "2026-10-01" });
    const doc = JSON.parse(r.stdout);
    const at = Date.parse(doc.scannedAt);
    assert.ok(at >= before - 1000 && at <= Date.now(), `scannedAt ${doc.scannedAt}`);
    assert.equal(doc.judgedAsOf, "2026-10-01", "a pinned date is said to be pinned");
    for (const name of ["gitleaks", "osv-scanner", "terraform", "checkov", "semgrep", "ruff", "go", "pytest"]) {
      assert.ok(Object.hasOwn(doc.toolchain, name), `${name} is in the report, found or not`);
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// --- names from before the rename (agent-gate, until v1.2.0) ------------------------------------
//
// Read in v1.2.0, not since v1.3.0. Neither may stop applying silently.

test("an AGENT_GATE_* variable left set is reported as unread, and pins nothing", () => {
  const d = scratch();
  try {
    const doc = JSON.parse(cli([path.join(d, "proj"), "--json"], { AGENT_GATE_TODAY: "2026-10-01" }).stdout);
    assert.equal(doc.judgedAsOf, null, "the old name pins no date");
    assert.ok(doc.advisories.some((a) => /AGENT_GATE_TODAY is set and no longer read since v1\.3\.0; set WOLFPROOF_TODAY instead/.test(a.message)),
      JSON.stringify(doc.advisories.map((a) => a.message)));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a project with only .agent-gate.json exits 3 and says to rename it", () => {
  // Its declared controls would otherwise quietly stop applying and the project be checked by
  // whatever node_modules holds. Could-not-run, because the configuration the project states was not read.
  const d = scratch();
  try {
    writeFileSync(path.join(d, "proj", ".agent-gate.json"), JSON.stringify({ controls: {} }));
    const r = cli([path.join(d, "proj"), "--json"]);
    assert.equal(r.code, 3, `exit ${r.code}`);
    const doc = JSON.parse(r.stdout);
    assert.equal(doc.incomplete, true);
    // The JSON says why, as the human report does: incomplete with no reason is no use to a reader.
    assert.match(String(doc.configError), /\.agent-gate\.json is no longer read: agent-gate was renamed wolfproof/);
    const human = cli([path.join(d, "proj")]);
    assert.match(human.stdout, /!! \.agent-gate\.json is no longer read: agent-gate was renamed wolfproof/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// --- a scanner that is not installed is named --------------------------------------------------

test("with gitleaks and osv-scanner missing, the run names each and exits 3", () => {
  // Only node and git on PATH. semgrep's absence was always named with its install command; the
  // credential and dependency scans said only "no parseable result" and dropped the controls' own
  // "gitleaks is not installed" and "osv-scanner is not installed".
  const d = scratch();
  const bin = path.join(d, "bin");
  mkdirSync(bin);
  for (const tool of ["git"]) {
    const where = spawnSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).stdout.trim();
    if (where) symlinkSync(where, path.join(bin, tool));
  }
  symlinkSync(process.execPath, path.join(bin, "node"));
  try {
    writeFileSync(path.join(d, "proj", "app.js"), "console.log(1);\n");
    // A dependency, so the dependency scan has something to do and asks for osv-scanner.
    writeFileSync(path.join(d, "proj", "package.json"), JSON.stringify({ name: "p", dependencies: { "left-pad": "1.3.0" } }));
    const r = cli([path.join(d, "proj"), "--json"], { PATH: `${bin}:/usr/bin:/bin` });
    assert.equal(r.code, 3, `exit ${r.code}`);
    const cnr = JSON.parse(r.stdout).couldNotRun;
    assert.ok(cnr.some((c) => /^scan_path: secret-guard could not scan — gitleaks is not installed or not on PATH\. Install it with `brew install gitleaks`/.test(c)), JSON.stringify(cnr));
    assert.ok(cnr.some((c) => /^check_dependencies: dep-audit could not scan — osv-scanner is not installed or not on PATH/.test(c)), JSON.stringify(cnr));
    assert.ok(!cnr.some((c) => /no parseable result/.test(c)), "nothing falls back to the generic line here");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// A source file over the size limit, through the real CLI. The only source file was a 600 KB
// server.js with an open DELETE /admin route, and the default mode exited 0 with a line above the
// verdict. Run here with only node and git on PATH, so the run is incomplete for the scanners as
// well: what is asserted is what the report says about the file, which no missing scanner supplies.
test("a code file over the limit is could-not-run in both modes; a data file is a line, a lockfile neither", () => {
  const d = scratch();
  const bin = path.join(d, "bin");
  mkdirSync(bin);
  const where = spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
  symlinkSync(where, path.join(bin, "git"));
  symlinkSync(process.execPath, path.join(bin, "node"));
  const env = { PATH: `${bin}:/usr/bin:/bin` };
  const proj = path.join(d, "proj");
  const git = (...a) => spawnSync("git", ["-C", proj, "-c", "user.email=t@example.invalid", "-c", "user.name=t", ...a], { encoding: "utf8" });
  const pad = (comment) => `${comment} ${"x".repeat(4000)}\n`.repeat(150);
  const run = (extra = []) => {
    const r = spawnSync(process.execPath, [CLI, ".", "--json", ...extra], { cwd: proj, encoding: "utf8", env: { ...process.env, ...env }, timeout: 120_000 });
    return { code: r.status, doc: JSON.parse(r.stdout) };
  };
  const sourceFiles = (doc) => doc.couldNotRun.filter((c) => /source_files: /.test(c));
  try {
    writeFileSync(path.join(proj, "package.json"), JSON.stringify({ name: "p" }));
    writeFileSync(path.join(proj, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n" + pad("#"));
    git("init", "-q");
    git("add", "-A");
    git("commit", "-q", "-m", "lockfile");

    // The lockfile alone: named nowhere, in either mode.
    for (const extra of [[], ["--factory", "--base=HEAD"]]) {
      const { doc } = run(extra);
      assert.deepEqual(doc.skippedFiles, [], extra.join(" "));
      assert.equal(doc.coverage, null);
      assert.deepEqual(sourceFiles(doc), []);
      if (doc.factory) assert.ok(!doc.factory.advisories.classified.some((c) => c.id === "skipped-files"));
    }

    // A data file: the line above the verdict by default, the skipped-files advisory in factory mode.
    mkdirSync(path.join(proj, "deploy"));
    writeFileSync(path.join(proj, "deploy", "values.yaml"), pad("#"));
    git("add", "-A");
    git("commit", "-q", "-m", "values");
    let r = run();
    assert.deepEqual(r.doc.skippedFiles.map((s) => [s.file, s.code]), [["deploy/values.yaml", false]]);
    assert.match(r.doc.coverage, /^1 file\(s\) of a kind the checks read were not read: deploy\/values\.yaml /);
    assert.deepEqual(sourceFiles(r.doc), []);
    r = run(["--factory", "--base=HEAD"]);
    assert.deepEqual(r.doc.factory.advisories.classified.filter((c) => c.id === "skipped-files"), [{ id: "skipped-files", class: "could-not-run", action: "incomplete" }]);
    assert.ok(r.doc.couldNotRun.some((c) => /^factory: 1 file\(s\) of a kind the checks read were not read: deploy\/values\.yaml /.test(c)), JSON.stringify(r.doc.couldNotRun));

    // The code file: could-not-run in both modes, said once.
    rmSync(path.join(proj, "deploy"), { recursive: true });
    writeFileSync(path.join(proj, "server.js"), 'const app = require("express")();\napp.delete("/admin/users/:id", (req, res) => res.sendStatus(204));\napp.listen(3000);\n' + pad("//"));
    git("add", "-A");
    git("commit", "-q", "-m", "server");
    for (const extra of [[], ["--factory", "--base=HEAD"]]) {
      const { code, doc } = run(extra);
      assert.equal(code, 3, extra.join(" "));
      assert.deepEqual(doc.skippedFiles.map((s) => [s.file, s.code]), [["server.js", true]]);
      const entries = sourceFiles(doc);
      assert.equal(entries.length, 1, JSON.stringify(doc.couldNotRun));
      assert.match(entries[0], /^source_files: 1 code file\(s\) were not read by the checks that read their language: server\.js \(\d+ KB, over the 512 KB limit; within injection's 1 MB\)\./);
      assert.equal(doc.coverage, null, "the entry is the report; the line does not repeat it");
      if (doc.factory) assert.ok(!doc.factory.advisories.classified.some((c) => c.id === "skipped-files"));
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
