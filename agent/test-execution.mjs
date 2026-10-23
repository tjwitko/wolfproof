// Run the project's test suite and report what happened, instead of reporting that test files exist.
//
// code_quality already reads the tests and says plainly that it did not run them. That honesty was
// correct and it was not enough. A Haiku deliverable shipped a jest config, a test file with
// thirteen cases, and no installed toolchain: `npm test` failed outright with `jest: command not
// found`, and the model's closing report claimed "Comprehensive test coverage". Once the
// dependencies were installed the suite ran 12 tests, and the 3 that failed were exactly the three
// the task names as its judging criteria -- forged signature rejected, repeated delivery not
// overwriting, payload retained as received. Nine passing tests around them read as a working
// suite. Nothing in the pipeline could tell the difference, because nothing ever ran it.
//
// Two deliberate limits on how this executes:
//
//  1. **The runner is invoked directly, never `npm test`.** A package.json `scripts.test` is a
//     model-authored shell string and would run whatever it contains. build_check's precedent is
//     the right one: it calls node --check, py_compile and ruff by name and never runs a script the
//     project defined. Test code is model-authored either way -- that is unavoidable and is the
//     point -- but the command that starts it does not have to be.
//  2. **Dependencies are never installed.** `npm install` on a generated manifest executes
//     arbitrary postinstall hooks, which is a larger step than running the tests themselves. A
//     missing toolchain is reported as what it is: a suite nobody can run, which is a finding
//     against a task that asked for tests someone else can run.
import { existsSync, readFileSync } from "fs";
import path from "path";
import { spawnSync } from "child_process";

import { isTestFile, TEST_EXT, walk } from "./source-files.mjs";
import { jvmSuites, dotnetSuites, cargoSuites, phpSuites, rubySuites, COUNTS, FAILING } from "./test-runners.mjs";
import { setting } from "../lib/settings.mjs";

const DEFAULT_TIMEOUT_S = 120;

/**
 * How long the suite may run: WOLFPROOF_TEST_TIMEOUT seconds, or 120. A suite that needs longer was
 * exit 3 on every run, with nothing the project could change but its tests. A value that is not a
 * whole number of seconds is an error, not the default: a limit someone set and the gate quietly
 * ignored would read as a suite that is slow rather than a setting that is wrong.
 */
export function testTimeout(env = process.env) {
  const v = setting(env, "TEST_TIMEOUT");
  if (v === undefined) return { ms: DEFAULT_TIMEOUT_S * 1000, seconds: DEFAULT_TIMEOUT_S, set: false };
  if (!/^\s*[1-9]\d*\s*$/.test(v)) return { error: `WOLFPROOF_TEST_TIMEOUT is "${v}", which is not a whole number of seconds` };
  const seconds = Number(v);
  return { ms: seconds * 1000, seconds, set: true };
}

/**
 * Every suite this project has, one entry each: a runner that can start it, as { label, cmd, args,
 * cwd }, or { unavailable } naming what is missing. Never returns a command the project itself
 * authored.
 *
 * Every suite, not the first one found. This returned at the first match: a package.json meant a
 * JavaScript project and nothing else was looked at, so a Python, Go, Java or PHP suite beside it --
 * a Laravel app with a package.json for its front end, a Python service with one for its tooling --
 * was neither run nor reported as unrun. A package.json now claims the project only when there are
 * JavaScript test files, or no other code tests at all.
 */
export function detectSuites(projectDir) {
  const files = walk(projectDir, [], projectDir, TEST_EXT);
  const testFiles = files.filter((f) => isTestFile(f.rel, f.text));
  if (testFiles.length === 0) return [{ unavailable: "no test files were found" }];

  const lang = (f) => TEST_LANGUAGE[path.extname(f.rel)];
  const code = testFiles.filter(lang);
  const of = (...names) => code.filter((f) => names.includes(lang(f)));
  const js = of("JavaScript", "TypeScript");
  const py = of("Python");
  const go = of("Go");
  const suites = [];

  if (existsSync(path.join(projectDir, "package.json")) && (js.length || !code.length)) {
    suites.push(javascriptSuite(projectDir, testFiles));
  } else if (js.length) {
    // node's own runner needs nothing installed and no manifest.
    const nodeTests = js.filter((f) => /\.(test|spec)\.(m|c)?js$|_test\.(m|c)?js$/.test(f.rel));
    suites.push(
      nodeTests.length
        ? { label: "node --test", cmd: process.execPath, args: ["--test", ...nodeTests.map((f) => f.rel)], cwd: projectDir }
        : { noRunner: true, unavailable: "there is no package.json and no test file node --test can run" }
    );
  }

  if (py.length) {
    const probe = spawnSync("python3", ["-m", "pytest", "--version"], { cwd: projectDir, encoding: "utf8" });
    suites.push(
      probe.status !== 0
        ? { environmental: true, unavailable: "the tests are Python and pytest is not installed here" }
        : { label: "pytest", cmd: "python3", args: ["-m", "pytest", "-q"], cwd: projectDir }
    );
  }

  if (existsSync(path.join(projectDir, "go.mod")) && (go.length || !code.length)) {
    suites.push({ label: "go test", cmd: "go", args: ["test", "./..."], cwd: projectDir });
  } else if (go.length) {
    suites.push({ noRunner: true, unavailable: "the tests are Go and there is no go.mod, so go test cannot run them" });
  }

  // Java, Kotlin, C#, Rust, PHP and Ruby: agent/test-runners.mjs, offline, against dependencies the
  // project's CI installed. Java and Kotlin share a build, so they share a runner.
  const jvm = of("Java", "Kotlin");
  if (jvm.length) suites.push(...jvmSuites(projectDir, jvm, [...new Set(jvm.map(lang))].join(" and ")));
  if (of("C#").length) suites.push(...dotnetSuites(projectDir, of("C#")));
  if (of("Rust").length) suites.push(...cargoSuites(projectDir, of("Rust")));
  if (of("PHP").length) suites.push(...phpSuites(projectDir, of("PHP")));
  if (of("Ruby").length) suites.push(...rubySuites(projectDir, of("Ruby")));

  // Test-named files that are not code -- YAML fixtures under tests/, Terraform tests.
  if (!suites.length) suites.push({ unavailable: "no runner could be identified for the test files present" });
  return suites;
}

/** The first of detectSuites: the suite a single-language project has. */
export function detectSuite(projectDir) {
  return detectSuites(projectDir)[0];
}

/**
 * The JavaScript suite: the runner package.json declares, or node's own for files named like tests.
 * `testFiles` is every test file found; node --test is given only the ones named for it.
 */
function javascriptSuite(projectDir, testFiles) {
  const bin = (name) => path.join(projectDir, "node_modules", ".bin", name);
  const pkgPath = path.join(projectDir, "package.json");

  let pkg = {};
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch {
    return { noRunner: true, unavailable: "package.json could not be parsed, so no runner could be identified" };
  }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const declared = ["jest", "vitest", "mocha", "tap", "ava"].find((r) => deps[r]);

  if (declared) {
    if (!existsSync(bin(declared))) {
      // The project's OWN manifest names this runner. Its absence is not a fact about this
      // machine the way a missing pytest is -- it is the deliverable failing its own declared
      // requirement, and the task asks for tests someone else can run. Marked so the report
      // blocks rather than advises.
      return {
        declaredRunnerMissing: true,
        unavailable:
          `the suite is written for ${declared}, which this project declares in package.json and ` +
          `which is not installed — node_modules/.bin/${declared} does not exist. Nobody can run ` +
          `these tests as delivered, including whoever receives this project. Run \`npm install\` ` +
          `(dependencies are deliberately not installed by this check, because npm install on a ` +
          `generated manifest executes arbitrary postinstall hooks) and make sure the suite passes`,
      };
    }
    return { label: declared, cmd: bin(declared), args: declared === "jest" ? ["--ci"] : [], cwd: projectDir };
  }

  // No declared runner: node's own, which needs nothing installed. Note the narrower pattern --
  // isTestFile matches anything under a test/ directory, which is right for "does this project
  // have tests" and wrong for "what should I execute". Handing node --test a helper module like
  // test/fakes.mjs runs it as a test file: harmless when it only exports fakes, and not something
  // to rely on when the helper has side effects.
  const nodeTests = testFiles.filter((f) => /\.(test|spec)\.(m|c)?js$|_test\.(m|c)?js$/.test(f.rel));
  if (nodeTests.length) {
    return {
      label: "node --test",
      cmd: process.execPath,
      args: ["--test", ...nodeTests.map((f) => f.rel)],
      cwd: projectDir,
    };
  }
  return { noRunner: true, unavailable: "package.json declares no test runner and no runnable JavaScript tests were found" };
}

const TEST_LANGUAGE = {
  ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".rs": "Rust", ".php": "PHP", ".rb": "Ruby",
  ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
  ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".py": "Python",
};

// Each runner's own summary line. Falling back to the exit code alone would report "the suite
// failed" without saying how much of it did, which is the difference between one broken assertion
// and a suite that never started.
const COUNTERS = [
  // jest: "Tests:  3 failed, 9 passed, 12 total"
  { re: /^\s*Tests:\s+(?:(\d+) failed[,|\s]+)?(?:(\d+) skipped[,|\s]+)?(\d+) passed[,|\s]+(\d+) total/im,
    map: (m) => ({ failed: +(m[1] || 0), passed: +m[3], total: +m[4] }) },
  // vitest: "Tests  2 failed | 10 passed (12)", and with nothing failing "Tests  9 passed (9)".
  // Anchored, and the failed segment is optional. Without both, an all-passing vitest run fell
  // through to the loose counter at the bottom, which matched the "Test Files  1 passed (1)" line
  // above it and reported a nine-test suite as "1 of 1 passed" -- an undercount that still said
  // "passed", which is the kind of wrong answer nobody goes looking for.
  { re: /^\s*Tests\s+(?:(\d+) failed\s*\|\s*)?(\d+) passed\s*\((\d+)\)/im,
    map: (m) => ({ failed: +(m[1] || 0), passed: +m[2], total: +m[3] }) },
  // node --test: "# pass 21" / "# fail 0", or the ℹ-prefixed form
  { re: /[#ℹ]\s*pass\s+(\d+)[\s\S]*?[#ℹ]\s*fail\s+(\d+)/i,
    map: (m) => ({ passed: +m[1], failed: +m[2], total: +m[1] + +m[2] }) },
  // pytest: "3 failed, 9 passed" or "9 passed". Last, and deliberately not allowed to start
  // mid-line: every runner prints some other line containing "N passed", and this pattern will
  // happily read whichever it reaches first.
  { re: /^[^\n]*?(?:(\d+) failed,\s*)?(\d+) passed(?![^\n]*\bfiles?\b)/im,
    map: (m) => ({ failed: +(m[1] || 0), passed: +m[2], total: +(m[1] || 0) + +m[2] }) },
];

// vitest and jest colour their summaries even under CI, and an escape sequence sitting between
// "Tests" and its count defeats anchoring.
const ANSI = /\u001B\[[0-9;]*[A-Za-z]/g;

function parseCounts(rawOutput, parser) {
  const output = rawOutput.replace(ANSI, "");
  // A runner with its own summary format is read by that alone: the shared patterns below misread
  // other runners' summaries rather than missing them.
  if (parser && COUNTS[parser]) return COUNTS[parser](output);
  for (const c of COUNTERS) {
    const m = c.re.exec(output);
    if (m) return c.map(m);
  }
  return null;
}

// The names matter more than the count. Three failures that are all "could not connect" is an
// environment problem; three failures that name the task's own acceptance criteria is a broken
// deliverable, and only the reader can tell those apart.
function failingNames(output, parser) {
  output = output.replace(ANSI, "");
  if (parser && FAILING[parser]) return [...new Set([...output.matchAll(FAILING[parser])].map((m) => m[1].trim()))].slice(0, 12);
  const names = new Set();
  for (const re of [
    /^\s*[✕✖x×]\s+(.+?)(?:\s+\(\d+(?:\.\d+)?\s*m?s\))?$/gim, // node --test spec, vitest
    // TAP. `node --test` emits the spec format to a TTY and TAP to a pipe, and this always runs
    // against a pipe -- so which one arrives depends on the Node version, not on anything this code
    // controls. Node 26 emits spec either way; Node 22 emits TAP. Without this line the gate ran on
    // CI and printed "1 of 2 test(s) FAILED" followed by a sentence telling the reader to check the
    // names above, with no names above. Counts survived only because TAP's `# fail` happens to
    // match the count patterns.
    /^\s*not ok \d+ - (.+?)(?:\s+#.*)?$/gim,
    /^\s*●\s+(.+)$/gm, // jest
    /^---\s+FAIL:\s+(\S+)/gm, // go
    /^FAILED\s+(\S+)/gm, // pytest
  ]) {
    for (const m of output.matchAll(re)) {
      // TAP names a file-level subtest by its path, which is not a test name. The spec reporter
      // never emits those, so dropping them keeps the two formats reporting the same thing.
      const n = m[1].trim();
      if (!n || /^failing tests|^tests?:/i.test(n)) continue;
      if (/\.(m|c)?[jt]sx?$/.test(n) || /^[./]/.test(n)) continue;
      names.add(n);
    }
  }
  // jest prints each failure twice -- once as `✕ short name` in the run list and again as
  // `● Suite › nested › short name` in the detail. Keeping both padded a three-failure suite out to
  // six lines and made it read as worse than it was. The qualified form is the one to keep: it says
  // which suite the failure came from.
  const all = [...names];
  const deduped = all.filter((n) => !all.some((o) => o !== n && o.endsWith(`\u203a ${n}`)));
  return deduped.slice(0, 12);
}

/** Exposed for tests: each runner's summary is parsed from text, so all five can be checked
 *  without installing five runners. The vitest undercount was invisible in every other way. */
export const parseCountsForTest = parseCounts;

/** Exposed for the same reason parseCounts is: the TAP path only occurs naturally on a Node
 *  version this machine does not run, and it shipped broken because of that. */
export const failingNamesForTest = failingNames;

/**
 * Runs every suite. Returns one result per suite: { ran, unavailable, timedOut, counts, failing,
 * exitCode }. Each suite gets the full time limit.
 */
export function runSuites(projectDir, { timeoutMs, env = process.env } = {}) {
  let limitNote = "";
  if (timeoutMs === undefined) {
    const t = testTimeout(env);
    if (t.error) return [{ ran: false, environmental: true, unavailable: `${t.error}, so the suite was not run` }];
    timeoutMs = t.ms;
    limitNote = t.set ? ", the limit WOLFPROOF_TEST_TIMEOUT sets" : "; WOLFPROOF_TEST_TIMEOUT raises the limit, in seconds";
  }
  return detectSuites(projectDir).map((suite) => runSuite(suite, timeoutMs, limitNote));
}

/** Runs the first suite: what a single-language project has. */
export function runTests(projectDir, opts = {}) {
  return runSuites(projectDir, opts)[0];
}

function runSuite(suite, timeoutMs, limitNote) {
  if (suite.unavailable) {
    return {
      ran: false,
      unavailable: suite.unavailable,
      declaredRunnerMissing: !!suite.declaredRunnerMissing,
      environmental: !!suite.environmental,
      noRunner: !!suite.noRunner,
    };
  }

  const r = spawnSync(suite.cmd, suite.args, {
    cwd: suite.cwd,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 16 * 1024 * 1024,
    // NODE_TEST_CONTEXT is deleted, not merely overridden. When this check itself runs under
    // `node --test`, the child inherits it, switches to the TAP reporter for a parent that is not
    // listening, and its summary comes back in a shape the counters do not read -- so a suite that
    // passed was reported as "the summary could not be parsed". The same would happen to anyone
    // running the validator from inside a test harness, which is exactly where a gate gets used.
    env: (() => {
      const env = { ...process.env, CI: "1", NODE_ENV: process.env.NODE_ENV || "test", ...(suite.env || {}) };
      delete env.NODE_TEST_CONTEXT;
      delete env.NODE_OPTIONS;
      return env;
    })(),
  });

  const output = `${r.stdout || ""}\n${r.stderr || ""}`;
  if (r.error && r.error.code === "ENOENT") {
    return { ran: false, environmental: true, unavailable: `${suite.label} could not be started (${r.error.message})` };
  }
  if (r.signal || (r.error && /timed? ?out/i.test(r.error.message || ""))) {
    return { ran: false, timedOut: true, environmental: true, label: suite.label, unavailable: `${suite.label} did not finish within ${timeoutMs / 1000}s and was killed${limitNote}` };
  }

  // Dependencies the project's CI did not install: the run says so, and this check runs offline.
  if (suite.missingDeps && r.status !== 0 && suite.missingDeps.re.test(output.replace(ANSI, ""))) {
    return {
      ran: false,
      environmental: true,
      label: suite.label,
      unavailable: `${suite.label} could not resolve this project's dependencies, which this check never downloads -- ${suite.missingDeps.fix}`,
    };
  }

  const reports = suite.countsFrom ? suite.countsFrom(suite.cwd) : null;
  const counts = reports ? { passed: reports.passed, failed: reports.failed, total: reports.total } : parseCounts(output, suite.parser);
  const failing = [...new Set([...(reports?.names || []), ...failingNames(output, suite.parser)])].slice(0, 12);

  // The runners in test-runners.mjs: a run that exits 0 and names no test ran no test. dotnet test on
  // an unrestored solution builds nothing, tests nothing and exits 0 with no output; that must not
  // read as a pass. A run that fails before its summary -- a compile error -- still blocks below.
  if (suite.parser && r.status === 0 && (!counts || counts.total === 0)) {
    return {
      ran: false,
      environmental: true,
      label: suite.label,
      unavailable: `${suite.label} exited 0 and reported ${counts ? "0 tests" : "no test summary"}${suite.noSummaryHint || ""}, so no test is known to have run`,
    };
  }

  return {
    ran: true,
    label: suite.label,
    exitCode: r.status,
    counts,
    failing,
    output: output.slice(-4000),
  };
}

/**
 * Blocking when the suite ran and reported failures — the project's own tests contradicting its own
 * code needs no interpretation. Advisory when it could not run, timed out, or its outcome cannot be
 * read: those are environment facts, and blocking on them would fail work that may be correct.
 */
export function testExecutionReport(projectDir, { wanted = false } = {}) {
  if (!wanted) return { failures: [], advisories: [] };
  // One verdict per suite: a JavaScript suite that passed says nothing about a PHP one beside it.
  const verdicts = runSuites(projectDir).map(verdictFor);
  const all = (k) => verdicts.flatMap((v) => v[k] || []);
  const couldNotRun = all("couldNotRun");
  return { failures: all("failures"), advisories: all("advisories"), ...(couldNotRun.length ? { couldNotRun } : {}) };
}

/**
 * The verdict for one completed run. Separated from testExecutionReport so it can be exercised
 * against a synthetic result: the interesting cases here are a suite that exits non-zero without a
 * parseable summary and a runner that never started, and reproducing either through a real
 * project means arranging for a real toolchain to be broken in a specific way.
 */
export function verdictFor(r) {
  if (!r.ran) {
    const line =
      `tests: NOT EXECUTED — ${r.unavailable}. Test files existing is not evidence that they pass, ` +
      `and the task asks for tests someone else can run.`;
    // A runner the project itself declared and did not install is the project's claim failing, so
    // it blocks. Everything else stays out of the findings, because blocking on a fact about this
    // machine would fail work that may be correct -- which is how a gate gets switched off.
    if (r.declaredRunnerMissing) return { failures: [line], advisories: [] };

    // But "not blocking" is not "fine". A suite that could not be started, or was killed on a
    // timeout, produced no verdict at all, and an advisory saying so sits in a list nobody totals
    // up. It is reported as a check that could not run, which makes the RUN incomplete without
    // making the PROJECT at fault -- the same standing as a control that could not be reached.
    //
    // This was not academic: three Go deliverables recorded a clean `tests` verdict on a machine
    // with no Go toolchain, and their suites had never compiled. The corpus froze the non-answer
    // as the answer, and only a run on a machine that HAD Go found the defect.
    //
    // So are tests that nothing in the project says how to run -- a composer.json that declares no
    // runner, Java with no pom.xml or build.gradle, Rust with no Cargo.toml, a package.json with no
    // runner. The fix is in the project, but no test ran, and a suite that did not run does not pass:
    // decided 2026-10-22, after a Laravel-shaped project with a failing test and no runner declared
    // exited 0 on an advisory.
    if (r.environmental || r.noRunner) return { failures: [], advisories: [line], couldNotRun: [r.unavailable] };

    // Everything left: no test files at all, which code quality blocks on, and test-named files that
    // are not code.
    return { failures: [], advisories: [line] };
  }

  const c = r.counts;
  const failedCount = c ? c.failed : null;
  const suiteFailed = failedCount !== null ? failedCount > 0 : r.exitCode !== 0;

  if (!suiteFailed) {
    const detail = c ? `${c.passed} of ${c.total} passed` : `exit 0, though the summary could not be parsed`;
    return { failures: [], advisories: [`tests: ran under ${r.label} — ${detail}.`] };
  }

  const named = r.failing.length ? `\n  ${r.failing.join("\n  ")}` : "";
  const headline = c
    ? `${c.failed} of ${c.total} test(s) FAILED`
    : `the suite exited ${r.exitCode} and its summary could not be parsed`;

  // When the summary parsed, the failing names carry the evidence. When it did not, this finding
  // used to carry NO evidence at all -- it asked the reader to check the names above, and there
  // were no names above, because nothing could be extracted. The output was captured the whole
  // time and discarded here. A suite that exits non-zero without a parseable summary is most often
  // one that never ran: a test binary that would not compile, a missing module, an absent service.
  // Those read identically to a real failure unless the output is shown.
  const evidence =
    !c && r.output
      ? `\n\n  Output (last lines, the summary could not be parsed):\n${r.output
          .trim()
          .split("\n")
          .slice(-25)
          .map((l) => `    ${l}`)
          .join("\n")}`
      : "";

  return {
    failures: [
      `tests: ${headline} under ${r.label}.${named}\n` +
        `These are this project's own tests failing against this project's own code. Check the names ` +
        `above before changing anything: failures that all say the same thing about a connection are ` +
        `an environment this suite needs and does not have, while failures that name the task's ` +
        `acceptance criteria are the deliverable being wrong.${evidence}`,
    ],
    advisories: [],
  };
}
