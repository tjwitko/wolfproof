// An option a command does not define is a usage error, exit 2, naming it (lib/cli-flags.mjs).
//
// Measured on c54b4a9, on a clean project: `wolfproof <project> --json --no-such-flag` exited 0, and
// so did `wolfproof <project> --factroy`, in the default mode. `wolfproof known` and `wolfproof
// review` stepped over one the same way; `wolfproof init` already refused it. Through the real
// entry point.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(ROOT, "bin", "validate.mjs");
const wolfproof = (args, cwd) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", cwd, timeout: 120_000 });

// A project the gate has nothing to say against, were it to run.
function project() {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "unknown-option-")));
  const git = (...a) => spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(path.join(dir, "a.js"), "export const a = 1;\n");
  writeFileSync(path.join(dir, "task.txt"), "Add a.\n");
  git("add", "-A");
  git("commit", "-qm", "base");
  return { dir, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("the gate: an option it does not define is exit 2 and named, and nothing is reported on the project", () => {
  const p = project();
  try {
    for (const [args, says] of [
      [[p.dir, "--no-such-flag"], /^wolfproof: unknown option --no-such-flag\. wolfproof --help lists the options$/m],
      // The default mode, from a caller that asked for factory mode.
      [[p.dir, "--factroy"], /^wolfproof: unknown option --factroy \(did you mean --factory\?\)\./m],
      [[p.dir, "--factory", "--bse=HEAD"], /^wolfproof: unknown option --bse \(did you mean --base\?\)\./m],
      // Text, to a caller that asked for JSON.
      [[p.dir, "--json=1"], /^wolfproof: --json takes no value\./m],
      [[p.dir, "--pre-commit=yes"], /^wolfproof: --pre-commit takes no value\./m],
      [[p.dir, "task.txt", "-j"], /^wolfproof: unknown option -j\./m],
      // Another command's option.
      [[p.dir, "--reason", "x"], /^wolfproof: unknown option --reason\./m],
      // Asked before anything else is answered.
      [["--version", "--no-such-flag"], /^wolfproof: unknown option --no-such-flag\./m],
      [["--help", "--no-such-flag"], /^wolfproof: unknown option --no-such-flag\./m],
    ]) {
      const r = wolfproof(args, p.dir);
      assert.equal(r.status, 2, `wolfproof ${args.join(" ")}: exit ${r.status}; stderr: ${r.stderr.slice(0, 300)}`);
      assert.match(r.stderr, says, args.join(" "));
      assert.equal(r.stdout, "", `${args.join(" ")}: nothing on stdout, no verdict and no version`);
    }
  } finally {
    p.done();
  }
});

test("the gate in --json mode: the usage error is the one document, and it is not a verdict", () => {
  const p = project();
  try {
    const r = wolfproof([p.dir, "--json", "--no-such-flag"], p.dir);
    assert.equal(r.status, 2, r.stderr.slice(0, 300));
    assert.deepEqual(JSON.parse(r.stdout), { exitCode: 2, error: "unknown option --no-such-flag. wolfproof --help lists the options" });
    // And the options it does define are still taken: the same project, without the slip.
    const ok = wolfproof([p.dir, "--json"], p.dir);
    assert.equal(ok.status, 0, ok.stderr.slice(-300));
    assert.equal(JSON.parse(ok.stdout).exitCode, 0);
  } finally {
    p.done();
  }
});

test("wolfproof known and wolfproof review: an option they do not define is exit 2, and nothing is written", () => {
  const p = project();
  try {
    const before = readdirSync(p.dir).sort();
    for (const [args, says] of [
      [["known", p.dir, "--no-such-flag"], /^wolfproof known: unknown option --no-such-flag$/m],
      // The gate's options are not theirs.
      [["known", p.dir, "--json"], /^wolfproof known: unknown option --json$/m],
      [["known", p.dir, "--factory"], /^wolfproof known: unknown option --factory$/m],
      [["known", p.dir, "--file", path.join(p.dir, "k.json"), "--codeql=1"], /^wolfproof known: --codeql takes no value$/m],
      [["known", p.dir, "-x"], /^wolfproof known: unknown option -x$/m],
      [["review", p.dir, "--no-such-flag"], /^wolfproof review: unknown option --no-such-flag$/m],
      [["review", p.dir, "--json"], /^wolfproof review: unknown option --json$/m],
      [["review", p.dir, "authentication:GET /x:a.js", "--reason", "fine", "--resaon", "typo"], /^wolfproof review: unknown option --resaon \(did you mean --reason\?\)$/m],
      [["review", p.dir, "authentication:GET /x:a.js", "--reason", "fine", "--expire", "2027-01-01"], /^wolfproof review: unknown option --expire \(did you mean --expires\?\)$/m],
    ]) {
      const r = wolfproof(args, p.dir);
      assert.equal(r.status, 2, `wolfproof ${args.join(" ")}: exit ${r.status}; stderr: ${r.stderr.slice(0, 300)}`);
      assert.match(r.stderr, says, args.join(" "));
      assert.match(r.stderr, /^usage: wolfproof (known|review) /m);
      assert.equal(r.stdout, "");
    }
    // No snapshot, and no entry with the misspelt option's value left out of it.
    assert.deepEqual(readdirSync(p.dir).sort(), before);

    // What they do define still works, a value that begins with a dash included.
    const w = wolfproof(["review", p.dir, "authentication:GET /x:a.js", "--reason", "-ish, but fine", "--file", path.join(p.dir, "r.json")], p.dir);
    assert.equal(w.status, 0, w.stderr);
    assert.equal(JSON.parse(readFileSync(path.join(p.dir, "r.json"), "utf8")).reviewed[0].reason, "-ish, but fine");
    for (const command of ["known", "review"]) {
      const h = wolfproof([command, "-h"], p.dir);
      assert.equal(h.status, 0, `${command} -h: ${h.stderr}`);
      assert.match(h.stderr, new RegExp(`^usage: wolfproof ${command} `, "m"));
    }
  } finally {
    p.done();
  }
});

test("wolfproof init: an option with one dash is refused too, and no directory is made for it", () => {
  const p = project();
  try {
    for (const args of [["init", "-x", "--new"], ["init", p.dir, "--no-such-flag"]]) {
      const r = wolfproof(args, p.dir);
      assert.equal(r.status, 2, `wolfproof ${args.join(" ")}: exit ${r.status}; stderr: ${r.stderr.slice(0, 300)}`);
      assert.match(r.stderr, /^wolfproof init: unknown option (-x|--no-such-flag)$/m);
    }
    assert.ok(!existsSync(path.join(p.dir, "-x")), "init made a directory named -x");
    assert.ok(!existsSync(path.join(p.dir, "AGENTS.md")));
  } finally {
    p.done();
  }
});

// The callers this package ships: the Action and the hook `wolfproof init` writes. Each option
// either passes must be one the gate defines, or every run of it is a usage error.
test("every option the Action and the pre-commit hook pass is one the gate defines, and --help names each", async () => {
  const { GATE_OPTIONS } = await import("./validate.mjs");
  const defined = new Set([...GATE_OPTIONS.flags, ...GATE_OPTIONS.values]);
  const action = readFileSync(path.join(ROOT, "action.yml"), "utf8");
  const passed = new Set();
  for (const line of action.split("\n")) {
    if (!/ARGS\+?=\(|bin\/validate\.mjs/.test(line)) continue;
    for (const m of line.matchAll(/(?<![\w$-])(--[a-z][a-z-]*)/g)) passed.add(m[1]);
  }
  for (const m of readFileSync(path.join(ROOT, "bin", "init.mjs"), "utf8").matchAll(/const flags = preCommit \? " (--[a-z-]+)"/g)) passed.add(m[1]);
  assert.ok(passed.has("--json") && passed.has("--factory") && passed.has("--pre-commit"), `read from the Action and the hook: ${[...passed].join(" ")}`);
  for (const option of passed) assert.ok(defined.has(option), `${option} is passed and not defined`);

  const help = wolfproof(["--help"], ROOT);
  assert.equal(help.status, 0);
  for (const option of defined) if (option.startsWith("--")) assert.ok(help.stdout.includes(option), `--help does not name ${option}`);
});
