import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, readdirSync, symlinkSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

import { sastFailures, sastTargets } from "./sast.mjs";
import { setting } from "../lib/settings.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const haveSemgrep = spawnSync("semgrep", ["--version"], { env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" } }).status === 0;
const required = setting(process.env, "REQUIRE_SCANNERS") === "1";
const scanner = (name, fn) =>
  test(name, { skip: !haveSemgrep && !required && "semgrep not installed" }, () => {
    assert.ok(haveSemgrep, "WOLFPROOF_REQUIRE_SCANNERS is set and semgrep is not on PATH");
    fn();
  });

function project(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "sast-"));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
const within = (files, fn) => {
  const d = project(files);
  try {
    return fn(d);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
};

// The probe from the outside review: blocked only for a missing authentication check, with neither
// injection mentioned.
const FLASK = `import sqlite3, subprocess
from flask import Flask, request
app = Flask(__name__)
@app.get("/ping")
def ping():
    return subprocess.run("ping -c1 " + request.args["host"], shell=True, capture_output=True).stdout
@app.get("/user")
def user():
    return str(sqlite3.connect("db").execute(f"SELECT * FROM users WHERE name = '{request.args['n']}'").fetchall())
`;

// The rules' own annotated samples, through semgrep's test runner: every \`ruleid:\` line must match
// and every \`ok:\` line must not.
//
// The samples are kept as .sample files and given their real extension only here, in a temporary
// directory. As .py, .go and .js files in the repository, deliberately vulnerable code is source to
// every tool that reads source: this gate's own Go build and authentication check flagged them, and
// so did the pre-commit hook, before a fixture marker could help.
//
// One semgrep run for all of them, not one per rule file: semgrep's test runner pairs each sample with
// the rule file of the same name (c.cpp with c.yaml), and its start-up was most of each run's cost --
// eleven runs took 63s, and pushed the gate's own 120-second test budget over on CI.
scanner("every rule matches its annotated samples, and nothing else", () => {
  const tmp = mkdtempSync(path.join(tmpdir(), "sast-samples-"));
  try {
    const rules = readdirSync(path.join(HERE, "sast-rules")).filter((f) => f.endsWith(".yaml"));
    const samples = readdirSync(path.join(HERE, "sast-samples")).filter((f) => f.endsWith(".sample"));
    for (const f of rules) writeFileSync(path.join(tmp, f), readFileSync(path.join(HERE, "sast-rules", f)));
    for (const f of samples) writeFileSync(path.join(tmp, f.replace(/\.sample$/, "")), readFileSync(path.join(HERE, "sast-samples", f)));
    const stem = (f) => f.split(".")[0];
    assert.deepEqual([...new Set(samples.map(stem))].sort(), rules.map(stem).sort(), "every rule file has a sample, and every sample a rule file");
    const r = spawnSync("semgrep", ["--test", "--metrics=off", "--disable-version-check", tmp], {
      encoding: "utf8",
      env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" },
    });
    const out = r.stdout + r.stderr;
    assert.equal(r.status, 0, out.slice(-2400));
    const passed = out.match(/(\d+)\/\1: ✓ All tests passed/);
    assert.ok(passed && Number(passed[1]) >= 74, `the samples' annotations all ran: ${out.slice(-600)}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

scanner("the rule files pass semgrep's strict validation", () => {
  // The scanner accepted YAML anchors that --validate rejected; a rule file one semgrep reads and
  // another refuses is not one to ship.
  const r = spawnSync("semgrep", ["scan", "--validate", "--config", path.join(HERE, "sast-rules"), "--metrics=off", "--disable-version-check"], {
    encoding: "utf8",
    env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" },
  });
  assert.equal(r.status, 0, (r.stdout + r.stderr).slice(-800));
});

scanner("the probe's two injections block, each with its own remedy and no duplicate advisory", () => {
  const r = within({ "app.py": FLASK }, sastFailures);
  assert.equal(r.failures.length, 2);
  assert.match(r.failures[0], /^sast: command injection — request data reaches a shell command: app\.py:6\. Pass arguments as a list/);
  assert.match(r.failures[1], /^sast: SQL injection — request data is built into a SQL statement: app\.py:9\. Use a parameterised query/);
  assert.deepEqual(r.advisories, [], "the construction rules fire on the same lines and add nothing");
});

scanner("a construction without a known source is an advisory, not a finding", () => {
  const r = within({ "report.py": 'def report(db, table):\n    return db.execute(f"SELECT count(*) FROM {table}")\n' }, sastFailures);
  assert.deepEqual(r.failures, []);
  assert.match(r.advisories.join("\n"), /SQL statement is built by string formatting .*not blocking.*report\.py:2/);
});

// Candidate #3: a broad handler that turns the handler's own 400 into a 500. Observed in four graded
// deliverables, webhook-5 among them.
const SWALLOWS = `from fastapi import HTTPException
def hook(body):
    try:
        if "id" not in body:
            raise HTTPException(status_code=400, detail="Missing event ID")
        store(body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
`;
const DISTINCT = "A client error must not be reported as a 500.";

scanner("a client error turned into a 500 blocks when the task asks for error distinction", () => {
  const r = within({ "app.py": SWALLOWS }, (d) => sastFailures(d, { taskText: DISTINCT }));
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /^sast: error distinction — .*app\.py:5\. A malformed request comes back as 5xx/);
  assert.match(r.advisories.join("\n"), /exception's text is sent to the caller \(error detail, not blocking.*app\.py:8/);
});

scanner("without that requirement it is an advisory, saying why", () => {
  const r = within({ "app.py": SWALLOWS }, (d) => sastFailures(d, { taskText: "" }));
  assert.deepEqual(r.failures, []);
  assert.match(r.advisories.join("\n"), /error distinction, not blocking — the task does not ask/);
});

// The regex this replaced flagged exactly this: the fix its own message recommended.
scanner("the corrected code passes", () => {
  const fixed = SWALLOWS.replace(
    "    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))",
    "    except HTTPException:\n        raise\n    except Exception:\n        raise HTTPException(status_code=500, detail=\"internal error\")"
  );
  assert.notEqual(fixed, SWALLOWS);
  const { failures, advisories } = within({ "app.py": fixed }, (d) => sastFailures(d, { taskText: DISTINCT }));
  assert.deepEqual({ failures, advisories }, { failures: [], advisories: [] });
});

// Two ways the code's author could hide code from the scan.
scanner("a .semgrepignore does not hide code: files are passed to semgrep explicitly", () => {
  const r = within({ "src/app.py": FLASK, ".semgrepignore": "src/\n" }, sastFailures);
  assert.equal(r.failures.length, 2);
});

scanner("an inline nosemgrep comment does not silence a finding", () => {
  const silenced = FLASK.replace('capture_output=True).stdout', 'capture_output=True).stdout  # nosemgrep');
  const r = within({ "app.py": silenced }, sastFailures);
  assert.match(r.failures.join("\n"), /command injection/);
});

test("installed dependencies and declared fixtures are not scanned", () => {
  within(
    {
      "app.js": "\n",
      "node_modules/lib/index.js": "\n",
      "samples/bad.py": FLASK,
      "samples/.identity-exception": "Deliberately vulnerable samples.\n",
    },
    (d) => assert.deepEqual(sastTargets(d).map((f) => path.relative(d, f)), ["app.js"])
  );
});

test("a project in a language no rule covers reports nothing", () => {
  const { failures, advisories } = within({ "main.swift": "print(1)\n" }, (d) => sastFailures(d));
  assert.deepEqual({ failures, advisories }, { failures: [], advisories: [] });
});

// The rules pass semgrep's own test runner above; this is the gate reading .php and .kt files at all,
// and turning what the rules find into its findings.
scanner("PHP and Kotlin are read: request data reaching a shell blocks in each", () => {
  const php = within({ "public/index.php": '<?php\nshell_exec("ping -c1 " . $_GET["host"]);\n' }, sastFailures);
  assert.equal(php.failures.length, 1, JSON.stringify(php));
  assert.match(php.failures[0], /^sast: command injection — request data reaches a shell command: public\/index\.php:2\./);
  const kt = within(
    { "src/main/kotlin/Ping.kt": '@GetMapping("/ping")\nfun ping(@RequestParam host: String) {\n    Runtime.getRuntime().exec("ping -c1 $host")\n}\n' },
    sastFailures
  );
  assert.equal(kt.failures.length, 1, JSON.stringify(kt));
  assert.match(kt.failures[0], /^sast: command injection — request data reaches a shell command: src\/main\/kotlin\/Ping\.kt:3\./);
});

// A check that cannot run says so: missing semgrep is could-not-run, exactly as a missing ruff is
// for Python. Run in a child whose PATH holds node alone, whatever this machine has installed.
test("without semgrep, the code is reported as not checked, not as clean", () => {
  const bin = mkdtempSync(path.join(tmpdir(), "nosemgrep-"));
  const dir = project({ "app.py": FLASK });
  try {
    symlinkSync(process.execPath, path.join(bin, "node"));
    const src = `import { sastFailures } from ${JSON.stringify(new URL("./sast.mjs", import.meta.url).href)};
      console.log(JSON.stringify(sastFailures(${JSON.stringify(dir)})));`;
    const r = spawnSync(path.join(bin, "node"), ["--input-type=module", "-e", src], { encoding: "utf8", env: { PATH: bin } });
    const out = JSON.parse(r.stdout);
    assert.deepEqual(out.failures, []);
    assert.match(out.couldNotRun[0], /^semgrep is not installed, so 1 Python file\(s\) were not checked for injection/);
  } finally {
    rmSync(bin, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no sample is a source file in the repository", () => {
  // See the first test: as source, they are findings in every scanner that reads this repository.
  const files = readdirSync(path.join(HERE, "sast-samples"));
  assert.ok(files.length >= 4);
  assert.deepEqual(files.filter((f) => !f.endsWith(".sample")), []);
});
