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
  assert.deepEqual(within({ "app.py": fixed }, (d) => sastFailures(d, { taskText: DISTINCT })), { failures: [], advisories: [] });
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
  assert.deepEqual(within({ "main.swift": "print(1)\n" }, sastFailures), { failures: [], advisories: [] });
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

// ---------------------------------------------------------------------------------------------
// Injection through a project helper (sast-hops.mjs, docs/candidate-rules.md #22)
// ---------------------------------------------------------------------------------------------

// WebGoat's SQL lessons: the handler hands the request parameter to a helper in the same class, and
// only the helper builds and runs the query. Before the helper hops this was an advisory.
scanner("a request parameter passed to a same-class helper that runs SQL blocks, naming the helper", () => {
  const lesson = `package lessons;
import java.sql.*;
public class Lesson5a {
  @PostMapping("/SqlInjection/assignment5a")
  public AttackResult completed(@RequestParam String account, @RequestParam String operator) {
    return injectableQuery(account + " " + operator);
  }
  protected AttackResult injectableQuery(String accountName) {
    String query = "";
    try (Connection connection = dataSource.getConnection()) {
      query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
      try (Statement statement = connection.createStatement()) {
        ResultSet results = statement.executeQuery(query);
      }
    }
    return null;
  }
}
`;
  // Another class with a method of the same name, reached through an object: it could be either.
  const other = `package lessons;
public class Mitigation {
  @PostMapping("/SqlOnlyInputValidation")
  public AttackResult attack(@RequestParam String userId) {
    return lesson.injectableQuery(userId);
  }
  @PostMapping("/relay")
  public AttackResult viaRelay(@RequestParam String userId) {
    return relay(userId);
  }
  // A helper whose only path to a sink is a call through an object: not summarised, so its callers
  // are not reported through it -- the object could be anything.
  AttackResult relay(String id) {
    return lesson.injectableQuery(id);
  }
}
`;
  const { failures, advisories } = within({ "src/Lesson5a.java": lesson, "src/Mitigation.java": other }, (d) => sastFailures(d));
  assert.equal(failures.length, 1, JSON.stringify(failures));
  assert.match(failures[0], /^sast: SQL injection — request data is built into a SQL statement, through a call to a project helper: src\/Lesson5a\.java:6 \(via injectableQuery\(\) at src\/Lesson5a\.java:8\)\./);
  const via = advisories.find((a) => /through a call to a project helper/.test(a));
  assert.ok(via, advisories.join("\n"));
  assert.match(via, /not blocking — the call is through an object whose type is not known here/);
  assert.match(via, /src\/Mitigation\.java:5 \(via injectableQuery\(\) at src\/Lesson5a\.java:8\)/);
  assert.doesNotMatch(advisories.join("\n") + failures.join("\n"), /relay\(\)/);
});

scanner("helpers of helpers across files block; a sanitised helper, a constant argument and a twice-defined name do not", () => {
  const files = {
    "app/db.py":
      "def run_query(db, name):\n    q = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n    return db.execute(q)\n\n" +
      "def by_id(db, n):\n    return db.execute(\"SELECT * FROM t WHERE id = \" + str(int(n)))\n\n" +
      "def lookup(db, who):\n    return run_query(db, who)\n",
    "app/routes.py":
      "from flask import request\nfrom app.db import lookup, by_id, run_query\nfrom app.cache import purge\n\n" +
      "@app.route('/u')\ndef user():\n    return lookup(db, request.args.get('n'))\n\n" +
      "@app.route('/id')\ndef by_number():\n    return by_id(db, request.args.get('id'))\n\n" +
      "@app.route('/fixed')\ndef fixed():\n    return run_query(db, 'admin')\n\n" +
      "@app.route('/purge')\ndef purge_route():\n    return purge(db, request.args.get('k'))\n\n" +
      "@app.route('/w')\ndef w():\n    return wrapper(db, request.args.get('w'))\n\n" +
      "@app.route('/page')\ndef page():\n    return main.render(db, request.args.get('p'))\n\n" +
      "@app.route('/both')\ndef both():\n    return db.execute(\"SELECT 1 WHERE a = '\" + request.args['b'] + \"'\") or run_query(db, request.args['b']) or repo.lookup(db, request.args['b'])\n",
    // purge is defined twice, and only one definition injects: a bare call cannot say which it reaches.
    "app/cache.py": "def purge(db, key):\n    return db.execute(\"DELETE FROM cache WHERE k = '\" + key + \"'\")\n",
    "app/memo.py": "def purge(db, key):\n    return memo.pop(key)\n",
    // A wrapper the route reaches surely, around a call that is not sure: the chain is only as sure as
    // its weakest link.
    "app/svc.py": "def wrapper(db, k):\n    return purge(db, k)\n",
    // Two modules named main, and only one main.render injects: main.render(...) could be either.
    "app/a/main.py": "def render(db, page):\n    return db.execute(\"SELECT body FROM pages WHERE slug = '\" + page + \"'\")\n",
    "app/b/main.py": "def render(db, page):\n    return templates[page]\n",
  };
  const { failures, advisories } = within(files, (d) => sastFailures(d));
  assert.equal(failures.length, 1, JSON.stringify(failures));
  assert.match(failures[0], /[:,] app\/routes\.py:7 \(via lookup\(\) at app\/db\.py:8 → run_query\(\) at app\/db\.py:1\)\./);
  assert.doesNotMatch(failures[0], /routes\.py:11|routes\.py:15/, "int() sanitises by_id; a literal is not request data");
  assert.match(advisories.join("\n"), /app\/routes\.py:19 \(via purge\(\) at app\/cache\.py:1\)/);
  assert.match(advisories.join("\n"), /app\/routes\.py:23 \(via wrapper\(\) at app\/svc\.py:1 → purge\(\) at app\/cache\.py:1\)/);
  assert.match(advisories.join("\n"), /app\/routes\.py:27 \(via render\(\) at app\/a\/main\.py:1\)/);
  // A line that already blocks for SQL injection is reported once, not again through the helper.
  assert.equal(failures[0].match(/app\/routes\.py:31/g)?.length, 1, failures[0]);
  // ...and the call through an object on that line is not an advisory as well.
  assert.doesNotMatch(advisories.join("\n"), /app\/routes\.py:31/);
});

// RailsGoat's shape: a controller passes an upload to a class method on a model, which passes it on
// to another, which interpolates its file name into a shell command.
scanner("a call through the class that defines the helper blocks, two hops deep", () => {
  const files = {
    "app/models/benefits.rb":
      "class Benefits < ApplicationRecord\n  def self.save(file, backup = false)\n    make_backup(file, backup) if backup == \"true\"\n  end\n\n" +
      "  def self.make_backup(file, full_file_name)\n    system(\"cp #{full_file_name} bak_#{file.original_filename}\")\n  end\nend\n",
    "app/controllers/benefit_forms_controller.rb":
      "class BenefitFormsController < ApplicationController\n  def upload\n    file = params[:benefits][:upload]\n    Benefits.save(file, params[:benefits][:backup])\n  end\nend\n",
  };
  const { failures } = within(files, (d) => sastFailures(d));
  assert.equal(failures.length, 1, JSON.stringify(failures));
  assert.match(failures[0], /^sast: command injection — /);
  assert.match(failures[0], /app\/controllers\/benefit_forms_controller\.rb:4 \(via save\(\) at app\/models\/benefits\.rb:2 → make_backup\(\) at app\/models\/benefits\.rb:6\)/);
});

// Two things the calibration set taught. NetBox names Django migrations 0096_multi_protocol_services,
// which no pattern can spell as a module, and one such helper made the whole check could-not-run.
// Lemmy builds a URL from configuration and puts request data only in its query, and SSRF through a
// helper -- which cannot see whether its caller fixed the host -- blocked falsely three times.
scanner("a helper in a module no pattern can name is still followed; SSRF through a helper is an advisory", () => {
  const files = {
    "app/migrations/0096_backfill.py": "def backfill(db, table):\n    return db.execute(\"UPDATE \" + table + \" SET x = 1\")\n",
    // A keyword passes the identifier test and still cannot be a pattern: its rule is dropped, not the check.
    "app/lambda.py": "def purge_all(db, scope):\n    return db.execute(\"DELETE FROM t WHERE scope = '\" + scope + \"'\")\n",
    "app/fetch.py": "import requests\n\ndef fetch_json(url):\n    return requests.get(url).json()\n",
    "app/views.py":
      "from flask import request\n\n@app.route('/b')\ndef b():\n    return backfill(db, request.args['t'])\n\n" +
      "@app.route('/f')\ndef f():\n    return fetch_json(CONFIG_BASE + '/items?q=' + request.args['q'])\n\n" +
      "@app.route('/p')\ndef p():\n    return purge_all(db, request.args['s'])\n",
  };
  const r = within(files, (d) => sastFailures(d));
  assert.equal(r.couldNotRun, undefined, JSON.stringify(r.couldNotRun));
  assert.equal(r.failures.length, 1, JSON.stringify(r.failures));
  assert.match(r.failures[0], /^sast: SQL injection — .*app\/views\.py:5 \(via backfill\(\) at app\/migrations\/0096_backfill\.py:1\)/);
  assert.match(r.failures[0], /app\/views\.py:13 \(via purge_all\(\) at app\/lambda\.py:1\)/);
  assert.match(r.advisories.join("\n"), /\(SSRF, not blocking — the call is through .*\): app\/views\.py:9 \(via fetch_json\(\) at app\/fetch\.py:3\)/);
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
