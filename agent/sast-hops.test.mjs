// Injection through a project helper (sast-hops.mjs, docs/candidate-rules.md #22). Its own file so
// node runs it beside sast.test.mjs rather than after it: each case is two or three Semgrep runs, and
// in one file the injection tests had grown from 47 to 103 seconds, past the gate's own 120-second
// limit for this repository's suite.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { sastFailures } from "./sast.mjs";
import { setting } from "../lib/settings.mjs";

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

// The value passed by name, which the positional call patterns missed outright -- not even an
// advisory. Python, Kotlin, C# and PHP 8 all have named arguments, and each is matched in any order.
scanner("a helper called with the value as a named argument blocks; a named argument to a safe parameter does not", () => {
  const files = {
    "py/app.py":
      "from flask import request\n\ndef run_query(db, name):\n    return db.execute(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n\n" +
      "@app.route('/k')\ndef k():\n    return run_query(db, name=request.args['n'])\n\n" +
      "@app.route('/safe')\ndef safe():\n    return run_query(db=request.args['d'], name='admin')\n",
    "kt/Routes.kt":
      "fun findUser(conn: Connection, name: String) = conn.createStatement().executeQuery(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n\n" +
      "fun Route.users() {\n    get(\"/u\") {\n        findUser(name = call.parameters[\"n\"]!!, conn = conn)\n    }\n}\n",
    "cs/Users.cs":
      "class Users {\n  static object Find(SqlConnection conn, string name) { return new SqlCommand(\"SELECT * FROM u WHERE n = '\" + name + \"'\", conn); }\n" +
      "  static void Map(WebApplication app) {\n    app.MapGet(\"/u\", (HttpRequest Request) => Find(name: Request.Query[\"n\"], conn: conn));\n  }\n}\n",
    "php/users.php":
      "<?php\nfunction find_user($conn, $name) { return mysqli_query($conn, \"SELECT * FROM u WHERE n = '\" . $name . \"'\"); }\n" +
      "find_user(name: $_GET['n'], conn: $conn);\n",
  };
  const { failures } = within(files, (d) => sastFailures(d));
  const sql = failures.find((f) => /^sast: SQL injection/.test(f)) || "";
  assert.match(sql, /py\/app\.py:8 \(via run_query\(\) at py\/app\.py:3\)/);
  assert.match(sql, /kt\/Routes\.kt:5 \(via findUser\(\) at kt\/Routes\.kt:1\)/);
  assert.match(sql, /cs\/Users\.cs:4 \(via Find\(\) at cs\/Users\.cs:2\)/);
  assert.match(sql, /php\/users\.php:3 \(via find_user\(\) at php\/users\.php:2\)/);
  assert.doesNotMatch(sql, /py\/app\.py:12/, "db= is not the parameter that reaches the query");
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
