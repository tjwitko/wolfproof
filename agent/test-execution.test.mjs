import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, chmodSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { existsSync } from "fs";

import { detectSuite, detectSuites, runTests, testExecutionReport, testTimeout, verdictFor, parseCountsForTest, failingNamesForTest } from "./test-execution.mjs";

function run(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "testexec-"));
  for (const [rel, contents] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents);
  }
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const PASSING = `
  import test from "node:test";
  import assert from "node:assert/strict";
  test("adds", () => { assert.equal(1 + 1, 2); });
`;
const FAILING = `
  import test from "node:test";
  import assert from "node:assert/strict";
  test("a genuine callback is accepted", () => { assert.equal(1 + 1, 2); });
  test("a forged callback is rejected", () => { assert.equal(1 + 1, 3); });
`;

test("a passing suite is executed and reported as passing", () => {
  run({ "package.json": "{}", "src/a.test.mjs": PASSING }, (dir) => {
    const r = testExecutionReport(dir, { wanted: true });
    assert.equal(r.failures.length, 0);
    assert.match(r.advisories[0], /ran under node --test/);
    assert.match(r.advisories[0], /1 of 1 passed/);
  });
});

test("a failing suite blocks and names which tests failed", () => {
  run({ "package.json": "{}", "src/a.test.mjs": FAILING }, (dir) => {
    const r = testExecutionReport(dir, { wanted: true });
    assert.equal(r.failures.length, 1);
    assert.match(r.failures[0], /1 of 2 test\(s\) FAILED/);
    assert.match(r.failures[0], /a forged callback is rejected/);
    // The passing test must not be listed as a failure.
    assert.doesNotMatch(r.failures[0], /a genuine callback is accepted/);
  });
});

// The Haiku deliverable's exact state: a jest config, a test file, and no installed toolchain.
// Reported, never blocking -- a missing node_modules is an environment fact, and failing work that
// may be correct is how a gate gets switched off.
// A runner the project declares in its own manifest and did not install is the project's claim
// failing, not a fact about this machine: nobody can run the suite as delivered, and the task asks
// for tests someone else can run. This blocks, unlike every other unavailable reason.
test("a declared runner that is not installed BLOCKS", () => {
  run(
    {
      "package.json": JSON.stringify({ devDependencies: { jest: "^29.7.0" } }),
      "src/__tests__/a.test.ts": "it('x', () => {});",
    },
    (dir) => {
      const r = testExecutionReport(dir, { wanted: true });
      assert.equal(r.failures.length, 1);
      assert.equal(r.advisories.length, 0);
      assert.match(r.failures[0], /declares in package.json/);
      assert.match(r.failures[0], /npm install/);
    }
  );
});

// The boundary: an environment fact must still only advise. Blocking on a toolchain this machine
// happens not to have would fail work that may be perfectly correct.
//
// Driven through verdictFor, because whether pytest is installed is a property of the machine and
// this test used to read that property instead of controlling it. Its guard anticipated the wrong
// shape -- "pytest is here, so there will be failures" -- but a pytest that is present and passing
// produces no failures, so the guard never fired and the assertion below it could not hold. It
// passed for years by being run only where pytest was absent, and failed the moment one was
// installed. The real pytest path is now covered end to end by the corpus's Python fixture.
test("a Python suite with no pytest is advised, not blocked", () => {
  const r = verdictFor({
    ran: false,
    environmental: true,
    unavailable: "the tests are Python and pytest is not installed here",
  });
  assert.equal(r.failures.length, 0, "a missing toolchain is not the project's defect");
  assert.match(r.advisories[0], /NOT EXECUTED/);
  assert.equal(r.couldNotRun.length, 1, "but nothing was measured, and the run must say so");
});

test("a project with no tests at all is reported as having none to run", () => {
  run({ "package.json": "{}", "src/index.mjs": "export const x = 1;" }, (dir) => {
    const r = testExecutionReport(dir, { wanted: true });
    assert.equal(r.failures.length, 0);
    assert.match(r.advisories[0], /no test files were found/);
  });
});

test("nothing runs when the task did not ask for tests", () => {
  run({ "package.json": "{}", "src/a.test.mjs": FAILING }, (dir) => {
    const r = testExecutionReport(dir, { wanted: false });
    assert.deepEqual(r, { failures: [], advisories: [] });
  });
});

// The command that starts the suite must never be one the project wrote. `scripts.test` is a
// model-authored shell string; build_check's precedent is to call known tools by name.
test("a hostile scripts.test is never the command that runs", () => {
  run(
    {
      "package.json": JSON.stringify({ scripts: { test: "touch PWNED && exit 0" } }),
      "src/a.test.mjs": PASSING,
    },
    (dir) => {
      const suite = detectSuite(dir);
      assert.doesNotMatch(JSON.stringify(suite), /PWNED|npm/);
      assert.equal(suite.label, "node --test");
      testExecutionReport(dir, { wanted: true });
      assert.equal(existsSync(path.join(dir, "PWNED")), false);
    }
  );
});

test("a suite that hangs is killed and reported, not treated as passing", () => {
  run(
    {
      "package.json": "{}",
      // A never-resolving promise is NOT a hang on every Node: 22 notices nothing is keeping the
      // event loop alive and fails the test immediately, so the timeout path this test exists to
      // prove was never reached there. The interval keeps the loop alive, which hangs on any
      // version.
      "src/a.test.mjs": `
        import test from "node:test";
        test("hangs", async () => {
          await new Promise(() => { setInterval(() => {}, 1000); });
        });
      `,
    },
    (dir) => {
      const r = runTests(dir, { timeoutMs: 2000 });
      assert.equal(r.ran, false);
      assert.equal(r.timedOut, true);
      assert.match(r.unavailable, /did not finish/);
    }
  );
});


test("test-named files that are not code -- fixtures under tests/ -- are not a suite that could not run", () => {
  run({ "main.tf": "\n", "tests/fixtures/plan.yaml": "a: 1\n" }, (dir) => {
    const suite = detectSuite(dir);
    assert.equal(suite.unsupported, undefined);
    assert.equal(testExecutionReport(dir, { wanted: true }).couldNotRun, undefined);
  });
});

// A package.json meant a JavaScript project and nothing else was looked at: a PHP, Python or Go suite
// beside it was neither run nor reported as unrun.
const PASSING_NODE = 'import test from "node:test";\nimport assert from "node:assert";\ntest("adds", () => assert.equal(1 + 1, 2));\n';
const PHP_TEST = "<?php\nfinal class AddTest extends TestCase { public function testAdds(): void { $this->assertSame(3, add(1, 2)); } }\n";



// The runners for Java, Kotlin, C#, Rust, PHP and Ruby (agent/test-runners.mjs) need their toolchains,
// which neither CI nor most machines have. Each is exercised here through a stub of its command on PATH
// that prints what the real one printed -- every output below is from a real run, trimmed to the lines
// that are read -- and answers --version.
function withStubs(stubs, fn) {
  const bin = mkdtempSync(path.join(tmpdir(), "stubs-"));
  for (const [name, output] of Object.entries(stubs)) {
    const exit = output.exit ?? 0;
    const text = output.text ?? output;
    writeFileSync(path.join(bin, `${name}.out`), typeof text === "string" ? text : "");
    writeFileSync(
      path.join(bin, name),
      `#!/bin/sh\ncase "$1" in --version|-v|-version) echo "${name} 1.0"; exit 0;; esac\ncat "${path.join(bin, `${name}.out`)}"\nexit ${exit}\n`
    );
    chmodSync(path.join(bin, name), 0o755);
  }
  const saved = process.env.PATH;
  process.env.PATH = `${bin}${path.delimiter}${saved}`;
  try {
    return fn();
  } finally {
    process.env.PATH = saved;
    rmSync(bin, { recursive: true, force: true });
  }
}

const REAL = {
  mavenFail:
    "[ERROR] Tests run: 2, Failures: 1, Errors: 0, Skipped: 0, Time elapsed: 0.029 s <<< FAILURE! -- in app.AddTest\n" +
    "[ERROR] app.AddTest.adds -- Time elapsed: 0.016 s <<< FAILURE!\n[ERROR] Failures: \n[ERROR]   AddTest.adds:5 expected: <3> but was: <-1>\n" +
    "[INFO] \n[ERROR] Tests run: 2, Failures: 1, Errors: 0, Skipped: 0\n[INFO] \n[ERROR] BUILD FAILURE\n",
  mavenPass: "[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.025 s -- in app.AddTest\n[INFO] \n[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0\n[INFO] BUILD SUCCESS\n",
  mavenOffline:
    "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-surefire-plugin:3.5.2:test (default-test) on project app: The following " +
    "artifacts could not be resolved: org.apache.maven.surefire:surefire-junit-platform:jar:3.5.2 (absent): Cannot access central (https://repo.maven.apache.org/maven2) in offline mode\n",
  gradleFail: "> Task :test FAILED\n\nAddTest > adds() FAILED\n    org.opentest4j.AssertionFailedError at AddTest.kt:4\n\n2 tests completed, 1 failed\n\nBUILD FAILED in 998ms\n",
  gradleOffline: "* What went wrong:\nPlugin [id: 'org.jetbrains.kotlin.jvm', version: '2.4.10'] was not found in any of the following sources:\n",
  dotnetFail: "  Failed AddTests.Adds [1 ms]\nFailed!  - Failed:     1, Passed:     1, Skipped:     0, Total:     2, Duration: 16 ms - App.Tests.dll (net10.0)\n",
  dotnetPass: "Passed!  - Failed:     0, Passed:     2, Skipped:     0, Total:     2, Duration: 11 ms - App.Tests.dll (net10.0)\n",
  cargoFail:
    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\ntest adds ... FAILED\n\nfailures:\n    adds\n\n" +
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
  cargoOffline: "error: no matching package named `itoa` found\nnote: offline mode (via `--offline`) can sometimes cause surprising resolution failures\n",
  phpunitFail: "There was 1 failure:\n\n1) AddTest::testAdds\nFailed asserting that -1 is identical to 3.\n\nFAILURES!\nTests: 2, Assertions: 2, Failures: 1.\n",
  phpunitPass: "OK (2 tests, 2 assertions)\n",
  pestFail: "   FAIL  Tests\\AddTest\n  ⨯ adds\n  ✓ zero\n   FAILED  Tests\\AddTest > adds\n  Tests:    1 failed, 1 passed (2 assertions)\n",
  rspecFail: "Failures:\n\n  1) add adds\n\n2 examples, 1 failure\n\nFailed examples:\n\nrspec ./spec/add_spec.rb:3 # add adds\n",
  rspecMissing: "bundler: command not found: rspec\nInstall missing gem executables with `bundle install`\n",
  minitestFail: "  1) Failure:\nAddTest#test_adds [test/add_test.rb:4]:\nExpected: 3\n  Actual: -1\n\n2 runs, 2 assertions, 1 failures, 0 errors, 0 skips\n",
};

test("each runner's summary and failing names are read from its own format", () => {
  for (const [parser, out, counts, names] of [
    ["maven", REAL.mavenFail, { total: 2, failed: 1, passed: 1 }, ["app.AddTest.adds"]],
    ["maven", REAL.mavenPass, { total: 2, failed: 0, passed: 2 }, []],
    ["gradle", REAL.gradleFail, { total: 2, failed: 1, passed: 1 }, ["AddTest > adds()"]],
    ["dotnet", REAL.dotnetFail, { total: 2, failed: 1, passed: 1 }, ["AddTests.Adds"]],
    ["cargo", REAL.cargoFail, { total: 2, failed: 1, passed: 1 }, ["adds"]],
    ["phpunit", REAL.phpunitFail, { total: 2, failed: 1, passed: 1 }, ["AddTest::testAdds"]],
    ["phpunit", REAL.phpunitPass, { total: 2, failed: 0, passed: 2 }, []],
    ["pest", REAL.pestFail, { total: 2, failed: 1, passed: 1 }, ["Tests\\AddTest > adds"]],
    ["rspec", REAL.rspecFail, { total: 2, failed: 1, passed: 1 }, ["add adds"]],
    ["minitest", REAL.minitestFail, { total: 2, failed: 1, passed: 1 }, ["AddTest#test_adds"]],
  ]) {
    assert.deepEqual(parseCountsForTest(out, parser), counts, parser);
    assert.deepEqual(failingNamesForTest(out, parser), names, parser);
  }
  // The shared pytest pattern reads cargo's FAILED line as 0 passed and nothing failed; cargo's own does not.
  assert.equal(parseCountsForTest(REAL.cargoFail, "cargo").failed, 1);
});

test("each language goes to its runner, with the build file that says how to run it", () => {
  withStubs({ mvn: REAL.mavenPass, gradle: "", dotnet: REAL.dotnetPass, cargo: "", php: REAL.phpunitPass, bundle: "" }, () => {
    for (const [files, label] of [
      [{ "pom.xml": "<project/>", "src/test/java/app/AddTest.java": "class AddTest {}\n" }, "mvn test"],
      [{ "build.gradle.kts": "", "src/test/kotlin/AddTest.kt": "class AddTest\n" }, "gradle test"],
      [{ "App.slnx": "<Solution/>", "App.Tests/AddTests.cs": "public class AddTests {}\n" }, "dotnet test App.slnx"],
      [{ "Cargo.toml": "[package]\n", "src/lib.rs": "#[test]\nfn adds() {}\n" }, "cargo test"],
      [{ "composer.json": '{"require-dev":{"phpunit/phpunit":"^12"}}', "vendor/bin/phpunit": "", "tests/AddTest.php": "<?php\n" }, "phpunit"],
      [{ "Gemfile": "", "spec/add_spec.rb": "describe 'add' do end\n" }, "rspec"],
      [{ "Gemfile": "", "test/add_test.rb": "class AddTest; end\n" }, "minitest"],
    ]) {
      run(files, (dir) => assert.deepEqual(detectSuites(dir).map((x) => x.label), [label], label));
    }
  });
});

// Decided 2026-10-22: the fix is in the project, but no test ran, and a suite that did not run does not
// pass. A Laravel-shaped project with a failing test and no runner in composer.json exited 0.
test("tests with nothing that says how to run them could not run", () => {
  for (const [files, msg] of [
    [{ "src/test/java/app/AddTest.java": "class AddTest {}\n" }, /there is no pom\.xml or build\.gradle/],
    [{ "tests/AddTest.php": "<?php\n" }, /there is no composer\.json/],
    [{ "composer.json": "{}", "tests/AddTest.php": "<?php\n" }, /declares neither phpunit\/phpunit nor pestphp\/pest/],
    [{ "src/lib.rs": "#[test]\nfn adds() {}\n" }, /there is no Cargo\.toml/],
    [{ "App.Tests/AddTests.cs": "public class AddTests {}\n" }, /there is no \.sln, \.slnx or \.csproj/],
    [{ "spec/add.rb": "describe 'add' do end\n" }, /none is named for RSpec or Minitest/],
    [{ "package.json": "{}", "test/helpers.js": "export {};\n" }, /package\.json declares no test runner/],
    [{ "package.json": "{\n", "src/a.test.js": "" }, /package\.json could not be parsed/],
  ]) {
    run(files, (dir) => {
      assert.match(detectSuite(dir).unavailable, msg);
      const v = testExecutionReport(dir, { wanted: true });
      assert.deepEqual(v.failures, [], String(msg));
      assert.equal(v.couldNotRun.length, 1, String(msg));
      assert.match(v.couldNotRun[0], msg);
    });
  }
  // Not code -- YAML fixtures under tests/ -- and no tests at all stay as they were.
  run({ "main.tf": "\n", "tests/fixtures/plan.yaml": "a: 1\n" }, (dir) => assert.equal(testExecutionReport(dir, { wanted: true }).couldNotRun, undefined));
  run({ "src/app.js": "export {};\n" }, (dir) => assert.equal(testExecutionReport(dir, { wanted: true }).couldNotRun, undefined));
});

test("the Laravel shape that exited 0 -- a composer.json with no runner, a failing test, a front-end package.json -- could not run", () => {
  run(
    { "package.json": '{"devDependencies":{"vite":"^5"}}', "composer.json": '{"name":"a/b"}', "app/add.php": "<?php\n", "tests/Feature/AddTest.php": "<?php\n" },
    (dir) => assert.deepEqual(testExecutionReport(dir, { wanted: true }).couldNotRun, ["composer.json declares neither phpunit/phpunit nor pestphp/pest, so no runner could be identified"])
  );
});

test("a toolchain that is not installed, or dependencies that were not, could not run; a declared PHP runner not installed blocks", () => {
  run({ "pom.xml": "<project/>", "src/test/java/app/AddTest.java": "class AddTest {}\n" }, (dir) => {
    const saved = process.env.PATH;
    process.env.PATH = "/nonexistent";
    try {
      assert.deepEqual(testExecutionReport(dir, { wanted: true }).couldNotRun, ["the tests are Java and Maven is not installed here (mvn is not on PATH)"]);
    } finally {
      process.env.PATH = saved;
    }
  });
  for (const [stub, files, fix] of [
    [{ mvn: { text: REAL.mavenOffline, exit: 1 } }, { "pom.xml": "<project/>", "src/test/java/app/AddTest.java": "" }, /mvn -B test-compile/],
    [{ gradle: { text: REAL.gradleOffline, exit: 1 } }, { "build.gradle": "", "src/test/java/app/AddTest.java": "" }, /gradle --no-daemon testClasses/],
    [{ cargo: { text: REAL.cargoOffline, exit: 101 } }, { "Cargo.toml": "", "tests/it.rs": "#[test]\nfn x() {}\n" }, /cargo fetch/],
    [{ bundle: { text: REAL.rspecMissing, exit: 127 } }, { "Gemfile": "", "spec/add_spec.rb": "" }, /bundle install/],
  ]) {
    withStubs(stub, () =>
      run(files, (dir) => {
        const v = testExecutionReport(dir, { wanted: true });
        assert.deepEqual(v.failures, []);
        assert.equal(v.couldNotRun.length, 1);
        assert.match(v.couldNotRun[0], /could not resolve this project's dependencies, which this check never downloads/);
        assert.match(v.couldNotRun[0], fix);
      })
    );
  }
  withStubs({ php: REAL.phpunitPass }, () =>
    run({ "composer.json": '{"require-dev":{"phpunit/phpunit":"^12"}}', "tests/AddTest.php": "<?php\n" }, (dir) => {
      const v = testExecutionReport(dir, { wanted: true });
      assert.equal(v.failures.length, 1, "declared in composer.json, not installed: as for a JavaScript runner");
      assert.match(v.failures[0], /written for phpunit, which this project declares in composer\.json and which is not installed/);
    })
  );
});

// Measured: dotnet test --no-restore on a solution whose packages were never restored built nothing,
// ran nothing, printed nothing and exited 0.
test("a runner that exits 0 and names no test could not run; one that fails before its summary blocks", () => {
  withStubs({ dotnet: "" }, () =>
    run({ "App.slnx": "<Solution/>", "App.Tests/App.Tests.csproj": "<Project/>", "App.Tests/AddTests.cs": "" }, (dir) => {
      const v = testExecutionReport(dir, { wanted: true });
      assert.deepEqual(v.failures, []);
      assert.match(v.couldNotRun[0], /^dotnet test App\.slnx exited 0 and reported no test summary; obj\/project\.assets\.json is missing/);
    })
  );
  withStubs({ cargo: { text: "error[E0425]: cannot find function `ad` in this scope\n", exit: 101 } }, () =>
    run({ "Cargo.toml": "", "tests/it.rs": "#[test]\nfn x() {}\n" }, (dir) => {
      const v = testExecutionReport(dir, { wanted: true });
      assert.equal(v.failures.length, 1, "a compile error blocks, as for go test");
      assert.match(v.failures[0], /^tests: the suite exited 101 and its summary could not be parsed under cargo test/);
    })
  );
});

test("a package.json for front-end tooling does not hide a PHP suite, and a failing one blocks", () => {
  withStubs({ php: { text: REAL.phpunitFail, exit: 1 } }, () =>
    run(
      {
        "package.json": '{"devDependencies":{"vite":"^5"}}',
        "resources/js/app.js": "export {};\n",
        "composer.json": '{"require-dev":{"phpunit/phpunit":"^12"}}',
        "vendor/bin/phpunit": "",
        "tests/Feature/AddTest.php": "<?php\n",
      },
      (dir) => {
        assert.deepEqual(detectSuites(dir).map((x) => x.label), ["phpunit"]);
        const v = testExecutionReport(dir, { wanted: true });
        assert.match(v.failures[0], /^tests: 1 of 2 test\(s\) FAILED under phpunit\.\n  AddTest::testAdds/);
      }
    )
  );
});

test("a JavaScript suite and a PHP suite both run, each with its own verdict", () => {
  withStubs({ php: REAL.phpunitPass }, () =>
    run(
      { "package.json": "{}", "src/math.test.mjs": PASSING_NODE, "composer.json": '{"require-dev":{"phpunit/phpunit":"^12"}}', "vendor/bin/phpunit": "", "tests/AddTest.php": "<?php\n" },
      (dir) => {
        assert.deepEqual(detectSuites(dir).map((x) => x.label), ["node --test", "phpunit"]);
        const v = testExecutionReport(dir, { wanted: true });
        assert.deepEqual(v.failures, []);
        assert.ok(v.advisories.some((a) => /^tests: ran under node --test — 1 of 1 passed/.test(a)), JSON.stringify(v.advisories));
        assert.ok(v.advisories.some((a) => /^tests: ran under phpunit — 2 of 2 passed/.test(a)), JSON.stringify(v.advisories));
      }
    )
  );
});

test("a JavaScript suite and a Python suite are both found", () => {
  run({ "package.json": "{}", "src/math.test.mjs": PASSING_NODE, "tests/test_add.py": "def test_adds():\n    assert 1 + 1 == 2\n" }, (dir) => {
    const suites = detectSuites(dir);
    assert.equal(suites.length, 2, JSON.stringify(suites));
    assert.equal(suites[0].label, "node --test");
    // pytest when it is installed here, and otherwise a check that could not run -- never skipped.
    assert.ok(suites[1].label === "pytest" || /pytest is not installed/.test(suites[1].unavailable), JSON.stringify(suites[1]));
  });
});

test("JavaScript tests with no package.json run under node's own runner", () => {
  run({ "math.test.mjs": PASSING_NODE }, (dir) => {
    assert.equal(detectSuite(dir).label, "node --test");
    const v = testExecutionReport(dir, { wanted: true });
    assert.ok(v.advisories.some((a) => /^tests: ran under node --test — 1 of 1 passed/.test(a)), JSON.stringify(v));
    assert.equal(v.couldNotRun, undefined);
  });
});

test("Go tests with no go.mod could not run, and say why", () => {
  run({ "add_test.go": "package main\nimport \"testing\"\nfunc TestAdd(t *testing.T) {}\n" }, (dir) => {
    assert.deepEqual(detectSuite(dir), { noRunner: true, unavailable: "the tests are Go and there is no go.mod, so go test cannot run them" });
    assert.deepEqual(testExecutionReport(dir, { wanted: true }).couldNotRun, ["the tests are Go and there is no go.mod, so go test cannot run them"]);
  });
});

const HANGS = {
  "package.json": "{}",
  "src/a.test.mjs": `
    import test from "node:test";
    test("hangs", async () => {
      await new Promise(() => { setInterval(() => {}, 1000); });
    });
  `,
};

test("the suite's limit is 120 seconds, or WOLFPROOF_TEST_TIMEOUT seconds", () => {
  assert.deepEqual(testTimeout({}), { ms: 120_000, seconds: 120, set: false });
  assert.deepEqual(testTimeout({ WOLFPROOF_TEST_TIMEOUT: "" }), { ms: 120_000, seconds: 120, set: false }, "empty is unset, as for every setting");
  assert.deepEqual(testTimeout({ WOLFPROOF_TEST_TIMEOUT: "300" }), { ms: 300_000, seconds: 300, set: true });
  assert.deepEqual(testTimeout({ WOLFPROOF_TEST_TIMEOUT: " 45 " }), { ms: 45_000, seconds: 45, set: true });
  for (const bad of ["0", "-5", "1.5", "120s", "2m", "abc", "0x10"]) {
    assert.match(testTimeout({ WOLFPROOF_TEST_TIMEOUT: bad }).error, /^WOLFPROOF_TEST_TIMEOUT is ".*", which is not a whole number of seconds$/, bad);
  }
  assert.equal(testTimeout({ AGENT_GATE_TEST_TIMEOUT: "300" }).seconds, 120, "only the WOLFPROOF_ name is read");
});

test("WOLFPROOF_TEST_TIMEOUT sets the limit a suite is killed at, and the report names it", () => {
  run(HANGS, (dir) => {
    const t0 = Date.now();
    const r = runTests(dir, { env: { ...process.env, WOLFPROOF_TEST_TIMEOUT: "2" } });
    assert.ok(Date.now() - t0 < 60_000, "killed at the setting's 2s, not the default 120s");
    assert.equal(r.timedOut, true);
    assert.match(r.unavailable, /did not finish within 2s and was killed, the limit WOLFPROOF_TEST_TIMEOUT sets$/);
  });
});

test("a WOLFPROOF_TEST_TIMEOUT that is not a number of seconds runs nothing and says why, rather than using the default", () => {
  run({ "package.json": "{}", "src/a.test.mjs": 'import test from "node:test"; test("ok", () => {});' }, (dir) => {
    const r = runTests(dir, { env: { ...process.env, WOLFPROOF_TEST_TIMEOUT: "5m" } });
    assert.equal(r.ran, false);
    assert.equal(r.environmental, true, "a setting of this machine, so could-not-run and not a finding against the project");
    assert.equal(r.unavailable, 'WOLFPROOF_TEST_TIMEOUT is "5m", which is not a whole number of seconds, so the suite was not run');
    const v = verdictFor(r);
    assert.deepEqual(v.failures, []);
    assert.deepEqual(v.couldNotRun, [r.unavailable]);
  });
});

test("without the setting a quick suite runs, and a caller's own limit is reported without naming the setting", () => {
  run({ "package.json": "{}", "src/a.test.mjs": 'import test from "node:test"; test("ok", () => {});' }, (dir) => {
    const env = { ...process.env };
    delete env.WOLFPROOF_TEST_TIMEOUT;
    assert.equal(runTests(dir, { env }).ran, true, "the default limit runs a quick suite");
  });
  run(HANGS, (dir) => {
    const r = runTests(dir, { timeoutMs: 2000 });
    assert.doesNotMatch(r.unavailable, /WOLFPROOF_TEST_TIMEOUT/, "an explicit limit from a caller is not the setting's to explain");
  });
});

// --- counter parsing, against each runner's real summary ------------------
// vitest's all-passing summary reported a nine-test suite as "1 of 1 passed": the anchored vitest
// pattern required a `N failed |` segment that was not there, so parsing fell through to the loose
// counter, which matched the "Test Files  1 passed (1)" line printed just above. An undercount that
// still says "passed" is the kind of wrong answer nobody goes looking for.
const E = "\u001B[";
const SUMMARIES = [
  ["vitest, all passing", " Test Files  1 passed (1)\n      Tests  9 passed (9)\n", { passed: 9, failed: 0, total: 9 }],
  ["vitest, with failures", " Test Files  1 failed (1)\n      Tests  3 failed | 6 passed (9)\n", { passed: 6, failed: 3, total: 9 }],
  ["vitest, coloured", `${E}2m Test Files ${E}22m ${E}32m1 passed${E}39m (1)\n${E}2m      Tests ${E}22m ${E}32m9 passed${E}39m (9)\n`, { passed: 9, failed: 0, total: 9 }],
  ["jest", "Tests:       3 failed, 9 passed, 12 total\n", { passed: 9, failed: 3, total: 12 }],
  ["node --test", "\u2139 tests 21\n\u2139 suites 0\n\u2139 pass 21\n\u2139 fail 0\n", { passed: 21, failed: 0, total: 21 }],
  ["pytest", "3 failed, 9 passed in 0.42s\n", { passed: 9, failed: 3, total: 12 }],
];

for (const [label, output, expected] of SUMMARIES) {
  test(`the ${label} summary is counted correctly`, () => {
    assert.deepEqual(parseCountsForTest(output), expected);
  });
}

// --- both reporter formats -------------------------------------------------
// `node --test` emits the spec format to a TTY and TAP to a pipe, and this code always reads a
// pipe, so which one arrives depends on the Node version rather than on anything here: 26 emits
// spec, 22 emits TAP. The gate ran on CI under Node 22 and printed "1 of 2 test(s) FAILED" followed
// by a sentence telling the reader to check the names above, with no names above.
test("a failing test is named in TAP output as well as spec", () => {
  const tap = [
    "TAP version 13",
    "# Subtest: a genuine callback is accepted",
    "ok 1 - a genuine callback is accepted",
    "# Subtest: a forged callback is rejected",
    "not ok 2 - a forged callback is rejected",
    "1..2",
    "# tests 2",
    "# pass 1",
    "# fail 1",
  ].join("\n");
  const names = failingNamesForTest(tap);
  assert.deepEqual(names, ["a forged callback is rejected"]);
});

test("a TAP file-level subtest path is not reported as a test name", () => {
  const tap = ["not ok 1 - src/a.test.mjs", "not ok 2 - a forged callback is rejected"].join("\n");
  assert.deepEqual(failingNamesForTest(tap), ["a forged callback is rejected"]);
});

test("the spec format still works", () => {
  assert.deepEqual(failingNamesForTest("\u2716 a forged callback is rejected (1.2ms)"), [
    "a forged callback is rejected",
  ]);
});

// A suite that exits non-zero without a parseable summary used to produce a finding carrying no
// evidence whatsoever: it told the reader to check the names above, and there were no names above,
// because nothing could be extracted. The output was captured the whole time and thrown away.
//
// Found on CI, where three Go deliverables reported "the suite exited 1 and its summary could not
// be parsed" and the log said nothing about why -- the difference between a test binary that would
// not compile and a deliverable that is actually wrong, invisible.
//
// Driven through verdictFor rather than a real project: reproducing this end to end means breaking
// a real toolchain in a specific way, and the thing under test is what the verdict does with a run
// that already happened.
test("an unparseable failure carries the runner's output as evidence", () => {
  const r = verdictFor({
    ran: true,
    label: "go test",
    exitCode: 1,
    counts: null,
    failing: [],
    output: "# webhook/store\nstore/dynamo.go:4:2: no required module provides package widgets/thing\n",
  });
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /summary could not be parsed/);
  assert.match(r.failures[0], /Output \(last lines/);
  assert.match(r.failures[0], /no required module provides package widgets\/thing/);
});

// The other half: when the summary DID parse, the failing names are the evidence and appending the
// whole transcript on top of them is noise.
test("a parseable failure does not append the transcript", () => {
  const r = verdictFor({
    ran: true,
    label: "node --test",
    exitCode: 1,
    counts: { passed: 9, failed: 3, total: 12 },
    failing: ["forged signature rejected"],
    output: "lots and lots of transcript",
  });
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /3 of 12 test\(s\) FAILED/);
  assert.match(r.failures[0], /forged signature rejected/);
  assert.doesNotMatch(r.failures[0], /Output \(last lines/);
});

// A run that never started is still an environment fact, not a finding.
test("a runner that could not start is advisory, not blocking", () => {
  const r = verdictFor({ ran: false, unavailable: "the tests are Python and pytest is not installed here" });
  assert.equal(r.failures.length, 0);
  assert.match(r.advisories[0], /NOT EXECUTED/);
});

// The distinction the Go fixtures exposed. A suite that could not be started produced an advisory
// and nothing else, so the run still exited clean and the corpus froze that as the verdict. Three
// deliverables recorded passing tests on a machine with no Go toolchain; their suites had never
// compiled. Not blocking -- the project is not at fault for this machine -- but not a pass either.
test("a suite that could not be started makes the run incomplete", () => {
  const r = verdictFor({
    ran: false,
    environmental: true,
    unavailable: "go test could not be started (spawn go ENOENT)",
  });
  assert.equal(r.failures.length, 0, "the project is not at fault for a missing toolchain");
  assert.equal(r.couldNotRun.length, 1, "but the run did not measure anything");
  assert.match(r.couldNotRun[0], /could not be started/);
});

test("a timed-out suite is also unmeasured rather than clean", () => {
  const r = verdictFor({
    ran: false,
    environmental: true,
    timedOut: true,
    unavailable: "node --test did not finish within 120s and was killed",
  });
  assert.equal(r.failures.length, 0);
  assert.equal(r.couldNotRun.length, 1);
});

// The other side: nothing was prevented from running, so nothing is unmeasured. A project with no
// test files has an answer -- it has no tests -- and calling that "could not run" would make every
// such project incomplete forever.
test("having no tests is an answer, not a failure to measure", () => {
  const r = verdictFor({ ran: false, unavailable: "no test files were found" });
  assert.equal(r.failures.length, 0);
  assert.ok(!r.couldNotRun || r.couldNotRun.length === 0);
});

// A runner the project declares and did not install stays blocking: that is the deliverable's own
// claim failing, not a fact about the machine.
test("a declared runner that is not installed still blocks", () => {
  const r = verdictFor({
    ran: false,
    declaredRunnerMissing: true,
    unavailable: "the suite is written for jest, which this project declares and did not install",
  });
  assert.equal(r.failures.length, 1);
  assert.ok(!r.couldNotRun || r.couldNotRun.length === 0);
});
