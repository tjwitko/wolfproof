// Test runners for Java and Kotlin (Maven, Gradle), C# (dotnet test), Rust (cargo test), PHP (PHPUnit,
// Pest) and Ruby (RSpec, Minitest). Until these existed a suite in any of those languages was found and
// not run, and a task asking for tests was exit 3.
//
// Every runner here works offline, against dependencies the project's own CI already installed: mvn -o,
// gradle --offline, dotnet test --no-restore, cargo --offline, vendor/bin/phpunit, bundle exec. This
// check does not install dependencies for JavaScript either (npm install runs arbitrary postinstall
// hooks), and these ecosystems go further: a Maven plugin, a crate's build.rs and an MSBuild target all
// run code at build time. Fetching them here would run third-party code chosen by the project under
// test, at gate time. So a dependency that is not already installed is a check that could not run, with
// the install step named -- the same contract as `npm ci` before the gate.
//
// Nor does it run a command the project authored: never ./gradlew, which downloads whatever Gradle the
// project's wrapper names, and never rake or bin/rails, which run the project's own task definitions.
//
// Each suite carries:
//   parser       which summary format to read (COUNTS, FAILING below)
//   missingDeps  output that means the dependencies were not installed, and the step that installs them
//   countsFrom   for Gradle, which prints no counts when everything passes: its JUnit XML reports
// and every one requires a summary. Measured on a solution whose packages were never restored,
// `dotnet test --no-restore` built nothing, ran nothing and exited 0 with no output: a run that names no
// test is a run that could not be judged, never a pass.
import { existsSync, readdirSync, readFileSync } from "fs";
import path from "path";
import { spawnSync } from "child_process";

const has = (projectDir, file) => existsSync(path.join(projectDir, file));

function rootFiles(projectDir, re) {
  try {
    return readdirSync(projectDir).filter((f) => re.test(f));
  } catch {
    return [];
  }
}

/** Whether `cmd` starts. Run only when there are tests that need it. */
function installed(cmd, args = ["--version"], env) {
  const r = spawnSync(cmd, args, { encoding: "utf8", env, timeout: 60_000 });
  return !r.error && r.status === 0;
}

const DOTNET_ENV = { DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE: "1" };

const list = (files) => `${files.slice(0, 3).map((f) => f.rel).join(", ")}${files.length > 3 ? `, +${files.length - 3} more` : ""}`;

/** Java and Kotlin: Maven when there is a pom.xml, Gradle when there is a build.gradle. */
export function jvmSuites(projectDir, files, language) {
  if (has(projectDir, "pom.xml")) {
    if (!installed("mvn", ["-v"])) {
      return [{ environmental: true, unavailable: `the tests are ${language} and Maven is not installed here (mvn is not on PATH)` }];
    }
    return [
      {
        label: "mvn test",
        cmd: "mvn",
        args: ["-B", "-o", "test"],
        cwd: projectDir,
        parser: "maven",
        missingDeps: {
          re: /could not be resolved|Cannot access \S+ in offline mode|offline mode and the artifact/i,
          fix: "install them before the gate, for example with `mvn -B test-compile` or `mvn -B dependency:go-offline` " +
            "in the same job (go-offline alone can miss the test provider)",
        },
      },
    ];
  }
  if (has(projectDir, "build.gradle") || has(projectDir, "build.gradle.kts")) {
    if (!installed("gradle", ["--version"])) {
      return [{ environmental: true, unavailable: `the tests are ${language} and Gradle is not installed here (gradle is not on PATH)` }];
    }
    return [
      {
        label: "gradle test",
        cmd: "gradle",
        // --rerun: an up-to-date test task runs nothing. --no-daemon: a gate run leaves no process behind.
        args: ["test", "--offline", "--rerun", "--no-daemon", "--console=plain"],
        cwd: projectDir,
        parser: "gradle",
        countsFrom: gradleReports,
        missingDeps: {
          re: /No cached version of \S+ available for offline mode|was not found in any of the following sources|Could not resolve (all|plugin)/i,
          fix: "install them before the gate, for example with `gradle --no-daemon testClasses` in the same job",
        },
      },
    ];
  }
  return [{ noRunner: true, unavailable: `the tests are ${language} (${list(files)}) and there is no pom.xml or build.gradle, so nothing says how to build them` }];
}

/** Sums the JUnit XML reports Gradle writes, which carry counts when the console does not. */
function gradleReports(projectDir) {
  const totals = { passed: 0, failed: 0, total: 0, names: [] };
  let found = false;
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules" || e.name === ".git" || e.name === ".gradle") continue;
        walk(full, depth + 1);
      } else if (/^TEST-.*\.xml$/.test(e.name) && full.includes(`${path.sep}test-results${path.sep}`)) {
        const xml = readFileSync(full, "utf8");
        const suite = /<testsuite\b[^>]*>/.exec(xml);
        if (!suite) continue;
        const attr = (n) => +((new RegExp(`\\b${n}="(\\d+)"`).exec(suite[0]) || [])[1] || 0);
        const tests = attr("tests");
        const failed = attr("failures") + attr("errors");
        const skipped = attr("skipped");
        found = true;
        totals.total += tests;
        totals.failed += failed;
        totals.passed += tests - failed - skipped;
        for (const m of xml.matchAll(/<testcase\b[^>]*\bname="([^"]*)"[^>]*\bclassname="([^"]*)"[^>]*>\s*<(failure|error)\b/g)) {
          totals.names.push(`${m[2]} > ${m[1]}`);
        }
      }
    }
  };
  walk(projectDir, 0);
  return found ? totals : null;
}

/** C#: the solution at the root, or else each test project. */
export function dotnetSuites(projectDir, files) {
  if (!installed("dotnet", ["--version"], { ...process.env, ...DOTNET_ENV })) {
    return [{ environmental: true, unavailable: "the tests are C# and the .NET SDK is not installed here (dotnet is not on PATH)" }];
  }
  const suite = (target) => ({
    label: `dotnet test${target ? ` ${target}` : ""}`,
    cmd: "dotnet",
    args: ["test", ...(target ? [target] : []), "--no-restore"],
    cwd: projectDir,
    env: DOTNET_ENV,
    parser: "dotnet",
    missingDeps: {
      re: /NETSDK1004|project\.assets\.json' not found|Run a NuGet package restore/i,
      fix: "restore them before the gate with `dotnet restore` in the same job",
    },
    // Without restored packages a test project is not recognised as one, and the run builds, tests
    // nothing and exits 0 with no output. Said here, because "no summary" alone does not say why.
    noSummaryHint: unrestored(projectDir) ? "; obj/project.assets.json is missing, so the packages were never restored -- run `dotnet restore` first" : "",
  });
  const solutions = rootFiles(projectDir, /\.slnx?$/);
  if (solutions.length === 1) return [suite(solutions[0])];
  const rootProjects = rootFiles(projectDir, /\.csproj$/);
  if (rootProjects.length === 1) return [suite(rootProjects[0])];
  // Each test project, found from the test files: the nearest .csproj above each.
  const projects = new Set();
  for (const f of files) {
    let dir = path.dirname(path.join(projectDir, f.rel));
    while (dir.startsWith(projectDir)) {
      const csproj = rootFiles(dir, /\.csproj$/);
      if (csproj.length) {
        projects.add(path.relative(projectDir, path.join(dir, csproj[0])));
        break;
      }
      if (dir === projectDir) break;
      dir = path.dirname(dir);
    }
  }
  if (projects.size) return [...projects].sort().map(suite);
  return [{ noRunner: true, unavailable: `the tests are C# (${list(files)}) and there is no .sln, .slnx or .csproj to build them with` }];
}

function unrestored(projectDir) {
  const csprojDirs = [];
  const walk = (dir, depth) => {
    if (depth > 4) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (entries.some((e) => e.isFile() && e.name.endsWith(".csproj"))) csprojDirs.push(dir);
    for (const e of entries) {
      if (e.isDirectory() && !["bin", "obj", "node_modules", ".git"].includes(e.name)) walk(path.join(dir, e.name), depth + 1);
    }
  };
  walk(projectDir, 0);
  return csprojDirs.length > 0 && csprojDirs.some((d) => !existsSync(path.join(d, "obj", "project.assets.json")));
}

/** Rust: cargo at the root, every test binary run (--no-fail-fast) even after one fails. */
export function cargoSuites(projectDir, files) {
  if (!has(projectDir, "Cargo.toml")) {
    return [{ noRunner: true, unavailable: `the tests are Rust (${list(files)}) and there is no Cargo.toml, so cargo test cannot run them` }];
  }
  if (!installed("cargo", ["--version"])) {
    return [{ environmental: true, unavailable: "the tests are Rust and cargo is not installed here" }];
  }
  return [
    {
      label: "cargo test",
      cmd: "cargo",
      args: ["test", "--offline", "--no-fail-fast"],
      cwd: projectDir,
      env: { CARGO_TERM_COLOR: "never" },
      parser: "cargo",
      missingDeps: {
        re: /no matching package named|failed to download|attempting to make an HTTP request, but --offline/i,
        fix: "fetch them before the gate with `cargo fetch` in the same job",
      },
    },
  ];
}

/** PHP: the runner composer.json declares, as installed in vendor/. */
export function phpSuites(projectDir, files) {
  if (!has(projectDir, "composer.json")) {
    return [{ noRunner: true, unavailable: `the tests are PHP (${list(files)}) and there is no composer.json, so nothing says which runner they need` }];
  }
  let composer = {};
  try {
    composer = JSON.parse(readFileSync(path.join(projectDir, "composer.json"), "utf8"));
  } catch {
    return [{ noRunner: true, unavailable: "composer.json could not be parsed, so no runner could be identified" }];
  }
  const deps = { ...(composer.require || {}), ...(composer["require-dev"] || {}) };
  const runner = deps["pestphp/pest"] ? "pest" : deps["phpunit/phpunit"] ? "phpunit" : null;
  if (!runner) return [{ noRunner: true, unavailable: "composer.json declares neither phpunit/phpunit nor pestphp/pest, so no runner could be identified" }];
  if (!installed("php", ["--version"])) {
    return [{ environmental: true, unavailable: "the tests are PHP and php is not installed here" }];
  }
  const bin = path.join("vendor", "bin", runner);
  if (!has(projectDir, bin)) {
    // As for a JavaScript runner package.json declares and node_modules lacks: the project's own
    // manifest names it, and nobody can run the tests as delivered.
    return [
      {
        declaredRunnerMissing: true,
        unavailable:
          `the suite is written for ${runner}, which this project declares in composer.json and which is not installed -- ` +
          `${bin} does not exist. Run \`composer install\` before the gate (dependencies are deliberately not installed by ` +
          `this check) and make sure the suite passes`,
      },
    ];
  }
  return [{ label: runner, cmd: "php", args: [bin, "--colors=never"], cwd: projectDir, parser: runner }];
}

/** Ruby: RSpec for *_spec.rb, Minitest for the rest, through Bundler when there is a Gemfile. */
export function rubySuites(projectDir, files) {
  const specs = files.filter((f) => /_spec\.rb$/.test(f.rel));
  const tests = files.filter((f) => !/_spec\.rb$/.test(f.rel) && /(^|\/)(test_[^/]*|[^/]*_test)\.rb$/.test(f.rel));
  if (!specs.length && !tests.length) return [{ noRunner: true, unavailable: `the tests are Ruby (${list(files)}) and none is named for RSpec or Minitest` }];
  const bundled = has(projectDir, "Gemfile");
  const tool = bundled ? "bundle" : specs.length ? "rspec" : "ruby";
  if (!installed(tool, ["--version"])) {
    return [{ environmental: true, unavailable: `the tests are Ruby and ${tool} is not installed here` }];
  }
  const missingDeps = {
    re: /Install missing gem executables with `bundle install`|Could not find .* in locally installed gems|Bundler::GemNotFound|run `bundle install`/i,
    fix: "install them before the gate with `bundle install` in the same job",
  };
  const via = (args) => (bundled ? { cmd: "bundle", args: ["exec", ...args] } : { cmd: args[0], args: args.slice(1) });
  const suites = [];
  if (specs.length) suites.push({ label: "rspec", ...via(["rspec", "--no-color"]), cwd: projectDir, parser: "rspec", missingDeps });
  if (tests.length) {
    // Each file loaded directly: rake test and bin/rails test run the project's own task definitions.
    const load = "ARGV.each { |f| require File.expand_path(f) }";
    suites.push({ label: "minitest", ...via(["ruby", "-Ilib", "-Itest", "-e", load, ...tests.map((f) => f.rel)]), cwd: projectDir, parser: "minitest", missingDeps });
  }
  return suites;
}

// Each runner's own summary, read before the shared patterns: those were written for the JavaScript and
// Python runners, and pytest's loose "N passed" reads cargo's "test result: FAILED. 2 passed; 1 failed"
// as two passed and nothing failed. Every format below was taken from a real run.
export const COUNTS = {
  // "[ERROR] Tests run: 2, Failures: 1, Errors: 0, Skipped: 0" -- the totals line, without the "-- in"
  // of the per-class line; one per module, so summed.
  maven: (out) => sum(out, /^\[(?:INFO|ERROR|WARNING)\] Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)\s*$/gm,
    (m) => ({ total: +m[1], failed: +m[2] + +m[3], passed: +m[1] - +m[2] - +m[3] - +m[4] })),
  // "2 tests completed, 1 failed" -- only when something failed; the XML reports otherwise.
  gradle: (out) => sum(out, /^(\d+) tests? completed, (\d+) failed/gm, (m) => ({ total: +m[1], failed: +m[2], passed: +m[1] - +m[2] })),
  // "Failed!  - Failed:     1, Passed:     1, Skipped:     0, Total:     2" -- one per test project.
  dotnet: (out) => sum(out, /(?:Passed|Failed)!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+),\s+Skipped:\s+(\d+),\s+Total:\s+(\d+)/g,
    (m) => ({ failed: +m[1], passed: +m[2], total: +m[4] })),
  // "test result: FAILED. 0 passed; 1 failed; 0 ignored" -- one per test binary, doc tests included.
  cargo: (out) => sum(out, /^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored/gm,
    (m) => ({ passed: +m[1], failed: +m[2], total: +m[1] + +m[2] + +m[3] })),
  // "OK (2 tests, 2 assertions)", or "Tests: 2, Assertions: 2, Failures: 1." with Errors when any.
  phpunit: (out) => {
    const ok = /^OK \((\d+) tests?, \d+ assertions?\)/m.exec(out);
    if (ok) return { total: +ok[1], failed: 0, passed: +ok[1] };
    const m = /^Tests: (\d+), Assertions: \d+(?:, Errors: (\d+))?(?:, Failures: (\d+))?/m.exec(out);
    if (!m) return null;
    const failed = +(m[2] || 0) + +(m[3] || 0);
    return { total: +m[1], failed, passed: +m[1] - failed };
  },
  // "Tests:    1 failed, 1 passed (2 assertions)"
  pest: (out) => {
    const m = /^\s*Tests:\s+(?:(\d+) failed,?\s*)?(?:(\d+) skipped,?\s*)?(?:(\d+) passed)?\s*\(\d+ assertions?\)/m.exec(out);
    return m ? { failed: +(m[1] || 0), passed: +(m[3] || 0), total: +(m[1] || 0) + +(m[2] || 0) + +(m[3] || 0) } : null;
  },
  // "2 examples, 1 failure" (", 1 pending" when any)
  rspec: (out) => {
    const m = /^(\d+) examples?, (\d+) failures?/m.exec(out);
    return m ? { total: +m[1], failed: +m[2], passed: +m[1] - +m[2] } : null;
  },
  // "2 runs, 2 assertions, 1 failures, 0 errors, 0 skips"
  minitest: (out) => {
    const m = /^(\d+) runs, \d+ assertions, (\d+) failures, (\d+) errors/m.exec(out);
    return m ? { total: +m[1], failed: +m[2] + +m[3], passed: +m[1] - +m[2] - +m[3] } : null;
  },
};

function sum(out, re, map) {
  let acc = null;
  for (const m of out.matchAll(re)) {
    const c = map(m);
    acc = acc ? { total: acc.total + c.total, failed: acc.failed + c.failed, passed: acc.passed + c.passed } : c;
  }
  return acc;
}

// Failing test names, per runner, each from a real run's output.
export const FAILING = {
  maven: /^\[ERROR\] (\S+) -- Time elapsed: .*<<< (?:FAILURE|ERROR)!/gm, // app.AddTest.adds
  gradle: /^(\S.*? > \S.*?) FAILED$/gm, // AddTest > adds() FAILED
  dotnet: /^\s*Failed (\S+) \[/gm, // Failed AddTests.Adds [1 ms]
  cargo: /^test (\S+) \.\.\. FAILED$/gm, // test adds ... FAILED
  phpunit: /^\d+\) (\S+::\S+)/gm, // 1) AddTest::testAdds
  pest: /^\s*FAILED\s+(.+?)\s*$/gm, // FAILED  Tests\AddTest > adds
  rspec: /^rspec \S+ # (.+)$/gm, // rspec ./spec/add_spec.rb:3 # add adds
  minitest: /^(\w[\w:]*#\w+) \[/gm, // AddTest#test_adds [test/add_test.rb:4]:
};
