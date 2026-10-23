// Reading a project's source, shared by the checks that scan it.
//
// Extracted rather than copied. This file's neighbours have twice paid for a duplicated definition:
// two credential word lists in authentication.mjs drifted until one learned `authorization` and the
// other did not, and immutability.mjs briefly carried two answers to "what is a comment". A check
// that reads a different set of files, or strips a different set of lines, from the check beside it
// gives two verdicts about one project and no way to tell which is right.
import { readdirSync, readFileSync, statSync } from "fs";
import path from "path";

import { SKIP_DIRS } from "./skip-dirs.mjs";
import { isDeclaredFixture } from "./fixture-markers.mjs";

// .go, .rb and .java were absent once, so a check could not read a Go deliverable's source at all —
// it reported a project that HAD its control as having none, and no amount of fixing the pattern
// would have helped because the file was never opened. The language list must track the languages
// the loop can actually build.
export const READ_EXT = new Set([
  ".py", ".sql", ".tf", ".tfvars", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rb", ".java",
  ".yaml", ".yml",
]);

const MAX_FILE_BYTES = 512 * 1024;

// Test files, defined once for the two checks that ask about them: code quality (are there tests that
// assert something) and the tests check (are there tests to run). Each used to keep its own pattern,
// and neither knew Maven's src/test/java: a Java project with tests was blocked for having none, and a
// PHP project's tests/ was "no test files were found". This is the union of both old patterns, plus
// the conventions of the languages the injection rules read.
//
// The extensions include every READ_EXT, so nothing either check found before is lost.
export const TEST_EXT = new Set([...READ_EXT, ".jsx", ".kt", ".cs", ".rs", ".php"]);
// A test/, tests/, spec/ or __tests__ path segment (Maven's src/test/java, .NET's MyApp.Tests/), or a
// file named the JavaScript, Python, Go or Ruby way.
const TEST_PATH = /(^|[\/._-])(tests?|spec|__tests__)([\/._-]|$)|_test\.(py|go|js|mjs|ts|rb)$|\.(test|spec)\.(m|c)?(js|ts)x?$/i;
// JVM, .NET and PHP test classes, by their name. Case-sensitive: Latest.java is not a test.
const TEST_CLASS = /(^|\/)(\w*(Test|Tests|IT)|\w+Spec)\.(java|kt|cs|php)$|(^|\/)Test[A-Z]\w*\.(java|kt|cs|php)$/;
// Rust keeps unit tests in the file they test, under #[cfg(test)].
const RUST_TEST = /#\[(?:tokio::|async_std::)?test\]/;

// Where package managers and builds put other people's code: Composer's and Bundler's vendor/,
// .bundle/, and Maven's and Cargo's target/. A Ruby project whose gems Bundler installed into
// vendor/bundle had Minitest's own 379 tests found as its own, and run. Not bin/: .NET builds .dll files
// there, and this repository's own tests live in one.
const DEPENDENCY_DIR = /(^|\/)(vendor|\.bundle|target)\//;

/** Whether `rel` is a test file. `text` is needed only for Rust, whose tests are named by attribute. */
export function isTestFile(rel, text = "") {
  if (DEPENDENCY_DIR.test(rel)) return false;
  return TEST_PATH.test(rel) || TEST_CLASS.test(rel) || (rel.endsWith(".rs") && RUST_TEST.test(text));
}

/** Every readable source file under `dir` with one of `exts`, as [{ rel, text }]. */
export function walk(dir, acc = [], root = dir, exts = READ_EXT) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      // A declared fixture is deliberately unrepresentative; see fixture-markers.mjs.
      if (!SKIP_DIRS.has(e.name) && !isDeclaredFixture(full)) walk(full, acc, root, exts);
    } else if (exts.has(path.extname(e.name))) {
      try {
        if (statSync(full).size <= MAX_FILE_BYTES) {
          acc.push({ rel: path.relative(root, full), text: readFileSync(full, "utf8") });
        }
      } catch {
        /* unreadable is not a check's problem to report */
      }
    }
  }
  return acc;
}

// Drops whole-line comments only. A line-anywhere stripper would cut at the `//` inside a URL and
// could remove real code sitting after it; the case this exists for -- a commented-out terraform
// setting read as a live one -- is always a leading marker.
export function uncommented(text) {
  return text
    .split("\n")
    .filter((l) => !/^\s*(?:#|\/\/|\*|--)/.test(l))
    .join("\n");
}

export function firstMatch(re, text) {
  const m = re.exec(text);
  return m ? m[0] : null;
}
