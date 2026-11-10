import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, symlinkSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { sourceCoverage, coverageLine, skippedCodeLine, skippedFilesLine } from "./coverage.mjs";

function cov(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "coverage-"));
  try {
    for (const [rel, body] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), body);
    }
    return sourceCoverage(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// The probe: a Rust project exited 0, and the only sign none of its code was read was one advisory
// among several.
test("a project written in a language nothing reads says so, loudly", () => {
  // Rust is read now (agent/sast-rules/rust.yaml), and PHP (php.yaml); Swift is the example of a
  // language nothing reads.
  const c = cov({ "Package.swift": "\n", "Sources/App/main.swift": "\n", "Sources/App/routes.swift": "\n" });
  assert.deepEqual(c.unread, [{ language: "Swift", files: 3 }]);
  assert.equal(c.mostlyUnread, true);
  assert.match(coverageLine(c), /^MOST OF THIS PROJECT'S SOURCE WAS NOT READ: 3 Swift file\(s\), against 0/);
});

test("a minority of unread files is still named, without the capitals", () => {
  const c = cov({ "app.py": "\n", "server.py": "\n", "jobs/Main.scala": "\n" });
  assert.equal(c.mostlyUnread, false);
  assert.match(coverageLine(c), /^1 Scala file\(s\) were not read/);
});

test("a project entirely in languages the checks read gets no line", () => {
  assert.equal(coverageLine(cov({ "index.js": "\n", "app.py": "\n", "main.tf": "\n", "run.sh": "\n" })), null);
});

test("installed dependencies are not the project's source; vendored code is", () => {
  const c = cov({ "index.js": "\n", "node_modules/native/binding.swift": "\n", "vendor/x.swift": "\n" });
  assert.deepEqual(c.unread, [{ language: "Swift", files: 1 }]);
});

test("languages the injection rules read are not called unread", () => {
  const c = cov({ "main.rs": "\n", "Program.cs": "\n", "server.c": "\n", "lib.cpp": "\n", "App.jsx": "\n", "index.php": "\n", "Main.kt": "\n" });
  assert.deepEqual(c.unread, []);
  assert.equal(coverageLine(c), null);
});

// A 545 KB server.js with two open admin routes: the checks that read source skipped it, four of
// them said the project had no source files, and the gate passed. The limit is each walker's; this
// is where it is said. A code file is the gate's could-not-run entry (skippedCodeLine), not a line.
test("a code file over the size limit, or one that cannot be read, is named as skipped code", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "coverage-"));
  try {
    writeFileSync(path.join(dir, "index.js"), "\n");
    writeFileSync(path.join(dir, "big.js"), Buffer.alloc(600 * 1024, 0x20));
    writeFileSync(path.join(dir, "notes.md"), Buffer.alloc(600 * 1024, 0x20));
    const root = process.getuid?.() === 0;
    if (!root) {
      writeFileSync(path.join(dir, "secret.py"), "\n");
      chmodSync(path.join(dir, "secret.py"), 0o000);
    }
    const c = sourceCoverage(dir);
    assert.deepEqual(c.skipped, [
      { file: "big.js", bytes: 600 * 1024, why: "over the 512 KB limit", code: true, readBy: "injection" },
      ...(root ? [] : [{ file: "secret.py", bytes: 1, why: "not readable (EACCES)", code: true, readBy: null }]),
    ]);
    // Not counted as read, and a file no check reads is not counted at all.
    assert.equal(c.readFiles, 1);
    assert.deepEqual(c.unread, []);
    // Code is not the line above the verdict; it is the could-not-run entry.
    assert.equal(coverageLine(c), null);
    assert.equal(skippedFilesLine(c), null);
    const line = skippedCodeLine(c);
    assert.match(line, /^\d code file\(s\) were not read by the checks that read their language: big\.js \(600 KB, over the 512 KB limit; within injection's 1 MB\)/);
    if (!root) assert.match(line, /secret\.py \(not readable \(EACCES\)\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// "Every check that reads source skipped them" was the sentence, and between 512 KB and 1 MB it was
// untrue: injection reads to 1 MB. The sentence names who stops where, and each file says whether
// injection read it.
test("the sentence says which checks skipped a file, and which read it", () => {
  const c = cov({
    "between.js": Buffer.alloc(600 * 1024, 0x20),
    "beyond.js": Buffer.alloc(1100 * 1024, 0x20),
    "view.jsx": Buffer.alloc(600 * 1024, 0x20),
  });
  assert.deepEqual(c.skipped.map((s) => [s.file, s.why, s.readBy]), [
    ["between.js", "over the 512 KB limit", "injection"],
    ["beyond.js", "over the 512 KB limit", null],
    ["view.jsx", "over the 512 KB limit", "injection"],
  ]);
  const line = skippedCodeLine(c);
  assert.match(line, /between\.js \(600 KB, over the 512 KB limit; within injection's 1 MB\)/);
  assert.match(line, /beyond\.js \(1100 KB, over the 512 KB limit\)/);
  assert.match(line, /Authentication, code quality, immutability, retention, secret rotation, the manifest contract and the test check stop at 512 KB; injection reads up to 1 MB and is the only check that reads C and C\+\+\./);
  assert.doesNotMatch(line, /Every check/);
});

// Injection is the only check that reads C and C++, and it reads to 1 MB: a 700 KB C file was read
// by everything that reads C. The first version of the list named it as skipped.
test("a C file is skipped only over injection's limit, the one limit that applies to it", () => {
  const c = cov({ "ok.c": Buffer.alloc(700 * 1024, 0x20), "ok.hpp": Buffer.alloc(900 * 1024, 0x20), "huge.c": Buffer.alloc(1100 * 1024, 0x20) });
  assert.deepEqual(c.skipped, [{ file: "huge.c", bytes: 1100 * 1024, why: "over the 1 MB limit", code: true, readBy: null }]);
  assert.equal(c.readFiles, 2);
  assert.match(skippedCodeLine(c), /huge\.c \(1100 KB, over the 1 MB limit\)/);
});

// The review's repro: a 624 KB pnpm-lock.yaml was "of a kind the checks read ... the verdict says
// nothing about that code", and factory mode exited 3 on every run. The dependency scanner reads
// that file, at any size.
test("a lockfile the dependency scanner reads is not listed, whatever its size", () => {
  const c = cov({
    "package.json": "{}\n",
    "pnpm-lock.yaml": Buffer.alloc(624 * 1024, 0x20),
    "web/pnpm-lock.yaml": Buffer.alloc(2 * 1024 * 1024, 0x20),
  });
  assert.deepEqual(c.skipped, []);
  assert.equal(coverageLine(c), null);
  assert.equal(skippedCodeLine(c), null);
  // Its name is what exempts it, not its extension: another YAML file that size is still named.
  const other = cov({ "pnpm-lock.yaml": Buffer.alloc(624 * 1024, 0x20), "pnpm-lock.backup.yaml": Buffer.alloc(624 * 1024, 0x20) });
  assert.deepEqual(other.skipped.map((s) => s.file), ["pnpm-lock.backup.yaml"]);
});

test("data and configuration over the limit stay a line above the verdict, and are not code", () => {
  const c = cov({
    "index.js": "\n",
    "k8s/values.yaml": Buffer.alloc(600 * 1024, 0x20),
    "db/seed.sql": Buffer.alloc(700 * 1024, 0x20),
    "infra/big.tf": Buffer.alloc(600 * 1024, 0x20),
  });
  assert.deepEqual(c.skipped.map((s) => [s.file, s.code, s.readBy]), [
    ["db/seed.sql", false, null],
    ["infra/big.tf", false, null],
    ["k8s/values.yaml", false, null],
  ]);
  assert.equal(skippedCodeLine(c), null);
  const line = coverageLine(c);
  assert.match(line, /^3 file\(s\) of a kind the checks read were not read: db\/seed\.sql \(700 KB, over the 512 KB limit\), infra\/big\.tf \(600 KB, over the 512 KB limit\), k8s\/values\.yaml \(600 KB, over the 512 KB limit\)\./);
  assert.match(line, /Immutability, retention, the Kubernetes manifest check and the IAM and manifest contracts read YAML, SQL and Terraform up to 512 KB/);
  assert.doesNotMatch(line, /Every check|that code/);
});

// Mastodon's public/sw.js: a link to a file the build writes. A walker that follows links met it
// and moved on, so it is named; there is no code behind it, so it is not could-not-run.
test("a link to a file that is not there is named, and is not code that went unread", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "coverage-"));
  try {
    writeFileSync(path.join(dir, "index.js"), "\n");
    symlinkSync(path.join(dir, "packs", "sw.js"), path.join(dir, "sw.js"));
    const c = sourceCoverage(dir);
    assert.deepEqual(c.skipped, [{ file: "sw.js", bytes: null, why: "a symbolic link to a file that is not there", code: false, readBy: null }]);
    assert.equal(skippedCodeLine(c), null);
    assert.match(coverageLine(c), /^1 file\(s\) of a kind the checks read were not read: sw\.js \(a symbolic link to a file that is not there\)\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a project whose files are all under the limit has nothing skipped", () => {
  const c = cov({ "index.js": "\n", "app.py": "\n" });
  assert.deepEqual(c.skipped, []);
  assert.equal(coverageLine(c), null);
});
