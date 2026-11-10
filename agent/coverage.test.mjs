import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { sourceCoverage, coverageLine } from "./coverage.mjs";

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

// A 545 KB server.js with two open admin routes: every check that reads source skipped it, four of
// them said the project had no source files, and the gate passed. The limit is each walker's; this
// is where it is said.
test("a source file over the size limit, or one that cannot be read, is named as skipped", () => {
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
      { file: "big.js", bytes: 600 * 1024, why: "over the 512 KB limit" },
      ...(root ? [] : [{ file: "secret.py", bytes: 1, why: "not readable (EACCES)" }]),
    ]);
    // Not counted as read, and a file no check reads is not counted at all.
    assert.equal(c.readFiles, 1);
    assert.deepEqual(c.unread, []);
    assert.match(coverageLine(c), /^\d file\(s\) of a kind the checks read were not read: big\.js \(600 KB, over the 512 KB limit\)/);
    assert.match(coverageLine(c), /the checks say "no source files" when these were the only ones\.$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a project whose files are all under the limit has nothing skipped", () => {
  const c = cov({ "index.js": "\n", "app.py": "\n" });
  assert.deepEqual(c.skipped, []);
  assert.equal(coverageLine(c), null);
});
