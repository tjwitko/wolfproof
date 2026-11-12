// lib/tool-on-path.mjs: what is on PATH under a name, read without starting anything. The three
// checkov checks use it after a start fails with ENOENT (lib/checkov-starts.test.mjs has them).
import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { entryOnPath, presentNotStarted } from "./tool-on-path.mjs";

function withDirs(n, fn) {
  const dirs = Array.from({ length: n }, () => mkdtempSync(path.join(tmpdir(), "tool-on-path-")));
  try {
    return fn(dirs, { PATH: dirs.join(path.delimiter) });
  } finally {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }
}

test("nothing on PATH with the name: no entry, and not 'present'", () => {
  withDirs(2, (dirs, env) => {
    writeFileSync(path.join(dirs[0], "checkov-other"), "");
    assert.equal(entryOnPath("checkov", env), null);
    assert.equal(presentNotStarted("checkov", env), null);
  });
  assert.equal(entryOnPath("checkov", { PATH: "" }), null);
  assert.equal(entryOnPath("checkov", {}), null);
  assert.equal(entryOnPath("checkov", { PATH: "/no/such/directory:/dev/null" }), null);
});

test("the first entry on PATH is the one named, and a directory of that name is not an entry", () => {
  withDirs(3, (dirs, env) => {
    mkdirSync(path.join(dirs[0], "checkov"));
    writeFileSync(path.join(dirs[1], "checkov"), "#!/opt/gone/python3\n", { mode: 0o755 });
    writeFileSync(path.join(dirs[2], "checkov"), "#!/bin/sh\n", { mode: 0o755 });
    assert.equal(entryOnPath("checkov", env), path.join(dirs[1], "checkov"));
    assert.equal(presentNotStarted("checkov", env), `${path.join(dirs[1], "checkov")} is on PATH and could not be started: its #! line names /opt/gone/python3, which does not exist`);
  });
});

test("why it did not start, where the file shows it: a #! interpreter that is gone, a link to nothing", () => {
  withDirs(1, ([dir], env) => {
    const file = path.join(dir, "checkov");
    symlinkSync("/opt/gone/venv/bin/checkov", file);
    assert.equal(presentNotStarted("checkov", env), `${file} is on PATH and could not be started: it is a link to /opt/gone/venv/bin/checkov, which does not exist`);
  });
  withDirs(1, ([dir], env) => {
    writeFileSync(path.join(dir, "checkov"), "#! /opt/gone/python3 -I\nimport checkov\n", { mode: 0o755 });
    assert.match(presentNotStarted("checkov", env), /its #! line names \/opt\/gone\/python3, which does not exist$/);
  });
});

// The caller is here because a start failed with ENOENT. When the file does not show why (its
// interpreter exists, it has no #! line, it cannot be read), the entry is still named: it is there,
// which is the thing "not installed" got wrong.
test("an entry whose file does not show the reason is still present, with the general reason", () => {
  for (const [content, mode] of [["#!/bin/sh\n", 0o755], ["\x7fELF\x02\x01\x01", 0o755], ["", 0o755], ["#!/bin/sh\n", 0o000]]) {
    withDirs(1, ([dir], env) => {
      const file = path.join(dir, "checkov");
      writeFileSync(file, content);
      chmodSync(file, mode);
      assert.equal(presentNotStarted("checkov", env), `${file} is on PATH and could not be started: the system could not start it (ENOENT)`);
    });
  }
});
