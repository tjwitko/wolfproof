import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");

// secret-guard from v1.0.4 says what gitleaks walked past, and a scan that found nothing and left
// something unread is an error. The gate sets that aside for one thing only: a directory it could
// not list itself and git ignores, which it reports in a line above the verdict (a container's bind
// mount; agent/coverage.mjs). Everything else the scanner did not read is exit 3, and names it.
//
// These run the real CLI with the real secret-guard and gitleaks, because an exit code is a
// property of a process. Mode 000 stands in for a file or directory another user owns.

const asRoot = process.getuid?.() === 0 && "root reads every file";

function cli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000 });
  let doc = null;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    /* not --json, or it did not get that far */
  }
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "", doc };
}

/** A git repository in a temporary directory. `lock` makes a path mode 000 until `done`. */
function repo() {
  const dir = mkdtempSync(path.join(tmpdir(), "scan-unread-cli-"));
  const locked = [];
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  };
  git("init", "-q");
  const self = {
    dir,
    write(rel, text) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), text);
      return self;
    },
    commit(message) {
      git("add", "-A");
      git("commit", "-qm", message);
      return self;
    },
    lock(rel) {
      chmodSync(path.join(dir, rel), 0o000);
      locked.push([path.join(dir, rel), rel]);
      return self;
    },
    unlock(rel, mode) {
      chmodSync(path.join(dir, rel), mode);
      return self;
    },
    done() {
      for (const [p] of locked) chmodSync(p, 0o755);
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return self;
}

const scanLines = (doc) => (doc?.couldNotRun || []).filter((c) => c.startsWith("scan_path"));
const failures = (doc) => (doc?.findings || []).map((f) => f.message);
const secretGuard = (doc) => doc.controls.find((c) => c.name === "secret-guard");

test("an ignored directory that cannot be listed, beside a tracked file that cannot be read: exit 3, naming the file", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write("notes.txt", "nothing to see\n").write(".gitignore", "data/\n").commit("base");
    r.write("data/postgres/pg.js", "const x = 1;\n").lock("data/postgres");

    // The directory alone is the line above the verdict, in both modes: the scan counts as run.
    for (const mode of [[], ["--factory", "--base=HEAD"]]) {
      const ok = cli([r.dir, "--json", ...mode]);
      assert.equal(ok.code, 0, `${mode.join(" ")} exit ${ok.code}; couldNotRun: ${JSON.stringify(ok.doc?.couldNotRun)}; failures: ${JSON.stringify(failures(ok.doc))}`);
      assert.deepEqual(ok.doc.couldNotRun, []);
      assert.ok(ok.doc.validatorsRun.includes("scan_path"));
      assert.equal(secretGuard(ok.doc).status, "ran");
      assert.match(ok.doc.coverage, /^1 directory git ignores could not be listed, so no check read the files in it: data\/postgres\//);
    }

    // With the tracked file unreadable as well, the scan did not read something the gate has not
    // accounted for. The line names that file, from the project's top, and not the directory.
    r.lock("notes.txt");
    for (const mode of [[], ["--factory", "--base=HEAD"]]) {
      const d = cli([r.dir, "--json", ...mode]);
      assert.equal(d.code, 3, `${mode.join(" ")} exit ${d.code}; couldNotRun: ${JSON.stringify(d.doc?.couldNotRun)}`);
      assert.deepEqual(scanLines(d.doc), [
        "scan_path: secret-guard could not scan all of the project — it did not read notes.txt (permission denied). What it did not read was not checked for credentials.",
      ]);
    }
    const text = cli([r.dir]);
    assert.equal(text.code, 3);
    assert.match(text.stdout, /it did not read notes\.txt \(permission denied\)/);
  } finally {
    r.done();
  }
});

test("a file git ignores that cannot be read (.env, mode 000) is exit 3: only a directory the gate could not list is set aside", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", ".env\n").commit("base");
    r.write(".env", "PORT=8080\n");
    assert.equal(cli([r.dir, "--json"]).code, 0, "readable, it is scanned and holds nothing");
    r.lock(".env");
    for (const mode of [[], ["--factory", "--base=HEAD"]]) {
      const d = cli([r.dir, "--json", ...mode]);
      assert.equal(d.code, 3, `${mode.join(" ")} exit ${d.code}; couldNotRun: ${JSON.stringify(d.doc?.couldNotRun)}`);
      // Nothing else could not run, and nothing blocks: the file is the whole reason.
      assert.deepEqual(d.doc.couldNotRun, [
        "scan_path: secret-guard could not scan all of the project — it did not read .env (permission denied). What it did not read was not checked for credentials.",
      ]);
      assert.deepEqual(failures(d.doc), []);
      assert.deepEqual(d.doc.unreadDirectories, []);
    }
  } finally {
    r.done();
  }
});

test("a directory only the change's own ignore line ignores is still the grant the change added: exit 1, with the secret scan run", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").commit("base");
    r.write(".gitignore", "vendor_src/\n").write("a.js", "console.log(2);\n").commit("change");
    r.write("vendor_src/v.js", "const x = 1;\n").lock("vendor_src");
    const f = cli([r.dir, "--json", "--factory", "--base=HEAD~1"]);
    assert.equal(f.code, 1, `exit ${f.code}; couldNotRun: ${JSON.stringify(f.doc?.couldNotRun)}; failures: ${JSON.stringify(failures(f.doc))}`);
    assert.deepEqual(f.doc.couldNotRun, []);
    assert.ok(f.doc.validatorsRun.includes("scan_path"));
    const blocking = failures(f.doc);
    assert.equal(blocking.length, 1, JSON.stringify(blocking));
    assert.match(blocking[0], /^factory: 1 ignored-directory grant\(s\) this change added — vendor_src\/ \(\.gitignore:1: vendor_src\/\)\./);
    assert.deepEqual(
      f.doc.factory.grants.filter((g) => g.kind === "ignored-directory").map((g) => ({ path: g.path, status: g.status })),
      [{ path: "vendor_src", status: "added" }]
    );
  } finally {
    r.done();
  }
});
