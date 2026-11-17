import test from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");

// A directory the gate cannot list, which git ignores and tracks nothing under, is a line above the
// verdict (agent/coverage.mjs), and since v1.16.6 factory mode drops that line. So a change that
// wrote the ignore rule took its own run from exit 3 to exit 0, with nothing naming the rule.
//
// Factory mode asks git the same question against the base's ignore files. A directory they already
// ignored stays as it was. One only the change's ignore rules ignore is an `ignored-directory` grant
// the change added, and blocks. The default mode is the same in every case here.
//
// These run the real CLI, because an exit code is a property of a process. Mode 000 stands in for a
// directory another user owns with mode 700; the EACCES is the same.

const asRoot = process.getuid?.() === 0 && "root reads every directory";

function cli(args, env = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000, env: { ...process.env, ...env } });
  let doc = null;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    /* not --json, or it did not get that far */
  }
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "", doc };
}

/** A git repository in a temporary directory, with the project at `sub` inside it (the top by default). */
function repo(sub = "") {
  const top = mkdtempSync(path.join(tmpdir(), "factory-ignore-"));
  const dir = path.join(top, sub);
  mkdirSync(dir, { recursive: true });
  const locked = [];
  const git = (...args) => {
    const r = spawnSync("git", ["-C", top, "-c", "user.email=t@example.invalid", "-c", "user.name=t", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout;
  };
  git("init", "-q");
  const self = {
    top,
    dir,
    git,
    /** Write a file, from the repository's top. */
    write(rel, text) {
      mkdirSync(path.dirname(path.join(top, rel)), { recursive: true });
      writeFileSync(path.join(top, rel), text);
      return self;
    },
    commit(message) {
      git("add", "-A");
      git("commit", "-qm", message);
      return self;
    },
    /** A directory holding one code file that git never tracked, then made unlistable. */
    lock(rel) {
      self.write(path.join(rel, "v.js"), "const x = 1;\n");
      chmodSync(path.join(top, rel), 0o000);
      locked.push(path.join(top, rel));
      return self;
    },
    done() {
      for (const d of locked) chmodSync(d, 0o755);
      rmSync(top, { recursive: true, force: true });
    },
  };
  return self;
}

const ignoredGrants = (doc) => doc.factory.grants.filter((g) => g.kind === "ignored-directory");
/** The blocking findings' messages. */
const failures = (doc) => (doc?.findings || []).map((f) => f.message);
const ignoredFailures = (doc) => failures(doc).filter((f) => /ignored-directory grant\(s\) this change added/.test(f));
// With work that is not committed, both modes also block on that: it is not what these tests are about.
const UNCOMMITTED = /^uncommitted work: /;

/**
 * The default mode, the same in every case: the directory named above the verdict, nothing
 * could-not-run, and nothing blocking. `uncommitted` when the case leaves work uncommitted, which the
 * default mode blocks on by itself.
 */
function defaultModeUnchanged(r, dir, { uncommitted = false } = {}) {
  const d = cli([r.dir, "--json"]);
  assert.equal(d.code, uncommitted ? 1 : 0, `default mode exit ${d.code}; couldNotRun: ${JSON.stringify(d.doc?.couldNotRun)}; failures: ${JSON.stringify(failures(d.doc))}`);
  assert.deepEqual(failures(d.doc).filter((f) => !UNCOMMITTED.test(f)), []);
  assert.deepEqual(d.doc.unreadDirectories, [{ dir, why: "not readable (EACCES)", ignored: true }]);
  assert.deepEqual(d.doc.couldNotRun, []);
  assert.match(d.doc.coverage, /^1 directory git ignores could not be listed/);
  assert.equal(d.doc.factory, null);
}

/** Factory mode for a directory only this change's ignore rules ignore: exit 1, the directory and the ignore file named. */
function blocksAsAdded(r, base, dir, ignoreFile, line) {
  const f = cli([r.dir, "--json", "--factory", `--base=${base}`]);
  assert.equal(f.code, 1, `factory exit ${f.code}; failures: ${JSON.stringify(failures(f.doc))}; couldNotRun: ${JSON.stringify(f.doc?.couldNotRun)}`);
  assert.equal(ignoredGrants(f.doc).length, 1, JSON.stringify(f.doc.factory.grants));
  const g = ignoredGrants(f.doc)[0];
  assert.deepEqual({ path: g.path, status: g.status, ignoreFile: g.ignoreFile }, { path: dir, status: "added", ignoreFile });
  // The one blocking finding, apart from uncommitted work where the case leaves some.
  const blocking = failures(f.doc).filter((m) => !UNCOMMITTED.test(m));
  assert.equal(blocking.length, 1, JSON.stringify(blocking));
  assert.deepEqual(ignoredFailures(f.doc), blocking);
  assert.ok(blocking[0].includes(`${dir}/ (${ignoreFile}:${line}: `), blocking[0]);
  assert.match(blocking[0], /the ignore rules at the base \([0-9a-f]{12}\) did not ignore it/);
  assert.deepEqual(f.doc.couldNotRun, []);
  return f;
}

/** Factory mode for a directory the base's ignore rules already ignored: exit 0, as v1.16.6 left it. */
function passesAsPreExisting(r, base, dir, ignoreFile) {
  const f = cli([r.dir, "--json", "--factory", `--base=${base}`]);
  assert.equal(f.code, 0, `factory exit ${f.code}; failures: ${JSON.stringify(failures(f.doc))}; couldNotRun: ${JSON.stringify(f.doc?.couldNotRun)}`);
  assert.equal(ignoredGrants(f.doc).length, 1, JSON.stringify(f.doc.factory.grants));
  const g = ignoredGrants(f.doc)[0];
  assert.deepEqual({ path: g.path, status: g.status, ignoreFile: g.ignoreFile }, { path: dir, status: "pre-existing", ignoreFile });
  assert.deepEqual(failures(f.doc), []);
  assert.deepEqual(f.doc.couldNotRun, []);
  assert.deepEqual(
    f.doc.factory.advisories.classified.filter((c) => c.id === "unread-ignored-dirs"),
    [{ id: "unread-ignored-dirs", class: "info", action: "drop" }]
  );
  assert.match(f.doc.coverage, /^1 directory git ignores could not be listed/);
  return f;
}

test("factory mode blocks a directory it cannot list when the change's own ignore line is what ignores it", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").commit("base");
    r.write(".gitignore", "vendor_src/\n").write("a.js", "console.log(2);\n").commit("change").lock("vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    const f = blocksAsAdded(r, "HEAD~1", "vendor_src", ".gitignore", 1);
    // The line above the verdict is still there, and still information.
    assert.match(f.doc.coverage, /^1 directory git ignores could not be listed/);
    const text = cli([r.dir, "--factory", "--base=HEAD~1"]);
    assert.equal(text.code, 1);
    assert.match(text.stdout, /^factory grants : 0 predate the change, 0 allowlisted, 1 added by it$/m);
    assert.match(text.stdout, /^ {2}- factory: 1 ignored-directory grant\(s\) this change added — vendor_src\/ \(\.gitignore:1: vendor_src\/\)\./m);

    // The pipeline's allowlist approves the directory by path, like any other grant.
    const allow = path.join(r.top, "..", `${path.basename(r.top)}-allowlist.json`);
    try {
      writeFileSync(allow, JSON.stringify({ exemptions: [{ kind: "ignored-directory", path: "vendor_src", reason: "a volume the platform team mounts" }] }));
      const a = cli([r.dir, "--json", "--factory", "--base=HEAD~1", `--allowlist=${allow}`]);
      assert.equal(a.code, 0, `exit ${a.code}; failures: ${JSON.stringify(failures(a.doc))}`);
      assert.deepEqual(
        ignoredGrants(a.doc).map((g) => ({ path: g.path, status: g.status, approvedBy: g.approvedBy })),
        [{ path: "vendor_src", status: "allowlisted", approvedBy: "a volume the platform team mounts" }]
      );
    } finally {
      rmSync(allow, { force: true });
    }

    // No base to compare with: nothing can be told apart from anything, so no grant is judged, this
    // one included, and the run is exit 3 as it is for every other grant. Never exit 0.
    const none = cli([r.dir, "--json", "--factory", "--base=no-such-ref"]);
    assert.equal(none.code, 3, `exit ${none.code}`);
    assert.deepEqual(none.doc.factory.grants, []);
    assert.deepEqual(ignoredFailures(none.doc), []);
    assert.equal(none.doc.couldNotRun.length, 1, JSON.stringify(none.doc.couldNotRun));
    assert.match(none.doc.couldNotRun[0], /^factory: the base ref no-such-ref is not in this checkout, so what predates this change cannot be told apart from what it added\. No self-granted exemption was judged/);
  } finally {
    r.done();
  }
});

test("factory mode drops a directory the base already ignored, when the change does not touch an ignore file", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", "vendor_src/\n").commit("base");
    r.write("a.js", "console.log(2);\n").commit("change").lock("vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    passesAsPreExisting(r, "HEAD~1", "vendor_src", ".gitignore");
  } finally {
    r.done();
  }
});

test("factory mode drops a directory the base already ignored, when the change adds an unrelated line to the same .gitignore", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", "vendor_src/\n").commit("base");
    r.write(".gitignore", "*.log\nvendor_src/\ncoverage/\n").write("a.js", "console.log(2);\n").commit("change").lock("vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    passesAsPreExisting(r, "HEAD~1", "vendor_src", ".gitignore");
  } finally {
    r.done();
  }
});

test("factory mode blocks when the change removes the negation that kept the directory from being ignored", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", "vendor_src/\n!vendor_src/\n").commit("base");
    r.write(".gitignore", "vendor_src/\n").write("a.js", "console.log(2);\n").commit("change").lock("vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    // The line that ignores it was there at the base; what the change did was make it take effect.
    blocksAsAdded(r, "HEAD~1", "vendor_src", ".gitignore", 1);
  } finally {
    r.done();
  }
});

test("factory mode blocks when the change adds a nested .gitignore, in the directory's parent, that ignores it", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write("pkg/b.js", "console.log(1);\n").commit("base");
    r.write("pkg/.gitignore", "vendor_src/\n").write("a.js", "console.log(2);\n").commit("change").lock("pkg/vendor_src");
    defaultModeUnchanged(r, "pkg/vendor_src");
    blocksAsAdded(r, "HEAD~1", "pkg/vendor_src", "pkg/.gitignore", 1);
  } finally {
    r.done();
  }
});

test("factory mode drops a directory ignored before and after, when the change moves the pattern to another ignore file", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write("pkg/b.js", "console.log(1);\n").write(".gitignore", "pkg/vendor_src/\n").commit("base");
    r.write(".gitignore", "*.log\n").write("pkg/.gitignore", "vendor_src/\n").write("a.js", "console.log(2);\n").commit("change").lock("pkg/vendor_src");
    defaultModeUnchanged(r, "pkg/vendor_src");
    passesAsPreExisting(r, "HEAD~1", "pkg/vendor_src", "pkg/.gitignore");
  } finally {
    r.done();
  }
});

test("factory mode drops a directory only .git/info/exclude ignores, which a change cannot carry", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").commit("base");
    r.write("a.js", "console.log(2);\n").commit("change");
    appendFileSync(path.join(r.top, ".git", "info", "exclude"), "vendor_src/\n");
    r.lock("vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    passesAsPreExisting(r, "HEAD~1", "vendor_src", ".git/info/exclude");
  } finally {
    r.done();
  }
});

test("factory mode blocks on an ignore line that is not committed, as on one that is", { skip: asRoot }, () => {
  const r = repo();
  try {
    // The working tree is what factory mode compares with the base, so the base is HEAD here.
    r.write("a.js", "console.log(1);\n").write(".gitignore", "*.log\n").commit("base");
    r.write(".gitignore", "*.log\nvendor_src/\n").write("a.js", "console.log(2);\n").lock("vendor_src");
    defaultModeUnchanged(r, "vendor_src", { uncommitted: true });
    const f = blocksAsAdded(r, "HEAD", "vendor_src", ".gitignore", 2);
    assert.equal(failures(f.doc).filter((m) => UNCOMMITTED.test(m)).length, 1, "the work is not committed, and that blocks too");
  } finally {
    r.done();
  }
});

test("a project in a subdirectory is held to the repository's ignore files above it, as they were at the base", { skip: asRoot }, () => {
  // The base is materialised for the project's own subtree, which does not hold the ignore files
  // above it; the ignore question is asked from the repository's top.
  let r = repo("services/api");
  try {
    r.write("services/api/a.js", "console.log(1);\n").write(".gitignore", "vendor_src/\n").commit("base");
    r.write("services/api/a.js", "console.log(2);\n").commit("change").lock("services/api/vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    passesAsPreExisting(r, "HEAD~1", "vendor_src", ".gitignore");
  } finally {
    r.done();
  }
  r = repo("services/api");
  try {
    r.write("services/api/a.js", "console.log(1);\n").write(".gitignore", "*.log\n").commit("base");
    r.write(".gitignore", "*.log\nvendor_src/\n").write("services/api/a.js", "console.log(2);\n").commit("change").lock("services/api/vendor_src");
    defaultModeUnchanged(r, "vendor_src");
    blocksAsAdded(r, "HEAD~1", "vendor_src", ".gitignore", 2);
  } finally {
    r.done();
  }
});

// The base's rules are asked in a temporary tree holding the base's ignore files. Git applies a
// directory-only pattern such as `!*/` only to a path that is a directory there, so in a tree
// without the directory the negation was skipped and `*` won: measured on 7f56106, the change below
// exited 0 with the grant "pre-existing". The directory is made in that tree before git is asked.

/** The default mode for a directory git does not ignore: exit 3, could-not-run, nothing blocking. */
function defaultModeCouldNotRun(r, dir) {
  const d = cli([r.dir, "--json"]);
  assert.equal(d.code, 3, `default mode exit ${d.code}; failures: ${JSON.stringify(failures(d.doc))}`);
  assert.deepEqual(d.doc.unreadDirectories, [{ dir, why: "not readable (EACCES)", ignored: false }]);
  assert.deepEqual(failures(d.doc), []);
  assert.ok(d.doc.couldNotRun.some((c) => c.startsWith("source_files: 1 directory could not be listed") && c.includes(`${dir}/`)), JSON.stringify(d.doc.couldNotRun));
}

test("factory mode blocks when the change removes a directory-only negation (!*/) that kept the directory from being ignored", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", "*\n!*/\n!*.js\n!.gitignore\n").commit("base").lock("vendor_src");
    // At the base the directory is not ignored, so the run that could not list it was exit 3.
    defaultModeCouldNotRun(r, "vendor_src");
    r.write(".gitignore", "*\n!*.js\n!.gitignore\n").write("a.js", "console.log(2);\n").commit("change");
    defaultModeUnchanged(r, "vendor_src");
    // `*` was line 1 at the base too; what the change did was take away the line that overrode it.
    blocksAsAdded(r, "HEAD~1", "vendor_src", ".gitignore", 1);
  } finally {
    r.done();
  }
});

test("factory mode is exit 3, with no grant, when the directory-only negation is kept and the change adds an unrelated line", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", "*\n!*/\n!*.js\n!.gitignore\n").commit("base");
    r.write(".gitignore", "*\n!*/\n!*.js\n!.gitignore\n*.log\n").write("a.js", "console.log(2);\n").commit("change").lock("vendor_src");
    defaultModeCouldNotRun(r, "vendor_src");
    // Git does not ignore the directory, so there is no ignore rule to judge: could-not-run, as for
    // any directory the gate cannot list, and never blocked.
    const f = cli([r.dir, "--json", "--factory", "--base=HEAD~1"]);
    assert.equal(f.code, 3, `factory exit ${f.code}; failures: ${JSON.stringify(failures(f.doc))}`);
    assert.deepEqual(ignoredGrants(f.doc), []);
    assert.deepEqual(failures(f.doc), []);
    assert.deepEqual(f.doc.unreadDirectories, [{ dir: "vendor_src", why: "not readable (EACCES)", ignored: false }]);
    assert.ok(f.doc.couldNotRun.some((c) => c.startsWith("source_files: 1 directory could not be listed") && c.includes("vendor_src/")), JSON.stringify(f.doc.couldNotRun));
  } finally {
    r.done();
  }
});

test("factory mode blocks when the change removes a nested directory-only negation (!pkg/*/)", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write(".gitignore", "pkg/*\n!pkg/*/\n").commit("base").lock("pkg/vendor_src");
    defaultModeCouldNotRun(r, "pkg/vendor_src");
    r.write(".gitignore", "pkg/*\n").write("a.js", "console.log(2);\n").commit("change");
    defaultModeUnchanged(r, "pkg/vendor_src");
    blocksAsAdded(r, "HEAD~1", "pkg/vendor_src", ".gitignore", 1);
  } finally {
    r.done();
  }
});

test("factory mode blocks when the change removes a directory-only negation from a nested .gitignore", { skip: asRoot }, () => {
  const r = repo();
  try {
    r.write("a.js", "console.log(1);\n").write("pkg/.gitignore", "*\n!*/\n!.gitignore\n").commit("base").lock("pkg/vendor_src");
    defaultModeCouldNotRun(r, "pkg/vendor_src");
    r.write("pkg/.gitignore", "*\n!.gitignore\n").write("a.js", "console.log(2);\n").commit("change");
    defaultModeUnchanged(r, "pkg/vendor_src");
    blocksAsAdded(r, "HEAD~1", "pkg/vendor_src", "pkg/.gitignore", 1);
  } finally {
    r.done();
  }
});

test("a base whose tree holds a path above the repository's top is exit 3, and nothing is written outside the temporary tree", { skip: asRoot }, () => {
  // Git refuses to check such a path out, and `git archive` refuses it too, which is exit 3 for a
  // project at the repository's top. A project in a subdirectory is archived from its own subtree,
  // so the entry was reached: measured on 7f56106, `.gitignore` was written beside the temporary
  // tree, in the system's temporary directory.
  const r = repo("services/api");
  const tmp = mkdtempSync(path.join(tmpdir(), "factory-ignore-tmpdir-"));
  try {
    r.write("services/api/a.js", "console.log(1);\n").commit("base");
    const mktree = (lines) => {
      const m = spawnSync("git", ["-C", r.top, "mktree"], { input: lines.join("\n") + "\n", encoding: "utf8" });
      assert.equal(m.status, 0, m.stderr);
      return m.stdout.trim();
    };
    const blob = spawnSync("git", ["-C", r.top, "hash-object", "-w", "--stdin"], { input: "planted\n", encoding: "utf8" }).stdout.trim();
    const above = mktree([`100644 blob ${blob}\t.gitignore`]);
    const tree = mktree([`040000 tree ${r.git("rev-parse", "HEAD:services").trim()}\tservices`, `040000 tree ${above}\t..`]);
    const base = r.git("commit-tree", "-m", "crafted", tree).trim();
    r.write(".gitignore", "vendor_src/\n").write("services/api/a.js", "console.log(2);\n").commit("change").lock("services/api/vendor_src");
    const f = cli([r.dir, "--json", "--factory", `--base=${base}`], { TMPDIR: tmp });
    assert.equal(existsSync(path.join(tmp, ".gitignore")), false, "the base's ../.gitignore was written outside the temporary tree");
    assert.equal(f.code, 3, `factory exit ${f.code}; failures: ${JSON.stringify(failures(f.doc))}`);
    assert.deepEqual(ignoredGrants(f.doc), []);
    assert.deepEqual(ignoredFailures(f.doc), []);
    assert.ok(f.doc.couldNotRun.some((c) => /^factory: the base's ignore files could not be read, .*\.\.\/\.gitignore/.test(c)), JSON.stringify(f.doc.couldNotRun));
  } finally {
    r.done();
    rmSync(tmp, { recursive: true, force: true });
  }
});
