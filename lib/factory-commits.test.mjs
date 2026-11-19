import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { commitRange, commitSecrets } from "./factory-commits.mjs";
import { fetchForFactory } from "../bin/factory-fetch.mjs";
import { GRANT_KINDS, parseAllowlist } from "./factory.mjs";
import { factoryFindingId } from "./corpus-keys.mjs";

// A temporary directory of this file's own, so that "nothing is left behind" is not a statement about
// what other test files, running at the same time, have in the shared one.
const OWN_TMP = mkdtempSync(path.join(tmpdir(), "factory-commits-own-"));
process.env.TMPDIR = OWN_TMP;
process.on("exit", () => rmSync(OWN_TMP, { recursive: true, force: true }));

// What each commit between the base and the head added, read from git and handed to a scanner
// (lib/factory-commits.mjs). The scanner here is a stand-in that reports every line holding the word
// MARK and skips a line carrying gitleaks:allow, as gitleaks does, so these test which lines of
// which commits reach the scanner and what is done with its answer. The real scanner, through the
// real CLI, is in bin/factory-commits.test.mjs.

function repo(sub = "") {
  const top = mkdtempSync(path.join(tmpdir(), "factory-commits-"));
  const dir = path.join(top, sub);
  mkdirSync(dir, { recursive: true });
  const git = (...args) => {
    const r = spawnSync("git", ["-C", top, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q", "-b", "main");
  const self = {
    top,
    dir,
    git,
    write(rel, text) {
      mkdirSync(path.dirname(path.join(top, rel)), { recursive: true });
      writeFileSync(path.join(top, rel), text);
      return self;
    },
    remove(rel) {
      rmSync(path.join(top, rel), { recursive: true, force: true });
      return self;
    },
    /** Commit everything, and return the commit's name. */
    commit(message) {
      git("add", "-A");
      git("commit", "-q", "--allow-empty", "-m", message);
      return git("rev-parse", "HEAD");
    },
    done() {
      rmSync(top, { recursive: true, force: true });
    },
  };
  return self;
}

const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));

/** The stand-in scanner, and a record of every directory it was given and every line it read. */
function scanner({ answer } = {}) {
  const seen = { dirs: [], lines: [], files: [] };
  const scan = async (dir) => {
    seen.dirs.push(dir);
    seen.files.push(...walk(dir).map((f) => path.relative(dir, f).split(path.sep).join("/")));
    const findings = [];
    for (const file of walk(dir)) {
      readFileSync(file, "utf8")
        .split("\n")
        .forEach((line, i) => {
          seen.lines.push(line);
          if (line.includes("MARK") && !line.includes("gitleaks:allow")) findings.push({ rule: "stand-in", file, startLine: i + 1, endLine: i + 1 });
        });
    }
    return answer ? answer(dir, findings) : { text: JSON.stringify({ target: dir, clean: !findings.length, findings }) };
  };
  return { scan, seen };
}

const found = (r) => r.findings.map((f) => `${f.commit.slice(0, 7)} ${f.path}:${f.line} ${f.status}`);
const leftovers = () => readdirSync(tmpdir()).filter((n) => n.startsWith("wolfproof-commits-"));

test("a line one commit added and the next removed is found, with the commit, the file and the line", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    const added = r.write("config.js", "const region = 1;\nconst key = MARK;\n").commit("add");
    r.write("config.js", "const region = 1;\n").commit("remove");
    const before = leftovers();
    const s = scanner();
    const res = await commitSecrets(r.dir, { sha: base, scan: s.scan });
    assert.equal(res.error, undefined);
    // Two commits, and one file handed to the scanner: the second commit added no line.
    assert.deepEqual({ commits: res.commits, files: res.files }, { commits: 2, files: 1 });
    assert.deepEqual(found(res), [`${added.slice(0, 7)} config.js:2 added`]);
    assert.equal(res.failures.length, 1);
    assert.ok(res.failures[0].startsWith(`factory: 1 credential in the commits of this change — commit ${added.slice(0, 12)} config.js:2 (stand-in). `), res.failures[0]);
    assert.ok(res.failures[0].includes(`the base (${base.slice(0, 12)})`), res.failures[0]);
    assert.deepEqual(factoryFindingId(res.failures[0]), { id: "factory: secret-in-commit", n: 1 });
    assert.deepEqual(leftovers(), before, "the temporary directory is removed");
  } finally {
    r.done();
  }
});

test("only the lines a commit added count: one the base already held is not this change's", async () => {
  const r = repo();
  try {
    const base = r.write("legacy.js", "const old = MARK;\nconst b = 2;\n").commit("base");
    const edit = r.write("legacy.js", "const old = MARK;\nconst b = 2;\nconst fresh = MARK;\n").commit("edit");
    r.write("legacy.js", "const old = MARK;\nconst b = 3;\n").commit("remove the new line, edit another");
    const res = await commitSecrets(r.dir, { sha: base, scan: scanner().scan });
    assert.deepEqual(found(res), [`${edit.slice(0, 7)} legacy.js:3 added`]);
  } finally {
    r.done();
  }
});

test("no commits between the base and the head: nothing is scanned and nothing is refused", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = MARK;\n").commit("base");
    r.write("uncommitted.js", "const b = MARK;\n");
    const s = scanner();
    const res = await commitSecrets(r.dir, { sha: base, scan: s.scan });
    assert.deepEqual({ commits: res.commits, files: res.files, findings: res.findings, failures: res.failures, error: res.error }, { commits: 0, files: 0, findings: [], failures: [], error: undefined });
    assert.deepEqual(s.seen.dirs, []);
  } finally {
    r.done();
  }
});

test("a gitleaks:allow that exists only in a commit of the change does not hide the line", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    const added = r.write("config.js", "const key = MARK; // gitleaks:allow\n").commit("add, with the comment");
    r.remove("config.js").commit("remove");
    const s = scanner();
    const res = await commitSecrets(r.dir, { sha: base, scan: s.scan });
    assert.deepEqual(found(res), [`${added.slice(0, 7)} config.js:1 added`]);
    assert.ok(!s.seen.lines.some((l) => l.includes("gitleaks:allow")), "the comment was taken out of the copy that was scanned");
    assert.ok(s.seen.lines.includes("const key = MARK; // gitleaks_allow"), JSON.stringify(s.seen.lines));
  } finally {
    r.done();
  }
});

test("a gitleaks:allow the base held, or the allowlist approves, is honoured in a commit as it is in the tree", async () => {
  const r = repo();
  try {
    const line = "const sample = MARK; // gitleaks:allow";
    const base = r.write("docs/sample.js", `${line}\n`).commit("base");
    r.write("docs/sample.js", "// moved\n").commit("take it out");
    r.write("docs/sample.js", `// moved\n${line}\n`).write("docs/other.js", `${line}\n`).commit("put it back, and copy it");
    const other = r.git("rev-parse", "HEAD");
    // The key inventoryGrants gives the base's line: kind, path, the line's text.
    const baseKeys = () => new Set([`gitleaks:allow|docs/sample.js|${line}`]);
    const res = await commitSecrets(r.dir, { sha: base, baseKeys, scan: scanner().scan });
    // The same words in another file are a grant the base did not hold.
    assert.deepEqual(found(res), [`${other.slice(0, 7)} docs/other.js:1 added`]);
    const { entries } = parseAllowlist({ exemptions: [{ kind: "gitleaks:allow", path: "docs", reason: "sample values for the documentation" }] });
    const approved = await commitSecrets(r.dir, { sha: base, baseKeys, allowlist: entries, scan: scanner().scan });
    assert.deepEqual(found(approved), []);
    assert.deepEqual(approved.failures, []);
  } finally {
    r.done();
  }
});

test("a .gitleaksignore entry is honoured only when the base held it or the allowlist approves the file", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    const print = (root) => `${root}/config.js:stand-in:1`;
    const added = r.write("config.js", "const key = MARK;\n").write(".gitleaksignore", `${print(r.dir)}\n`).commit("add, with its fingerprint");
    r.remove("config.js").remove(".gitleaksignore").commit("remove both");
    const s = scanner();
    const res = await commitSecrets(r.dir, { sha: base, scan: s.scan });
    assert.deepEqual(found(res), [`${added.slice(0, 7)} config.js:1 added`]);
    // The commit's own ignore file is scanned as a file, under the commit's directory, and never sits where gitleaks reads one.
    assert.deepEqual(s.seen.files.filter((f) => f.endsWith(".gitleaksignore")), ["000000.0/.gitleaksignore"]);
    // The entry as the base's inventory keys it.
    const held = await commitSecrets(r.dir, { sha: base, baseKeys: () => new Set([`.gitleaksignore|.gitleaksignore|${print(r.dir)}`]), scan: scanner().scan });
    assert.deepEqual(found(held), []);
    const { entries } = parseAllowlist({ exemptions: [{ kind: ".gitleaksignore", path: ".gitleaksignore", reason: "the security team owns this file" }] });
    const approved = await commitSecrets(r.dir, { sha: base, allowlist: entries, scan: scanner().scan });
    assert.deepEqual(found(approved), []);
  } finally {
    r.done();
  }
});

test("the allowlist approves a finding by its file, kind secret-in-commit", async () => {
  const r = repo();
  try {
    assert.ok("secret-in-commit" in GRANT_KINDS);
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    const added = r.write("test/data/sample.pem", "MARK\n").write("src/k.js", "const k = MARK;\n").commit("add");
    r.remove("test/data/sample.pem").remove("src/k.js").commit("remove");
    const { entries, ignored } = parseAllowlist({ exemptions: [{ kind: "secret-in-commit", path: "test/data", reason: "a sample key that was never live" }] });
    assert.deepEqual(ignored, []);
    const res = await commitSecrets(r.dir, { sha: base, allowlist: entries, scan: scanner().scan });
    assert.deepEqual(found(res).sort(), [`${added.slice(0, 7)} src/k.js:1 added`, `${added.slice(0, 7)} test/data/sample.pem:1 allowlisted`]);
    assert.equal(res.failures.length, 1);
    assert.ok(res.failures[0].includes("src/k.js:1") && !res.failures[0].includes("sample.pem"), res.failures[0]);
  } finally {
    r.done();
  }
});

test("a file a commit wrote where secret-guard does not scan blocks, and is not handed to the scanner", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    const added = r.write("vendor/lib/k.js", "const k = MARK;\n").commit("add under vendor");
    r.remove("vendor").commit("remove");
    const gitleaksAllow = [/(^|\/)vendor\//];
    const s = scanner();
    const res = await commitSecrets(r.dir, { sha: base, gitleaksAllow, scan: s.scan });
    assert.deepEqual(res.findings, []);
    assert.deepEqual(res.skipped, [{ commit: added, path: "vendor/lib/k.js", why: gitleaksAllow[0].source }]);
    assert.ok(res.failures[0].startsWith(`factory: 1 file a commit of this change wrote where secret-guard's gitleaks allowlist does not scan — commit ${added.slice(0, 12)} vendor/lib/k.js. `), res.failures[0]);
    assert.deepEqual(factoryFindingId(res.failures[0]), { id: "factory: skipped-location in a commit", n: 1 });
    assert.ok(!s.seen.lines.some((l) => l.includes("MARK")));
    // Approved as the same location is approved in the tree, or already reported there.
    const { entries } = parseAllowlist({ exemptions: [{ kind: "skipped-location", path: "vendor", reason: "vendored by the platform team" }] });
    assert.deepEqual((await commitSecrets(r.dir, { sha: base, gitleaksAllow, allowlist: entries, scan: scanner().scan })).failures, []);
    assert.deepEqual((await commitSecrets(r.dir, { sha: base, gitleaksAllow, reported: new Set(["vendor/lib/k.js"]), scan: scanner().scan })).failures, []);
  } finally {
    r.done();
  }
});

test("a .gitattributes the change carries cannot turn its added lines into a binary diff", async () => {
  const r = repo();
  try {
    const base = r.write("app.py", "a = 1\nb = 2\n").commit("base");
    const added = r.write(".gitattributes", "* -diff\n*.py binary\n").write("app.py", "a = 1\nkey = MARK\nb = 2\n").commit("add, with attributes");
    r.write("app.py", "a = 1\nb = 2\n").commit("remove");
    const res = await commitSecrets(r.dir, { sha: base, scan: scanner().scan });
    assert.deepEqual(found(res), [`${added.slice(0, 7)} app.py:2 added`]);
  } finally {
    r.done();
  }
});

test("a merge: the target branch's commits are not the change's, and a line the merge itself wrote is", async () => {
  const r = repo();
  try {
    r.write("shared.js", "const one = 1;\n").commit("fork point");
    r.git("checkout", "-q", "-b", "feature");
    const f1 = r.write("feature.js", "const f = MARK;\n").commit("feature: add");
    r.write("feature.js", "const f = 0;\n").commit("feature: remove");
    r.git("checkout", "-q", "main");
    r.write("main-only.js", "const m = MARK;\n").commit("main: a line the target branch already holds");
    const base = r.write("shared.js", "const one = 1;\nconst two = 2;\n").commit("main: moves on");
    r.git("checkout", "-q", "feature");
    r.git("merge", "-q", "--no-commit", "--no-ff", "main");
    // Written by the merge and by neither parent.
    r.write("shared.js", "const one = 1;\nconst two = 2;\nconst merged = MARK;\n");
    const merge = r.commit("merge main into feature");
    r.write("shared.js", "const one = 1;\nconst two = 2;\n").commit("remove the merge's line");
    const res = await commitSecrets(r.dir, { sha: base, scan: scanner().scan });
    assert.equal(res.commits, 4);
    assert.deepEqual(found(res).sort(), [`${f1.slice(0, 7)} feature.js:1 added`, `${merge.slice(0, 7)} shared.js:3 added`].sort());
  } finally {
    r.done();
  }
});

test("a renamed file is read at its new path, and only for the lines the rename's commit added", async () => {
  const r = repo();
  try {
    const body = Array.from({ length: 30 }, (_, i) => `const v${i} = ${i};`).join("\n");
    const base = r.write("old.js", `const held = MARK;\n${body}\n`).commit("base");
    r.remove("old.js");
    const moved = r.write("src/new.js", `const held = MARK;\n${body}\nconst fresh = MARK;\n`).commit("rename and add a line");
    r.write("src/new.js", `const held = MARK;\n${body}\n`).commit("remove the line");
    const res = await commitSecrets(r.dir, { sha: base, scan: scanner().scan });
    assert.deepEqual(found(res), [`${moved.slice(0, 7)} src/new.js:32 added`]);
  } finally {
    r.done();
  }
});

test("a project in a subdirectory is read by its own paths, and a commit outside it adds nothing to it", async () => {
  const r = repo("services/api");
  try {
    const base = r.write("services/api/a.js", "const a = 1;\n").commit("base");
    const added = r.write("services/api/k.js", "const k = MARK;\n").write("elsewhere/k.js", "const k = MARK;\n").commit("add inside and outside");
    r.remove("services/api/k.js").remove("elsewhere").commit("remove");
    const res = await commitSecrets(r.dir, { sha: base, scan: scanner().scan });
    assert.deepEqual(found(res), [`${added.slice(0, 7)} k.js:1 added`]);
  } finally {
    r.done();
  }
});

test("two paths in one commit that differ only by case are both scanned", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    // Built with plumbing, so it does not depend on this machine's filesystem telling the two apart.
    const blob = (text) => spawnSync("git", ["-C", r.top, "hash-object", "-w", "--stdin"], { input: text, encoding: "utf8" }).stdout.trim();
    const upper = blob("const upper = MARK;\n");
    const lower = blob("const lower = MARK;\n");
    const nested = blob("const nested = MARK;\n");
    const a = r.git("rev-parse", "HEAD:a.js");
    const sub = spawnSync("git", ["-C", r.top, "mktree"], { input: `100644 blob ${nested}\tinner.js\n`, encoding: "utf8" }).stdout.trim();
    const tree = spawnSync("git", ["-C", r.top, "mktree"], { input: `100644 blob ${upper}\tKey.js\n100644 blob ${a}\ta.js\n100644 blob ${lower}\tkey.js\n040000 tree ${sub}\tKEY.JS.d\n`, encoding: "utf8" }).stdout.trim();
    const commit = r.git("commit-tree", tree, "-p", base, "-m", "two names, one letter case apart");
    r.git("reset", "-q", "--hard", commit);
    r.git("reset", "-q", "--soft", commit);
    const res = await commitSecrets(r.dir, { sha: base, scan: scanner().scan });
    assert.equal(res.error, undefined);
    assert.deepEqual(found(res).sort(), [`${commit.slice(0, 7)} KEY.JS.d/inner.js:1 added`, `${commit.slice(0, 7)} Key.js:1 added`, `${commit.slice(0, 7)} key.js:1 added`].sort());
  } finally {
    r.done();
  }
});

test("a scan that did not happen is an error, never a clean result", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "const a = 1;\n").commit("base");
    r.write("k.js", "const k = MARK;\n").commit("add");
    r.remove("k.js").commit("remove");
    const cases = [
      [() => ({ error: "secret-guard was not found" }), /secret-guard did not scan them: secret-guard was not found/],
      [() => ({ text: "TOOL REPORTED A PROBLEM:\ngitleaks is not installed or not on PATH. Install it with `brew install gitleaks` and retry." }), /secret-guard could not scan them: gitleaks is not installed/],
      [() => ({ text: "" }), /produced no parseable result/],
      [(dir, findings) => ({ text: JSON.stringify({ clean: true, findings: [] }) }), /does not say it scanned the directory it was given/],
      [(dir, findings) => ({ text: JSON.stringify({ target: path.dirname(dir), clean: true, findings: [] }) }), /does not say it scanned the directory it was given/],
      [(dir, findings) => ({ text: JSON.stringify({ target: dir, findings: [{ rule: "x", file: path.join(dir, "..", "elsewhere.js"), startLine: 1 }] }) }), /which is not a file it was given/],
    ];
    for (const [answer, re] of cases) {
      const res = await commitSecrets(r.dir, { sha: base, scan: scanner({ answer }).scan });
      assert.match(res.error || "", re);
      assert.match(res.error, /^the commits between the base \([0-9a-f]{12}\) and the head were not all scanned for credentials — /);
      assert.deepEqual(res.failures, []);
    }
    // And a temporary directory that secret-guard's own allowlist would not scan.
    const hidden = await commitSecrets(r.dir, { sha: base, gitleaksAllow: [/wolfproof-commits-/], scan: scanner().scan });
    assert.match(hidden.error || "", /is under a path secret-guard's gitleaks allowlist does not scan/);
  } finally {
    r.done();
  }
});

// ---- Shallow clones ---------------------------------------------------------------------------

/** A remote with main (3 commits), a feature branch of 4 commits forked from main's third, and main moved 5 further. */
function remote() {
  const r = repo();
  r.git("config", "uploadpack.allowAnySHA1InWant", "true");
  for (const i of [1, 2, 3]) r.write(`m${i}.txt`, `m${i}\n`).commit(`main ${i}`);
  const fork = r.git("rev-parse", "HEAD");
  r.git("checkout", "-q", "-b", "feature");
  r.write("f1.js", "const k = MARK;\n").commit("feature 1: add");
  const added = r.git("rev-parse", "HEAD");
  r.write("f1.js", "const k = 0;\n").commit("feature 2: remove");
  r.write("f3.js", "3\n").commit("feature 3");
  const head = r.write("f4.js", "4\n").commit("feature 4");
  r.git("checkout", "-q", "main");
  for (const i of [4, 5, 6, 7, 8]) r.write(`m${i}.txt`, `m${i}\n`).commit(`main ${i}`);
  const base = r.git("rev-parse", "HEAD");
  r.git("checkout", "-q", "-b", "merge-ref");
  r.git("merge", "-q", "--no-ff", "-m", "Merge feature into main", "feature");
  const merge = r.git("rev-parse", "HEAD");
  r.git("checkout", "-q", "main");
  return { ...r, fork, added, head, base, merge };
}

/** A checkout as actions/checkout makes one: one commit, fetched by name at depth 1. */
function checkout(origin, sha, ref) {
  const dir = mkdtempSync(path.join(tmpdir(), "factory-commits-clone-"));
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q");
  git("remote", "add", "origin", `file://${origin}`);
  git("-c", "protocol.version=2", "fetch", "-q", "--no-tags", "--prune", "--depth=1", "origin", `+${sha}:${ref}`);
  git("checkout", "-q", "--detach", ref);
  return { dir, git, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("a pull request checked out at depth 1: the commits are not there, and that is an error, not an empty range", async () => {
  const o = remote();
  const c = checkout(o.top, o.merge, "refs/remotes/pull/1/merge");
  try {
    // What the Action used to fetch: the base, by itself.
    c.git("fetch", "-q", "--no-tags", "--depth=1", "origin", o.base);
    const range = commitRange(c.dir, o.base);
    assert.equal(range.incomplete, true);
    assert.match(range.error, /^the clone is shallow, and it was cut at \d+ commits? between the base \([0-9a-f]{12}\) and the head/);
    assert.match(range.error, /fetch-depth: 0/);
    const s = scanner();
    const res = await commitSecrets(c.dir, { sha: o.base, scan: s.scan });
    assert.match(res.error || "", /were not all scanned for credentials — the clone is shallow/);
    assert.deepEqual(res.failures, []);
    assert.deepEqual(s.seen.dirs, [], "nothing was scanned, so nothing was passed");
  } finally {
    c.done();
    o.done();
  }
});

test("what the Action fetches for a pull request brings every commit of the change, and no more of the target branch", async () => {
  const o = remote();
  const c = checkout(o.top, o.merge, "refs/remotes/pull/1/merge");
  try {
    // Small steps, so that the loop is what is tested: the first is not enough.
    const f = fetchForFactory(c.dir, o.base, { deepen: [2, 4, 8] });
    assert.deepEqual({ base: f.base, complete: f.complete, commits: f.commits }, { base: o.base, complete: true, commits: 5 });
    assert.deepEqual(f.fetched, [`--depth=1 origin ${o.base}`, `--deepen=2 origin ${o.merge} ${o.base}`, `--deepen=4 origin ${o.merge} ${o.base}`]);
    const range = commitRange(c.dir, o.base);
    assert.deepEqual(range.commits.map((x) => x.sha), [...o.git("rev-list", "--reverse", "--topo-order", `${o.base}..${o.merge}`).split("\n")]);
    const res = await commitSecrets(c.dir, { sha: o.base, scan: scanner().scan });
    assert.deepEqual(found(res), [`${o.added.slice(0, 7)} f1.js:1 added`]);
  } finally {
    c.done();
    o.done();
  }
});

test("what the Action fetches for a push brings every pushed commit", async () => {
  const o = remote();
  const c = checkout(o.top, o.head, "refs/remotes/origin/feature");
  try {
    // github.event.before: the branch's head before the push, here the fork point. It is not in the
    // checkout yet, and git says so itself.
    const before = commitRange(c.dir, o.fork);
    assert.match(before.error || "", /rev-list of [0-9a-f]{12}\.\.\.HEAD failed/);
    const f = fetchForFactory(c.dir, o.fork, { deepen: [2, 4, 8] });
    assert.deepEqual({ base: f.base, complete: f.complete, commits: f.commits }, { base: o.fork, complete: true, commits: 4 });
    const res = await commitSecrets(c.dir, { sha: o.fork, scan: scanner().scan });
    assert.deepEqual(found(res), [`${o.added.slice(0, 7)} f1.js:1 added`]);
  } finally {
    c.done();
    o.done();
  }
});

test("a change longer than the Action fetches is left incomplete, and says so", async () => {
  const o = remote();
  const c = checkout(o.top, o.merge, "refs/remotes/pull/1/merge");
  try {
    const f = fetchForFactory(c.dir, o.base, { deepen: [1] });
    assert.equal(f.complete, false);
    assert.match(f.why, /the clone is shallow/);
    assert.match((await commitSecrets(c.dir, { sha: o.base, scan: scanner().scan })).error || "", /the clone is shallow/);
  } finally {
    c.done();
    o.done();
  }
});

test("a push that creates a branch: the base is the head's parent, fetched by deepening one level", async () => {
  const o = remote();
  const c = checkout(o.top, o.head, "refs/remotes/origin/feature");
  try {
    const f = fetchForFactory(c.dir, "HEAD~1");
    assert.equal(f.complete, true);
    assert.equal(f.commits, 1);
    assert.equal(f.fetched[0], "--deepen=1 origin");
  } finally {
    c.done();
    o.done();
  }
});

test("the temporary directory is removed when the scan fails", async () => {
  const r = repo();
  try {
    const base = r.write("a.js", "1\n").commit("base");
    r.write("b.js", "MARK\n").commit("add");
    const before = leftovers();
    await commitSecrets(r.dir, { sha: base, scan: async () => ({ error: "no" }) });
    await assert.rejects(commitSecrets(r.dir, { sha: base, scan: async () => { throw new Error("thrown"); } }));
    assert.deepEqual(leftovers(), before);
    assert.ok(statSync(r.dir).isDirectory());
  } finally {
    r.done();
  }
});
