import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { createHash, createPrivateKey, randomInt } from "crypto";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");
const FETCH = path.resolve(__dirname, "factory-fetch.mjs");

// A credential one commit adds and a later commit of the same change removes is in no tree the gate
// compares: measured on 0907366, `--factory --base=<base>` exited 0 with the key in the branch's
// history. Factory mode now scans what each commit between the base and the head added, with the
// pipeline's own secret-guard (lib/factory-commits.mjs). The default mode is as it was.
//
// These run the real CLI and the real scanner, because an exit code is a property of a process and
// the rules are gitleaks'. CI installs gitleaks and sets WOLFPROOF_REQUIRE_SCANNERS, so its absence
// fails there instead of skipping.

const haveGitleaks = !spawnSync("gitleaks", ["version"], { encoding: "utf8" }).error;
const skip = !haveGitleaks && "gitleaks is not on PATH";
test("the scanner these tests need is installed", () => {
  if (process.env.WOLFPROOF_REQUIRE_SCANNERS) assert.ok(haveGitleaks, "WOLFPROOF_REQUIRE_SCANNERS is set and gitleaks is not on PATH");
});

// Nothing credential-shaped is written in this file: GitHub's push protection reads every commit.
// An AWS access key ID is a four-letter prefix and sixteen base32 characters, drawn here without
// replacement so that its entropy is fixed and above the floor of gitleaks' aws-access-token rule
// (test/fixtures/factory-scenario.mjs measured the miss rate of drawing with replacement).
const range = (from, to) => Array.from({ length: to.charCodeAt(0) - from.charCodeAt(0) + 1 }, (_, i) => String.fromCharCode(from.charCodeAt(0) + i));
function keyId() {
  const chars = [...range("A", "Z"), ...range("2", "7")];
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return ["A", "K", "I", "A"].join("") + chars.slice(0, 16).join("");
}

// The lines of a private key, the same key on every run: an Ed25519 key in PKCS#8 whose 32 secret
// bytes are the hash of a sentence. It is made here, so nothing key-shaped is written in this file,
// and it opens nothing.
//
// It was a new 2048-bit RSA key each run, and what the scanner made of the text depended on the
// draw. Measured with gitleaks 8.30.1 and the pipeline's rules, on text of that key's shape (the two
// label lines around a random base64 body, 28 lines):
//   - lines in reverse order: 36 of 60,000 were a generic-api-key finding, each on a body ending in
//     "=" padding, as about 7 real keys in 10 do. "key" or "api" in any letter case a few characters
//     before the "=" reads as a name being assigned, and the line after it as the value. The gate's
//     run on e33ffdc failed on the test below, which commits the key reversed and expects no finding.
//   - lines in reverse order, no padding: 1 of 200,000 (square-access-token, on a line starting EAAA).
//   - lines in order: 5 of 120,000 were no finding at all. Each held "false" in some letter case, and
//     gitleaks' default allowlist drops any secret that does. That is the scanner missing a key,
//     which no choice of key here mends.
// One fixed text is read the same way every time: if a rule ever reads this one differently, the
// test fails on every run and not on one in a thousand.
function privateKeyLines() {
  const secret = createHash("sha256").update("wolfproof test fixture: a key that opens nothing").digest();
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), secret]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" }).export({ type: "pkcs8", format: "pem" }).trim().split("\n");
}

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

function repo() {
  const top = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-commit-secrets-")));
  const git = (...args) => {
    const r = spawnSync("git", ["-C", top, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q", "-b", "main");
  const self = {
    top,
    dir: top,
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
    commit(message) {
      git("add", "-A");
      git("commit", "-qm", message);
      return git("rev-parse", "HEAD");
    },
    done() {
      rmSync(top, { recursive: true, force: true });
    },
  };
  return self;
}

const failures = (doc) => (doc?.findings || []).map((f) => f.message);
const factory = (r, base, extra = []) => cli([r.dir, "--json", "--factory", `--base=${base}`, ...extra]);
const say = (x) => `exit ${x.code}; failures: ${JSON.stringify(failures(x.doc))}; couldNotRun: ${JSON.stringify(x.doc?.couldNotRun)}`;

/** Factory mode blocks on exactly one finding, the credential `commit` added at `where`. */
function blocksOnCommit(f, commit, where, rule = "aws-access-token") {
  assert.equal(f.code, 1, say(f));
  assert.deepEqual(f.doc.couldNotRun, []);
  assert.equal(failures(f.doc).length, 1, say(f));
  const [file, line] = where.split(":");
  assert.ok(failures(f.doc)[0].startsWith(`factory: 1 credential in the commits of this change — commit ${commit.slice(0, 12)} ${where} (${rule}). `), failures(f.doc)[0]);
  assert.deepEqual(f.doc.factory.commits.findings, [{ commit, path: file, line: Number(line), rule, status: "added" }]);
}

test("a credential one commit adds and the next removes: factory mode blocks and names the commit, the file and the line", { skip }, () => {
  const r = repo();
  try {
    const key = keyId();
    const base = r.write("a.js", "export const a = 1;\n").commit("base");
    const added = r.write("config.js", `export const region = "us-east-1";\nexport const uploadKey = "${key}";\n`).commit("add config");
    r.write("config.js", `export const region = "us-east-1";\n`).commit("drop the key");
    assert.ok(r.git("log", "-p").includes(key), "the key is in the branch's history");

    const f = factory(r, base);
    blocksOnCommit(f, added, "config.js:2");
    assert.deepEqual({ scanned: f.doc.factory.commits.scanned, count: f.doc.factory.commits.count }, { scanned: true, count: 2 });
    assert.ok(!f.stdout.includes(key), "the value is not in the report");
    // The same line above the verdict in the text report.
    const text = cli([r.dir, "--factory", `--base=${base}`]);
    assert.equal(text.code, 1);
    assert.match(text.stdout, /^factory commits: 2 between the base and the head, 2 file\(s\) they changed scanned for credentials, 1 finding\(s\)$/m);

    // The default mode is as it was: it reads the tree, and the tree is clean.
    const d = cli([r.dir, "--json"]);
    assert.equal(d.code, 0, say(d));
    assert.equal(d.doc.factory, null);
  } finally {
    r.done();
  }
});

test("a gitleaks:allow that exists only in a commit of the change does not hide the credential", { skip }, () => {
  const r = repo();
  try {
    const base = r.write("a.js", "export const a = 1;\n").commit("base");
    const added = r.write("config.js", `export const uploadKey = "${keyId()}"; // gitleaks:allow\n`).commit("add config, with the comment");
    // In the tree the comment hid the line from the scan, and factory mode blocked the comment as a grant the change added.
    const then = factory(r, base);
    assert.equal(then.code, 1, say(then));
    assert.ok(failures(then.doc).some((m) => /^factory: 1 gitleaks:allow grant\(s\) this change added — config\.js:1\./.test(m)), say(then));
    r.remove("config.js").commit("drop the file");
    blocksOnCommit(factory(r, base), added, "config.js:1");
  } finally {
    r.done();
  }
});

test("a .gitleaksignore entry that exists only in a commit of the change does not hide the credential", { skip }, () => {
  const r = repo();
  try {
    const base = r.write("a.js", "export const a = 1;\n").commit("base");
    // The fingerprint as secret-guard prints it: the file's whole path, the rule, the line.
    r.write("config.js", `export const uploadKey = "${keyId()}";\n`).write(".gitleaksignore", `${r.dir}/config.js:aws-access-token:1\n`);
    const added = r.commit("add config, and its fingerprint");
    // The entry does hide the finding from the tree's scan: the default mode passes on it.
    const tree = cli([r.dir, "--json"]);
    assert.equal(tree.code, 0, say(tree));
    r.remove("config.js").remove(".gitleaksignore").commit("drop both");
    blocksOnCommit(factory(r, base), added, "config.js:1");
  } finally {
    r.done();
  }
});

test("what the base held or the pipeline approved is not refused: a gitleaks:allow from the base, and an allowlisted file", { skip }, () => {
  const r = repo();
  const outside = mkdtempSync(path.join(tmpdir(), "factory-commit-secrets-allow-"));
  try {
    const sample = `export const sample = "${keyId()}"; // gitleaks:allow`;
    const base = r.write("docs/sample.js", `${sample}\n`).commit("base");
    r.write("docs/sample.js", "// moved below\n").commit("take the sample out");
    r.write("docs/sample.js", `// moved below\n${sample}\n`).commit("put it back");
    const added = r.write("test/data/key.js", `export const fixture = "${keyId()}";\n`).commit("a fixture");
    r.remove("test/data").commit("drop the fixture");

    // The comment was at the base on that line, so the commit that put the line back added no credential the base did not hold.
    blocksOnCommit(factory(r, base), added, "test/data/key.js:1");

    const allowlist = path.join(outside, "allowlist.json");
    writeFileSync(allowlist, JSON.stringify({ exemptions: [{ kind: "secret-in-commit", path: "test/data", reason: "a generated fixture that was never a live key" }] }));
    const f = factory(r, base, [`--allowlist=${allowlist}`]);
    assert.equal(f.code, 0, say(f));
    assert.deepEqual(failures(f.doc), []);
    assert.deepEqual(f.doc.factory.commits.findings, [{ commit: added, path: "test/data/key.js", line: 1, rule: "aws-access-token", status: "allowlisted", approvedBy: "a generated fixture that was never a live key" }]);
    assert.equal(f.doc.factory.commits.count, 4);
  } finally {
    r.done();
    rmSync(outside, { recursive: true, force: true });
  }
});

test("a file a commit wrote under vendor/, where secret-guard does not scan, blocks though the tree no longer holds it", { skip }, () => {
  const r = repo();
  try {
    const base = r.write("a.js", "export const a = 1;\n").commit("base");
    const added = r.write("vendor/keys/k.js", `export const k = "${keyId()}";\n`).commit("add under vendor");
    r.remove("vendor").commit("drop it");
    const f = factory(r, base);
    assert.equal(f.code, 1, say(f));
    assert.deepEqual(f.doc.couldNotRun, []);
    assert.equal(failures(f.doc).length, 1, say(f));
    assert.ok(failures(f.doc)[0].startsWith(`factory: 1 file a commit of this change wrote where secret-guard's gitleaks allowlist does not scan — commit ${added.slice(0, 12)} vendor/keys/k.js. `), failures(f.doc)[0]);
    assert.equal(f.doc.factory.commits.skipped.length, 1);
  } finally {
    r.done();
  }
});

test("a depth-1 checkout without the commits in between is exit 3, never a pass; with what the Action fetches it is exit 1", { skip }, () => {
  const o = repo();
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-commit-secrets-clone-")));
  try {
    // A pull request: the base, two commits, and the merge commit GitHub checks out.
    o.git("config", "uploadpack.allowAnySHA1InWant", "true");
    const base = o.write("a.js", "export const a = 1;\n").commit("base");
    o.git("checkout", "-q", "-b", "feature");
    const added = o.write("config.js", `export const uploadKey = "${keyId()}";\n`).commit("add config");
    o.write("config.js", "export const uploadKey = process.env.UPLOAD_KEY;\n").commit("read it from the environment");
    o.git("checkout", "-q", "main");
    o.git("merge", "-q", "--no-ff", "-m", "Merge feature into main", "feature");
    const merge = o.git("rev-parse", "HEAD");

    const git = (...args) => {
      const r = spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
      assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout.trim();
    };
    git("init", "-q");
    git("remote", "add", "origin", `file://${o.top}`);
    // As actions/checkout does at its default fetch-depth, and then what the Action fetched before: the base alone.
    git("-c", "protocol.version=2", "fetch", "-q", "--no-tags", "--prune", "--depth=1", "origin", `+${merge}:refs/remotes/pull/1/merge`);
    git("checkout", "-q", "--detach", "refs/remotes/pull/1/merge");
    git("fetch", "-q", "--no-tags", "--depth=1", "origin", base);

    const shallow = cli([dir, "--json", "--factory", `--base=${base}`]);
    assert.equal(shallow.code, 3, say(shallow));
    assert.deepEqual(failures(shallow.doc), []);
    // Two: the merge commit, whose parents are missing, and the base, which without them is not known to be one of them.
    assert.equal(shallow.doc.couldNotRun.length, 1, say(shallow));
    assert.match(shallow.doc.couldNotRun[0], /^factory: the commits between the base \([0-9a-f]{12}\) and the head were not all scanned for credentials — the clone is shallow, and it was cut at 2 commits between the base/);
    assert.equal(shallow.doc.factory.commits.scanned, false);

    const fetched = spawnSync(process.execPath, [FETCH, dir, base], { encoding: "utf8" });
    assert.equal(fetched.status, 0, fetched.stderr);
    assert.match(fetched.stdout, /^factory: 3 commit\(s\) between the base and the head are in the checkout \(fetched: git fetch --deepen=50 origin <sha> <sha>\)\n$/);
    blocksOnCommit(cli([dir, "--json", "--factory", `--base=${base}`]), added, "config.js:1");
  } finally {
    o.done();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a credential in a commit's message blocks, naming the commit and the line of the message", { skip }, () => {
  const r = repo();
  try {
    const key = keyId();
    const base = r.write("a.js", "export const a = 1;\n").commit("base");
    r.write("a.js", "export const a = 2;\n");
    r.git("add", "-A");
    r.git("commit", "-q", "-m", "Fix the upload", "-m", `It failed until the key ${key} was set.`);
    const told = r.git("rev-parse", "HEAD");
    const f = factory(r, base);
    assert.equal(f.code, 1, say(f));
    assert.deepEqual(f.doc.couldNotRun, []);
    assert.equal(failures(f.doc).length, 1, say(f));
    assert.ok(failures(f.doc)[0].startsWith(`factory: 1 credential in the commits of this change — commit ${told.slice(0, 12)} message, line 3 (aws-access-token). `), failures(f.doc)[0]);
    assert.deepEqual(f.doc.factory.commits.findings, [{ commit: told, message: true, line: 3, rule: "aws-access-token", status: "added" }]);
    assert.ok(!f.stdout.includes(key), "the value is not in the report");
    // The default mode is as it was.
    assert.equal(cli([r.dir, "--json"]).code, 0);
  } finally {
    r.done();
  }
});

test("a private key committed with its lines out of order, then put in order by the next commit, is the second commit's", { skip }, () => {
  const r = repo();
  try {
    const pem = privateKeyLines();
    const base = r.write("a.js", "export const a = 1;\n").commit("base");
    // In reverse, no rule matches it: the tree's scan passes on this commit.
    r.write("k.txt", [...pem].reverse().join("\n") + "\n").commit("the lines, last first");
    assert.equal(cli([r.dir, "--json"]).code, 0, "reversed, it is not a finding");
    r.write("k.txt", pem.join("\n") + "\n");
    const ordered = r.commit("put them in order");
    r.remove("k.txt").commit("delete it");
    // Every line's text was in the parent's copy. The credential was not.
    blocksOnCommit(factory(r, base), ordered, "k.txt:1", "private-key");
  } finally {
    r.done();
  }
});
