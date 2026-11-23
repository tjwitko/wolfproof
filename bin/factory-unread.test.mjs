import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

import { localTools } from "../lib/gate-core.mjs";

// Factory mode's list of places the secret scan does not look, from the secret-guard that runs,
// through the real CLI with the real scanner. Credentials are assembled here at run time and written
// only to temporary directories. A run of the CLI is the cost here, so a test writes its cases into
// one change and holds the one run to naming each of them.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "validate.mjs");
const MODULES = path.resolve(__dirname, "..", "node_modules");
const PINNED = path.join(MODULES, "@tjwitko", "secret-guard-mcp");

const B62 = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
const chars = (what, n, set) => Array.from({ length: n }, (_, i) => set[createHash("sha256").update(`wolfproof test fixture: ${what} ${i}`).digest()[0] % set.length]).join("");
const token = (what) => ["gh", "p_"].join("") + chars(what, 36, B62);
const awsKey = () => ["AK", "IA"].join("") + chars("aws", 16, "BCDFGHJKLMNPQRSTVWXZ234567");

function cli(args, env = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000, maxBuffer: 1 << 26, env: { ...process.env, ...env } });
  let doc = null;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    /* said by the assertion that reads it */
  }
  return { code: r.status, doc, messages: (doc?.findings || []).map((f) => f.message) };
}

function repo() {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-unread-")));
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const self = {
    dir,
    write(rel, text) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), text);
      return self;
    },
    commit(m = "c") {
      git("add", "-A", "-f");
      git("commit", "-qm", m);
      return git("rev-parse", "HEAD");
    },
    move(from, to) {
      renameSync(path.join(dir, from), path.join(dir, to));
      return self;
    },
    remove(rel) {
      rmSync(path.join(dir, rel));
      return self;
    },
    done: () => rmSync(dir, { recursive: true, force: true }),
  };
  git("init", "-q");
  self.write("a.js", "export const a = 1;\n");
  self.base = self.commit("base");
  return self;
}

const modes = (r, extra = []) => ({
  plain: cli([r.dir, "--json"]),
  factory: cli([r.dir, "--json", "--factory", `--base=${r.base}`, ...extra]),
});

test("credentials in files the scan now reads block in both modes, each counted", () => {
  const files = {
    "go.sum": `aws = ${awsKey()}\n`,
    "art.svg": `<svg xmlns="http://www.w3.org/2000/svg"><!-- ${token("svg")} --></svg>\n`,
    "bootstrap.js": `// deploy token: ${token("bootstrap")}\n`,
  };
  const r = repo();
  try {
    for (const [rel, text] of Object.entries(files)) r.write(rel, text);
    r.commit();
    const { plain, factory } = modes(r);
    assert.equal(plain.code, 1, `default mode: ${JSON.stringify(plain.messages)}`);
    assert.equal(factory.code, 1, `factory mode: ${JSON.stringify(factory.messages)}`);
    // Each file holds one credential, so three is each of them read. The message is cut at 1,200
    // characters and need not reach the third file's name.
    for (const run of [plain, factory]) {
      assert.ok(run.messages.some((m) => m.startsWith("scan_path: 3 hardcoded credential")), JSON.stringify(run.messages));
    }
  } finally {
    r.done();
  }
});

test("one change writing each kind the scan leaves unread: default mode cannot see them, factory mode names each, an approval clears them, and a lockfile edit beside them costs nothing", () => {
  const lock = (v) => JSON.stringify({ name: "p", version: v, lockfileVersion: 3, requires: true, packages: { "": { name: "p", version: v } } }, null, 2) + "\n";
  const pkg = (v) => JSON.stringify({ name: "p", version: v }) + "\n";
  const unreadText = (what) => `MZ_REGION=maputo\ntoken: ${token(what)}\n`;
  const byName = ["logo.png", "data.zip", "app.browser.js", "assets.png/config.js"];
  const r = repo();
  try {
    r.write("package.json", pkg("1.0.0")).write("package-lock.json", lock("1.0.0")).write("at-base.env", unreadText("at base"));
    r.base = r.commit("with a lockfile");
    for (const rel of byName) r.write(rel, `token: ${token(rel)}\n`);
    for (const rel of ["settings.env", "replaced.env", "gone.env"]) r.write(rel, unreadText(rel));
    r.write("package.json", pkg("1.0.1")).write("package-lock.json", lock("1.0.1")).commit("add");
    // The same blob as the base had, so no commit added it: only the scan of the tree says it is unread.
    r.move("at-base.env", "renamed.env").write("replaced.env", "REGION=maputo\n").move("gone.env", "gone-next.js").commit("move");
    r.remove("gone-next.js").commit("delete");

    const { plain, factory } = modes(r);
    assert.equal(plain.code, 0, `default mode: ${JSON.stringify(plain.messages)}`);
    assert.equal(factory.code, 1, "factory mode");
    const said = (re, what) => {
      const line = factory.messages.find((m) => re.test(m));
      assert.ok(line, `${what}: ${JSON.stringify(factory.messages)}`);
      return line;
    };
    const image = said(/under the project's top, where secret-guard's gitleaks allowlist does not scan it \(image\) — logo\.png\./, "logo.png");
    const archive = said(/under the project's top, where secret-guard does not read a file whose name says it is an archive, whatever it holds — /, "archives");
    for (const rel of ["data.zip", "app.browser.js"]) assert.ok(archive.includes(rel), rel);
    const inDir = said(/under assets\.png, where .* — assets\.png\/config\.js\./, "a file under a directory named like an unread file");
    for (const line of [image, archive, inDir]) {
      assert.match(line, /approve (?:the|each) file by its path \(kind "skipped-location"\)/);
      assert.ok(!/approve \.(\s|$)/.test(line), "and never the whole project");
    }
    for (const rel of ["settings.env", "replaced.env", "gone.env", "renamed.env"]) {
      said(new RegExp(`${rel.replace(".", "\\.")}(?: \\(for its|: )[^;]*first bytes`), rel);
    }
    assert.ok(!factory.messages.some((m) => m.includes("package-lock.json")), "the lockfile edit is not named");

    const allow = path.join(mkdtempSync(path.join(tmpdir(), "factory-unread-allow-")), "allow.json");
    const paths = [...byName, "settings.env", "replaced.env", "gone.env", "renamed.env"];
    writeFileSync(allow, JSON.stringify({ exemptions: paths.map((p) => ({ kind: "skipped-location", path: p, reason: "a test" })) }));
    const approved = cli([r.dir, "--json", "--factory", `--base=${r.base}`, `--allowlist=${allow}`]);
    rmSync(path.dirname(allow), { recursive: true, force: true });
    assert.equal(approved.code, 0, `approved: ${JSON.stringify(approved.messages)}`);
  } finally {
    r.done();
  }
});

test("credentials that moved through a name and were deleted, and one in a commit message, block in factory mode only", () => {
  const r = repo();
  try {
    r.write("go.sum", `aws = ${awsKey()}\n`).write("logo.png", `token: ${token("moved")}\n`).commit("add");
    r.move("go.sum", "moved-sum.js").move("logo.png", "moved-png.js").commit("rename");
    // A message is read however it begins.
    r.remove("moved-sum.js").remove("moved-png.js").commit(`MZ region fix\n\ntoken: ${token("message")}\n`);
    const { plain, factory } = modes(r);
    assert.equal(plain.code, 0, `default mode: ${JSON.stringify(plain.messages)}`);
    assert.equal(factory.code, 1, `factory mode: ${JSON.stringify(factory.messages)}`);
    const line = factory.messages.find((m) => m.startsWith("factory: 3 credentials in the commits of this change"));
    assert.ok(line, JSON.stringify(factory.messages));
    for (const part of ["go.sum:1", "moved-png.js:1", "message, line 3 (github-pat)"]) assert.ok(line.includes(part), part);
  } finally {
    r.done();
  }
});

test("the agent loop's write_file, with the real scanner: content the scan skips for its first bytes does not reach disk", async () => {
  const scanner = await import(pathToFileURL(path.join(PINNED, "lib", "gitleaks.mjs")).href);
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-unread-write-")));
  try {
    const out = String(localTools(dir, scanner).write_file.run({ path: "settings.env", content: `MZ_REGION=maputo\ntoken: ${token("write")}\n` }));
    assert.match(out, /^REFUSED: settings\.env was NOT written: the credential scan could not read it/);
    assert.match(out, /first bytes/);
    assert.ok(!out.includes(token("write")), "and the refusal does not hold the value");
    assert.throws(() => readFileSync(path.join(dir, "settings.env")), /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a project at a path the scan will not enter is exit 3 in both modes, never clean", () => {
  const outer = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-unread-outer-")));
  const dir = path.join(outer, "vendor", "app");
  mkdirSync(dir, { recursive: true });
  const git = (...args) => assert.equal(spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" }).status, 0, args.join(" "));
  try {
    git("init", "-q");
    writeFileSync(path.join(dir, "a.js"), "export const a = 1;\n");
    git("add", "-A");
    git("commit", "-qm", "base");
    const base = spawnSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();
    writeFileSync(path.join(dir, "config.js"), `// ${token("vendor project")}\n`);
    git("add", "-A");
    git("commit", "-qm", "c");
    assert.equal(cli([dir, "--json"]).code, 3, "default mode");
    assert.equal(cli([dir, "--json", "--factory", `--base=${base}`]).code, 3, "factory mode");
  } finally {
    rmSync(outer, { recursive: true, force: true });
  }
});

test("a list the gate cannot read is exit 3, whatever else the run found", () => {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "factory-unread-sg-")));
  const sg = path.join(dir, "node_modules", "@tjwitko", "secret-guard-mcp");
  mkdirSync(path.dirname(sg), { recursive: true });
  cpSync(PINNED, sg, { recursive: true });
  for (const dep of ["@modelcontextprotocol", "zod"]) {
    try {
      symlinkSync(path.join(MODULES, dep), path.join(dir, "node_modules", dep));
    } catch {
      /* the copy brought it */
    }
  }
  const listFile = path.join(sg, "gitleaks", "unread-paths.json");
  const good = JSON.parse(readFileSync(listFile, "utf8"));
  const env = { SECRETGUARD_SERVER: path.join(sg, "index.mjs") };
  const r = repo();
  try {
    r.write("b.js", "export const b = 2;\n").commit();
    assert.equal(cli([r.dir, "--json", "--factory", `--base=${r.base}`], env).code, 0, "with the list as it is");
    // One fault through the CLI: lib/secret-guard-unread.test.mjs holds each kind of fault to the same error.
    writeFileSync(listFile, JSON.stringify({ ...good, entries: [...good.entries, { kind: "x", from: "y", pattern: "(?i)\\.png$", flags: "", directories: true }] }));
    const f = cli([r.dir, "--json", "--factory", `--base=${r.base}`], env);
    assert.equal(f.code, 3, `a Go pattern: exit ${f.code}`);
    assert.ok(f.doc.couldNotRun.some((c) => c.startsWith("factory: secret-guard's list of what it does not read") && /\(x\) does not compile/.test(c)), JSON.stringify(f.doc.couldNotRun));
  } finally {
    r.done();
    rmSync(dir, { recursive: true, force: true });
  }
});
