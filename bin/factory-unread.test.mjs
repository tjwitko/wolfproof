import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

// Factory mode's list of places the secret scan does not look, from the secret-guard that runs,
// through the real CLI with the real scanner. Credentials are assembled here at run time and written
// only to temporary directories.

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
    renameToConfigAndDelete(from) {
      renameSync(path.join(dir, from), path.join(dir, "config.js"));
      self.commit("rename");
      rmSync(path.join(dir, "config.js"));
      return self.commit("delete");
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

test("a credential in a file the scan now reads blocks in both modes", () => {
  for (const [rel, text] of [
    ["go.sum", `aws = ${awsKey()}\n`],
    ["art.svg", `<svg xmlns="http://www.w3.org/2000/svg"><!-- ${token("svg")} --></svg>\n`],
    ["bootstrap.js", `// deploy token: ${token("bootstrap")}\n`],
  ]) {
    const r = repo();
    try {
      r.write(rel, text).commit();
      const { plain, factory } = modes(r);
      assert.equal(plain.code, 1, `${rel}, default mode: ${JSON.stringify(plain.messages)}`);
      assert.equal(factory.code, 1, `${rel}, factory mode: ${JSON.stringify(factory.messages)}`);
      assert.ok(plain.messages.some((m) => m.startsWith("scan_path: 1 hardcoded credential")), rel);
    } finally {
      r.done();
    }
  }
});

test("text holding a token under a name the scan skips: default mode cannot see it, factory mode blocks the write", () => {
  for (const [rel, says] of [
    ["logo.png", /wrote under the project's top, where secret-guard's gitleaks allowlist does not scan it \(image\) — logo\.png\./],
    ["data.zip", /wrote under the project's top, where secret-guard does not read a file whose name says it is an archive, whatever it holds — data\.zip\./],
    ["app.browser.js", /whose name says it is an archive, whatever it holds — app\.browser\.js\./],
  ]) {
    const r = repo();
    try {
      r.write(rel, `token: ${token(rel)}\n`).commit();
      const { plain, factory } = modes(r);
      assert.equal(plain.code, 0, `${rel}, default mode`);
      assert.equal(factory.code, 1, `${rel}, factory mode`);
      const line = factory.messages.find((m) => says.test(m));
      assert.ok(line, `${rel}: ${JSON.stringify(factory.messages)}`);
      assert.match(line, /approve the file by its path \(kind "skipped-location"\)/);
      assert.ok(!/approve \.(\s|$)/.test(line), "and never the whole project");

      const allow = path.join(mkdtempSync(path.join(tmpdir(), "factory-unread-allow-")), "allow.json");
      writeFileSync(allow, JSON.stringify({ exemptions: [{ kind: "skipped-location", path: rel, reason: "a test" }] }));
      const approved = cli([r.dir, "--json", "--factory", `--base=${r.base}`, `--allowlist=${allow}`]);
      assert.equal(approved.code, 0, `${rel}, approved: ${JSON.stringify(approved.messages)}`);
      rmSync(path.dirname(allow), { recursive: true, force: true });
    } finally {
      r.done();
    }
  }
});

test("a credential that moved through a name, and was then deleted, blocks in factory mode only", () => {
  for (const from of ["go.sum", "logo.png"]) {
    const r = repo();
    try {
      r.write(from, from === "go.sum" ? `aws = ${awsKey()}\n` : `token: ${token("moved")}\n`).commit("add");
      r.renameToConfigAndDelete(from);
      const { plain, factory } = modes(r);
      assert.equal(plain.code, 0, `${from}, default mode`);
      assert.equal(factory.code, 1, `${from}, factory mode: ${JSON.stringify(factory.messages)}`);
      assert.ok(factory.messages.some((m) => m.startsWith("factory: 1 credential in the commits of this change")), from);
    } finally {
      r.done();
    }
  }
});

test("an edited lockfile with no credential passes in both modes", () => {
  const lock = (v) => JSON.stringify({ name: "p", version: v, lockfileVersion: 3, requires: true, packages: { "": { name: "p", version: v } } }, null, 2) + "\n";
  const r = repo();
  try {
    r.write("package.json", JSON.stringify({ name: "p", version: "1.0.0" }) + "\n").write("package-lock.json", lock("1.0.0"));
    r.base = r.commit("with a lockfile");
    r.write("package.json", JSON.stringify({ name: "p", version: "1.0.1" }) + "\n").write("package-lock.json", lock("1.0.1")).commit();
    const { plain, factory } = modes(r);
    assert.equal(plain.code, 0, JSON.stringify(plain.messages));
    assert.equal(factory.code, 0, JSON.stringify(factory.messages));
  } finally {
    r.done();
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
    for (const [what, text, why] of [
      ["not JSON", "{ nope", /it is not JSON/],
      ["another schema", JSON.stringify({ ...good, schema: 2 }), /schema 2/],
      ["a Go pattern", JSON.stringify({ ...good, entries: [...good.entries, { kind: "x", from: "y", pattern: "(?i)\\.png$", flags: "" }] }), /\(x\) does not compile/],
    ]) {
      writeFileSync(listFile, text);
      const f = cli([r.dir, "--json", "--factory", `--base=${r.base}`], env);
      assert.equal(f.code, 3, `${what}: exit ${f.code}`);
      assert.ok(f.doc.couldNotRun.some((c) => c.startsWith("factory: secret-guard's list of what it does not read") && why.test(c)), `${what}: ${JSON.stringify(f.doc.couldNotRun)}`);
    }
  } finally {
    r.done();
    rmSync(dir, { recursive: true, force: true });
  }
});
