import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "child_process";
import { createHash } from "crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

import { existing } from "./fetch.mjs";

// The route run itself is the check on the counts; it clones, so it is run by hand (npm run
// calibration:routes). These hold routes.json to what that run relies on, and drive the runner
// offline: a local repository, a local package tarball and a local corpus archive.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const routes = JSON.parse(readFileSync(path.join(__dirname, "routes.json"), "utf8"));
const sast = new Map(JSON.parse(readFileSync(path.join(__dirname, "manifest.json"), "utf8")).apps.map((a) => [a.name, a]));
const KEYS = ["routes", "open", "exempt", "unread", "blocking"];

test("every app is pinned exactly and was measured", () => {
  const names = new Set();
  const corpus = execFileSync("tar", ["-tzf", path.join(__dirname, "..", "corpus", "fixtures.tar.gz")], { encoding: "utf8" });
  for (const app of routes.apps) {
    assert.ok(!names.has(app.name), `${app.name} is listed twice, and a checkouts directory holds one of each name`);
    names.add(app.name);
    if (app.from === "manifest") assert.ok(sast.has(app.name), `${app.name} is not in manifest.json`);
    else if (app.from === "corpus") assert.match(corpus, new RegExp(`^(\\./)?${app.name.replace(/[.]/g, "\\.")}/`, "m"), `${app.name} is not in the corpus archive`);
    else if (app.npm) {
      assert.match(app.version, /^\d+\.\d+\.\d+$/, `${app.name}: a range can move under the counts`);
      assert.match(app.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/, app.name);
      assert.ok(Object.keys(app.paths).length, app.name);
    } else {
      assert.match(app.commit, /^[0-9a-f]{40}$/, `${app.name}: a branch or short SHA can move under the counts`);
      assert.match(app.repo, /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/, app.name);
      assert.ok(!sast.has(app.name), `${app.name} has its own pin here and another in manifest.json`);
    }
    for (const k of KEYS) assert.ok(Number.isInteger(app.expected?.[k]), `${app.name}: ${k} never measured`);
    assert.ok(app.expected.open <= app.expected.routes, app.name);
  }
});

const OPEN_ROUTE = 'const express = require("express");\nconst app = express();\napp.delete("/records/:id", (req, res) => res.send("gone"));\napp.listen(3000);\n';

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "routes-test-"));
  const git = (dir, ...args) => execFileSync("git", ["-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t", ...args], { stdio: "ignore" });
  // A repository whose pinned commit has one open route, and a later commit with a second one.
  const repo = path.join(root, "repo");
  mkdirSync(repo);
  git(repo, "init", "-q");
  writeFileSync(path.join(repo, "server.js"), OPEN_ROUTE);
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "one");
  const commit = execFileSync("git", ["-C", repo, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  writeFileSync(path.join(repo, "more.js"), OPEN_ROUTE.replace("/records/:id", "/users/:id"));
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "two");
  // A package whose kept path has one open route and whose dropped path has another.
  const pkg = path.join(root, "pkg");
  mkdirSync(path.join(pkg, "package", "lib", "server"), { recursive: true });
  mkdirSync(path.join(pkg, "package", "examples"), { recursive: true });
  writeFileSync(path.join(pkg, "package", "lib", "server", "app.js"), OPEN_ROUTE);
  writeFileSync(path.join(pkg, "package", "examples", "app.js"), OPEN_ROUTE.replace("/records/:id", "/example/:id"));
  const checkouts = path.join(root, "checkouts");
  mkdirSync(checkouts);
  execFileSync("tar", ["-czf", path.join(checkouts, "pkg.tgz"), "-C", pkg, "package"]);
  const integrity = `sha512-${createHash("sha512").update(readFileSync(path.join(checkouts, "pkg.tgz"))).digest("base64")}`;
  // A corpus archive with one deliverable.
  mkdirSync(path.join(root, "corpus", "deliverable"), { recursive: true });
  writeFileSync(path.join(root, "corpus", "deliverable", "server.js"), OPEN_ROUTE);
  execFileSync("tar", ["-czf", path.join(root, "corpus.tgz"), "-C", path.join(root, "corpus"), "deliverable"]);
  const one = { routes: 1, open: 1, exempt: 0, unread: 0, blocking: 1 };
  const manifest = {
    apps: [
      { name: "repo", repo, commit, expected: one },
      { name: "pkg", npm: "pkg", version: "1.0.0", integrity, paths: { server: "package/lib/server" }, expected: one },
      { name: "deliverable", from: "corpus", expected: one },
    ],
  };
  writeFileSync(path.join(root, "routes.json"), JSON.stringify(manifest));
  writeFileSync(path.join(root, "sast.json"), JSON.stringify({ apps: [] }));
  const run = (...extra) =>
    spawnSync(process.execPath, [path.join(__dirname, "routes.mjs"), `--manifest=${path.join(root, "routes.json")}`, `--sast-manifest=${path.join(root, "sast.json")}`, `--corpus=${path.join(root, "corpus.tgz")}`, `--checkouts=${checkouts}`, ...extra], { encoding: "utf8" });
  return { root, repo, commit, checkouts, manifest, run };
}

test("the runner reads the pinned commit, the kept paths of the package, and the corpus deliverable", () => {
  const f = fixture();
  try {
    const r = f.run();
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /3 apps: 3 routes, 3 open; 3 apps blocked/);
    assert.match(r.stdout, /all 3 apps match/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("a count that moved is drift, exit 1, and --update freezes what was measured", () => {
  const f = fixture();
  try {
    f.manifest.apps[0].expected = { ...f.manifest.apps[0].expected, open: 0 };
    writeFileSync(path.join(f.root, "routes.json"), JSON.stringify(f.manifest));
    const r = f.run();
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /DRIFT {4}repo {2}open 0 -> 1/);
    const u = f.run("--update");
    assert.equal(u.status, 0, u.stdout + u.stderr);
    assert.equal(JSON.parse(readFileSync(path.join(f.root, "routes.json"), "utf8")).apps[0].expected.open, 1);
    assert.equal(f.run().status, 0);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("a checkout is reused only when it is the pinned commit and nothing else", () => {
  const f = fixture();
  try {
    const dir = path.join(f.checkouts, "repo");
    execFileSync("git", ["clone", "-q", f.repo, dir]);
    assert.equal(existing(f.checkouts, "repo", f.commit), null, "a later commit is not the pinned one");
    execFileSync("git", ["-C", dir, "checkout", "-q", f.commit]);
    assert.deepEqual(existing(f.checkouts, "repo", f.commit), { dir, kept: true });
    writeFileSync(path.join(dir, "extra.js"), OPEN_ROUTE);
    assert.equal(existing(f.checkouts, "repo", f.commit), null, "an added file would be measured");
    rmSync(path.join(dir, "extra.js"));
    writeFileSync(path.join(dir, ".gitignore"), "ignored.js\n");
    execFileSync("git", ["-C", dir, "add", ".gitignore"]);
    assert.equal(existing(f.checkouts, "repo", f.commit), null, "a staged file is a change");
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("a package tarball without the pinned integrity is not used, and --offline fetches nothing", () => {
  const f = fixture();
  try {
    // The local tarball is not the pinned one, so it is not read; offline, nothing else is fetched,
    // and the app is incomplete, exit 3 -- never a match.
    f.manifest.apps[1].integrity = `sha512-${"A".repeat(86)}==`;
    writeFileSync(path.join(f.root, "routes.json"), JSON.stringify(f.manifest));
    const r = f.run("--offline");
    assert.equal(r.status, 3, r.stdout + r.stderr);
    assert.match(r.stdout, /INCOMPLETE pkg/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});
