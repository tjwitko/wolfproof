import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

import { FALLBACK_UNREAD, reportedUnread, secretGuardUnread, unreadMatch } from "./secret-guard-unread.mjs";
import { secretGuardAllowlist, uncheckedLocation } from "./factory.mjs";

// Factory mode's list of places the secret scan does not look comes from the secret-guard that will
// run. The fallback is for one from before the file existed, and is the only copy here.

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PINNED = path.join(HERE, "..", "node_modules", "@tjwitko", "secret-guard-mcp");

/** A stand-in for a secret-guard install whose list holds `text`, or has no list. */
function install(text) {
  const dir = mkdtempSync(path.join(tmpdir(), "sg-unread-"));
  mkdirSync(path.join(dir, "gitleaks"));
  if (text !== undefined) writeFileSync(path.join(dir, "gitleaks", "unread-paths.json"), text);
  return { entry: path.join(dir, "index.mjs"), done: () => rmSync(dir, { recursive: true, force: true }) };
}
const entry = (over = {}) => ({ kind: "image", pattern: "\\.png$", flags: "i", directories: true, ...over });

test("the fallback list is the pinned secret-guard's, entry for entry", () => {
  const doc = JSON.parse(readFileSync(path.join(PINNED, "gitleaks", "unread-paths.json"), "utf8"));
  assert.deepEqual(
    FALLBACK_UNREAD,
    doc.entries.map(({ kind, pattern, flags, directories }) => ({ kind, pattern, flags, directories })),
    "lib/secret-guard-unread.mjs differs from the list in the pinned secret-guard: copy its entries"
  );
});

test("the list is read from the secret-guard that will run", () => {
  const i = install(JSON.stringify({ schema: 1, entries: [entry({ pattern: "\\.only-here$", flags: "" })] }));
  try {
    const r = secretGuardUnread(i.entry);
    assert.equal(r.error, null);
    assert.equal(r.source, "secret-guard");
    assert.deepEqual(r.patterns.map((re) => re.source), ["\\.only-here$"]);
    assert.equal(r.patterns[0].unreadKind, "image");
  } finally {
    i.done();
  }
});

test("an older secret-guard, with no list, gets the fallback and is not an error", () => {
  const i = install();
  try {
    const r = secretGuardUnread(i.entry);
    assert.equal(r.error, null);
    assert.equal(r.source, "fallback");
    assert.equal(r.patterns.length, FALLBACK_UNREAD.length);
  } finally {
    i.done();
  }
  assert.equal(secretGuardUnread(null).source, "fallback");
});

test("a list that is there and cannot be read is an error, never fewer patterns", () => {
  const cases = {
    "not JSON": ["{ nope", /not JSON/],
    "another schema": [JSON.stringify({ schema: 2, entries: [entry()] }), /schema 2/],
    "no schema": [JSON.stringify({ entries: [entry()] }), /schema undefined/],
    "no entries": [JSON.stringify({ schema: 1, entries: [] }), /lists nothing/],
    "entries not a list": [JSON.stringify({ schema: 1, entries: "all" }), /lists nothing/],
    "no pattern": [JSON.stringify({ schema: 1, entries: [entry(), entry({ pattern: undefined })] }), /entry 1 has no kind or no pattern/],
    "no kind": [JSON.stringify({ schema: 1, entries: [entry({ kind: "" })] }), /entry 0 has no kind/],
    "other flags": [JSON.stringify({ schema: 1, entries: [entry({ flags: "g" })] }), /entry 0 \(image\) has flags "g"/],
    "no word on directories": [JSON.stringify({ schema: 1, entries: [entry({ directories: undefined })] }), /entry 0 \(image\) does not say whether it applies to directories/],
    "Go syntax": [JSON.stringify({ schema: 1, entries: [entry(), entry({ kind: "x", pattern: "(?i)\\.png$", flags: "" })] }), /entry 1 \(x\) does not compile/],
  };
  for (const [what, [text, why]] of Object.entries(cases)) {
    const i = install(text);
    try {
      const r = secretGuardUnread(i.entry);
      assert.match(r.error || "", why, what);
      assert.equal(r.patterns.length, FALLBACK_UNREAD.length, `${what}: the judgement still has the whole fallback`);
    } finally {
      i.done();
    }
  }
});

test("what stays unread is a location, and what is now read is not", () => {
  const gitleaksAllow = secretGuardAllowlist(path.join(PINNED, "index.mjs"));
  const at = (rel) => uncheckedLocation(rel, { gitleaksAllow });
  for (const rel of ["logo.png", "assets/font.woff2", "doc.pdf", "app.exe", "bower_components/x/y.js", "env/lib64/x.py", "lib/python3.11/x.py"]) {
    assert.match(at(rel)?.why || "", /gitleaks allowlist does not scan it \(/, rel);
  }
  for (const rel of ["data.zip", "data.tar.gz", "app.browser.js", "deploy.target.yaml"]) {
    assert.match(at(rel)?.why || "", /name says it is an archive/, rel);
  }
  for (const rel of ["go.sum", "go.mod", "package-lock.json", "yarn.lock", "art.svg", "bootstrap.js", "gradlew", "a.bin", "lib.dll", "settings.v2", "mango.sum", "data.tgz", "src/app.js"]) {
    assert.equal(at(rel), null, rel);
  }
});

test("a file skipped for its name is approved by its path, and the message never says to approve the whole project", () => {
  const gitleaksAllow = secretGuardAllowlist(path.join(PINNED, "index.mjs"));
  for (const rel of ["logo.png", "assets/font.woff2", "doc.pdf", "app.exe", "x.gem", "my.gitleaks.toml", "data.zip", "app.browser.js"]) {
    assert.equal(uncheckedLocation(rel, { gitleaksAllow }).byName, true, rel);
  }
  for (const rel of ["bower_components/x/y.js", "env/lib64/x.py", "lib/python3.11/x.py", "vendor/a.js"]) {
    assert.ok(!uncheckedLocation(rel, { gitleaksAllow }).byName, rel);
  }
});

test("a path is unread through a parent directory, an archive only by its own name, and case folds as the scanner's does", () => {
  const patterns = secretGuardAllowlist(path.join(PINNED, "index.mjs"));
  for (const rel of ["logo.png/config.js", "docs.pdf/notes.md", "pkg.gem/lib/x.rb", "x.gitleaks.toml/y.js", "img.JPG/z.yaml", "a/b.ttf/c/d.css", "a.xl\u017fx", "a.\u017fuo", "pkg\u212a-1.2.dist-info/RECORD"]) {
    assert.ok(unreadMatch(rel, patterns), rel);
    assert.ok(uncheckedLocation(rel, { gitleaksAllow: patterns }), rel);
  }
  for (const rel of ["x.gz/inner.js", "data.zip/a.js", "X.GEM", "NODE_MODULES/x.js", "Vendor/Bundle/x.rb", "a.\u017fz"]) {
    assert.equal(unreadMatch(rel, patterns), undefined, rel);
    assert.equal(uncheckedLocation(rel, { gitleaksAllow: patterns }), null, rel);
  }
});

test("the scan's own list: a file, what is under a directory, and an entry the gate cannot place is an error", () => {
  const root = "/p";
  const said = reportedUnread([{ path: "/p/s.env", kind: "first-bytes", mime: "application/pdf" }, { path: "/p/a.ttf", kind: "directory" }, { path: "/p/logo.png", kind: "file" }], root);
  assert.equal(said.at("s.env").kind, "first-bytes");
  assert.equal(said.at("a.ttf/x.css").kind, "directory");
  assert.equal(said.at("logo.png").kind, "file");
  assert.equal(said.at("a.ttfx"), null);
  assert.equal(said.at("src/s.env"), null);
  for (const bad of ["all", [{ path: null, kind: "file" }], [{ path: "x", kind: "file" }], [{ path: "/p/a", kind: "other" }], [{ path: "/elsewhere/a", kind: "file" }], [{ path: "/p", kind: "directory" }]]) {
    assert.ok(reportedUnread(bad, root).error, JSON.stringify(bad));
  }
});
