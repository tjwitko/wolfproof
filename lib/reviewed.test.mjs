import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { parseReviews, activeReviews, lineFingerprint, withIds, applyReviews, reviewedLine, reviewableLine, loadProjectReviews, REVIEW_FILE } from "./reviewed.mjs";

test("an entry needs an ID naming a reviewable finding and a reason; a malformed expiry is not a date", () => {
  const { entries, ignored } = parseReviews(
    {
      reviewed: [
        { id: "sast:python-sql-injection:app.py:9a31b23f", reason: "fixture", reviewer: "tj", expires: "2027-01-01" },
        { id: "sast:python-sql-injection:app.py:00000000" },
        { id: "sast:python-sql-injection:app.py:11111111", reason: "   " },
        { id: "*", reason: "everything" },
        { id: "dockerfile:EOL:Dockerfile", reason: "no IDs for this check yet" },
        { id: "authentication:GET /x:app.py", reason: "public", expires: "next year" },
        { id: "authentication:GET /y:app.py", reason: "public" },
      ],
    },
    "test"
  );
  assert.deepEqual(entries.map((e) => e.id), ["sast:python-sql-injection:app.py:9a31b23f", "authentication:GET /y:app.py"]);
  assert.deepEqual(entries[0], { id: "sast:python-sql-injection:app.py:9a31b23f", reason: "fixture", reviewer: "tj", expires: "2027-01-01", source: "test" });
  assert.deepEqual(ignored.map((i) => i.why), [
    "gives no reason",
    "gives no reason",
    'needs an "id" naming a finding of sast or authentication',
    'needs an "id" naming a finding of sast or authentication',
    'has an "expires" that is not a date, YYYY-MM-DD',
  ]);
  assert.match(parseReviews({ exemptions: [] }, "x").ignored[0].why, /has no "reviewed" list/);
});

test("an entry applies through its expiry date and not after it", () => {
  const e = (expires) => ({ id: `sast:r:f:${expires}`, reason: "x", expires });
  const { active, expired } = activeReviews([e("2026-10-25"), e("2026-10-26"), { id: "sast:r:f:none", reason: "x" }], "2026-10-26");
  assert.deepEqual(active.map((x) => x.id), ["sast:r:f:2026-10-26", "sast:r:f:none"]);
  assert.deepEqual(expired.map((x) => x.id), ["sast:r:f:2026-10-25"]);
});

test("a fingerprint ignores whitespace and nothing else; identical lines are told apart by order", () => {
  assert.equal(lineFingerprint("  db.execute(q)  "), lineFingerprint("db.execute(q)"));
  assert.equal(lineFingerprint("db.execute( q )"), lineFingerprint("db.execute( q )"));
  assert.notEqual(lineFingerprint("db.execute(q)"), lineFingerprint("db.execute(q2)"));
  assert.notEqual(lineFingerprint("call(x)"), lineFingerprint("call(x)", "def helper(x):"), "the helper's line is part of a helper finding's ID");
  const ids = withIds([{ k: "a" }, { k: "b" }, { k: "a" }, { k: "a" }], (x) => `sast:r:f:${x.k}`).map((x) => x.id);
  assert.deepEqual(ids, ["sast:r:f:a", "sast:r:f:b", "sast:r:f:a#2", "sast:r:f:a#3"]);
});

test("a review covers exactly the finding it names", () => {
  const findings = [{ id: "sast:r:f:a" }, { id: "sast:r:f:a#2" }, { id: "sast:r:f:b" }];
  const { kept, reviewed } = applyReviews(findings, [{ id: "sast:r:f:a", reason: "ok", source: "t" }]);
  assert.deepEqual(kept.map((f) => f.id), ["sast:r:f:a#2", "sast:r:f:b"]);
  assert.deepEqual(reviewed.map((f) => f.id), ["sast:r:f:a"]);
});

test("an unreadable project list applies nothing and says so", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "reviewed-"));
  try {
    writeFileSync(path.join(dir, REVIEW_FILE), "{ not json");
    const r = loadProjectReviews(dir);
    assert.deepEqual(r.entries, []);
    assert.match(r.error, /could not be read .* so no review in it was applied/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Two renderers print the result, the CLI and the script in action.yml, and they must agree
// (AGENTS.md). The Action's line is rendered here from its own template.
test("the Action prints a reviewed finding exactly as the CLI does", () => {
  const yml = readFileSync(new URL("../action.yml", import.meta.url), "utf8");
  const m = /console\.log\(`reviewed      : (.*?)`\);/.exec(yml);
  assert.ok(m, "action.yml renders reviewed findings");
  const render = new Function("v", `return \`${m[1]}\`;`);
  for (const review of [
    { reason: "public page", source: ".wolfproof-reviewed.json" },
    { reason: "admin only", reviewer: "tj", expires: "2027-04-01", source: "--reviewed /tmp/r.json" },
  ]) {
    const finding = { id: "authentication:GET /x:app.py", where: "GET /x (app.py:5)", review };
    const v = { id: finding.id, where: finding.where, reason: review.reason, reviewer: review.reviewer || null, expires: review.expires || null, source: review.source };
    assert.equal(render(v), reviewedLine(finding));
  }
});

test("the Action points at wolfproof review exactly as the CLI does", () => {
  const yml = readFileSync(new URL("../action.yml", import.meta.url), "utf8");
  const m = /console\.log\(`reviewable    : (.*?)\\n`\);/.exec(yml);
  assert.ok(m, "action.yml renders the pointer to wolfproof review");
  const render = new Function("rv", `return \`${m[1]}\`;`);
  for (const [n, project] of [[1, "."], [3, "services/api"]]) {
    assert.equal(render({ n, project }), reviewableLine(n, project));
  }
  assert.equal(reviewableLine(1, "."), "1 injection or authentication finding above can be marked reviewed once read — wolfproof review . lists its ID");
});
