import test from "node:test";
import assert from "node:assert/strict";

import { parseKnown, familyOf, EVERY_FINDING, staleKnownLine, knownLine, splitAt } from "./known.mjs";
import { applyReviews } from "./reviewed.mjs";

test("an entry needs an ID of a family a snapshot can hold; a secret's or a build's is ignored, a repeat is one entry", () => {
  const { entries, ignored } = parseKnown(
    {
      known: [
        { id: "sast:python-sql-injection:app.py:9a31b23f", where: "app.py:12" },
        { id: "dependencies:npm/lodash:GHSA-jf85-cpcp-j695" },
        { id: "dependencies:npm/lodash:GHSA-jf85-cpcp-j695" },
        { id: "scan_path:conf.py:1" },
        { id: "build_check:ruff" },
        { id: "*" },
        "presence:empty:a.js",
        { id: " quality:patch:tests/test_a.py:pkg.mod.f " },
      ],
    },
    "test"
  );
  assert.deepEqual(entries, [
    { id: "sast:python-sql-injection:app.py:9a31b23f", kind: "known", where: "app.py:12", source: "test" },
    { id: "dependencies:npm/lodash:GHSA-jf85-cpcp-j695", kind: "known", source: "test" },
    { id: "quality:patch:tests/test_a.py:pkg.mod.f", kind: "known", source: "test" },
  ]);
  assert.equal(ignored.length, 4);
  assert.match(ignored[0].why, /^needs an "id" naming a finding of sast, authentication, codeql, dependencies, identity, dockerfile, presence or quality$/);
  assert.match(parseKnown({ reviewed: [] }, "x").ignored[0].why, /has no "known" list/);
  assert.equal(familyOf("identity:auth.db-password:db.py:1234abcd"), "identity");
  assert.equal(familyOf("secret:x"), null);
});

test("a review of a finding wins over the snapshot's entry; the every-finding entry takes only blocking findings", () => {
  const findings = [
    { id: "sast:a:f:1", blocking: true },
    { id: "sast:b:f:2", blocking: true },
    { id: "sast:c:f:3", blocking: false },
  ];
  const review = { id: "sast:a:f:1", reason: "fixture", source: "r" };
  const known = { id: "sast:a:f:1", kind: "known", source: "k" };
  // In either order.
  for (const active of [[review, known], [known, review]]) {
    const { reviewed } = applyReviews(findings, active);
    assert.deepEqual(reviewed.map((r) => [r.id, r.review.source]), [["sast:a:f:1", "r"]]);
  }
  const { kept, reviewed } = applyReviews(findings, [review, EVERY_FINDING]);
  assert.deepEqual(reviewed.map((r) => [r.id, r.review.kind || "review"]), [["sast:a:f:1", "review"], ["sast:b:f:2", "known"]]);
  assert.deepEqual(kept.map((f) => f.id), ["sast:c:f:3"]);
});

test("the report's lines: a count of known findings, and the stale entries named, five at most", () => {
  assert.equal(knownLine(1, [".wolfproof-known.json"]), "1 finding known from the snapshot (.wolfproof-known.json), not blocking — --json lists it");
  const stale = Array.from({ length: 7 }, (_, i) => ({ id: `presence:empty:${i}.js` }));
  assert.equal(
    staleKnownLine(stale),
    "known: 7 snapshot entries match no finding — presence:empty:0.js, presence:empty:1.js, presence:empty:2.js, presence:empty:3.js, presence:empty:4.js, +2 more. The finding was fixed or the code it names changed; `wolfproof known` removes them."
  );
  assert.deepEqual(splitAt("src/a:b.py:12"), { file: "src/a:b.py", line: 12 });
  assert.deepEqual(splitAt("Dockerfile"), { file: "Dockerfile", line: null });
});
