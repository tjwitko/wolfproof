// Reviewed findings through the whole check run (lib/gate-core.mjs validateProject): what is applied,
// and every entry that did nothing -- stale, expired, ignored -- reported rather than dropped.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { validateProject } from "./gate-core.mjs";
import { REVIEW_FILE } from "./reviewed.mjs";

async function project(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "reviewed-gate-"));
  for (const [rel, contents] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), contents);
  }
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const APP = "const app = require('express')();\napp.post('/hooks/stripe', receive);\napp.get('/report', report);\n";

test("a reviewed route is listed and not counted; stale, expired and reasonless entries are reported", async () => {
  const reviews = {
    reviewed: [
      { id: "authentication:POST /hooks/stripe:app.js", reason: "verifies Stripe's signature in the handler", reviewer: "tj" },
      { id: "authentication:GET /gone:app.js", reason: "the route was removed" },
      { id: "authentication:GET /report:app.js", reason: "was public until the redesign", expires: "2020-01-01" },
      { id: "authentication:GET /report:app.js" },
    ],
  };
  await project({ "app.js": APP, [REVIEW_FILE]: JSON.stringify(reviews) }, async (dir) => {
    const r = await validateProject(dir, new Map(), "");
    assert.deepEqual(
      r.reviewed.map((x) => [x.id, x.reason, x.reviewer, x.source]),
      [["authentication:POST /hooks/stripe:app.js", "verifies Stripe's signature in the handler", "tj", REVIEW_FILE]]
    );
    const auth = r.failures.find((f) => /^authentication: /.test(f));
    assert.match(auth, /^authentication: 1 of 2 endpoint\(s\) accept requests from anyone who can reach the service — GET \/report \(app\.js:3\)\. 1 more is open and reviewed, listed separately\./);
    const review = r.advisories.filter((a) => /^review: /.test(a)).join("\n");
    assert.match(review, /1 entry matches no finding, so it does nothing — authentication:GET \/gone:app\.js \(\.wolfproof-reviewed\.json\)/);
    assert.match(review, /authentication:GET \/report:app\.js expired on 2020-01-01 .* and was not applied/);
    assert.match(review, /an entry in \.wolfproof-reviewed\.json gives no reason, so it was ignored/);
  });
});

test("the pipeline's list applies beside the project's, and a review of every open route clears the finding", async () => {
  await project({ "app.js": APP, [REVIEW_FILE]: JSON.stringify({ reviewed: [{ id: "authentication:POST /hooks/stripe:app.js", reason: "signed webhook" }] }) }, async (dir) => {
    const pipeline = { entries: [{ id: "authentication:GET /report:app.js", reason: "public report", source: "--reviewed /ci/reviewed.json" }], ignored: [] };
    const r = await validateProject(dir, new Map(), "", { reviews: pipeline });
    assert.deepEqual(r.reviewed.map((x) => x.source).sort(), ["--reviewed /ci/reviewed.json", REVIEW_FILE]);
    assert.equal(r.failures.filter((f) => /^authentication: /.test(f)).length, 0, r.failures.join("\n"));
    assert.equal(r.advisories.filter((a) => /^review: /.test(a)).length, 0, r.advisories.join("\n"));
  });
});
