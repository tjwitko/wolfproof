import test from "node:test";
import assert from "node:assert/strict";

import { controlProblem } from "./gate-core.mjs";

// A control that answers with an error has said why. The could-not-run line used to drop that and
// say only "the scan produced no parseable result" -- with gitleaks missing, nobody was told so.

test("a control's error is kept, word for word", () => {
  const said = "gitleaks is not installed or not on PATH. Install it with `brew install gitleaks` and retry.";
  assert.equal(controlProblem(`TOOL REPORTED A PROBLEM:\n${said}`), said);
  assert.equal(controlProblem("ERROR: request timed out"), "request timed out", "a protocol error too");
});

test("a scanner's raw stderr is cut off, and the text is capped", () => {
  // secret-guard and dep-audit append up to 2000 characters of the scanner's stderr. That is the
  // scanner's output, not the control's explanation, and a could-not-run line is printed and logged.
  const r = controlProblem("TOOL REPORTED A PROBLEM:\ngitleaks produced no parseable output (exit 2). stderr: <anything the scanner printed>");
  assert.equal(r, "gitleaks produced no parseable output (exit 2).");
  assert.ok(controlProblem(`TOOL REPORTED A PROBLEM:\n${"x".repeat(500)}`).length <= 301);
  assert.equal(controlProblem("TOOL REPORTED A PROBLEM:\nline one\n  line two"), "line one line two", "one line");
});

test("anything that is not a control's error keeps the generic line", () => {
  assert.equal(controlProblem('{"clean": tru'), null, "a truncated result is not an explanation");
  assert.equal(controlProblem(""), null);
  assert.equal(controlProblem(undefined), null);
});
