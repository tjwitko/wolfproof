import test from "node:test";
import assert from "node:assert/strict";

import { optionProblems } from "./cli-flags.mjs";

const GATE = { flags: ["--help", "-h", "--json", "--factory", "--codeql"], values: ["--baseline", "--base", "--known"] };
const REVIEW = { flags: ["--help", "--codeql"], values: ["--reason", "--file"], separate: true };

test("optionProblems: the options a command defines are no problem, in either form of a value", () => {
  assert.deepEqual(optionProblems(["proj", "task.txt", "--json", "--factory", "--base=main", "--baseline=req.txt", "-h"], GATE), []);
  assert.deepEqual(optionProblems(["proj", "id", "--reason", "fine by me", "--file=out.json", "--codeql"], REVIEW), []);
  assert.deepEqual(optionProblems([], GATE), []);
  // What is not an option: a path, and a lone dash.
  assert.deepEqual(optionProblems(["./-odd-name", "-"], GATE), []);
});

test("optionProblems: an option the command does not define is named, with the nearest one when it is a slip", () => {
  assert.deepEqual(optionProblems(["proj", "--no-such-flag"], GATE), ["unknown option --no-such-flag"]);
  assert.deepEqual(optionProblems(["proj", "--factroy"], GATE), ["unknown option --factroy (did you mean --factory?)"]);
  assert.deepEqual(optionProblems(["proj", "--jsno"], GATE), ["unknown option --jsno (did you mean --json?)"]);
  // By its name, not with whatever value it was given.
  assert.deepEqual(optionProblems(["proj", "--bse=main"], GATE), ["unknown option --bse (did you mean --base?)"]);
  // One dash is an option too, and so is another command's.
  assert.deepEqual(optionProblems(["proj", "task.txt", "-j"], GATE), ["unknown option -j"]);
  assert.deepEqual(optionProblems(["proj", "--reason", "x"], GATE), ["unknown option --reason"]);
  // Each one, in the order given.
  assert.deepEqual(optionProblems(["--a-long-way-off", "proj", "--another-one"], GATE), ["unknown option --a-long-way-off", "unknown option --another-one"]);
});

test("optionProblems: an option that takes no value is not quietly dropped when given one", () => {
  // `--json=1` is not `--json`: the caller asked for JSON and would get text.
  assert.deepEqual(optionProblems(["proj", "--json=1"], GATE), ["--json takes no value"]);
  assert.deepEqual(optionProblems(["proj", "--factory=yes", "--base=main"], GATE), ["--factory takes no value"]);
});

test("optionProblems: a value given as the next argument is not read as an option, only where the command takes it so", () => {
  // The value is whatever follows, a leading dash included, as the command itself reads it.
  assert.deepEqual(optionProblems(["proj", "id", "--reason", "-ish"], REVIEW), []);
  // Unless it is another option: then the first has no value, which the command says, and the second is looked at.
  assert.deepEqual(optionProblems(["proj", "id", "--reason", "--nope"], REVIEW), ["unknown option --nope"]);
  // The gate takes values with "=" only, so what follows one is looked at.
  assert.deepEqual(optionProblems(["proj", "--base", "-x"], GATE), ["unknown option -x"]);
});
