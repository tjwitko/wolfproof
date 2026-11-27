import test from "node:test";
import assert from "node:assert/strict";

import { parseToml, readToml } from "./toml.mjs";

// The reader the dependency rule reads pyproject.toml, Pipfile and the Python lockfiles with. It was
// checked on 2026-11-25 against Python 3.14's tomllib over 539 files (every TOML file in the
// calibration checkouts, and CPython's own tomllib test data, valid and invalid): the same document
// for 438, both refusing 99, and two differing, both a date that is not a day (2021-02-30), which
// this accepts as text. These hold what that comparison found and what the rule depends on.

test("tables, arrays of tables, dotted keys and inline tables read as TOML says", () => {
  const doc = parseToml(`
title = "x" # a comment
[project]
name = "p"
dependencies = [
  "requests>=2",  # trailing comments and commas
  'flask',
]
[project.optional-dependencies]
dev = ["pytest"]
[[package]]
name = "a"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "b"
wheels = [{ url = "https://x/b.whl" }]
[tool.uv.sources]
c.git = "https://example.com/c"
`);
  assert.equal(doc.title, "x");
  assert.deepEqual(doc.project.dependencies, ["requests>=2", "flask"]);
  assert.deepEqual(doc.project["optional-dependencies"], { dev: ["pytest"] });
  assert.deepEqual(doc.package.map((p) => p.name), ["a", "b"]);
  assert.equal(doc.package[0].source.registry, "https://pypi.org/simple");
  assert.equal(doc.tool.uv.sources.c.git, "https://example.com/c");
});

test("strings: escapes, literal strings, multi-line strings and a line-ending backslash", () => {
  const doc = parseToml(String.raw`a = "tab\there \u00e9"
b = 'C:\path'
c = """
one \
   two"""
d = '''
raw\n'''
e = """quote""""
`);
  assert.equal(doc.a, "tab\there é");
  assert.equal(doc.b, "C:\\path");
  assert.equal(doc.c, "one two");
  assert.equal(doc.d, "raw\\n");
  assert.equal(doc.e, 'quote"');
});

test("numbers, booleans and dates", () => {
  const doc = parseToml("a = 1_000\nb = 0x1F\nc = 3.5e2\nd = true\ne = 1979-05-27T07:32:00Z\nf = 1979-05-27 07:32:00\ng = inf\n");
  assert.deepEqual([doc.a, doc.b, doc.c, doc.d, doc.e, doc.f, doc.g], [1000, 31, 350, true, "1979-05-27T07:32:00Z", "1979-05-27 07:32:00", Infinity]);
});

test("CRLF line endings, after a comment and inside a multi-line string", () => {
  assert.deepEqual(parseToml('a = 1 # x\r\nb = """\r\nl1\r\nl2"""\r\n'), { a: 1, b: "l1\r\nl2" });
});

test("anything TOML does not allow is refused with its line, never read as something else", () => {
  for (const [text, why] of [
    ["a = 1\na = 2\n", /line 2: a is defined twice/],
    ["[t]\nx = 1\n[t]\ny = 2\n", /line 3: \[t\] is defined twice/],
    ["a = { x = 1 }\n[a]\ny = 2\n", /defined twice|already defined/],
    ["a = { x = 1 }\na.y = 2\n", /already defined/],
    ["a = [1, 2\n", /line \d: /],
    ["a = \"no end\n", /a newline in a string/],
    ["a = bare\n", /a value TOML does not have/],
    ["a = 1 b = 2\n", /unexpected/],
    ['b = """x\ry"""\n', /a control character in a string/],
    ["= 1\n", /a key was expected/],
  ]) {
    const r = readToml(text);
    assert.ok(r.error, `${JSON.stringify(text)} was read as ${JSON.stringify(r.value)}`);
    assert.match(r.error, why, JSON.stringify(text));
  }
});

test("a newline and a trailing comma inside an inline table, as TOML 1.1 and uv allow", () => {
  assert.deepEqual(parseToml("a = {\n  x = 1,\n  y = 2,\n}\n"), { a: { x: 1, y: 2 } });
});

test("an array written out as a value is closed: a [[header]] or a [table] under it is refused", () => {
  for (const bad of ["a = [1]\n[[a]]\n", "a = []\n[[a]]\nb = 1\n", "dependencies = [\"a\"]\n[[dependencies]]\nname = \"b\"\n", "a = [{ x = 1 }]\n[a.b]\nc = 1\n", "[t]\na = [1]\n[[t.a]]\n"]) {
    assert.match(readToml(bad).error || "", /^line \d+: /, JSON.stringify(bad));
    assert.throws(() => parseToml(bad), JSON.stringify(bad));
  }
  // An array of tables made by headers is still added to, and a table under its last item still opens.
  assert.deepEqual(parseToml("[[a]]\nb = 1\n[[a]]\nb = 2\n[a.c]\nd = 3\n"), { a: [{ b: 1 }, { b: 2, c: { d: 3 } }] });
  assert.deepEqual(parseToml("x = [[1], [2]]\ny = [{ z = [1] }]\n"), { x: [[1], [2]], y: [{ z: [1] }] });
  // A value TOML does not have is not quoted: where it is, and not what it says.
  assert.equal(readToml("a = https://user:" + "s3".repeat(30) + "@host/x\n").error, "line 1: a value TOML does not have, at column 5");
  assert.equal(readToml('[tool]\nname = "p"\npassword = zq7-made-up-0123456789\n').error, "line 3: a value TOML does not have, at column 12");
});

test("a key is the table's own whatever it is called: __proto__ is a key, and not the table's prototype", () => {
  const doc = parseToml('__proto__ = 1\na = 2\n[tool.uv]\n__proto__ = { index-url = "https://x/simple" }\n[tool.uv.constructor]\nb = 3\n');
  assert.deepEqual(Object.keys(doc), ["__proto__", "a", "tool"]);
  assert.equal(Object.getOwnPropertyDescriptor(doc, "__proto__").value, 1);
  assert.equal(Object.getPrototypeOf(doc.tool.uv), Object.prototype);
  assert.deepEqual(Object.keys(doc.tool.uv), ["__proto__", "constructor"]);
  assert.equal(doc.tool.uv["index-url"], undefined, "what the key holds is not read as the table's own settings");
  assert.deepEqual(Object.getOwnPropertyDescriptor(doc.tool.uv, "__proto__").value, { "index-url": "https://x/simple" });
  assert.deepEqual(Object.keys(parseToml("[__proto__]\nx = 1\n[[__proto__.list]]\ny = 2\n")), ["__proto__"]);
  for (const twice of ["__proto__ = 1\n__proto__ = 2\n", "[__proto__]\n[__proto__]\n", "a.__proto__ = 1\na.__proto__ = 2\n"]) assert.match(readToml(twice).error || "", /defined twice/, JSON.stringify(twice));
});
