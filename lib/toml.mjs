// TOML, read for the dependency rule (lib/factory-deps.mjs): pyproject.toml, Pipfile, uv.toml,
// uv.lock and poetry.lock.
//
// Its own reader rather than a package, because the rule it serves asks a person to approve every
// dependency a change adds, and this file would be one. It reads TOML 1.0 and throws on anything it
// does not understand, a key defined twice included: a manifest the rule cannot read is could-not-run,
// never "declares nothing". Two things TOML 1.1 allows are accepted, since the tools that read these
// files accept them: a newline and a trailing comma inside an inline table, and `\e` and `\xHH` in a
// basic string.
//
// Dates and times come back as their text; nothing here needs them as dates.

class TomlError extends Error {}

const BARE = /[A-Za-z0-9_-]/;

/** The document as plain objects and arrays. Throws a TomlError naming the line. */
export function parseToml(text) {
  let i = 0;
  const src = String(text).replace(/^﻿/, "");
  const lineAt = (at) => src.slice(0, at).split("\n").length;
  const fail = (why, at = i) => {
    throw new TomlError(`line ${lineAt(at)}: ${why}`);
  };

  const root = {};
  // Tables made by a [header] or [[header]], which another [header] may not make again; tables a
  // value or an inline table made, which nothing may add to.
  const explicit = new Set();
  const frozen = new Set();
  const implicitByDotted = new Set();
  let current = root;

  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

  const ws = () => {
    while (i < src.length && (src[i] === " " || src[i] === "\t")) i++;
  };
  const comment = () => {
    if (src[i] === "#") {
      while (i < src.length && src[i] !== "\n" && !(src[i] === "\r" && src[i + 1] === "\n")) {
        const c = src.charCodeAt(i);
        if ((c < 0x20 && c !== 9) || c === 0x7f) fail("a control character in a comment");
        i++;
      }
    }
  };
  // Whitespace, newlines and comments, inside an array.
  const wsAll = () => {
    for (;;) {
      ws();
      comment();
      if (src[i] === "\n") i++;
      else if (src[i] === "\r" && src[i + 1] === "\n") i += 2;
      else return;
    }
  };
  const endOfLine = () => {
    ws();
    comment();
    if (i >= src.length) return;
    if (src[i] === "\n") return void i++;
    if (src[i] === "\r" && src[i + 1] === "\n") return void (i += 2);
    fail(`unexpected ${JSON.stringify(src[i])} after a value`);
  };

  const hex = (n) => {
    const h = src.slice(i, i + n);
    if (h.length !== n || !/^[0-9A-Fa-f]+$/.test(h)) fail("a bad escape");
    i += n;
    const cp = parseInt(h, 16);
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail("an escape that is not a character");
    return String.fromCodePoint(cp);
  };
  const ESC = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", e: "\x1b", '"': '"', "\\": "\\" };
  const basicString = (multi) => {
    let out = "";
    if (multi && src[i] === "\n") i++;
    else if (multi && src[i] === "\r" && src[i + 1] === "\n") i += 2;
    for (;;) {
      if (i >= src.length) fail("a string that does not end");
      const c = src[i];
      if (multi && src.startsWith('"""', i)) {
        // Up to two quotes may sit before the closing three.
        let n = 3;
        while (src[i + n] === '"' && n < 5) n++;
        out += '"'.repeat(n - 3);
        i += n;
        return out;
      }
      if (!multi && c === '"') {
        i++;
        return out;
      }
      if (c === "\\") {
        i++;
        const e = src[i];
        if (multi && (e === " " || e === "\t" || e === "\n" || e === "\r")) {
          // A backslash at the end of a line takes the newline and the whitespace after it.
          let j = i;
          while (src[j] === " " || src[j] === "\t") j++;
          if (src[j] !== "\n" && !(src[j] === "\r" && src[j + 1] === "\n")) fail("a backslash followed by spaces in a string");
          i = j;
          while (i < src.length && /[ \t\r\n]/.test(src[i])) i++;
          continue;
        }
        if (e === "u") {
          i++;
          out += hex(4);
        } else if (e === "U") {
          i++;
          out += hex(8);
        } else if (e === "x") {
          i++;
          out += hex(2);
        } else if (e in ESC) {
          i++;
          out += ESC[e];
        } else fail(`an unknown escape \\${e}`);
        continue;
      }
      if (c === "\n" && !multi) fail("a newline in a string");
      const code = src.charCodeAt(i);
      if ((code < 0x20 && code !== 9 && !(multi && (code === 10 || (code === 13 && src[i + 1] === "\n")))) || code === 0x7f) fail("a control character in a string");
      out += c;
      i++;
    }
  };
  const literalString = (multi) => {
    if (multi && src[i] === "\n") i++;
    else if (multi && src[i] === "\r" && src[i + 1] === "\n") i += 2;
    const start = i;
    for (;;) {
      if (i >= src.length) fail("a string that does not end");
      if (multi && src.startsWith("'''", i)) {
        let n = 3;
        while (src[i + n] === "'" && n < 5) n++;
        const out = src.slice(start, i) + "'".repeat(n - 3);
        i += n;
        return out;
      }
      if (!multi && src[i] === "'") {
        const out = src.slice(start, i);
        i++;
        return out;
      }
      if (src[i] === "\n" && !multi) fail("a newline in a string");
      i++;
    }
  };
  const string = () => {
    if (src.startsWith('"""', i)) {
      i += 3;
      return basicString(true);
    }
    if (src.startsWith("'''", i)) {
      i += 3;
      return literalString(true);
    }
    if (src[i] === '"') {
      i++;
      return basicString(false);
    }
    i++;
    return literalString(false);
  };

  const keyPart = () => {
    if (src[i] === '"' || src[i] === "'") {
      if (src.startsWith('"""', i) || src.startsWith("'''", i)) fail("a multi-line string as a key");
      return string();
    }
    const start = i;
    while (i < src.length && BARE.test(src[i])) i++;
    if (i === start) fail(`a key was expected, not ${JSON.stringify(src[i] ?? "the end")}`);
    return src.slice(start, i);
  };
  const dottedKey = () => {
    const parts = [];
    for (;;) {
      ws();
      parts.push(keyPart());
      ws();
      if (src[i] !== ".") return parts;
      i++;
    }
  };

  const SCALAR_END = /[\s,\]}#]/;
  const scalar = () => {
    const start = i;
    while (i < src.length && !SCALAR_END.test(src[i])) i++;
    // A date and time may hold one space between them.
    if (src[i] === " " && /^\d{4}-\d{2}-\d{2}$/.test(src.slice(start, i)) && /\d/.test(src[i + 1] || "")) {
      i++;
      while (i < src.length && !SCALAR_END.test(src[i])) i++;
    }
    const t = src.slice(start, i);
    if (t === "true") return true;
    if (t === "false") return false;
    if (/^[+-]?(?:inf|nan)$/.test(t)) return t.includes("nan") ? NaN : t.startsWith("-") ? -Infinity : Infinity;
    if (/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)?$/i.test(t) || /^\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(t)) return t;
    if (/^0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*$/.test(t)) return parseInt(t.slice(2).replace(/_/g, ""), 16);
    if (/^0o[0-7](?:_?[0-7])*$/.test(t)) return parseInt(t.slice(2).replace(/_/g, ""), 8);
    if (/^0b[01](?:_?[01])*$/.test(t)) return parseInt(t.slice(2).replace(/_/g, ""), 2);
    if (/^[+-]?(?:0|[1-9](?:_?\d)*)$/.test(t)) return Number(t.replace(/_/g, ""));
    if (/^[+-]?(?:0|[1-9](?:_?\d)*)(?:\.\d(?:_?\d)*)?(?:[eE][+-]?\d(?:_?\d)*)?$/.test(t) && /[.eE]/.test(t)) return Number(t.replace(/_/g, ""));
    fail(`a value TOML does not have: ${JSON.stringify(t.slice(0, 40))}`, start);
  };

  const value = () => {
    const c = src[i];
    if (c === '"' || c === "'") return string();
    if (c === "[") {
      i++;
      const arr = [];
      for (;;) {
        wsAll();
        if (src[i] === "]") {
          i++;
          return arr;
        }
        arr.push(value());
        wsAll();
        if (src[i] === ",") {
          i++;
          continue;
        }
        if (src[i] === "]") {
          i++;
          return arr;
        }
        fail("an array whose items are not separated by commas");
      }
    }
    if (c === "{") {
      i++;
      const tbl = {};
      const inner = new Set();
      wsAll();
      if (src[i] === "}") {
        i++;
        frozen.add(tbl);
        return tbl;
      }
      for (;;) {
        wsAll();
        if (src[i] === "}") {
          i++;
          break;
        }
        const keys = dottedKey();
        ws();
        if (src[i] !== "=") fail("an inline table entry with no =");
        i++;
        ws();
        assign(tbl, keys, value(), inner);
        wsAll();
        if (src[i] === ",") {
          i++;
          continue;
        }
        if (src[i] === "}") {
          i++;
          break;
        }
        fail("an inline table whose entries are not separated by commas");
      }
      frozen.add(tbl);
      for (const t of inner) frozen.add(t);
      return tbl;
    }
    if (c === undefined || c === "\n" || c === "\r") fail("a key with no value");
    return scalar();
  };

  // `made` collects the tables a dotted key creates inside an inline table, which freeze with it.
  function assign(table, keys, v, made = null) {
    let t = table;
    for (const k of keys.slice(0, -1)) {
      if (!Object.hasOwn(t, k)) {
        t[k] = {};
        implicitByDotted.add(t[k]);
        made?.add(t[k]);
      } else if (!isObj(t[k]) || frozen.has(t[k]) || explicit.has(t[k])) {
        fail(`${keys.join(".")} adds to a value that is already defined`);
      }
      t = t[k];
    }
    const last = keys[keys.length - 1];
    if (Object.hasOwn(t, last)) fail(`${keys.join(".")} is defined twice`);
    t[last] = v;
  }

  const header = (array) => {
    const keys = dottedKey();
    ws();
    if (array) {
      if (!src.startsWith("]]", i)) fail("a [[table]] header that does not close");
      i += 2;
    } else {
      if (src[i] !== "]") fail("a [table] header that does not close");
      i++;
    }
    let t = root;
    for (const k of keys.slice(0, -1)) {
      if (!Object.hasOwn(t, k)) t[k] = {};
      let next = t[k];
      if (Array.isArray(next)) {
        if (frozen.has(next) || !next.length) fail(`${keys.join(".")} adds to an array that is already defined`);
        next = next[next.length - 1];
      }
      if (!isObj(next) || frozen.has(next)) fail(`${keys.join(".")} adds to a value that is already defined`);
      t = next;
    }
    const last = keys[keys.length - 1];
    if (array) {
      if (!Object.hasOwn(t, last)) {
        t[last] = [];
      } else if (!Array.isArray(t[last]) || frozen.has(t[last])) {
        fail(`[[${keys.join(".")}]] names something that is not an array of tables`);
      }
      const item = {};
      t[last].push(item);
      return item;
    }
    if (Object.hasOwn(t, last)) {
      const existing = t[last];
      if (!isObj(existing) || explicit.has(existing) || frozen.has(existing) || implicitByDotted.has(existing)) fail(`[${keys.join(".")}] is defined twice`);
      explicit.add(existing);
      return existing;
    }
    t[last] = {};
    explicit.add(t[last]);
    return t[last];
  };

  while (i < src.length) {
    ws();
    if (i >= src.length) break;
    const c = src[i];
    if (c === "#" || c === "\n" || c === "\r") {
      endOfLine();
      continue;
    }
    if (c === "[") {
      const array = src[i + 1] === "[";
      i += array ? 2 : 1;
      current = header(array);
      endOfLine();
      continue;
    }
    const keys = dottedKey();
    ws();
    if (src[i] !== "=") fail(`${keys.join(".")} has no =`);
    i++;
    ws();
    assign(current, keys, value());
    endOfLine();
  }
  return root;
}

/** { value } or { error }. */
export function readToml(text) {
  try {
    return { value: parseToml(text) };
  } catch (err) {
    if (err instanceof TomlError) return { error: err.message };
    throw err;
  }
}
