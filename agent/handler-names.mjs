// Which function a handler name in a JavaScript or Go route means.
//
// A route names its handler (`app.get("/x", handler)`, `mux.HandleFunc("/x", s.handleX)`), and the
// handler's body is where a check inside it is read. The name was looked up as the first function of
// that name anywhere in the project's files of the language, so with two files each defining
// `handler`, a route was credited with the other file's check: `GET /open`, whose own handler checks
// nothing, read as "a credential checked in the handler" because another file's `handler` checks an
// API key. Resolved now as the language resolves it, and a name that cannot be resolved has no body.
//
// JavaScript: a definition in the route's own file; else what the file imports under that name from a
// module of the project (`import { h } from "./h"`, `const h = require("./h")`, a default export,
// re-exports followed); `mod.h` for an imported module `mod`; and `obj.h` for anything else, a method
// named `h` in the file or in the project modules it imports, else the project's only method of that
// name, for an object passed in rather than imported. A package import is not the project's.
// Go: a function in the route's own package (its directory); `pkg.H` in the package `pkg` is imported
// from; a method value `s.H` on the type `s` is made or declared as (`s := &T{}`, `s := NewT()`,
// `var s T`, a parameter `s *T`), else the one method of that name in the route's package, else in
// the project packages it imports. JavaScript likewise reads `const s = new S()`.
//
// Each returns `{ file, at }`, the file and the offset of the definition, or null.

import path from "path";

const posix = path.posix;
const JS_EXT = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"];
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const memo = new WeakMap();
function cached(owner, kind, key, make) {
  if (!memo.has(owner)) memo.set(owner, new Map());
  const m = memo.get(owner);
  const k = `${kind}\0${key}`;
  if (!m.has(k)) m.set(k, make());
  return m.get(k);
}
const byRel = (project) => cached(project, "rel", "", () => new Map(project.map((f) => [f.rel, f])));

// --- JavaScript ---------------------------------------------------------------------------------

/** The project file a relative module specifier names from `from`, or null. */
function jsModuleFile(spec, from, project) {
  if (!spec.startsWith(".")) return null;
  const base = posix.normalize(posix.join(posix.dirname(from.rel), spec));
  // TypeScript imports "./h.js" for h.ts, and its compiler takes h.ts first; Node takes the file named.
  const stem = base.replace(/\.(?:js|mjs|cjs|jsx)$/, "");
  const fromTs = /\.[mc]?tsx?$/.test(from.rel);
  const files = byRel(project);
  const named = fromTs ? [stem + ".ts", stem + ".tsx", base] : [base];
  for (const c of [...named, ...JS_EXT.map((e) => stem + e), ...JS_EXT.map((e) => posix.join(base, `index${e}`))]) {
    if (files.has(c)) return files.get(c);
  }
  return null;
}

/** The names a file imports: local name -> { spec, imported } with imported a name, "default", "*" or "module". */
function jsImportsOf(file) {
  return cached(file, "imports", "", () => {
    const out = new Map();
    for (const m of file.text.matchAll(/\bimport\s+(?!type\b)([\w$*{}\s,]+?)\s+from\s*['"]([^'"]+)['"]/g)) {
      const clause = m[1];
      const spec = m[2];
      const braces = /\{([^}]*)\}/.exec(clause);
      const rest = clause.replace(/\{[^}]*\}/, "");
      const ns = /\*\s*as\s+([\w$]+)/.exec(rest);
      if (ns) out.set(ns[1], { spec, imported: "*" });
      const def = /^\s*([\w$]+)\s*(?:,|$)/.exec(rest.replace(/\*\s*as\s+[\w$]+/, ""));
      if (def) out.set(def[1], { spec, imported: "default" });
      for (const part of braces ? braces[1].split(",") : []) {
        const [orig, alias] = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/);
        if (orig) out.set(alias || orig, { spec, imported: orig });
      }
    }
    for (const m of file.text.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)(\s*\.\s*([\w$]+))?/g)) {
      out.set(m[1], { spec: m[2], imported: m[4] || "module" });
    }
    for (const m of file.text.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      for (const part of m[1].split(",")) {
        const [orig, alias] = part.trim().split(/\s*:\s*/);
        if (orig) out.set(alias || orig, { spec: m[2], imported: orig });
      }
    }
    return out;
  });
}

/** Where a file itself defines `name`: a function, a const/let/var, or `exports.name =`. */
function jsOwnDefinition(name, file) {
  return cached(file, "own", name, () => {
    const n = escapeRe(name);
    const re = new RegExp(
      `(?:^|[^\\w$.])(?:export\\s+)?(?:async\\s+)?function\\s*\\*?\\s*${n}\\s*\\(|(?:^|[^\\w$.])(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*=|(?:^|[^\\w$])(?:module\\s*\\.\\s*)?exports\\s*\\.\\s*${n}\\s*=`,
      "m"
    );
    const m = re.exec(file.text);
    return m ? m.index + (/^[^\w$]/.test(m[0]) ? 1 : 0) : -1;
  });
}

/** Every method `name(...) {` in a class body or object literal in the file. */
function jsMethods(name, file) {
  return cached(file, "methods", name, () => {
    if (!file.text.includes(name)) return [];
    const re = new RegExp(`(?:^|[{;,]|\\n)\\s*(?:async\\s+)?${escapeRe(name)}\\s*\\([^)]*\\)\\s*\\{`, "gm");
    return [...file.text.matchAll(re)].map((m) => ({ file, at: m.index }));
  });
}

// The one definition among these, or null: two methods of one name on different objects are the
// ambiguity this file exists to refuse, whichever of them was found first.
const onlyOne = (defs) => (defs.length === 1 ? defs[0] : null);

/** The text span of `class C ... { ... }` in a file, or null. */
function jsClassSpan(name, file) {
  const m = new RegExp(`\\bclass\\s+${escapeRe(name)}\\b[^{]*\\{`).exec(file.text);
  if (!m) return null;
  let depth = 0;
  for (let i = m.index + m[0].length - 1; i < file.text.length; i++) {
    if (file.text[i] === "{") depth++;
    else if (file.text[i] === "}" && --depth === 0) return { file, from: m.index, to: i };
  }
  return null;
}

/** The class a receiver is made from in this file, `const y = new Y(...)`: where class Y is. */
function jsClassOf(receiver, file, project, depth) {
  const m = new RegExp(`\\b(?:const|let|var)\\s+${escapeRe(receiver)}\\s*=\\s*new\\s+([\\w$]+)\\s*\\(`).exec(file.text);
  if (!m) return null;
  const here = jsClassSpan(m[1], file);
  if (here) return here;
  const imp = jsImportsOf(file).get(m[1]);
  const target = imp && jsModuleFile(imp.spec, file, project);
  if (!target || depth > 4) return null;
  if (imp.imported === "default" || imp.imported === "module") {
    const d = /\b(?:export\s+default|module\s*\.\s*exports\s*=)\s*(?:class\s+)?([\w$]+)/.exec(target.text);
    return d ? jsClassSpan(d[1], target) : null;
  }
  return jsClassSpan(imp.imported, target);
}

/** What a module exports as `name` ("default" for its default export). */
function jsExported(name, file, project, depth) {
  if (depth > 4) return null;
  const t = file.text;
  if (name === "default") {
    let m = /\bexport\s+default\s+(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)/.exec(t) || /\bmodule\s*\.\s*exports\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)/.exec(t);
    if (m) return { file, at: m.index };
    m = /\bexport\s+default\s+([\w$]+)\s*;?\s*$/m.exec(t) || /\bmodule\s*\.\s*exports\s*=\s*([\w$]+)\s*;?\s*$/m.exec(t);
    return m ? jsResolve(m[1], null, file, project, depth + 1) : null;
  }
  const own = jsOwnDefinition(name, file);
  if (own >= 0) return { file, at: own };
  // `module.exports = { list: listAll }`, and `export { listAll as list }` with no `from`.
  const n = escapeRe(name);
  let m = new RegExp(`\\bmodule\\s*\\.\\s*exports\\s*=\\s*\\{[^}]*\\b${n}\\s*:\\s*([\\w$]+)`).exec(t) || new RegExp(`\\bexport\\s*\\{[^}]*\\b([\\w$]+)\\s+as\\s+${n}\\b[^}]*\\}(?!\\s*from)`).exec(t);
  if (m) return jsResolve(m[1], null, file, project, depth + 1);
  for (const r of t.matchAll(/\bexport\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) {
    for (const part of r[1].split(",")) {
      const [orig, alias] = part.trim().split(/\s+as\s+/);
      if ((alias || orig) !== name) continue;
      const target = jsModuleFile(r[2], file, project);
      return target ? jsExported(orig, target, project, depth + 1) : null;
    }
  }
  for (const r of t.matchAll(/\bexport\s*\*\s*from\s*['"]([^'"]+)['"]/g)) {
    const target = jsModuleFile(r[1], file, project);
    const found = target && jsExported(name, target, project, depth + 1);
    if (found) return found;
  }
  // Re-exported from what the file imports: `import { h } from "./h"; export { h }`.
  return jsImportsOf(file).has(name) ? jsResolve(name, null, file, project, depth + 1) : null;
}

/** The definition a JavaScript handler `receiver.name` (receiver may be null) refers to from `file`. */
export function jsResolve(name, receiver, file, project, depth = 0) {
  if (depth > 4 || !file) return null;
  const imports = jsImportsOf(file);
  if (receiver) {
    const imp = imports.get(receiver);
    if (imp && imp.imported !== "*" && imp.imported !== "module" && imp.imported !== "default") return null;
    if (imp) {
      const target = jsModuleFile(imp.spec, file, project);
      return target ? jsExported(name, target, project, depth + 1) : null;
    }
    // An instance of a class this file names, `const y = new Y()`: that class's method.
    const cls = jsClassOf(receiver, file, project, depth);
    if (cls) return onlyOne(jsMethods(name, cls.file).filter((d) => d.at > cls.from && d.at < cls.to));
    // An object or instance: the method of that name here; else among the project modules this
    // file imports; else, for an object passed in rather than imported (`createApp({ svc })`, wired
    // by another file), in the project. At each step there must be exactly one, or none is taken.
    const here = jsMethods(name, file);
    if (here.length) return onlyOne(here);
    const targets = [...new Set([...imports.values()].map((i) => jsModuleFile(i.spec, file, project)).filter(Boolean))];
    const imported = targets.flatMap((t) => jsMethods(name, t));
    if (imported.length) return onlyOne(imported);
    return onlyOne(project.flatMap((f) => jsMethods(name, f)));
  }
  const own = jsOwnDefinition(name, file);
  if (own >= 0) return { file, at: own };
  const imp = imports.get(name);
  if (!imp) return null;
  const target = jsModuleFile(imp.spec, file, project);
  return target ? jsExported(imp.imported === "module" ? "default" : imp.imported, target, project, depth + 1) : null;
}

// --- Go -----------------------------------------------------------------------------------------

/** The import paths a Go file names, by the name it uses them under. */
function goImportsOf(file) {
  return cached(file, "goimports", "", () => {
    const out = new Map();
    const specs = [];
    for (const m of file.text.matchAll(/\bimport\s*\(([\s\S]*?)\)/g)) specs.push(...m[1].split("\n"));
    for (const m of file.text.matchAll(/\bimport\s+((?:[\w.]+\s+)?"[^"]+")/g)) specs.push(m[1]);
    for (const s of specs) {
      const m = /^\s*([\w.]+)?\s*"([^"]+)"/.exec(s);
      if (!m) continue;
      const last = m[2].split("/").filter((p) => !/^v\d+$/.test(p)).pop();
      out.set(m[1] && m[1] !== "_" && m[1] !== "." ? m[1] : last, m[2]);
    }
    return out;
  });
}

/** The project directory an import path names: the longest one it ends with. */
function goPackageDir(importPath, project) {
  const dirs = cached(project, "godirs", "", () => [...new Set(project.map((f) => posix.dirname(f.rel)))]);
  let best = null;
  for (const d of dirs) {
    if ((importPath === d || importPath.endsWith(`/${d}`)) && (!best || d.length > best.length)) best = d;
  }
  return best;
}
const goPackage = (dir, project) => cached(project, "gopkg", dir, () => project.filter((f) => posix.dirname(f.rel) === dir));

function goAll(re, files) {
  const g = new RegExp(re.source, "g");
  return files.flatMap((f) => [...f.text.matchAll(g)].map((m) => ({ file: f, at: m.index })));
}
// A function name is unique in a package; a method name may be on several types, and then which one
// a method value means is not read.
const goFind = (re, files) => goAll(re, files)[0] || null;
const goOne = (re, files) => {
  const all = goAll(re, files);
  return all.length === 1 ? all[0] : null;
};

/** The package directory a Go type or function name `T` / `pkg.T`, read in `file`, is in. */
function goNamed(ref, file, project) {
  const [a, b] = ref.split(".");
  if (!b) return { name: a, dir: posix.dirname(file.rel) };
  const imp = goImportsOf(file).get(a);
  const dir = imp && goPackageDir(imp, project);
  return dir ? { name: b, dir } : null;
}

/** The type of a receiver variable in this file, from how it is made or declared, or null. */
function goTypeOf(receiver, file, project) {
  const r = escapeRe(receiver);
  const t = file.text;
  let m = new RegExp(`\\b${r}\\s*:?=\\s*&?\\s*([\\w.]+)\\s*\\{`).exec(t) || new RegExp(`\\bvar\\s+${r}\\s+\\*?([\\w.]+)`).exec(t) || new RegExp(`[(,]\\s*${r}\\s+\\*?([\\w.]+)\\s*[,)]`).exec(t);
  if (m) return goNamed(m[1], file, project);
  // `h := NewHandler(...)`: the type the constructor's signature returns.
  m = new RegExp(`\\b${r}\\s*:?=\\s*([\\w.]+)\\s*\\(`).exec(t);
  const ctor = m && goNamed(m[1], file, project);
  if (!ctor) return null;
  const def = goFind(new RegExp(`\\bfunc\\s+${escapeRe(ctor.name)}\\s*\\([^)]*\\)\\s*\\(?\\s*\\*?\\s*([\\w.]+)`), goPackage(ctor.dir, project));
  if (!def) return null;
  const ret = new RegExp(`\\bfunc\\s+${escapeRe(ctor.name)}\\s*\\([^)]*\\)\\s*\\(?\\s*\\*?\\s*([\\w.]+)`).exec(def.file.text.slice(def.at))[1];
  return goNamed(ret, def.file, project);
}

/** The definition a Go handler `receiver.name` (receiver may be null) refers to from `file`. */
export function goResolve(name, receiver, file, project) {
  const n = escapeRe(name);
  const func = new RegExp(`\\bfunc\\s+${n}\\s*[[(]`);
  const method = new RegExp(`\\bfunc\\s*\\([^)]*\\)\\s*${n}\\s*\\(`);
  const own = goPackage(posix.dirname(file.rel), project);
  const imports = goImportsOf(file);
  if (!receiver) return goFind(func, own);
  if (imports.has(receiver)) {
    const dir = goPackageDir(imports.get(receiver), project);
    return dir ? goFind(func, goPackage(dir, project)) : null;
  }
  // A method of the receiver's own type, where its type is read; else the one method of that name.
  const type = goTypeOf(receiver, file, project);
  if (type) {
    const own = new RegExp(`\\bfunc\\s*\\(\\s*\\w*\\s*\\*?\\s*${escapeRe(type.name)}\\s*(?:\\[[^\\]]*\\])?\\s*\\)\\s*${n}\\s*\\(`);
    return goOne(own, goPackage(type.dir, project));
  }
  const here = goAll(method, own);
  if (here.length) return here.length === 1 ? here[0] : null;
  const dirs = [...new Set([...imports.values()].map((p) => goPackageDir(p, project)).filter(Boolean))];
  return goOne(method, dirs.flatMap((d) => goPackage(d, project)));
}
