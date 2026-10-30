// What protects a Flask view from outside it: a decorator under its route, or a `before_request`
// hook. Neither was read, so Flask's two standard forms -- Flask-Login's `@login_required` and an
// app-wide hook that refuses a caller without a session -- were reported open, and the only Flask
// fix the check credited was a check written into every view.
//
// Both are credited only when they would run for the route and would refuse:
//
// - A decorator counts below the route decorator, never above it. Flask registers the function the
//   route decorator receives, so `@login_required` written above `@app.route` wraps a function Flask
//   never calls. A library decorator counts when the file imports it from that library; a project's
//   own counts when a function it wraps in refuses the caller, read by the same rule as a handler
//   (agent/auth-handler.mjs). `optional=True` protects nothing.
// - A hook counts for the routes it runs for: a Flask app's for the routes under the app's directory,
//   a blueprint's for that blueprint's routes. A route the hook lets through by endpoint or path
//   stays open -- a path rule matched against the route's full path, its blueprint's prefix included,
//   and taken to reach any route whose full path cannot be read -- and a hook that lets requests
//   through on any other condition credits nothing, since which routes that condition opens cannot
//   be read.

import path from "path";
import { handlerGuard, _internals } from "./auth-handler.mjs";

const { pythonStatements } = _internals;

// Decorators whose library refuses the caller itself, by module. Flask-HTTPAuth's is a method of the
// auth object (`@auth.login_required`) and is handled where the object is found.
const LIBRARY_DECORATORS = {
  flask_login: ["login_required", "fresh_login_required"],
  flask_security: [
    "auth_required",
    "login_required",
    "roles_required",
    "roles_accepted",
    "permissions_required",
    "permissions_accepted",
    "auth_token_required",
    "http_auth_required",
  ],
  flask_jwt_extended: ["jwt_required", "fresh_jwt_required"],
};
const HTTPAUTH_OBJECT = /^[ \t]*(\w+)\s*=\s*(?:flask_httpauth\s*\.\s*)?(?:HTTP(?:Basic|Digest|Token)Auth|MultiAuth)\s*\(/gm;
const OPTIONAL = /\boptional\s*=\s*True\b/;

// A def and its body: the signature, however it wraps, then the lines indented past it.
function defBlock(lines, d) {
  const indentOf = (l) => /^\s*/.exec(l)[0].length;
  const indent = indentOf(lines[d]);
  const out = [];
  let depth = 0;
  let j = d;
  for (; j < lines.length; j++) {
    out.push(lines[j]);
    for (const ch of lines[j]) depth += "([{".includes(ch) ? 1 : ")]}".includes(ch) ? -1 : 0;
    if (depth <= 0 && /:\s*$/.test(lines[j])) break;
  }
  for (j++; j < lines.length && out.length < 300; j++) {
    if (lines[j].trim() && indentOf(lines[j]) <= indent) break;
    out.push(lines[j]);
  }
  return out;
}

// The names a file imports from a module, under the names it uses them by.
function importedFrom(text, module) {
  const names = new Map();
  const re = new RegExp(`^[ \\t]*from\\s+${module}(?:\\.[\\w.]+)?\\s+import\\s+(\\([^)]*\\)|[^\\n]+)`, "gm");
  for (const m of text.matchAll(re)) {
    for (const part of m[1].replace(/#[^\n]*/g, "").replace(/[()\n]/g, " ").split(",")) {
      const [name, alias] = part.trim().split(/\s+as\s+/);
      if (name) names.set(alias || name, name);
    }
  }
  return names;
}
const importsModule = (text, module) => new RegExp(`^[ \\t]*import\\s+${module}\\b`, "m").test(text);

/** The decorators under a route's decorator, down to its def. */
export function viewDecorators(lines, routeLine) {
  const out = [];
  for (let j = routeLine; j < lines.length && j < routeLine + 20; j++) {
    if (/^\s*(?:async\s+)?def\b/.test(lines[j])) break;
    // A route on a class: what follows are its methods' decorators, each for that method alone.
    if (/^\s*class\b/.test(lines[j])) return [];
    const m = /^\s*@\s*([\w.]+)\s*(\(.*)?$/.exec(lines[j]);
    if (m) out.push({ name: m[1], args: m[2] || "" });
  }
  return out;
}

// Every def of `name` in the project, each with the bodies of the functions defined inside it.
const projectDefs = new WeakMap();
function wrappersOf(name, texts) {
  if (!projectDefs.has(texts)) projectDefs.set(texts, new Map());
  const memo = projectDefs.get(texts);
  if (memo.has(name)) return memo.get(name);
  const defs = [];
  for (const text of texts) {
    const lines = text.split("\n");
    lines.forEach((l, d) => {
      if (!new RegExp(`^\\s*(?:async\\s+)?def\\s+${name}\\s*\\(`).test(l)) return;
      const block = defBlock(lines, d);
      const inner = [];
      block.forEach((b, k) => {
        if (k > 0 && /^\s+(?:async\s+)?def\b/.test(b)) inner.push(defBlock(block, k).join("\n"));
      });
      defs.push(inner);
    });
  }
  memo.set(name, defs);
  return defs;
}

/** What a decorator under the route protects it with, or null. */
function decoratorAuth(dec, fileText, texts) {
  if (OPTIONAL.test(dec.args)) return null;
  const [head, ...rest] = dec.name.split(".");
  const attr = rest.join(".");
  for (const [module, allowed] of Object.entries(LIBRARY_DECORATORS)) {
    if (!attr) {
      const original = importedFrom(fileText, module).get(head);
      if (original && allowed.includes(original)) return `@${dec.name} from ${module}`;
    } else if (head === module && importsModule(fileText, module) && allowed.includes(attr)) {
      return `@${dec.name}`;
    }
  }
  if (attr === "login_required") {
    const all = texts.join("\n");
    const objects = [...all.matchAll(HTTPAUTH_OBJECT)].map((m) => m[1]);
    if (objects.includes(head) && /^[ \t]*(?:from\s+flask_httpauth\b|import\s+flask_httpauth\b)/m.test(all)) {
      return `@${dec.name} from flask_httpauth`;
    }
  }
  if (attr) return null;
  // The project's own decorator: every def of that name must wrap the view in a function that
  // refuses, or the name could be either.
  const defs = wrappersOf(head, texts);
  if (!defs.length) return null;
  const guarded = defs.every((inner) => inner.some((body) => handlerGuard([body], "python")));
  return guarded ? `the @${head} decorator, which refuses the caller` : null;
}

// --- before_request hooks ------------------------------------------------------------------------

const LITERALS = (s) => [...s.matchAll(/(['"])([^'"]*)\1/g)].map((m) => m[2]);

// The routes a hook lets through: `if <cond>: return` before the check. Each disjunct of <cond> has
// to be one of these, or the hook's reach cannot be read and it credits nothing.
// Parentheses that enclose the whole expression, and only those: stripping a trailing `)` alone took
// the end off `request.path.startswith("/public")`, and `(a) or (b)` is not wrapped.
function unwrap(s) {
  let t = s.trim();
  while (t.startsWith("(") && t.endsWith(")")) {
    let depth = 0;
    let closesAt = -1;
    for (let k = 0; k < t.length; k++) {
      if (t[k] === "(") depth++;
      else if (t[k] === ")" && --depth === 0) {
        closesAt = k;
        break;
      }
    }
    if (closesAt !== t.length - 1) break;
    t = t.slice(1, -1).trim();
  }
  return t;
}

// The values a rule names, or `unread` where they are not all written out: `request.path in PUBLIC`
// read as naming nothing, so a hook that let a whole list of paths through was credited on all of them.
const valuesOf = (s) => ({ values: LITERALS(s), unread: s.replace(/(['"])[^'"]*\1/g, "").replace(/[\s,()[\]{}]/g, "") !== "" });

function exemptionOf(cond) {
  const rules = [];
  for (const part of unwrap(cond).split(/\s+or\s+/)) {
    const p = unwrap(part);
    let m;
    if ((m = /^request\s*\.\s*endpoint\s+(?:in|==)\s*([\s\S]+)$/.exec(p))) rules.push({ endpoints: valuesOf(m[1]) });
    else if ((m = /^request\s*\.\s*(?:path|url_rule\s*\.\s*rule)\s*(?:in|==)\s*([\s\S]+)$/.exec(p))) rules.push({ paths: valuesOf(m[1]) });
    else if ((m = /^request\s*\.\s*path\s*\.\s*startswith\s*\(([\s\S]+)\)$/.exec(p))) rules.push({ prefixes: valuesOf(m[1]) });
    else if (/^(?:not\s+request\s*\.\s*endpoint|request\s*\.\s*endpoint\s+is\s+None)$/.test(p)) rules.push({});
    else return null;
  }
  return rules;
}

function hookCredit(body) {
  const { guards } = pythonStatements(body);
  const exemptions = [];
  for (const g of guards) {
    if (g.branches.length !== 1 || !/^\s*(?:return(?:\s+None)?|pass)\s*$/.test(g.branches[0].trim())) continue;
    const rules = exemptionOf(g.cond);
    if (!rules) return null;
    exemptions.push(...rules);
  }
  const reason = handlerGuard([body], "python");
  return reason ? { exemptions } : null;
}

const offsetOf = (lines, d) => lines.slice(0, d).reduce((n, l) => n + l.length + 1, 0);

/** Every hook in the project that refuses, with whom it runs for. */
const projectHooks = new WeakMap();
function hooksIn(texts, rels) {
  if (projectHooks.has(texts)) return projectHooks.get(texts);
  const hooks = [];
  texts.forEach((text, i) => {
    const lines = text.split("\n");
    const found = [];
    lines.forEach((l, d) => {
      const m = /^\s*@\s*(\w+)\s*\.\s*(before_request|before_app_request)\b/.exec(l);
      if (!m) return;
      let def = d + 1;
      while (def < lines.length && /^\s*@/.test(lines[def])) def++;
      if (def < lines.length && /^\s*(?:async\s+)?def\b/.test(lines[def])) found.push({ receiver: m[1], kind: m[2], body: defBlock(lines, def).join("\n"), line: d + 1, index: offsetOf(lines, d) });
    });
    for (const m of text.matchAll(/^\s*(\w+)\s*\.\s*(before_request|before_app_request)\s*\(\s*(\w+)\s*\)/gm)) {
      const d = lines.findIndex((l) => new RegExp(`^\\s*(?:async\\s+)?def\\s+${m[3]}\\s*\\(`).test(l));
      if (d >= 0) found.push({ receiver: m[1], kind: m[2], body: defBlock(lines, d).join("\n"), line: d + 1, index: m.index });
    }
    const files = filesOf(texts, rels);
    const classes = flaskClasses(files);
    for (const h of found) {
      const credit = hookCredit(h.body);
      if (!credit) continue;
      const own = { rel: rels[i], text, at: `${rels[i]}:${h.line}` };
      // What the hook is installed on, followed back as a registration's target is (sourcesOf): a
      // parameter to what each call passes, an imported name to its module. Matched by name in the file
      // instead, `def never_called(app): @app.before_request` beside `app = Flask(...)` credited the
      // module's app with a hook that is never installed. A hook whose target is not traced to an app or
      // a blueprint protects nothing; one installed on several is a hook on each.
      const targets = (sourcesOf(h.receiver, files[i], h.index, files) || []).flatMap((src) => {
        const via = resolve(src.expr, src.file, files);
        return (madeBy(via, files) || []).map((target) => ({ target, via }));
      });
      for (const { target, via } of targets) {
        const call = callOf(target, [...classes.keys()].join("|"));
        const kind = call && classes.get(call.callee);
        if (!kind) continue;
        // An app's hook, and a blueprint's before_app_request, run for the routes under the app's own
        // directory -- the directory of the file the app is made in, not the hook's.
        if (h.kind === "before_app_request" || kind === "Flask") hooks.push({ ...h, ...credit, ...own, scope: "app", appRel: target.file.rel, on: target, via });
        else hooks.push({ ...h, ...credit, ...own, scope: "blueprint", blueprint: target, via });
      }
    }
  });
  projectHooks.set(texts, hooks);
  return hooks;
}

// Does one of the hook's rules let this route through? `serving.paths` are the route's full paths as
// the request sees them, or null where they cannot be read, and then any path rule is taken to reach
// it -- as is a rule whose values are not written out.
function exempted(hook, route, serving) {
  return hook.exemptions.some((e) => {
    if (e.endpoints) {
      // A route on a class is not named after its first method: flask-restx names a Resource's
      // endpoint `<namespace>_<class>` (`public_things`). Which class an endpoint rule names is not
      // read, so any endpoint rule is taken to reach it.
      if (e.endpoints.unread || route.onClass || serving.restx) return true;
      return e.endpoints.values.some((ep) => ep === route.view || ep.endsWith(`.${route.view}`));
    }
    const rule = e.paths || e.prefixes;
    if (!rule) return false;
    if (rule.unread || !serving.paths) return true;
    return serving.paths.some((full) => rule.values.some((p) => (e.paths ? servesPath(full, p) : servesPrefix(ruleParts(full), p))));
  });
}

// --- the path a request has --------------------------------------------------------------------
// A path rule compares `request.path`, the whole path, with a literal, while the route decorator
// gives only the last part of it. Before the rest was read, a hook letting "/public" through was
// credited on a blueprint registered at `url_prefix="/public"`, whose routes it lets through.
// The joins are Flask's and flask-restx's own:
// - Flask: a blueprint's prefix is the `url_prefix` given to `register_blueprint`, else the one in
//   `Blueprint(...)`; a nested blueprint's is joined to its parent's with one "/"; the rule is joined
//   to the prefix with one "/" (sansio/blueprints.py).
// - flask-restx: the blueprint's prefix, the Api's `prefix`, the namespace's path and the route, as
//   strings end to end. The namespace's path is the one `add_namespace` gives, else `Namespace(path=)`,
//   else "/" and its name, without trailing "/"; `@api.route` is on a namespace whose path is "".

// A rule's variables: `<id>` and `<int:id>` match one segment, `<path:p>` any number of them.
function ruleParts(rule) {
  return rule
    .split(/(<[^>]*>)/)
    .filter(Boolean)
    .map((part) => (part.startsWith("<") ? { any: /^<\s*path\s*:/.test(part) } : { lit: part }));
}
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// `request.path == p`: some request the rule serves has the path p (or p is the rule as written,
// which is what `request.url_rule.rule` holds). A hook letting "/docs/intro" through opens
// "/docs/<page>" for that page, so the route is open.
function servesPath(rule, p) {
  const re = ruleParts(rule)
    .map((t) => (t.lit !== undefined ? escapeRe(t.lit) : t.any ? ".+" : "[^/]+"))
    .join("");
  return p === rule || new RegExp(`^${re}$`).test(p);
}

// `request.path.startswith(p)`: some request the rule serves has a path starting with p.
function servesPrefix(parts, p, pi = 0, ti = 0) {
  if (pi === p.length) return true;
  if (ti === parts.length) return false;
  const t = parts[ti];
  if (t.lit !== undefined) {
    let k = 0;
    while (k < t.lit.length && pi + k < p.length && p[pi + k] === t.lit[k]) k++;
    if (pi + k === p.length) return true;
    return k === t.lit.length && servesPrefix(parts, p, pi + k, ti + 1);
  }
  for (let k = pi + 1; k <= p.length; k++) {
    if (!t.any && p[k - 1] === "/") break;
    if (servesPrefix(parts, p, k, ti + 1)) return true;
  }
  return false;
}

const UNREAD = Symbol("unread");
// A literal argument: its string, null for None, undefined when the argument is absent, UNREAD otherwise.
function literal(expr) {
  if (expr === undefined) return undefined;
  if (expr.trim() === "None") return null;
  const m = /^[rRuU]?(['"])([^'"]*)\1$/.exec(expr.trim());
  return m ? m[2] : UNREAD;
}

// The parts of the bracketed list whose opening bracket is at `open`, split at its top-level commas.
function partsAt(text, open) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let start = open + 1;
  for (let k = open; k < text.length; k++) {
    const c = text[k];
    if (quote) {
      if (c === "\\") k++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c) && depth === 1) {
      parts.push(text.slice(start, k));
      return Object.assign(parts.map((p) => (/['"]/.test(p) ? p : p.replace(/#[^\n]*/g, "")).trim()).filter(Boolean), { end: k });
    } else if (c === "," && depth === 1) {
      parts.push(text.slice(start, k));
      start = k + 1;
    } else if (")]}".includes(c)) depth--;
  }
  return null;
}

// The arguments of the call whose "(" is at `open`, with `.end` at its ")".
export function argsAt(text, open) {
  const parts = partsAt(text, open);
  if (!parts) return null;
  const args = { positional: [], keywords: {}, spread: false, end: parts.end };
  for (const raw of parts) {
    const kw = /^(\w+)\s*=(?!=)\s*([\s\S]*)$/.exec(raw);
    if (raw.startsWith("*")) args.spread = true;
    else if (kw) args.keywords[kw[1]] = kw[2].trim();
    else args.positional.push(raw);
  }
  return args;
}

// The call a name is assigned from, when it is one of `callees`: `bp = Blueprint(...)`.
function callOf(def, callees) {
  if (!def) return null;
  if (def.call) return new RegExp(`^(?:${callees})$`).test(def.call.callee) ? def.call : null;
  const m = new RegExp(`^[ \\t]*${def.name}\\s*=(?!=)\\s*(?:\\w+\\s*\\.\\s*)?(${callees})\\s*\\(`, "m").exec(def.file.text);
  return m ? { callee: m[1], args: argsAt(def.file.text, m.index + m[0].length - 1) } : null;
}

// The module a name stands for: `from . import auth`, `from app import views as v`, `import app.views as v`.
function moduleOf(alias, file, files) {
  for (const m of file.text.matchAll(/^[ \t]*from\s+([\w.]+)\s+import\s+(\([^)]*\)|[^\n]+)/gm)) {
    for (const part of m[2].replace(/#[^\n]*/g, "").replace(/[()\n]/g, " ").split(",")) {
      const [orig, as] = part.trim().split(/\s+as\s+/);
      if ((as || orig) !== alias) continue;
      const found = moduleFile(/^\.+$/.test(m[1]) ? m[1] + orig : `${m[1]}.${orig}`, file, files);
      if (found) return found;
    }
  }
  for (const m of file.text.matchAll(/^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?[ \t]*(?:#[^\n]*)?$/gm)) {
    if ((m[2] || m[1]) === alias) return moduleFile(m[1], file, files);
  }
  return null;
}

// Where `bp` or `auth.bp` is assigned, from the file that uses it.
function resolve(expr, file, files) {
  const m = /^(\w+)(?:\s*\.\s*(\w+))?$/.exec(expr.trim());
  if (!m) return null;
  if (!m[2]) return definition(m[1], file, files);
  const mod = moduleOf(m[1], file, files);
  return mod ? definition(m[2], mod, files) : null;
}

// --- where a name's value comes from ----------------------------------------------------------
// Redash registers its blueprints inside `def init_app(app)`, so the app is whatever each caller
// passes, and its login blueprints in `for blueprint in [create_oidc_blueprint(app), ...]`, so the
// blueprint is what a factory returns. Read by name alone, neither was ever found registered.

// A file's logical lines: a line continued inside brackets or a string belongs to the one it began on.
const logicalCache = new WeakMap();
function logicalLines(file) {
  if (logicalCache.has(file)) return logicalCache.get(file);
  const t = file.text;
  const lines = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  const end = (k) => {
    const s = t.slice(start, k);
    const body = s.replace(/^[ \t]*/, "");
    if (body && !body.startsWith("#")) lines.push({ start, indent: s.length - body.length, text: s });
    start = k + 1;
  };
  for (let k = 0; k < t.length; k++) {
    const c = t[k];
    if (quote) {
      if (c === "\\") k++;
      else if (t.startsWith(quote, k)) {
        k += quote.length - 1;
        quote = null;
      } else if (c === "\n" && quote.length === 1) quote = null;
    } else if (c === "#") {
      while (k + 1 < t.length && t[k + 1] !== "\n") k++;
    } else if (c === '"' || c === "'") {
      quote = t.startsWith(c.repeat(3), k) ? c.repeat(3) : c;
      k += quote.length - 1;
    } else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth = Math.max(0, depth - 1);
    else if (c === "\\" && t[k + 1] === "\n") k++;
    else if (c === "\n" && depth === 0) end(k);
  }
  end(t.length);
  logicalCache.set(file, lines);
  return lines;
}
const lineAt = (file, index) => logicalLines(file).findLast((l) => l.start <= index);

// The blocks around a point in a file, innermost first: each `def`, each `for` with its target, a class.
function scopesAt(file, index) {
  const lines = logicalLines(file);
  let i = lines.findLastIndex((l) => l.start <= index);
  if (i < 0) return [];
  let need = lines[i].indent;
  const out = [];
  for (i--; i >= 0 && need > 0; i--) {
    const l = lines[i];
    if (l.indent >= need) continue;
    need = l.indent;
    let m;
    if ((m = /^[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/.exec(l.text))) out.push({ def: { name: m[1], file, at: l.start, open: l.start + m[0].length - 1, indent: l.indent } });
    else if ((m = /^[ \t]*(?:async\s+)?for\s+(\w+)\s+in\s+([\s\S]*?):\s*(?:#[^\n]*)?$/.exec(l.text))) out.push({ loop: m[1], iter: m[2], at: l.start });
    else if (/^[ \t]*class\b/.test(l.text)) out.push({ cls: true });
  }
  return out;
}

// A function's parameters in order; null where they cannot be read.
function paramsOf(fn) {
  const parts = partsAt(fn.file.text, fn.open);
  if (!parts) return null;
  const params = [];
  let keywordOnly = false;
  for (const p of parts) {
    if (p === "/" || p.startsWith("**")) continue;
    if (p.startsWith("*")) {
      keywordOnly = true;
      continue;
    }
    const m = /^(\w+)\s*(?::[^=]*)?(?:=\s*([\s\S]*))?$/.exec(p);
    if (!m) return null;
    params.push({ name: m[1], positional: !keywordOnly, given: m[2]?.trim() });
  }
  return params;
}

// The project's own top-level function a call names: `create_bp` here or imported, `auth.create_bp`.
function functionOf(expr, file, files, depth = 0) {
  const m = /^(\w+)(?:\s*\.\s*(\w+))?$/.exec(expr.trim());
  if (!m || depth > 3) return null;
  const target = m[2] ? moduleOf(m[1], file, files) : file;
  const name = m[2] || m[1];
  if (!target) return null;
  const d = new RegExp(`^(?:async[ \\t]+)?def[ \\t]+${name}\\s*\\(`, "m").exec(target.text);
  if (d) return { name, file: target, at: d.index, open: d.index + d[0].length - 1, indent: 0 };
  if (m[2]) return null;
  for (const i of target.text.matchAll(/^[ \t]*from\s+([\w.]*)\s+import\s+(\([^)]*\)|[^\n]+)/gm)) {
    for (const part of i[2].replace(/#[^\n]*/g, "").replace(/[()\n]/g, " ").split(",")) {
      const [orig, alias] = part.trim().split(/\s+as\s+/);
      if ((alias || orig) !== name) continue;
      const from = moduleFile(i[1], target, files);
      if (from) return functionOf(orig, from, files, depth + 1);
    }
  }
  return null;
}

// What a function returns: each `return` in its own body, not in a function nested in it.
function returnsOf(fn) {
  const lines = logicalLines(fn.file);
  let i = lines.findIndex((l) => l.start === fn.at);
  if (i < 0) return null;
  const out = [];
  let nested = Infinity;
  for (i++; i < lines.length && lines[i].indent > fn.indent; i++) {
    const l = lines[i];
    if (l.indent > nested) continue;
    nested = Infinity;
    if (/^[ \t]*(?:async\s+)?(?:def|class)\b/.test(l.text)) nested = l.indent;
    const m = /^[ \t]*return\b([\s\S]*)$/.exec(l.text);
    if (m) out.push({ expr: m[1].replace(/#[^\n]*$/, "").trim() || "None", file: fn.file, index: l.start });
  }
  return out;
}

// Every call of a top-level function: its arguments, and where it is made. Null where the function is
// named some other way too -- passed as a value, or in a string -- and so may be called with anything.
function callsOf(fn, files) {
  const calls = [];
  for (const f of files) {
    const refs = f === fn.file ? [fn.name] : [];
    for (const m of f.text.matchAll(/^[ \t]*from\s+([\w.]*)\s+import\s+(\([^)]*\)|[^\n]+)/gm)) {
      for (const part of m[2].replace(/#[^\n]*/g, "").replace(/[()\n]/g, " ").split(",")) {
        const [orig, alias] = part.trim().split(/\s+as\s+/);
        if (!orig) continue;
        if (orig === "*" || orig === fn.name) {
          if (moduleFile(m[1], f, files) === fn.file) refs.push(orig === "*" ? fn.name : alias || orig);
        } else if (moduleFile(/^\.+$/.test(m[1]) ? m[1] + orig : `${m[1]}.${orig}`, f, files) === fn.file) refs.push(`${alias || orig}.${fn.name}`);
      }
    }
    for (const m of f.text.matchAll(/^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?[ \t]*(?:#[^\n]*)?$/gm)) {
      if (moduleFile(m[1], f, files) === fn.file) refs.push(`${m[2] || m[1]}.${fn.name}`);
    }
    for (const ref of new Set(refs)) {
      const re = new RegExp(`(?<![\\w.])${ref.split(".").map(escapeRe).join("\\s*\\.\\s*")}\\b`, "g");
      for (const m of f.text.matchAll(re)) {
        const before = f.text.slice(f.text.lastIndexOf("\n", m.index) + 1, m.index);
        if (before.includes("#") || /\bdef\s+$/.test(before)) continue;
        if (/^[ \t]*(?:from|import)\b/.test(lineAt(f, m.index)?.text || "")) continue;
        const open = /^\s*\(/.exec(f.text.slice(m.index + m[0].length));
        if (!open) return null;
        const args = argsAt(f.text, m.index + m[0].length + open[0].length - 1);
        if (!args) return null;
        calls.push({ args, file: f, index: m.index });
      }
    }
  }
  return calls;
}

// The expressions a name can hold at a point in a file, each with the file and point to read it at.
// A parameter of a top-level function holds what each call of it passes; a loop variable each element
// of a list written out (or assigned to a name); a call of the project's own function what it returns.
// Anything else is its own source. Null where one of these cannot be followed. Each source carries the
// calls it came through (`pin`), so that a second name read under the same pin -- the app a helper's
// blueprint is registered on -- is taken from the same call, not from every call of the helper.
function sourcesOf(expr, file, index, files, depth = 0, pin = new Map()) {
  if (depth > 6) return null;
  const e = expr.trim();
  const call = /^(\w+(?:\s*\.\s*\w+)?)\s*\(/.exec(e);
  if (call && partsAt(e, call[0].length - 1)?.end === e.length - 1) {
    const fn = functionOf(call[1], file, files);
    if (!fn) return [{ expr: e, file, index, pin }];
    return followAll(returnsOf(fn), files, depth, pin);
  }
  if (!/^\w+$/.test(e)) return [{ expr: e, file, index, pin }];
  for (const s of scopesAt(file, index)) {
    if (s.cls) break;
    if (s.loop === e) return followAll(elementsOf(s.iter, file, s.at, files), files, depth, pin);
    if (!s.def) continue;
    const params = paramsOf(s.def);
    if (!params) return null;
    const i = params.findIndex((p) => p.name === e);
    if (i < 0) continue;
    if (s.def.indent > 0) return null;
    const key = `${s.def.file.rel}\0${s.def.at}`;
    const calls = pin.has(key) ? [pin.get(key)] : callsOf(s.def, files);
    if (!calls?.length) return null;
    const passed = [];
    for (const c of calls) {
      if (c.args.spread) return null;
      const p = params[i];
      const arg = (p.positional ? c.args.positional[i] : undefined) ?? c.args.keywords[p.name];
      if (arg === undefined && p.given === undefined) return null;
      // A default is read where the function is defined, which is where Python evaluates it.
      const at = arg === undefined ? { expr: p.given, file: s.def.file, index: s.def.at } : { expr: arg, file: c.file, index: c.index };
      passed.push({ ...at, pin: new Map(pin).set(key, c) });
    }
    return followAll(passed, files, depth, pin);
  }
  return [{ expr: e, file, index, pin }];
}
function followAll(found, files, depth, pin) {
  if (!found) return null;
  const out = [];
  for (const f of found) {
    const s = sourcesOf(f.expr, f.file, f.index, files, depth + 1, f.pin || pin);
    if (!s) return null;
    out.push(...s);
  }
  return out;
}

// The elements of a list or tuple written out, or of the one a name is assigned.
function elementsOf(expr, file, index, files) {
  let e = expr.trim();
  let at = { file, index };
  if (/^\w+$/.test(e)) {
    const def = definition(e, file, files);
    const line = def && logicalLines(def.file).find((l) => new RegExp(`^[ \\t]*${e}\\s*=(?!=)`).test(l.text));
    if (!line) return null;
    e = line.text.replace(/^[^=]*=\s*/, "").replace(/#[^\n]*$/, "").trim();
    at = { file: def.file, index: line.start };
  }
  const parts = /^[[(]/.test(e) ? partsAt(e, 0) : null;
  if (parts?.end !== e.length - 1) return null;
  return parts.map((p) => ({ expr: p, ...at }));
}

// The app or blueprint a name stands for: the `Flask(...)` or `Blueprint(...)` call it is assigned, or
// what it is assigned followed back as far as such a call -- for `app = create_app()`, each `return`
// of the project's function; for `alias = admin`, admin. Without it a hook on `app` imported from
// wsgi.py protected nothing and a blueprint made by a factory had no prefix. A `return None` gives
// nothing; anything else not traced makes it null.
//
// A call written where the value is, `return Blueprint("api", __name__)`, has no name, so it is known
// by where it is written. It was not known at all, and neither was what such a factory made.
function constructedAt(src, files) {
  const e = src.expr.trim();
  const m = new RegExp(`^(?:\\w+\\s*\\.\\s*)?(${[...flaskClasses(files).keys()].join("|")})\\s*\\(`).exec(e);
  const args = m && argsAt(e, m[0].length - 1);
  if (!args || args.end !== e.length - 1) return null;
  return { name: `${m[1]}@${src.index}`, file: src.file, at: src.index, call: { callee: m[1], args } };
}
function madeOf(src, files, seen) {
  if (src.expr.trim() === "None") return [];
  const made = constructedAt(src, files);
  return made ? [made] : madeBy(resolve(src.expr, src.file, files), files, seen);
}
const madeCache = new WeakMap();
function madeBy(def, files, seen = new Set()) {
  if (!def) return null;
  const key = `${def.file.rel}\0${def.name}`;
  if (!madeCache.has(files)) madeCache.set(files, new Map());
  const cache = madeCache.get(files);
  if (seen.size === 0 && cache.has(key)) return cache.get(key);
  let out = null;
  if (!seen.has(key)) {
    if (callOf(def, [...flaskClasses(files).keys()].join("|"))) out = [def];
    else {
      const line = logicalLines(def.file).find((l) => new RegExp(`^[ \\t]*${def.name}\\s*=(?!=)`).test(l.text));
      const value = line && line.text.replace(/^[^=]*=\s*/, "").replace(/#[^\n]*$/, "").trim();
      const sources = value ? sourcesOf(value, def.file, line.start, files) : null;
      if (sources) {
        out = [];
        for (const src of sources) {
          const made = madeOf(src, files, new Set(seen).add(key));
          if (!made) {
            out = null;
            break;
          }
          for (const m of made) if (!out.some((o) => same(o, m))) out.push(m);
        }
      }
    }
  }
  if (seen.size === 0) cache.set(key, out);
  return out;
}
const sameMade = (def, target, files) => madeBy(def, files)?.some((m) => same(m, target)) ?? false;

// Does the code at this point run once? Not inside a loop, and inside functions each called from one
// place that runs once. A factory called twice makes two blueprints, and a hook put on one of them
// (`b1.before_request(...)`) is not on the other: read as one, `b2`'s routes were credited with it.
function runsOnce(file, index, files, depth = 0) {
  if (depth > 4) return false;
  const scopes = scopesAt(file, index);
  if (scopes.some((s) => s.loop)) return false;
  const defs = scopes.filter((s) => s.def);
  if (!defs.length) return true;
  // A factory is a top-level function (functionOf), so its body is one def deep.
  const calls = callsOf(defs[0].def, files);
  if (calls?.length !== 1) return false;
  return runsOnce(calls[0].file, calls[0].index, files, depth + 1);
}
function madeOnce(made, files) {
  const at = made.at ?? logicalLines(made.file).find((l) => new RegExp(`^[ \\t]*${made.name}\\s*=(?!=)`).test(l.text))?.start;
  return at !== undefined && runsOnce(made.file, at, files);
}

// Is a route declared on `routeDef` on the object a hook was put on? The hook was put on `via`, which
// is `target` once followed back. A hook put on the name the factory itself makes runs on everything
// the factory makes; one put on a name a call of it was assigned only on that, unless it runs once.
function onHooked(routeDef, target, via, files) {
  if (!sameMade(routeDef, target, files)) return false;
  return same(via, target) || same(routeDef, via) || madeOnce(target, files);
}

// The url_prefix each registration gives an app's or blueprint's routes: [null] for an app, one per
// `register_blueprint` call for a blueprint. The blueprint registered, and what it is registered on,
// are followed back to where they come from (sourcesOf). Null where a prefix cannot be read: one that
// is not a literal, a blueprint whose registration is not found, or one registered on something not
// traced to an app or a blueprint -- including a parameter of a function not seen called.
const prefixCache = new WeakMap();
function prefixesOf(def, files, depth = 0) {
  if (!def || depth > 4) return null;
  if (depth === 0) {
    if (!prefixCache.has(files)) prefixCache.set(files, new Map());
    const cache = prefixCache.get(files);
    const key = `${def.file.rel}\0${def.name}`;
    if (!cache.has(key)) cache.set(key, prefixesOf(def, files, 1));
    return cache.get(key);
  }
  const kinds = flaskClasses(files);
  const call = callOf(def, [...kinds.keys()].join("|"));
  if (!call) {
    // Made by a factory: the prefixes of whatever it makes, all of them known or none.
    const made = madeBy(def, files);
    if (!made?.length) return null;
    const all = [];
    for (const m of made) {
      const p = prefixesOf(m, files, depth + 1);
      if (!p) return null;
      all.push(...p);
    }
    return [...new Set(all)];
  }
  if (!call.args) return null;
  if (kinds.get(call.callee) === "Flask") return [null];
  const { positional, keywords, spread } = call.args;
  if (spread || positional.length > 5) return null;
  const own = keywords.url_prefix === undefined ? null : literal(keywords.url_prefix);
  if (own === UNREAD || new RegExp(`^[ \\t]*${def.name}\\s*\\.\\s*url_prefix\\s*=`, "m").test(def.file.text)) return null;
  const out = [];
  for (const f of files) {
    for (const m of f.text.matchAll(/^[ \t]*([\w.]+?)\s*\.\s*register_blueprint\s*\(/gm)) {
      const args = argsAt(f.text, m.index + m[0].length - 1);
      const first = args && (args.keywords.blueprint ?? args.positional[0]);
      const registered = first && sourcesOf(first, f, m.index, files)?.filter((s) => sameMade(resolve(s.expr, s.file, files), def, files));
      if (!registered?.length) continue;
      const given = args.spread ? UNREAD : literal(args.keywords.url_prefix);
      if (given === UNREAD) return null;
      const prefix = given ?? own;
      for (const r of registered) {
        const owners = sourcesOf(m[1], f, m.index, files, 0, r.pin);
        if (!owners) return null;
        for (const o of owners) {
          const parents = prefixesOf(resolve(o.expr, o.file, files), files, depth + 1);
          if (!parents) return null;
          for (const s of parents) out.push(s != null && prefix != null ? `${s.replace(/\/+$/, "")}/${prefix.replace(/^\/+/, "")}` : prefix ?? s);
        }
      }
    }
  }
  return out.length ? [...new Set(out)] : null;
}

// Flask and Blueprint, and the project's own subclasses of them (CTFd's app is a `CTFdFlask`).
const projectClasses = new WeakMap();
function flaskClasses(files) {
  if (!projectClasses.has(files)) {
    const kinds = new Map([["Flask", "Flask"], ["Blueprint", "Blueprint"]]);
    for (let round = 0; round < 2; round++) {
      for (const f of files) {
        for (const m of f.text.matchAll(/^[ \t]*class\s+(\w+)\s*\(\s*(?:\w+\s*\.\s*)?(\w+)\s*\)/gm)) if (kinds.has(m[2])) kinds.set(m[1], kinds.get(m[2]));
      }
    }
    projectClasses.set(files, kinds);
  }
  return projectClasses.get(files);
}

// --- a rule made by a call -----------------------------------------------------------------------
// Redash writes 19 of its rules as `@routes.route(org_scoped_rule("/login"))`, and
// `def org_scoped_rule(rule)` returns `"/<org_slug>{}".format(rule)` when MULTI_ORG is set, else
// `rule`. The values a rule can have are read by binding the call's arguments to the function's
// parameters and reading each `return`, every branch alike, since which one runs is configuration.
// Followed: string literals, f-strings, `+`, `str.format`, a parameter, and a call of a project
// function. Anything else makes the rule unknown, so a hook's path rule is taken to reach the route.
const MAX_RULES = 16;

// `s` split at `sep` outside brackets and strings.
function splitTop(s, sep) {
  const out = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (quote) {
      if (c === "\\") k++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === sep && depth === 0) {
      out.push(s.slice(start, k));
      start = k + 1;
    }
  }
  out.push(s.slice(start));
  return out;
}

// Every string made by concatenating one value from each list, or null past MAX_RULES.
function product(lists) {
  let out = [""];
  for (const l of lists) {
    if (!l) return null;
    out = out.flatMap((a) => l.map((b) => a + b));
    if (out.length > MAX_RULES) return null;
  }
  return out;
}

// A template's text and `{...}` fields, in order. A field with a format spec or conversion, or `{{`,
// names no argument, so the rule is not known.
function fieldsOf(body) {
  const parts = [];
  let text = "";
  for (let k = 0; k < body.length; k++) {
    const c = body[k];
    if (c === "{") {
      const close = body.indexOf("}", k);
      if (close < 0) return null;
      parts.push(text, { field: body.slice(k + 1, close).trim() });
      text = "";
      k = close;
    } else if (c === "}") return null;
    else text += c;
  }
  parts.push(text);
  return parts;
}

/** The strings a rule expression can be, in `file` with `env` binding names to their values; or null. */
function ruleValues(expr, env, file, files, depth = 0) {
  const e = expr.trim();
  if (depth > 4 || !e) return null;
  const sum = splitTop(e, "+");
  if (sum.length > 1) return product(sum.map((s) => ruleValues(s, env, file, files, depth + 1)));
  let m;
  if ((m = /^([rRuUfF]{0,2})(['"])((?:(?!\2)[^\\\n])*)\2$/.exec(e))) {
    if (!/f/i.test(m[1])) return [m[3]];
    const parts = fieldsOf(m[3]);
    return parts && product(parts.map((p) => (typeof p === "string" ? [p] : (env.get(p.field) ?? null))));
  }
  if (/^\w+$/.test(e)) return env.get(e) ?? null;
  if (e.startsWith("(") && e.endsWith(")") && partsAt(e, 0)?.end === e.length - 1) return ruleValues(e.slice(1, -1), env, file, files, depth + 1);
  if ((m = /^[rRuU]?(['"])((?:(?!\1)[^\\\n])*)\1\s*\.\s*format\s*\(/.exec(e))) {
    const args = argsAt(e, m[0].length - 1);
    const parts = fieldsOf(m[2]);
    if (!parts || !args || args.spread || args.end !== e.length - 1) return null;
    let next = 0;
    const value = (f) => (f === "" ? args.positional[next++] : /^\d+$/.test(f) ? args.positional[+f] : args.keywords[f]);
    return product(parts.map((p) => (typeof p === "string" ? [p] : ((a) => (a === undefined ? null : ruleValues(a, env, file, files, depth + 1)))(value(p.field)))));
  }
  if ((m = /^(\w+(?:\s*\.\s*\w+)?)\s*\(/.exec(e))) {
    const args = argsAt(e, m[0].length - 1);
    if (!args || args.spread || args.end !== e.length - 1) return null;
    const fn = functionOf(m[1], file, files);
    const params = fn && paramsOf(fn);
    if (!params) return null;
    const bound = new Map();
    for (const [i, p] of params.entries()) {
      const arg = (p.positional ? args.positional[i] : undefined) ?? args.keywords[p.name];
      // A default is evaluated where the function is defined, with nothing bound.
      const v = arg !== undefined ? ruleValues(arg, env, file, files, depth + 1) : p.given !== undefined ? ruleValues(p.given, new Map(), fn.file, files, depth + 1) : null;
      if (!v) return null;
      bound.set(p.name, v);
    }
    const returns = returnsOf(fn);
    if (!returns?.length) return null;
    const out = [];
    for (const r of returns) {
      const v = ruleValues(r.expr, bound, fn.file, files, depth + 1);
      if (!v) return null;
      out.push(...v);
    }
    const unique = [...new Set(out)];
    return unique.length > MAX_RULES ? null : unique;
  }
  return null;
}

/** Each rule a route can have: the literal in its decorator, or what the call there can return. */
function rulesOf(route, file, files) {
  return route.ruleExpr === undefined ? [route.route] : file ? ruleValues(route.ruleExpr, new Map(), file, files) : null;
}

const joinRule = (prefix, rule) => (prefix == null ? rule : rule ? `${prefix.replace(/\/+$/, "")}/${rule.replace(/^\/+/, "")}` : prefix);

/** The full paths of a route declared on an app or a blueprint, or null. */
function routePaths(route, file, files) {
  const rules = rulesOf(route, file, files);
  const prefixes = rules && file && prefixesOf(resolve(route.receiver, file, files), files);
  return prefixes ? [...new Set(prefixes.flatMap((p) => rules.map((r) => joinRule(p, r))))] : null;
}


// --- flask-restx ---------------------------------------------------------------------------------
// A flask-restx route is declared on a Namespace (`@ns.route`) or on the Api (`@api.route`), not on
// the blueprint, so a blueprint's hook was never matched to it -- though Flask runs that hook for it
// once the Api is mounted on the blueprint: `api = Api(bp)`, `Api(app=bp)`, `api.init_app(bp)`. The
// chain read: the route's receiver, the Api that owns it (`ns = api.namespace(...)`, or
// `api.add_namespace(ns)` anywhere in the project), and the blueprint that Api is mounted on.

// The file a module names, from the importing file: `.things` and `..api` beside it, `CTFd.api.v1.users`
// by its whole dotted path. Matching on the last part alone took CTFd's `CTFd/users.py` for
// `CTFd.api.v1.users`. Where a dotted path matches in more than one place (two services in one
// repository), the one whose root holds the importing file; otherwise it is not resolved.
function moduleFile(module, file, files) {
  const dots = /^\.*/.exec(module)[0].length;
  const rest = module.slice(dots).replace(/\./g, "/");
  let candidates;
  if (dots) {
    let base = path.posix.dirname(file.rel);
    for (let k = 1; k < dots; k++) base = path.posix.dirname(base);
    const target = rest ? path.posix.join(base, rest) : base;
    candidates = files.filter((f) => f.rel === `${target}.py` || f.rel === path.posix.join(target, "__init__.py"));
  } else {
    const rootOf = (f) =>
      [`${rest}.py`, `${rest}/__init__.py`].map((p) => (f.rel === p ? "" : f.rel.endsWith(`/${p}`) ? f.rel.slice(0, -p.length) : null)).find((r) => r !== null);
    candidates = files.filter((f) => f !== file && rootOf(f) !== undefined);
    if (candidates.length > 1) candidates = candidates.filter((f) => file.rel.startsWith(rootOf(f)));
  }
  candidates = candidates.filter((f) => f !== file);
  return candidates.length === 1 ? candidates[0] : null;
}

// Where a name used in a file is assigned: in that file, or in the module it is imported from
// (`from .api import ns`, `from app.api import ns as things`, `from . import api` in a package).
function definition(name, file, files, depth = 0) {
  if (depth > 3) return null;
  if (new RegExp(`^[ \\t]*${name}\\s*=(?!=)`, "m").test(file.text)) return { name, file };
  for (const m of file.text.matchAll(/^[ \t]*from\s+([\w.]*)\s+import\s+(\([^)]*\)|[^\n]+)/gm)) {
    for (const part of m[2].replace(/#[^\n]*/g, "").replace(/[()\n]/g, " ").split(",")) {
      const [orig, alias] = part.trim().split(/\s+as\s+/);
      if ((alias || orig) !== name) continue;
      const target = moduleFile(m[1], file, files);
      if (target) return definition(orig, target, files, depth + 1);
    }
  }
  return null;
}
const same = (a, b) => a && b && a.name === b.name && a.file === b.file;
const assigned = (def) => (new RegExp(`^[ \\t]*${def.name}\\s*=(?!=)\\s*([^\\n]*)`, "m").exec(def.file.text) || [])[1] || "";

const projectFiles = new WeakMap();
function filesOf(texts, rels) {
  if (!projectFiles.has(texts)) projectFiles.set(texts, texts.map((text, i) => ({ text, rel: rels[i] })));
  return projectFiles.get(texts);
}

// A namespace's path, from `Namespace(name, description, path)` or `api.namespace(...)`.
function nsPathOf(args) {
  if (!args || args.spread) return UNREAD;
  const p = literal(args.keywords.path ?? args.positional[2]);
  if (p === UNREAD) return UNREAD;
  if (p) return p.replace(/\/+$/, "");
  const name = literal(args.keywords.name ?? args.positional[0]);
  return typeof name === "string" ? `/${name}`.replace(/\/+$/, "") : UNREAD;
}

// One Api a flask-restx route is served through: the blueprint it is mounted on, and the route's
// full paths there. Each Api mounted elsewhere is served separately and has to be protected too.
function mountOf(api, nsPath, route, files) {
  if (!api) return { restx: true, blueprint: null, paths: null };
  const call = callOf(api, "Api");
  let target = call?.args && !call.args.spread ? call.args.keywords.app ?? call.args.positional[0] : undefined;
  if (target === undefined || target === "None") {
    const m = new RegExp(`^[ \\t]*${api.name}\\s*\\.\\s*init_app\\s*\\(`, "m").exec(api.file.text);
    const args = m && argsAt(api.file.text, m.index + m[0].length - 1);
    target = args ? args.keywords.app ?? args.positional[0] : undefined;
  }
  const made = target ? madeBy(resolve(target, api.file, files), files) : null;
  const blueprint = made?.length === 1 ? made[0] : null;
  const prefixes = prefixesOf(blueprint, files);
  const apiPrefix = !call?.args || call.args.spread ? UNREAD : literal(call.args.keywords.prefix) ?? "";
  let paths = null;
  const rules = rulesOf(route, files.find((f) => f.rel === route.rel && f.text === route.text), files);
  if (prefixes && rules && apiPrefix !== UNREAD && nsPath !== UNREAD) {
    // A resource added after the blueprint is registered skips the Api's prefix.
    paths = [...new Set(rules.flatMap((rule) => prefixes.flatMap((p) => [(p || "") + apiPrefix + nsPath + rule, ...(p && apiPrefix ? [p + nsPath + rule] : [])])))];
  }
  return { restx: true, blueprint, paths };
}

/** For a flask-restx route, each Api it is served through (see mountOf); null for any other route. */
function restxOf(route, texts, rels) {
  const files = filesOf(texts, rels);
  const file = files.find((f) => f.rel === route.rel && f.text === route.text);
  if (!file) return null;
  const receiver = definition(route.receiver, file, files);
  if (!receiver) return null;
  const value = assigned(receiver);
  const apis = [];
  let m;
  if (/^(?:flask_restx\s*\.\s*)?Api\s*\(/.test(value)) apis.push({ api: receiver, nsPath: "" });
  else if ((m = /^(\w+)\s*\.\s*namespace\s*\(/.exec(value))) apis.push({ api: definition(m[1], receiver.file, files), nsPath: nsPathOf(callOf(receiver, "namespace")?.args) });
  else if (/^(?:flask_restx\s*\.\s*)?Namespace\s*\(/.test(value)) {
    const own = nsPathOf(callOf(receiver, "Namespace")?.args);
    for (const f of files) {
      for (const c of f.text.matchAll(/^[ \t]*([\w.]+?)\s*\.\s*add_namespace\s*\(/gm)) {
        const args = argsAt(f.text, c.index + c[0].length - 1);
        const first = args && (args.keywords.ns ?? args.positional[0]);
        if (!first || !same(resolve(first, f, files), receiver)) continue;
        const given = args.spread ? UNREAD : literal(args.keywords.path ?? args.positional[1]);
        apis.push({ api: resolve(c[1], f, files), nsPath: given === UNREAD ? UNREAD : given || own });
      }
    }
  } else return null;
  return apis.length ? apis.map(({ api, nsPath }) => mountOf(api, nsPath, route, files)) : [{ restx: true, blueprint: null, paths: null }];
}

// Does the hook run for the route? An app's hook for the routes under the app's directory; a
// blueprint's for its own routes, and for a flask-restx route served through an Api mounted on it.
function reaches(hook, route, serving, files) {
  if (hook.scope === "app") {
    const dir = path.posix.dirname(hook.appRel);
    if (route.rel.startsWith(dir === "." ? "" : `${dir}/`)) return true;
    // A route declared on what the hook is on, wherever it is: `app = create_app()` in wsgi.py.
    return onHooked(resolve(route.receiver, files.find((f) => f.rel === route.rel && f.text === route.text), files), hook.on, hook.via, files);
  }
  if (serving.restx) return same(serving.blueprint, hook.blueprint);
  return onHooked(resolve(route.receiver, files.find((f) => f.rel === route.rel && f.text === route.text), files), hook.blueprint, hook.via, files);
}

/** What protects a Flask route from outside its body, or null. */
export function flaskRouteAuth(route, texts, rels) {
  for (const dec of route.decorators || []) {
    const by = decoratorAuth(dec, route.text, texts);
    if (by) return by;
  }
  const hooks = hooksIn(texts, rels);
  if (!hooks.length) return null;
  const files = filesOf(texts, rels);
  const file = files.find((f) => f.rel === route.rel && f.text === route.text);
  // Each way the route is served must be protected: a namespace added to two Apis is served by both.
  const servings = restxOf(route, texts, rels) || [{ paths: routePaths(route, file, files) }];
  let by = null;
  for (const serving of servings) {
    const hook = hooks.find((h) => reaches(h, route, serving, files) && !exempted(h, route, serving));
    if (!hook) return null;
    by ||= hook;
  }
  return `a before_request hook (${by.at})`;
}
