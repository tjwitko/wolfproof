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
//   stays open, and a hook that lets requests through on any other condition credits nothing, since
//   which routes that condition opens cannot be read.

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
    for (const part of m[1].replace(/[()\n]/g, " ").split(",")) {
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

function exemptionOf(cond) {
  const rules = [];
  for (const part of unwrap(cond).split(/\s+or\s+/)) {
    const p = unwrap(part);
    let m;
    if ((m = /^request\s*\.\s*endpoint\s+(?:in|==)\s*([\s\S]+)$/.exec(p))) rules.push({ endpoints: LITERALS(m[1]) });
    else if ((m = /^request\s*\.\s*(?:path|url_rule\s*\.\s*rule)\s*(?:in|==)\s*([\s\S]+)$/.exec(p))) rules.push({ paths: LITERALS(m[1]) });
    else if ((m = /^request\s*\.\s*path\s*\.\s*startswith\s*\(([\s\S]+)\)$/.exec(p))) rules.push({ prefixes: LITERALS(m[1]) });
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

const stem = (rel) => (path.posix.basename(rel) === "__init__.py" ? path.posix.basename(path.posix.dirname(rel)) : path.posix.basename(rel, ".py"));

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
      if (def < lines.length && /^\s*(?:async\s+)?def\b/.test(lines[def])) found.push({ receiver: m[1], kind: m[2], body: defBlock(lines, def).join("\n"), line: d + 1 });
    });
    for (const m of text.matchAll(/^\s*(\w+)\s*\.\s*(before_request|before_app_request)\s*\(\s*(\w+)\s*\)/gm)) {
      const d = lines.findIndex((l) => new RegExp(`^\\s*(?:async\\s+)?def\\s+${m[3]}\\s*\\(`).test(l));
      if (d >= 0) found.push({ receiver: m[1], kind: m[2], body: defBlock(lines, d).join("\n"), line: d + 1 });
    }
    for (const h of found) {
      const credit = hookCredit(h.body);
      if (!credit) continue;
      const isApp = new RegExp(`^\\s*${h.receiver}\\s*=\\s*(?:flask\\s*\\.\\s*)?Flask\\s*\\(`, "m").test(text);
      const isBlueprint = new RegExp(`^\\s*${h.receiver}\\s*=\\s*(?:flask\\s*\\.\\s*)?Blueprint\\s*\\(`, "m").test(text);
      // A blueprint's before_app_request runs for the whole app, as the app's own hook does.
      const scope = h.kind === "before_app_request" || isApp ? "app" : isBlueprint ? "blueprint" : null;
      if (scope) hooks.push({ ...h, ...credit, scope, rel: rels[i], text, at: `${rels[i]}:${h.line}` });
    }
  });
  projectHooks.set(texts, hooks);
  return hooks;
}

// Does the route's receiver name the hook's blueprint? The same file, or a file importing that name
// from the hook's module (`from .auth import bp`, or `from . import main` in the package's
// __init__.py). Two blueprints both called `bp` in different modules are not one blueprint.
function sameBlueprint(hook, route) {
  if (route.receiver !== hook.receiver) return false;
  if (route.rel === hook.rel) return true;
  for (const m of route.text.matchAll(/^[ \t]*from\s+([\w.]*)\s+import\s+(\([^)]*\)|[^\n]+)/gm)) {
    const names = m[2].replace(/[()\n]/g, " ").split(",").map((p) => p.trim().split(/\s+as\s+/).pop());
    if (!names.includes(route.receiver)) continue;
    const module = m[1];
    if (/^\.+$/.test(module)) {
      if (path.posix.basename(hook.rel) === "__init__.py" && path.posix.dirname(hook.rel) === path.posix.dirname(route.rel)) return true;
    } else if (module.split(".").pop() === stem(hook.rel)) return true;
  }
  return false;
}

function exempted(hook, route) {
  return hook.exemptions.some((e) => {
    if (!e.endpoints && !e.paths && !e.prefixes) return false;
    if (e.endpoints?.some((ep) => ep === route.view || ep.endsWith(`.${route.view}`))) return true;
    // A blueprint's url_prefix is not part of the path read here, so a path rule is taken to reach
    // any route whose full path is not known.
    const prefixed = /url_prefix\s*=/.test(route.text);
    if (e.paths?.some((p) => p === route.route || prefixed)) return true;
    if (e.prefixes?.some((p) => route.route.startsWith(p) || prefixed)) return true;
    return false;
  });
}

/** What protects a Flask route from outside its body, or null. */
export function flaskRouteAuth(route, texts, rels) {
  for (const dec of route.decorators || []) {
    const by = decoratorAuth(dec, route.text, texts);
    if (by) return by;
  }
  for (const hook of hooksIn(texts, rels)) {
    const reaches =
      hook.scope === "app"
        ? route.rel.startsWith(path.posix.dirname(hook.rel) === "." ? "" : `${path.posix.dirname(hook.rel)}/`)
        : sameBlueprint(hook, route);
    if (reaches && !exempted(hook, route)) return `a before_request hook (${hook.at})`;
  }
  return null;
}
