// Fastify hooks scoped by directory: @fastify/autoload's `autohooks` files (docs/checks.md).
//
// A route loaded by @fastify/autoload is protected by the hooks in the `autohooks` file of its own
// directory, and of the directories above it when `cascadeHooks` is set. fastify/demo protects every
// API route this way, from `src/routes/api/autohooks.ts`, and all thirteen of its routes were reported
// open. The project-wide reading of `addHook` credited every route in a project instead, wherever the
// hook was, when its first 120 characters named authentication.
//
// Each rule here was measured on Fastify 5.12.7 with @fastify/autoload 6.5.1, against what autoload's
// source says (lib/find-plugins.js, index.js):
// - The file is `autohooks`, `_autohooks`, `.autohooks` or `auto_hooks`, any JS or TS extension, and is
//   read only with `autoHooks: true`; without it the file is not loaded at all, and its routes ran.
// - Its hooks reach the plugins of its own directory; with `cascadeHooks: true` the subdirectories'
//   too. A sibling directory is not reached. With `overwriteHooks: true` a directory that has its own
//   file starts the chain again, and a route there ran though its parent's hook refused it.
// - A route's URL is the `options.prefix`, then each directory name (unless `dirNameRoutePrefix` is
//   false), then its own path: `api/users/index.ts`'s `/update-password` is `/api/users/update-password`.
// - A hook that sends a refusal stops the route whether or not it returns (auth-handler.mjs).

import path from "path";
import { handlerGuard, _internals } from "./auth-handler.mjs";
import { ruleParts, servesPath, servesPrefix } from "./authentication-flask.mjs";

const { closeOf, maskStrings, braceStatements } = _internals;
const posix = path.posix;

export const AUTOHOOKS_FILE = /^[_.]?auto_?hooks\.(?:ts|js|cjs|mjs|cts|mts)$/i;
// Embedded in other patterns, so it has no group of its own to refer back to.
const AUTOLOAD_SOURCE = String.raw`['"\x60](?:@fastify\/autoload|fastify-autoload)['"\x60]`;
// Hooks that run before the handler. onSend, onResponse and the rest run after it, or not per request.
const BEFORE_HANDLER = /^(['"`])(onRequest|preParsing|preValidation|preHandler)\1\s*,\s*/;

// --- reading values --------------------------------------------------------------------------------

/** A quoted string with nothing interpolated, or undefined. */
function stringLiteral(expr) {
  const m = /^\s*(['"`])((?:(?!\1)[^\\$]|\\.)*)\1\s*$/.exec(expr);
  return m ? m[2] : undefined;
}

/** The text between the brackets at `open`, split at its top-level commas (strings masked in `masked`). */
function topLevelParts(text, masked, open) {
  const close = closeOf(masked, open);
  if (close < 0) return null;
  const parts = [];
  let depth = 0;
  let from = open + 1;
  for (let k = open + 1; k < close; k++) {
    const c = masked[k];
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) {
      parts.push(text.slice(from, k));
      from = k + 1;
    }
  }
  parts.push(text.slice(from, close));
  return Object.assign(parts.map((p) => p.trim()).filter(Boolean), { close });
}

/** An object literal's entries: `{ key: value }` and shorthand `{ key }` by key, and its spreads. */
function objectEntries(expr) {
  const t = expr.trim();
  if (!t.startsWith("{")) return null;
  const parts = topLevelParts(t, maskStrings(t, "brace"), 0);
  if (!parts) return null;
  const entries = new Map();
  const spreads = [];
  for (const p of parts) {
    let m;
    if ((m = /^\.\.\.\s*([\s\S]+)$/.exec(p))) spreads.push(m[1].trim());
    else if ((m = /^(?:(['"])(\w+)\1|(\w+))\s*:\s*([\s\S]+)$/.exec(p))) entries.set(m[2] || m[3], m[4].trim());
    else if (/^\w+$/.test(p)) entries.set(p, p);
    else return null;
  }
  return { entries, spreads };
}

/** `true` or `false` written out, the default when absent, null otherwise. */
function flag(entries, key, absent) {
  if (!entries.has(key)) return absent;
  const v = entries.get(key);
  return v === "true" ? true : v === "false" ? false : null;
}

// --- where autoload loads from ---------------------------------------------------------------------

// The directory a file is in, written as Node or ESM spells it, and as a name assigned one of those.
function isDirOfFile(expr, text) {
  const e = expr.trim();
  if (/^(?:__dirname|import\s*\.\s*meta\s*\.\s*dirname)$/.test(e)) return true;
  if (/^(?:path\s*\.\s*)?dirname\s*\(\s*(?:url\s*\.\s*)?fileURLToPath\s*\(\s*import\s*\.\s*meta\s*\.\s*url\s*\)\s*\)$/.test(e)) return true;
  if (!/^\w+$/.test(e)) return false;
  const def = new RegExp(String.raw`(?:const|let|var)\s+${e}\s*=\s*([^\n;]+)`).exec(text);
  return Boolean(def && def[1].trim() !== e && isDirOfFile(def[1], text));
}

/** The project-relative directory `dir:` names, or null when it is not written out from the file's own. */
function dirOf(expr, rel, text) {
  const here = posix.dirname(rel);
  const e = expr.trim();
  let m;
  if ((m = /^(?:path\s*\.\s*)?(?:join|resolve)\s*\(/.exec(e))) {
    const masked = maskStrings(e, "brace");
    const args = topLevelParts(e, masked, m[0].length - 1);
    if (!args || args.close !== e.length - 1 || !args.length || !isDirOfFile(args[0], text)) return null;
    const rest = args.slice(1).map(stringLiteral);
    return rest.some((s) => s === undefined) ? null : posix.normalize(posix.join(here, ...rest));
  }
  if ((m = /^`\$\{([^}]+)\}([^`$]*)`$/.exec(e)) && isDirOfFile(m[1], text)) return posix.normalize(posix.join(here, m[2]));
  return null;
}

// Where the plugin whose options `name` is comes from: the enclosing function's second parameter.
// `options: { ...opts }` passes on whatever the app was registered with, so its prefix is known only
// when every registration of that function in the project is read and passes no options -- fastify/demo
// registers `fp(serviceApp)` and nothing else. An app started by fastify-cli has no registration here,
// and its prefix is not known. A test's registration is not how the app is served: fastify/demo's
// test/helper.ts registers it with the test configuration.
const TEST_CODE = /(?:^|\/)(?:tests?|__tests__|spec)\/|\.(?:test|spec)\.[mc]?[jt]sx?$/;
function passesNoPrefix(name, file, index, project) {
  const before = file.text.slice(0, index);
  const fns = [...before.matchAll(/(export\s+default\s+)?(?:async\s+)?function\s*(\w*)\s*\(([^)]*)\)/g)];
  const fn = fns[fns.length - 1];
  if (!fn) return false;
  const params = fn[3].split(",").map((p) => p.replace(/[:=][\s\S]*$/, "").trim());
  if (params[1] !== name) return false;
  const exported = fn[1] ? "default" : fn[2];
  if (!exported) return false;
  const stem = (rel) => rel.replace(/\.(?:[cm]?[jt]s|tsx?)$/, "");
  const registrations = [];
  for (const other of project) {
    if (TEST_CODE.test(other.rel)) continue;
    for (const imp of other.text.matchAll(/import\s+(?:(\w+)|\{([^}]*)\})\s+from\s*(['"`])(\.{1,2}\/[^'"`]+)\3/g)) {
      const target = posix.normalize(posix.join(posix.dirname(other.rel), imp[4]));
      if (stem(target) !== stem(file.rel)) continue;
      const local =
        exported === "default"
          ? imp[1]
          : (imp[2] || "").split(",").map((s) => s.trim().split(/\s+as\s+/)).find(([n]) => n === exported)?.slice(-1)[0];
      if (!local) continue;
      const masked = maskStrings(other.text, "brace");
      for (const reg of masked.matchAll(/\.\s*register\s*\(/g)) {
        const args = topLevelParts(other.text, masked, reg.index + reg[0].length - 1);
        if (!args || !new RegExp(String.raw`^(?:\w+\s*\(\s*)?${local}\s*\)?$`).test(args[0])) continue;
        registrations.push(args.slice(1));
      }
    }
  }
  return registrations.length > 0 && registrations.every((rest) => rest.length === 0 || /^\{\s*\}$/.test(rest[0]));
}

/** The prefix autoload gives every route it loads, '' for none, or null when it is not read. */
function prefixOf(entries, file, index, project) {
  let prefix = "";
  if (entries.has("prefix")) {
    const p = stringLiteral(entries.get("prefix"));
    if (p === undefined) return null;
    prefix += p;
  }
  if (!entries.has("options")) return prefix;
  const value = entries.get("options");
  const options = objectEntries(value) || (/^\w+$/.test(value) ? { entries: new Map(), spreads: [value] } : null);
  if (!options) return null;
  for (const s of options.spreads) if (!/^\w+$/.test(s) || !passesNoPrefix(s, file, index, project)) return null;
  if (options.entries.has("prefix")) {
    const p = stringLiteral(options.entries.get("prefix"));
    if (p === undefined) return null;
    prefix += p;
  }
  return prefix;
}

/** Every `register(autoload, {...})` in the project, read. */
const rootsCache = new WeakMap();
function autoloadRoots(project) {
  if (rootsCache.has(project)) return rootsCache.get(project);
  const roots = [];
  for (const file of project) {
    if (!new RegExp(AUTOLOAD_SOURCE).test(file.text)) continue;
    const names = new Set();
    for (const m of file.text.matchAll(new RegExp(String.raw`import\s+(\w+)\s*(?:,\s*\{[^}]*\})?\s*from\s*${AUTOLOAD_SOURCE}`, "g"))) names.add(m[1]);
    for (const m of file.text.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*${AUTOLOAD_SOURCE}\s*\)`, "g"))) names.add(m[1]);
    const masked = maskStrings(file.text, "brace");
    for (const reg of masked.matchAll(/\.\s*register\s*\(/g)) {
      const args = topLevelParts(file.text, masked, reg.index + reg[0].length - 1);
      if (!args || args.length < 2) continue;
      const plugin = args[0];
      if (!names.has(plugin) && !new RegExp(String.raw`^(?:require|import)\s*\(\s*${AUTOLOAD_SOURCE}\s*\)$`).test(plugin)) continue;
      const opts = objectEntries(args[1]);
      if (!opts || opts.spreads.length || !opts.entries.has("dir")) continue;
      const dir = dirOf(opts.entries.get("dir"), file.rel, file.text);
      if (!dir) continue;
      const dirPrefix = flag(opts.entries, "dirNameRoutePrefix", true);
      roots.push({
        dir,
        at: `${file.rel}:${file.text.slice(0, reg.index).split("\n").length}`,
        autoHooks: flag(opts.entries, "autoHooks", false),
        cascade: flag(opts.entries, "cascadeHooks", false),
        overwrite: flag(opts.entries, "overwriteHooks", false),
        dirPrefix,
        prefix: prefixOf(opts.entries, file, reg.index, project),
      });
    }
  }
  rootsCache.set(project, roots);
  return roots;
}

// --- what a hook does --------------------------------------------------------------------------------

const URL_EXPR = String.raw`[\w$]+\s*\.\s*(?:raw\s*\.\s*)?(?:url|originalUrl|routerPath|routeOptions\s*\??\.\s*url)`;

/** The parts of a condition joined by `||` at its top level. */
function orParts(cond) {
  const masked = maskStrings(cond, "brace");
  const parts = [];
  let depth = 0;
  let from = 0;
  for (let k = 0; k < masked.length; k++) {
    const c = masked[k];
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (depth === 0 && masked.startsWith("||", k)) {
      parts.push(cond.slice(from, k));
      from = k + 2;
      k++;
    }
  }
  parts.push(cond.slice(from));
  return parts.map(unwrap);
}

function unwrap(s) {
  let t = s.trim();
  while (t.startsWith("(") && closeOf(maskStrings(t, "brace"), 0) === t.length - 1) t = t.slice(1, -1).trim();
  return t;
}

// What a hook's early `return` lets through, read as path rules. A condition that is not one of these
// is taken to let through every route: a pass-through not read cannot be bounded.
function exemptionOf(cond) {
  return orParts(cond).map((part) => {
    const neg = /^!\s*/.exec(part);
    const p = neg ? unwrap(part.slice(neg[0].length)) : part;
    let m;
    if ((m = new RegExp(String.raw`^${URL_EXPR}\s*\.\s*startsWith\s*\(\s*([\s\S]+?)\s*\)$`).exec(p))) {
      const lit = stringLiteral(m[1]);
      return lit === undefined ? { unread: true } : { prefix: lit, neg: Boolean(neg) };
    }
    if (!neg && ((m = new RegExp(String.raw`^${URL_EXPR}\s*===?\s*([\s\S]+)$`).exec(p)) || (m = new RegExp(String.raw`^([\s\S]+?)\s*===?\s*${URL_EXPR}$`).exec(p)))) {
      const lit = stringLiteral(m[1]);
      return lit === undefined ? { unread: true } : { paths: [lit] };
    }
    if (!neg && (m = new RegExp(String.raw`^\[([^\]]*)\]\s*\.\s*includes\s*\(\s*${URL_EXPR}\s*\)$`).exec(p))) {
      const lits = m[1].split(",").map((s) => s.trim()).filter(Boolean).map(stringLiteral);
      return lits.some((l) => l === undefined) ? { unread: true } : { paths: lits };
    }
    return { unread: true };
  });
}

// A branch that only lets the request on: `return`, `done()`, or both.
const PASS = /^\s*\{?\s*(?:return\s*(?:done\s*\(\s*\))?\s*;?|done\s*\(\s*\)\s*;?(?:\s*return\s*;?)?)\s*\}?\s*$/;

/** A hook function's verdict: { reason, exemptions } when it refuses a caller, else null. */
function judgeFunction(fnText, authWord) {
  const m = /^(?:async\s+)?(?:function\s*[\w$]*\s*)?\(([^)]*)\)\s*(?::\s*[^={]+)?(?:=>\s*)?\{/.exec(fnText);
  if (!m) return null;
  const params = m[1].split(",").map((s) => s.replace(/[:=][\s\S]*$/, "").trim());
  const open = m[0].length - 1;
  const close = closeOf(maskStrings(fnText, "brace"), open);
  if (close < 0) return null;
  const body = fnText.slice(open, close + 1);
  const reason = handlerGuard([body], "brace", { hook: params[1] || "\u0000" });
  if (!reason) return null;
  const exemptions = [];
  for (const g of braceStatements(body).guards) {
    if (g.branches.length === 1 && PASS.test(g.branches[0])) exemptions.push(...exemptionOf(g.cond));
  }
  return { reason, exemptions };
}

/** The before-handler hooks an autohooks file adds that refuse a caller. */
const hooksCache = new Map();
function hooksOf(file, authWord) {
  const key = `${file.rel}\u0000${file.text}`;
  if (hooksCache.has(key)) return hooksCache.get(key);
  const out = [];
  const masked = maskStrings(file.text, "brace");
  for (const call of masked.matchAll(/\baddHook\s*\(\s*/g)) {
    const at = call.index + call[0].length;
    const kind = BEFORE_HANDLER.exec(file.text.slice(at));
    if (!kind) continue;
    const fnAt = at + kind[0].length;
    const line = file.text.slice(0, call.index).split("\n").length;
    const fnText = file.text.slice(fnAt);
    let judged = judgeFunction(fnText, authWord);
    if (!judged) {
      // A function passed by name: one declared in this file is read; otherwise its name is the
      // evidence, as `preHandler: fastify.authenticate` on a route is.
      const ref = /^([\w$]+(?:\s*\.\s*[\w$]+)*)\s*[,)]/.exec(fnText);
      if (ref) {
        const name = ref[1].replace(/\s+/g, "");
        const decl = /^\w+$/.test(name)
          ? new RegExp(String.raw`(?:function\s+${name}\s*(?=\()|(?:const|let|var)\s+${name}\s*=\s*)`).exec(file.text)
          : null;
        if (decl) judged = judgeFunction(file.text.slice(decl.index + decl[0].length).replace(/^\s*/, "").replace(/^(?=\()/, "function "), authWord);
        else if (authWord.test(name)) judged = { reason: "names authentication", exemptions: [] };
      }
    }
    if (judged) out.push({ ...judged, kind: kind[2], at: `${file.rel}:${line}` });
  }
  hooksCache.set(key, out);
  return out;
}

// --- a route ---------------------------------------------------------------------------------------

// A Fastify path as the Flask matchers read one: `:id` is a segment, `*` any number of them.
const asRule = (full) => full.replace(/:(\w+)(\([^)]*\))?/g, "<$1>").replace(/\*/g, "<path:rest>");

// Does an exemption let a request for this route through? Unread rules, and every rule when the route's
// URL is not known, are taken to.
function reaches(e, full) {
  if (e.unread || full === null) return true;
  const rule = asRule(full);
  if (e.paths) return e.paths.some((p) => servesPath(rule, p));
  if (!e.neg) return servesPrefix(ruleParts(rule), e.prefix);
  // `!url.startsWith(p)` lets through what does not start with p: every request the route serves
  // starts with p only when the route's fixed beginning does.
  const fixed = rule.split("<")[0];
  return !fixed.startsWith(e.prefix);
}

/**
 * The autohooks hook protecting this route, as a reason, or null. `file` is { rel, text } in `project`,
 * the project's JavaScript and TypeScript files; `authWord` is what names authentication.
 */
export function autohookCredit(route, file, project, authWord) {
  for (const root of autoloadRoots(project)) {
    if (!file.rel.startsWith(`${root.dir}/`) || root.autoHooks !== true) continue;
    const segments = posix.dirname(file.rel).slice(root.dir.length).split("/").filter(Boolean);
    let chain = [];
    for (let i = 0; i <= segments.length; i++) {
      const dir = posix.join(root.dir, ...segments.slice(0, i));
      // A directory below the root inherits only when cascading is written out as true; overwriting
      // that is not written out is taken to happen, which credits less.
      const next = i === 0 || root.cascade !== true ? [] : [...chain];
      const own = project.find((f) => posix.dirname(f.rel) === dir && AUTOHOOKS_FILE.test(posix.basename(f.rel)));
      if (own) {
        if (root.overwrite !== false) next.length = 0;
        next.push(own);
      }
      chain = next;
    }
    const known = root.prefix !== null && root.dirPrefix !== null && !/\bautoPrefix\b/.test(file.text);
    const full = known
      ? `/${[root.prefix, ...(root.dirPrefix ? segments : []), route.route].join("/")}`.replace(/\/{2,}/g, "/").replace(/(.)\/$/, "$1")
      : null;
    for (const hookFile of chain) {
      const hook = hooksOf(hookFile, authWord).find((h) => !h.exemptions.some((e) => reaches(e, full)));
      if (hook) return `an autohooks ${hook.kind} hook (${hook.at})`;
    }
  }
  return null;
}
