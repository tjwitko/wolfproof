// PHP adapter for the authentication check: Laravel and Symfony. See authentication.mjs for the
// rules every adapter follows; this file only answers "where are the routes" and "is this one
// protected".
//
// Laravel declares routes as calls -- `Route::get('/pages/{id}', [PageController::class, 'show'])` --
// and protects them with middleware, which can sit in five places, all found in BookStack:
//   - chained on the route:          Route::delete(...)->middleware('auth');
//   - on a group around it:          Route::middleware('auth')->group(function () { ... });
//   - on the group that includes its route file, by name:
//                                    Route::group(['middleware' => 'api'], fn () => require base_path('routes/api.php'));
//     where 'api' is a middleware group, defined in the HTTP Kernel or bootstrap/app.php, that
//     contains the class doing the work (BookStack's ApiAuthenticate);
//   - in the controller's constructor: $this->middleware('auth')->except(['login']);
//   - globally, on every request (rare).
// A middleware name is resolved through the project's aliases and groups to a class, and the class
// is judged by what it does: Laravel's own authentication middleware, or code that answers 401 or
// 403, throws an authentication or authorization exception, or sends the caller to the login page.
// Judged by behaviour rather than name because BookStack's 'can' is its own class, its 'mfa-setup'
// lets through only a signed-in user, and its 'guard' only checks configuration and redirects home.
//
// Symfony declares routes as attributes -- `#[Route('/admin/post')]` on the class and on each
// action -- and protects them with `#[IsGranted(...)]`, `$this->denyAccessUnlessGranted(...)` at the
// top of the action, or an `access_control` rule in config/packages/security.yaml.
//
// Not read, so a project using only these falls through to "no routes identified" rather than a
// pass: plain PHP files served directly (DVWA -- every file is a page, and nothing in the code says
// which), Slim and other micro-frameworks, Symfony's YAML and docblock-annotation routing, and
// Laravel's route caching.

import { lineAt, matchClose, splitTopLevel, statementEnd, literalAt, literalsIn, maskPhp } from "./auth-parse.mjs";

const PHP_COMMENTS = { line: /^\s*(?:\/\/|#(?!\[))/, blockStart: /^\s*\/\*/, blockEnd: /\*\//, codeAfterEnd: true };

const basename = (name) => name.replace(/^\\+/, "").split("\\").pop();

// ---------------------------------------------------------------------------------------------
// Structure: classes (name, parent, attributes, body) and their methods.
// ---------------------------------------------------------------------------------------------

function parseAttributeGroup(text, masked, open) {
  // `#[A('x'), B(path: '/y')]` starting at the `#`.
  const close = matchClose(masked, open + 1, "[", "]");
  if (close < 0) return { attrs: [], end: open + 1 };
  const attrs = [];
  for (const [a, b] of splitTopLevel(masked, open + 2, close)) {
    const head = /^\s*\\?([\w\\]+)\s*/.exec(masked.slice(a, b));
    if (!head) continue;
    const at = a + head[0].length;
    const args = [];
    if (masked[at] === "(") {
      const end = matchClose(masked, at, "(", ")");
      for (const [x, y] of splitTopLevel(masked, at + 1, end < 0 ? b : end)) {
        const raw = masked.slice(x, y);
        const named = /^\s*(\w+)\s*:(?!:)\s*/.exec(raw);
        const from = x + (named ? named[0].length : raw.length - raw.trimStart().length);
        let q = from;
        while (/\s/.test(masked[q])) q++;
        args.push({
          name: named ? named[1] : null,
          literal: literalAt(text, masked, q),
          literals: literalsIn(text, masked, from, y),
          raw: text.slice(from, y).trim(),
        });
      }
    }
    attrs.push({ name: basename(head[1]), args, line: lineAt(text, a), raw: text.slice(a, b).trim() });
  }
  return { attrs, end: close + 1 };
}

function memberAt(text, masked, start) {
  let i = start;
  const attrs = [];
  for (;;) {
    while (i < masked.length && /\s/.test(masked[i])) i++;
    if (masked[i] === "#" && masked[i + 1] === "[") {
      const g = parseAttributeGroup(text, masked, i);
      attrs.push(...g.attrs);
      i = g.end;
      continue;
    }
    break;
  }
  let k = i;
  const limit = Math.min(masked.length, i + 400);
  while (k < limit && !"{};=(".includes(masked[k])) k++;
  const head = masked.slice(i, k);
  const cls = /(?:^|\s)(?:class|trait)\s+(\w+)(?:\s+extends\s+\\?([\w\\]+))?/.exec(head);
  if (cls && masked[k] === "{") {
    return { kind: "class", name: cls[1], parent: cls[2] ? basename(cls[2]) : null, attrs, braceAt: k, methods: [], line: lineAt(text, i) };
  }
  const fn = /\bfunction\s+&?\s*(\w+)\s*$/.exec(head);
  if (fn && masked[k] === "(") {
    const paramsEnd = matchClose(masked, k, "(", ")");
    if (paramsEnd < 0) return null;
    let b = paramsEnd + 1;
    while (b < masked.length && masked[b] !== "{" && masked[b] !== ";") b++;
    return {
      kind: "method",
      name: fn[1],
      attrs,
      line: lineAt(text, i),
      bodyStart: masked[b] === "{" ? b : -1,
      bodyEnd: masked[b] === "{" ? matchClose(masked, b, "{", "}") : -1,
    };
  }
  return null;
}

function parseFile(text) {
  const masked = maskPhp(text);
  const classes = [];
  const pending = new Map();
  const stack = [];
  const visit = (start) => {
    const owner = stack[stack.length - 1];
    if (!owner) {
      let s = start;
      while (s < masked.length && /\s/.test(masked[s])) s++;
      const ahead = masked.slice(s, s + 300).split(/[{};]/)[0];
      if (!(masked[s] === "#" && masked[s + 1] === "[") && !/\b(?:class|trait)\s/.test(ahead)) return;
    }
    const decl = memberAt(text, masked, start);
    if (!decl) return;
    if (decl.kind === "class") pending.set(decl.braceAt, decl);
    else if (owner) owner.methods.push(decl);
  };
  visit(0);
  for (let i = 0; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === "{") {
      const cls = pending.get(i) || null;
      if (cls) {
        cls.start = i;
        classes.push(cls);
      }
      stack.push(cls);
      visit(i + 1);
    } else if (ch === "}") {
      const top = stack.pop();
      if (top) top.end = i;
      visit(i + 1);
    } else if (ch === ";") visit(i + 1);
  }
  return { masked, classes };
}

// ---------------------------------------------------------------------------------------------
// Middleware: what a name means in this project, and whether the class behind it authenticates.
// ---------------------------------------------------------------------------------------------

// Laravel's own aliases that turn away a caller who is not signed in, or not allowed: `auth` and its
// guards, basic auth, `can` (a gate check), `verified` (needs a user to verify), `signed` (a URL
// signature), and Sanctum's ability checks. Used only when the project does not redefine the alias.
const DEFAULT_AUTH_ALIASES = new Set(["auth", "auth.basic", "auth.session", "can", "verified", "signed", "abilities", "ability"]);
// The classes behind those aliases, for a route that names the class instead.
const FRAMEWORK_AUTH_CLASSES = new Set([
  "Authenticate", "AuthenticateWithBasicAuth", "AuthenticateSession", "Authorize", "EnsureEmailIsVerified",
  "ValidateSignature", "CheckAbilities", "CheckForAnyAbility",
]);
// What a middleware of the project's own does when it turns a caller away.
const REJECTS_CALLER = new RegExp(
  [
    String.raw`\babort\s*\(\s*40[13]\b`,
    String.raw`\babort_(?:if|unless)\s*\([^;]*,\s*40[13]\b`,
    String.raw`[,(]\s*40[13]\s*\)`,
    String.raw`Response::HTTP_(?:UNAUTHORIZED|FORBIDDEN)\b`,
    String.raw`\b(?:Authentication|Authorization|AccessDeniedHttp|UnauthorizedHttp)Exception\b`,
    String.raw`->guest\s*\(`,
    String.raw`\bredirect\s*\([^;]*login`,
    String.raw`->route\s*\(\s*['"]login['"]`,
    String.raw`\bto\s*\(\s*url\s*\(\s*['"]/login`,
  ].join("|")
);

// `['k' => [...], 'k2' => X::class]` from the `[` at `open`: key literal -> [from, to] of its value.
function arrayEntries(text, masked, open) {
  const close = matchClose(masked, open, "[", "]");
  const out = new Map();
  if (close < 0) return out;
  for (const [a, b] of splitTopLevel(masked, open + 1, close)) {
    const arrow = masked.slice(a, b).indexOf("=>");
    if (arrow < 0) continue;
    let q = a;
    while (/\s/.test(masked[q])) q++;
    const key = literalAt(text, masked, q);
    if (key != null) out.set(key, [a + arrow + 2, b]);
  }
  return out;
}

// Middleware named in [from, to): string literals and `X::class` references, in order.
function middlewareItems(text, masked, from, to) {
  const items = [];
  const re = /(['"])|\\?([\w\\]+)\s*::\s*class\b/g;
  re.lastIndex = from;
  let m;
  while ((m = re.exec(masked)) && m.index < to) {
    if (m[1]) {
      const value = literalAt(text, masked, m.index);
      if (value) items.push(value.includes("\\") ? { cls: basename(value) } : { name: value });
      let end = m.index + 1;
      while (end < to && masked[end] !== m[1]) end++;
      re.lastIndex = end + 1;
    } else items.push({ cls: basename(m[2]) });
  }
  return items;
}

function projectMiddleware(files) {
  const aliases = new Map();
  const groups = new Map();
  const global = [];
  const addGroup = (name, items) => groups.set(name, [...(groups.get(name) || []), ...items]);
  for (const f of files) {
    const { text, masked } = f;
    // The HTTP Kernel (Laravel 10 and earlier): three properties holding arrays.
    for (const m of masked.matchAll(/\$(middlewareAliases|routeMiddleware|middlewareGroups|middleware)\s*=\s*\[/g)) {
      const open = m.index + m[0].length - 1;
      if (m[1] === "middleware") {
        global.push(...middlewareItems(text, masked, open, matchClose(masked, open, "[", "]")));
        continue;
      }
      for (const [key, [a, b]] of arrayEntries(text, masked, open)) {
        if (m[1] === "middlewareGroups") addGroup(key, middlewareItems(text, masked, a, b));
        else {
          const cls = middlewareItems(text, masked, a, b)[0];
          if (cls) aliases.set(key, cls.cls || cls.name);
        }
      }
    }
    // bootstrap/app.php (Laravel 11): calls on the $middleware the withMiddleware callback receives.
    for (const m of masked.matchAll(/\$middleware\s*(?=->)/g)) {
      for (const seg of chainFrom(masked, m.index + m[0].length, statementEnd(masked, m.index))) {
        const args = argList(masked, seg);
        const firstAt = args[0] ? args[0][0] + (masked.slice(args[0][0]).length - masked.slice(args[0][0]).trimStart().length) : -1;
        if (seg.name === "alias" && masked[firstAt] === "[") {
          for (const [key, [a, b]] of arrayEntries(text, masked, firstAt)) {
            const cls = middlewareItems(text, masked, a, b)[0];
            if (cls) aliases.set(key, cls.cls || cls.name);
          }
        } else if (["group", "appendToGroup", "prependToGroup"].includes(seg.name) && args.length >= 2) {
          const name = literalAt(text, masked, firstAt);
          if (name) addGroup(name, middlewareItems(text, masked, ...args[1]));
        } else if (seg.name === "web" || seg.name === "api") {
          addGroup(seg.name, middlewareItems(text, masked, seg.argsFrom, seg.argsTo));
        } else if (["append", "prepend", "use"].includes(seg.name)) {
          global.push(...middlewareItems(text, masked, seg.argsFrom, seg.argsTo));
        }
      }
    }
  }
  return { aliases, groups, global };
}

function classAuthenticates(index, name, seen = new Set()) {
  if (seen.has(name)) return false;
  seen.add(name);
  const c = index.classes.get(name);
  if (!c) return FRAMEWORK_AUTH_CLASSES.has(name);
  if (c.parent && FRAMEWORK_AUTH_CLASSES.has(c.parent) && !index.classes.has(c.parent)) return true;
  if (REJECTS_CALLER.test(c.file.text.slice(c.start, c.end))) return true;
  return Boolean(c.parent && classAuthenticates(index, c.parent, seen));
}

// The label of the first item that authenticates, or null.
function authenticatingItem(index, items, depth = 0) {
  if (depth > 4) return null;
  for (const item of items) {
    if (item.cls) {
      if (classAuthenticates(index, item.cls)) return `the ${item.cls} middleware`;
      continue;
    }
    const base = item.name.split(":")[0];
    if (index.middleware.groups.has(base)) {
      const inner = authenticatingItem(index, index.middleware.groups.get(base), depth + 1);
      if (inner) return `${inner}, in the '${base}' middleware group`;
      continue;
    }
    if (index.middleware.aliases.has(base)) {
      const cls = index.middleware.aliases.get(base);
      if (classAuthenticates(index, basename(cls))) return `the '${item.name}' middleware`;
      continue;
    }
    if (DEFAULT_AUTH_ALIASES.has(base)) return `the '${item.name}' middleware`;
  }
  return null;
}

const removeItems = (items, removed) =>
  items.filter((i) => !removed.some((r) => (r.cls && (i.cls === r.cls || i.name === r.cls)) || (r.name && i.name && i.name.split(":")[0] === r.name.split(":")[0])));

// ---------------------------------------------------------------------------------------------
// Laravel routes
// ---------------------------------------------------------------------------------------------

const ROUTE_RECEIVER = /(?<![\w$>\\:])(?:\\?(?:[\w]+\\)*Route\s*::|\$router\s*->|\$route\s*->)/g;
const VERBS = new Set(["get", "post", "put", "patch", "delete", "options", "any", "match", "view", "redirect", "permanentRedirect", "resource", "apiResource", "resources", "apiResources", "singleton"]);
const RESOURCE_ACTIONS = [
  ["index", "GET", ""], ["create", "GET", "/create"], ["store", "POST", ""], ["show", "GET", "/{id}"],
  ["edit", "GET", "/{id}/edit"], ["update", "PUT", "/{id}"], ["destroy", "DELETE", "/{id}"],
];

// `::name(args)->name(args)...` from `k`, the calls of one statement.
function chainFrom(masked, k, to) {
  const segments = [];
  for (;;) {
    while (k < to && /\s/.test(masked[k])) k++;
    let sep = masked.slice(k, k + 2);
    if (sep !== "::" && sep !== "->") {
      if (segments.length === 0) {
        // Called right after the receiver match, which consumed the separator.
        sep = "";
      } else break;
    }
    if (sep) k += 2;
    while (k < to && /\s/.test(masked[k])) k++;
    const id = /^\w+/.exec(masked.slice(k, to));
    if (!id) break;
    k += id[0].length;
    while (k < to && /\s/.test(masked[k])) k++;
    if (masked[k] !== "(") break;
    const close = matchClose(masked, k, "(", ")");
    if (close < 0) break;
    segments.push({ name: id[0], argsFrom: k + 1, argsTo: close });
    k = close + 1;
  }
  return segments;
}

const argList = (masked, seg) => splitTopLevel(masked, seg.argsFrom, seg.argsTo);

function firstLiteral(text, masked, [a]) {
  let q = a;
  while (/\s/.test(masked[q])) q++;
  return literalAt(text, masked, q);
}

// A route file that a group includes: `base_path('routes/api.php')`, `__DIR__.'/../routes/api.php'`.
function includedRouteFile(text, masked, from, to) {
  for (const lit of literalsIn(text, masked, from, to)) {
    const m = /(routes\/[\w./-]+\.php)$/.exec(lit.replace(/^\/?(\.\.\/)+/, ""));
    if (m) return m[1];
  }
  return null;
}

// Every group in a file: its extent, its middleware, prefix and controller, and any route file it
// includes. Groups nest by extent.
function laravelGroups(file) {
  const { text, masked } = file;
  const groups = [];
  ROUTE_RECEIVER.lastIndex = 0;
  let m;
  while ((m = ROUTE_RECEIVER.exec(masked))) {
    const end = statementEnd(masked, m.index);
    const segments = chainFrom(masked, m.index + m[0].length, end);
    const gi = segments.findIndex((s) => s.name === "group");
    if (gi < 0) continue;
    const group = { middleware: [], without: [], prefix: [], controller: null, from: -1, to: -1, file: null, at: m.index };
    for (const seg of segments.slice(0, gi)) applyGroupSegment(text, masked, seg, group);
    const args = argList(masked, segments[gi]);
    // Route::group(['middleware' => 'api', 'prefix' => 'api'], function () { ... })
    if (args.length >= 2) {
      let q = args[0][0];
      while (/\s/.test(masked[q])) q++;
      if (masked[q] === "[") {
        const entries = arrayEntries(text, masked, q);
        if (entries.has("middleware")) group.middleware.push(...middlewareItems(text, masked, ...entries.get("middleware")));
        if (entries.has("prefix")) group.prefix.push(...literalsIn(text, masked, ...entries.get("prefix")).slice(0, 1));
      }
    }
    const [a, b] = args[args.length - 1] || [segments[gi].argsFrom, segments[gi].argsTo];
    group.from = a;
    group.to = b;
    group.file = includedRouteFile(text, masked, a, b);
    groups.push(group);
  }
  return groups;
}

function applyGroupSegment(text, masked, seg, group) {
  if (seg.name === "middleware") group.middleware.push(...middlewareItems(text, masked, seg.argsFrom, seg.argsTo));
  else if (seg.name === "withoutMiddleware") group.without.push(...middlewareItems(text, masked, seg.argsFrom, seg.argsTo));
  else if (seg.name === "prefix") group.prefix.push(...literalsIn(text, masked, seg.argsFrom, seg.argsTo).slice(0, 1));
  else if (seg.name === "controller") {
    const c = /\\?([\w\\]+)\s*::\s*class/.exec(masked.slice(seg.argsFrom, seg.argsTo));
    if (c) group.controller = basename(c[1]);
  }
}

// The controller and method a route's action names.
function actionOf(text, masked, [a, b], groupController) {
  const raw = masked.slice(a, b);
  const pair = /^\s*\[\s*\\?([\w\\]+)\s*::\s*class\s*,\s*['"]/.exec(raw);
  if (pair) {
    const q = a + raw.indexOf(pair[0]) + pair[0].length - 1;
    return { controller: basename(pair[1]), method: literalAt(text, masked, q) };
  }
  const invokable = /^\s*\\?([\w\\]+)\s*::\s*class\s*$/.exec(raw);
  if (invokable) return { controller: basename(invokable[1]), method: "__invoke" };
  let q = a;
  while (/\s/.test(masked[q])) q++;
  const lit = literalAt(text, masked, q);
  if (lit && lit.includes("@")) return { controller: basename(lit.split("@")[0]), method: lit.split("@")[1] };
  if (lit && groupController) return { controller: groupController, method: lit };
  return null;
}

// A route's closure, when its action is one: `Route::post('/hook', function (Request $r) { ... })`.
function closureAt(text, masked, arg) {
  if (!arg) return null;
  return /^\s*(?:static\s+)?(?:function|fn)\b/.test(masked.slice(arg[0], arg[1])) ? text.slice(arg[0], arg[1]) : null;
}

// The source a route runs: its closure, or its controller's action -- for a check written inside it.
function actionBody(index, d) {
  if (d.closure) return d.closure;
  if (!d.action) return null;
  const c = index.classes.get(d.action.controller);
  const m = c && c.methods.find((x) => x.name === d.action.method && x.bodyStart >= 0);
  return m ? c.file.text.slice(m.bodyStart, m.bodyEnd + 1) : null;
}

// Middleware a controller applies to its own actions, in its constructor (Laravel 10 and earlier)
// or its static middleware() method (Laravel 11), through its parents.
function controllerMiddleware(index, controller, method, seen = new Set()) {
  const c = index.classes.get(controller);
  if (!c || seen.has(controller)) return [];
  seen.add(controller);
  const out = [];
  const { text, masked } = c.file;
  for (const m of c.methods) {
    if (m.bodyStart < 0) continue;
    if (m.name === "__construct") {
      for (const call of masked.slice(m.bodyStart, m.bodyEnd).matchAll(/\$this\s*->\s*middleware\s*\(/g)) {
        const open = m.bodyStart + call.index + call[0].length - 1;
        const close = matchClose(masked, open, "(", ")");
        const args = splitTopLevel(masked, open + 1, close);
        const items = args[0] ? middlewareItems(text, masked, ...args[0]) : [];
        let only = null;
        let except = null;
        if (args[1]) {
          let q = args[1][0];
          while (/\s/.test(masked[q])) q++;
          if (masked[q] === "[") {
            const e = arrayEntries(text, masked, q);
            if (e.has("only")) only = literalsIn(text, masked, ...e.get("only"));
            if (e.has("except")) except = literalsIn(text, masked, ...e.get("except"));
          }
        }
        for (const seg of chainFrom(masked, close + 1, statementEnd(masked, close + 1))) {
          if (seg.name === "only") only = literalsIn(text, masked, seg.argsFrom, seg.argsTo);
          if (seg.name === "except") except = literalsIn(text, masked, seg.argsFrom, seg.argsTo);
        }
        if ((!only || only.includes(method)) && !(except && except.includes(method))) out.push(...items);
      }
    }
    if (m.name === "middleware") {
      // return ['auth', new Middleware('auth', only: ['edit']), ...]
      const body = masked.slice(m.bodyStart, m.bodyEnd);
      for (const nm of body.matchAll(/new\s+\\?(?:[\w\\]+\\)?Middleware\s*\(/g)) {
        const open = m.bodyStart + nm.index + nm[0].length - 1;
        const close = matchClose(masked, open, "(", ")");
        const args = splitTopLevel(masked, open + 1, close);
        let only = null;
        let except = null;
        for (const [a, b] of args.slice(1)) {
          const named = /^\s*(only|except)\s*:/.exec(masked.slice(a, b));
          if (named?.[1] === "only") only = literalsIn(text, masked, a, b);
          if (named?.[1] === "except") except = literalsIn(text, masked, a, b);
        }
        if ((!only || only.includes(method)) && !(except && except.includes(method))) out.push(...middlewareItems(text, masked, ...args[0]));
      }
      const ret = /\breturn\s*\[/.exec(body);
      if (ret) {
        const open = m.bodyStart + ret.index + ret[0].length - 1;
        const close = matchClose(masked, open, "[", "]");
        for (const [a, b] of splitTopLevel(masked, open + 1, close)) {
          if (/^\s*['"]/.test(masked.slice(a, b))) out.push(...middlewareItems(text, masked, a, b));
        }
      }
    }
  }
  if (c.parent) out.push(...controllerMiddleware(index, c.parent, method, seen));
  return out;
}

function joinPath(parts) {
  const p = parts.filter((x) => x != null).map((x) => x.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/");
  return "/" + p;
}

function laravelRoutes(index, file) {
  const { text, masked } = file;
  const out = [];
  const groups = index.groupsByFile.get(file);
  // The groups that include this file, outermost first, wherever they are declared.
  const including = index.fileGroups.filter((g) => file.rel.endsWith(g.group.file)).map((g) => g.chain);
  ROUTE_RECEIVER.lastIndex = 0;
  let m;
  while ((m = ROUTE_RECEIVER.exec(masked))) {
    const end = statementEnd(masked, m.index);
    const segments = chainFrom(masked, m.index + m[0].length, end);
    if (segments.some((s) => s.name === "group")) continue;
    const vi = segments.findIndex((s) => VERBS.has(s.name));
    if (vi < 0) continue;
    const verb = segments[vi];
    const args = argList(masked, verb);
    if (!args.length) continue;
    // Groups around this statement, outermost first.
    const around = groups.filter((g) => g.from <= m.index && m.index < g.to).sort((x, y) => x.from - y.from);
    const chains = [...(including[0] || []), ...around];
    const own = { middleware: [], without: [], prefix: [], controller: null };
    for (const seg of segments) if (seg !== verb) applyGroupSegment(text, masked, seg, own);
    const groupController = [...chains].reverse().find((g) => g.controller)?.controller || null;

    let middleware = [...index.middleware.global];
    for (const g of [...chains, own]) {
      middleware.push(...g.middleware);
      middleware = removeItems(middleware, g.without);
    }
    const prefix = chains.flatMap((g) => g.prefix);

    const declared = [];
    const name = verb.name;
    if (name === "resource" || name === "apiResource" || name === "singleton") {
      const base = firstLiteral(text, masked, args[0]);
      const ctrl = args[1] ? actionOf(text, masked, args[1], null) : null;
      let actions = RESOURCE_ACTIONS.filter(([a]) => name !== "apiResource" || (a !== "create" && a !== "edit"));
      for (const seg of segments.slice(vi + 1)) {
        if (seg.name === "only") { const keep = literalsIn(text, masked, seg.argsFrom, seg.argsTo); actions = actions.filter(([a]) => keep.includes(a)); }
        if (seg.name === "except") { const drop = literalsIn(text, masked, seg.argsFrom, seg.argsTo); actions = actions.filter(([a]) => !drop.includes(a)); }
      }
      for (const [action, method, suffix] of actions) {
        declared.push({ method, uri: (base || "{resource}") + suffix, action: ctrl ? { controller: ctrl.controller, method: action } : null });
      }
    } else if (name === "resources" || name === "apiResources") {
      continue; // an array of resources; rare enough to leave to the advisory
    } else {
      const uri = firstLiteral(text, masked, args[0]);
      if (uri == null) continue;
      let method = { match: "ANY", any: "ANY", view: "GET", redirect: "ANY", permanentRedirect: "ANY" }[name] || name.toUpperCase();
      let methodSpec;
      let actionArg = args[1];
      if (name === "match") {
        const verbs = literalsIn(text, masked, ...args[0]).map((v) => v.toUpperCase());
        method = verbs.length === 1 ? verbs[0] : "ANY";
        methodSpec = `methods=[${verbs.join(", ")}]`;
        actionArg = args[2];
        declared.push({ method, methodSpec, uri: firstLiteral(text, masked, args[1]), action: actionArg ? actionOf(text, masked, actionArg, groupController) : null, closure: closureAt(text, masked, actionArg) });
      } else {
        declared.push({ method, uri, action: actionArg ? actionOf(text, masked, actionArg, groupController) : null, closure: closureAt(text, masked, actionArg) });
      }
    }

    for (const d of declared) {
      if (d.uri == null) continue;
      let items = middleware;
      if (d.action) items = removeItems([...middleware, ...controllerMiddleware(index, d.action.controller, d.action.method)], own.without);
      const auth = authenticatingItem(index, items);
      out.push({
        method: d.method,
        methodSpec: d.methodSpec,
        route: joinPath([...prefix, d.uri]),
        declaration: text.slice(m.index, verb.argsTo + 1),
        context: text.slice(m.index, end),
        line: lineAt(text, m.index),
        auth,
        body: actionBody(index, d),
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Symfony routes
// ---------------------------------------------------------------------------------------------

function routePath(attr) {
  const a = attr.args.find((x) => !x.name || x.name === "path");
  return a ? (a.literal != null ? a.literal : `{${a.raw}}`) : null;
}

const OPEN_ROLES = /^(?:PUBLIC_ACCESS|IS_AUTHENTICATED_ANONYMOUSLY)$/;

function isGranted(attr) {
  if (attr.name !== "IsGranted" && attr.name !== "Security") return false;
  const first = attr.args.find((a) => !a.name || a.name === "attribute" || a.name === "expression");
  return !(first && first.literal != null && OPEN_ROLES.test(first.literal));
}

// access_control rules from security.yaml: `- { path: ^/admin, roles: ROLE_ADMIN }`, in order.
function accessControl(configs) {
  const rules = [];
  for (const c of configs) {
    const at = c.text.search(/^\s*access_control\s*:/m);
    if (at < 0) continue;
    const lines = c.text.slice(at).split("\n").slice(1);
    let current = null;
    for (const line of lines) {
      if (/^\S/.test(line) || /^\s{0,4}\w[\w@-]*\s*:/.test(line) && !current) break;
      if (/^\s*#/.test(line) || !line.trim()) continue;
      const item = /^\s*-\s*(.*)$/.exec(line);
      const body = item ? item[1] : line;
      if (item) {
        current = {};
        rules.push(current);
      }
      if (!current) break;
      const inline = /^\{(.*)\}\s*$/.exec(body.trim());
      for (const kv of (inline ? inline[1] : body).matchAll(/(\w+)\s*:\s*(\[[^\]]*\]|'[^']*'|"[^"]*"|[^,}]+)/g)) {
        current[kv[1]] = kv[2].trim().replace(/^['"]|['"]$/g, "");
      }
    }
  }
  return rules
    .filter((r) => r.path && r.roles)
    .map((r) => {
      let re = null;
      try {
        re = new RegExp(r.path);
      } catch {
        /* a PCRE construct JavaScript does not have: the rule is not used */
      }
      const roles = r.roles.replace(/[[\]'"]/g, "").split(",").map((s) => s.trim()).filter(Boolean);
      const methods = r.methods ? r.methods.replace(/[[\]'"]/g, "").split(",").map((s) => s.trim().toUpperCase()) : null;
      return { re, roles, methods, open: roles.every((x) => OPEN_ROLES.test(x)) };
    })
    .filter((r) => r.re);
}

function symfonyRoutes(index, file) {
  const { text, masked } = file;
  const out = [];
  for (const cls of file.parsed.classes) {
    const classRoute = cls.attrs.find((a) => a.name === "Route");
    const prefix = classRoute ? routePath(classRoute) : null;
    const classGrant = cls.attrs.find(isGranted);
    for (const m of cls.methods) {
      const grant = m.attrs.find(isGranted);
      const denies = m.bodyStart >= 0 && /\$this\s*->\s*denyAccessUnlessGranted\s*\(/.test(masked.slice(m.bodyStart, m.bodyEnd));
      for (const r of m.attrs.filter((a) => a.name === "Route")) {
        const methodsArg = r.args.find((a) => a.name === "methods");
        const verbs = methodsArg ? methodsArg.literals.map((v) => v.toUpperCase()) : [];
        const route = joinPath([prefix, routePath(r)]);
        const method = verbs.length === 1 ? verbs[0] : "ANY";
        const protection =
          (grant && `an #[${grant.name}] attribute`) ||
          (classGrant && `an #[${classGrant.name}] attribute on the controller`) ||
          (denies && "denyAccessUnlessGranted() in the action") ||
          accessControlFor(index, route, verbs);
        out.push({
          method,
          methodSpec: verbs.length > 1 ? `methods=[${verbs.join(", ")}]` : undefined,
          route,
          declaration: r.raw,
          context: r.raw,
          line: r.line,
          auth: protection,
          body: m.bodyStart >= 0 ? text.slice(m.bodyStart, m.bodyEnd + 1) : null,
        });
      }
    }
  }
  return out;
}

function accessControlFor(index, route, verbs) {
  const probe = route.replace(/\{[^}]*\}/g, "x");
  for (const rule of index.accessControl) {
    if (rule.methods && verbs.length && !verbs.some((v) => rule.methods.includes(v))) continue;
    if (!rule.re.test(probe)) continue;
    return rule.open ? null : `an access_control rule requiring ${rule.roles.join(", ")}`;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// The project
// ---------------------------------------------------------------------------------------------

let memo = { texts: null, index: null };

function projectIndex(texts, ctx = {}) {
  if (memo.texts === texts) return memo.index;
  const rels = ctx.rels || texts.map((_, i) => `file${i}.php`);
  const files = texts.map((text, i) => {
    const parsed = parseFile(text);
    return { text, masked: parsed.masked, parsed, rel: rels[i] };
  });
  const classes = new Map();
  for (const f of files) for (const c of f.parsed.classes) if (!classes.has(c.name)) classes.set(c.name, { ...c, file: f });
  const index = { files, byRel: new Map(files.map((f) => [f.rel, f])), byText: new Map(files.map((f) => [f.text, f])), classes };
  index.middleware = projectMiddleware(files);
  index.groupsByFile = new Map(files.map((f) => [f, laravelGroups(f)]));
  // Groups that include a route file, each with the chain of groups around it, outermost first.
  index.fileGroups = [];
  for (const [f, groups] of index.groupsByFile) {
    for (const g of groups) {
      if (!g.file) continue;
      const chain = groups.filter((o) => o !== g && o.from <= g.at && g.at < o.to).sort((x, y) => x.from - y.from);
      index.fileGroups.push({ group: g, chain: [...chain, g], declaredIn: f });
    }
  }
  // Laravel 11: ->withRouting(web: __DIR__.'/../routes/web.php', api: ..., apiPrefix: 'api').
  for (const f of files) {
    const w = /->\s*withRouting\s*\(/.exec(f.masked);
    if (!w) continue;
    const open = w.index + w[0].length - 1;
    const args = splitTopLevel(f.masked, open + 1, matchClose(f.masked, open, "(", ")"));
    let apiPrefix = "api";
    for (const [a, b] of args) {
      const named = /^\s*apiPrefix\s*:/.exec(f.masked.slice(a, b));
      if (named) apiPrefix = literalsIn(f.text, f.masked, a, b)[0] ?? apiPrefix;
    }
    for (const [a, b] of args) {
      const named = /^\s*(web|api)\s*:/.exec(f.masked.slice(a, b));
      const target = named && includedRouteFile(f.text, f.masked, a, b);
      if (!target) continue;
      const group = { middleware: [{ name: named[1] }], without: [], prefix: named[1] === "api" ? [apiPrefix] : [], controller: null, file: target };
      index.fileGroups.push({ group, chain: [group], declaredIn: f });
    }
  }
  index.accessControl = accessControl(ctx.configs || []);
  memo = { texts, index };
  return index;
}

export const phpAdapter = {
  name: "PHP",
  extensions: [".php"],
  // Blade templates are views, not code that declares routes.
  skip: /\.blade\.php$/,
  // Symfony's access_control rules live here, not in PHP.
  configFiles: /(?:^|\/)config\/packages\/(?:[\w-]+\/)?security\.ya?ml$/,
  comments: PHP_COMMENTS,
  idiom: "the `auth` middleware on the route or its group, `#[IsGranted]` on a Symfony controller or action, or an `access_control` rule",

  routes(text, texts = [text], ctx = {}) {
    const index = projectIndex(texts, ctx);
    const file = (ctx.rel && index.byRel.get(ctx.rel)) || index.byText.get(text);
    return [...laravelRoutes(index, file), ...symfonyRoutes(index, file)];
  },

  globalAuth() {
    // Global middleware is folded into each route's list, so that `withoutMiddleware` can still
    // take it away from one.
    return null;
  },

  family: "brace",
  handlerBodies(r) {
    return [r.body];
  },

  routeAuth(r) {
    return r.auth || null;
  },
};

export { maskPhp };
