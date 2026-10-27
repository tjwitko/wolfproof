// C# (ASP.NET Core) adapter for the authentication check. See authentication.mjs for the rules every
// adapter follows; this file only answers "where are the routes" and "is this one protected".
//
// ASP.NET declares routes two ways, and both are read here:
//   - Controllers: `[HttpGet("{id}")]` on an action, a `[Route("api/[controller]")]` prefix on the
//     class, `[Authorize]` / `[AllowAnonymous]` on either.
//   - Minimal APIs: `app.MapGet("/items", handler)`, with `.RequireAuthorization()` or
//     `.AllowAnonymous()` chained on the call or on the `MapGroup` it hangs off.
//
// Two things make C# different from the other adapters, and both come from running it on real apps:
//   1. A controller inherits its prefix and its `[Authorize]` from a base class, usually in another
//      file. Jellyfin's 60-odd controllers all derive from one base that carries `[Route]`. So the
//      classes of the whole project are indexed first, and a route is judged against its class chain.
//   2. `[AllowAnonymous]` beats everything: an `[Authorize]` on the class, a global fallback policy,
//      a `RequireAuthorization()` on the group. That is ASP.NET's documented rule, and it is the
//      reason routes carry an `anonymous` flag the shared judgment honours.
//
// What counts as protection, deliberately narrow (rule 3 in authentication.mjs):
//   - `[Authorize]` in any form -- a policy, roles, a scheme -- or an attribute class in the project
//     that derives from AuthorizeAttribute or implements an authorization filter;
//   - `RequireAuthorization(...)` chained on the route, its group, or `MapControllers()`;
//   - an `AuthorizeFilter` added to the MVC filters (controllers only);
//   - a FallbackPolicy that requires an authenticated user (every endpoint without its own metadata).
// Not protection: `UseAuthentication()` / `UseAuthorization()` alone (they authenticate a caller
// but enforce nothing), and a DefaultPolicy, which only applies where `[Authorize]` already is.
//
// Not read, so it falls through to "no routes identified" rather than a pass: conventional routing
// (`MapControllerRoute` with actions that carry no route attribute), Razor Pages, gRPC services and
// SignalR hubs.

const C_COMMENTS = { line: /^\s*\/\//, blockStart: /^\s*\/\*/, blockEnd: /\*\//, codeAfterEnd: true };

// ---------------------------------------------------------------------------------------------
// Masking. Route templates are strings full of braces -- "{id}" -- so nothing structural can be
// read until string and comment contents are blanked. Same length, newlines kept, so every index
// and line number in the masked text is the same as in the original, where the literals are read.
// ---------------------------------------------------------------------------------------------

function blank(out, from, to) {
  for (let k = from; k < to; k++) if (out[k] !== "\n") out[k] = " ";
}

export function maskCSharp(text) {
  const out = text.split("");
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === "/" && text[i + 1] === "/") {
      const end = text.indexOf("\n", i);
      const stop = end < 0 ? n : end;
      blank(out, i, stop);
      i = stop;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      const stop = end < 0 ? n : end + 2;
      blank(out, i, stop);
      i = stop;
      continue;
    }
    if (c === '"') {
      let j = i - 1;
      let verbatim = false;
      while (j >= 0 && (text[j] === "@" || text[j] === "$")) {
        if (text[j] === "@") verbatim = true;
        j--;
      }
      if (text.startsWith('"""', i)) {
        let q = 3;
        while (text[i + q] === '"') q++;
        const close = text.indexOf('"'.repeat(q), i + q);
        const stop = close < 0 ? n : close;
        blank(out, i + q, stop);
        i = close < 0 ? n : close + q;
        continue;
      }
      let k = i + 1;
      while (k < n) {
        if (verbatim) {
          if (text[k] === '"') {
            if (text[k + 1] === '"') { k += 2; continue; }
            break;
          }
          k++;
        } else {
          if (text[k] === "\\") { k += 2; continue; }
          if (text[k] === '"' || text[k] === "\n") break;
          k++;
        }
      }
      blank(out, i + 1, k);
      i = k + 1;
      continue;
    }
    if (c === "'") {
      let k = i + 1;
      k += text[k] === "\\" ? 2 : 1;
      while (k < n && k < i + 12 && text[k] !== "'" && text[k] !== "\n") k++; // 'A'
      if (text[k] === "'") {
        blank(out, i + 1, k);
        i = k + 1;
        continue;
      }
    }
    i++;
  }
  return out.join("");
}

// The value of a string literal whose opening quote is at `q` in the masked text, or null when
// what is there is not a literal (a constant, a nameof).
function literalAt(text, masked, q) {
  if (masked[q] !== '"') return null;
  const verbatim = text[q - 1] === "@" || text[q - 2] === "@";
  let end = q + 1;
  while (end < masked.length && masked[end] !== '"') end++;
  const raw = text.slice(q + 1, end);
  return verbatim ? raw.replace(/""/g, '"') : raw;
}

function matchClose(masked, open, openCh, closeCh) {
  let depth = 0;
  for (let k = open; k < masked.length; k++) {
    if (masked[k] === openCh) depth++;
    else if (masked[k] === closeCh && --depth === 0) return k;
  }
  return -1;
}

// ---------------------------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------------------------

// One `[...]` group may hold several attributes: `[FromRoute, Required]`.
function splitTopLevel(s, from, to) {
  const parts = [];
  let depth = 0;
  let start = from;
  for (let k = from; k < to; k++) {
    const ch = s[k];
    if (ch === "(" || ch === "[" || ch === "{" || ch === "<") depth++;
    else if (ch === ")" || ch === "]" || ch === "}" || ch === ">") depth--;
    else if (ch === "," && depth === 0) {
      parts.push([start, k]);
      start = k + 1;
    }
  }
  parts.push([start, to]);
  return parts;
}

function parseAttribute(text, masked, from, to) {
  const head = /^\s*(?:(?:return|method|type|assembly|module)\s*:\s*)?([\w.]+)\s*/.exec(masked.slice(from, to));
  if (!head) return null;
  const name = head[1].split(".").pop().replace(/Attribute$/, "");
  const at = from + head[0].length;
  const args = [];
  if (masked[at] === "(") {
    const close = matchClose(masked, at, "(", ")");
    for (const [a, b] of splitTopLevel(masked, at + 1, close < 0 ? to : close)) {
      const argText = masked.slice(a, b);
      if (!argText.trim()) continue;
      const named = /^\s*(\w+)\s*=(?!=)\s*/.exec(argText);
      const valueFrom = a + (named ? named[0].length : argText.length - argText.trimStart().length);
      let q = valueFrom;
      while (masked[q] === "@" || masked[q] === "$") q++;
      args.push({
        name: named ? named[1] : null,
        literal: literalAt(text, masked, q),
        raw: text.slice(valueFrom, b).trim(),
      });
    }
  }
  const line = text.slice(0, from).split("\n").length;
  return { name, args, line, raw: text.slice(from, to).trim() };
}

// The attribute run starting at `i` (whitespace, then `[...]` groups), and where it ends.
function attributesAt(text, masked, i) {
  const attrs = [];
  for (;;) {
    while (i < masked.length && /\s/.test(masked[i])) i++;
    if (masked[i] !== "[") return { attrs, end: i };
    const close = matchClose(masked, i, "[", "]");
    if (close < 0) return { attrs, end: i };
    for (const [a, b] of splitTopLevel(masked, i + 1, close)) {
      const attr = parseAttribute(text, masked, a, b);
      if (attr) attrs.push(attr);
    }
    i = close + 1;
  }
}

// ---------------------------------------------------------------------------------------------
// Structure: classes, their bases and attributes, and the attributed methods inside them.
// ---------------------------------------------------------------------------------------------

const CLASS_HEAD = /(?:^|\s)(?:class|record)\s+(\w+)/;

function baseList(masked, from, to) {
  // After the name: generic parameters, a primary constructor, then `: Base, IFoo` up to `where`.
  let k = from;
  while (k < to && /\s/.test(masked[k])) k++;
  if (masked[k] === "<") k = matchClose(masked, k, "<", ">") + 1;
  while (k < to && /\s/.test(masked[k])) k++;
  if (masked[k] === "(") k = matchClose(masked, k, "(", ")") + 1;
  const rest = masked.slice(k, to);
  const colon = /^\s*:([\s\S]*?)(?:\bwhere\b|$)/.exec(rest);
  if (!colon) return [];
  return splitTopLevel(colon[1], 0, colon[1].length)
    .map(([a, b]) => colon[1].slice(a, b).trim().replace(/<[\s\S]*$/, "").replace(/\(.*$/, "").split(".").pop())
    .filter(Boolean);
}

function memberAt(text, masked, start) {
  const { attrs, end } = attributesAt(text, masked, start);
  // The declaration head runs to the first structural character.
  let k = end;
  const limit = Math.min(masked.length, end + 600);
  while (k < limit && !"{};=(".includes(masked[k])) k++;
  const head = masked.slice(end, k);
  const cls = CLASS_HEAD.exec(head);
  if (cls) {
    // Find the body, skipping a primary constructor's parentheses.
    let b = end + cls.index + cls[0].length;
    while (b < masked.length && masked[b] !== "{" && masked[b] !== ";") {
      if (masked[b] === "(") b = matchClose(masked, b, "(", ")");
      if (b < 0) return null;
      b++;
    }
    if (masked[b] !== "{") return null;
    return {
      kind: "class",
      name: cls[1],
      attrs,
      bases: baseList(masked, end + cls.index + cls[0].length, b),
      abstract: /\babstract\b/.test(head),
      braceAt: b,
      methods: [],
    };
  }
  if (masked[k] !== "(") return null;
  const name = /(\w+)\s*(?:<[^<>]*>)?\s*$/.exec(head);
  if (!name || /^(?:if|while|for|foreach|switch|using|lock|return|new|catch|nameof|typeof)$/.test(name[1])) return null;
  // Parameters, then a block body, an expression body, or none (abstract, extern, interface).
  const paramsEnd = matchClose(masked, k, "(", ")");
  if (paramsEnd < 0) return null;
  const params = masked.slice(k + 1, paramsEnd);
  const thisParam = /^\s*this\s+[\w.<>?,\s[\]]+?\s(\w+)\s*(?:,|$)/.exec(params);
  let b = paramsEnd + 1;
  while (b < masked.length && !"{;=".includes(masked[b])) b++;
  let bodyStart = -1;
  let bodyEnd = -1;
  if (masked[b] === "{") {
    bodyStart = b;
    bodyEnd = matchClose(masked, b, "{", "}");
  } else if (masked[b] === "=" && masked[b + 1] === ">") {
    bodyStart = b + 2;
    bodyEnd = statementEnd(masked, bodyStart);
  }
  return {
    kind: "method",
    name: name[1],
    attrs,
    line: text.slice(0, end).split("\n").length,
    params: params.split(",").map((p) => (/(\w+)\s*(?:=[^,]*)?$/.exec(p.trim()) || [])[1]).filter(Boolean),
    thisParam: thisParam ? thisParam[1] : null,
    bodyStart,
    bodyEnd,
  };
}

// The `;` that ends the statement starting at `from`, skipping nested brackets.
function statementEnd(masked, from) {
  let depth = 0;
  for (let k = from; k < masked.length; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    else if (ch === ")" || ch === "}" || ch === "]") {
      if (--depth < 0) return k;
    } else if (ch === ";" && depth === 0) return k;
  }
  return masked.length;
}

export function parseCSharp(text) {
  const masked = maskCSharp(text);
  const classes = [];
  const methods = [];
  const pending = new Map();
  const stack = [];
  const visit = (start) => {
    const owner = stack[stack.length - 1];
    // Cheap rejection outside a class body: only a class declaration matters there.
    if (!owner) {
      let s = start;
      while (s < masked.length && /\s/.test(masked[s])) s++;
      if (masked[s] !== "[" && !/\b(?:class|record)\s/.test(masked.slice(s, s + 300).split(/[{};]/)[0])) return;
    }
    const decl = memberAt(text, masked, start);
    if (!decl) return;
    if (decl.kind === "class") {
      pending.set(decl.braceAt, decl);
      return;
    }
    // Methods are members of a class body; a `(` after a boundary inside a method is a statement.
    if (!owner) return;
    decl.cls = owner;
    owner.methods.push(decl);
    methods.push(decl);
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
      if (top) {
        top.end = i;
        top.rejects = REJECTS_CALLER.test(masked.slice(top.start, i));
      }
      visit(i + 1);
    } else if (ch === ";") {
      visit(i + 1);
    }
  }
  return { masked, classes, methods };
}

// ---------------------------------------------------------------------------------------------
// The project: every class by name, so a controller can be judged against its base classes.
// ---------------------------------------------------------------------------------------------

// A filter that turns a caller away with 401 or 403 is doing authorization, whatever it derives
// from. Bitwarden's [InjectProvider(ProviderUserType.ProviderAdmin)] is an ActionFilterAttribute
// that answers Unauthorized to anyone who is not an admin of the provider; read as no protection,
// seven billing routes were reported open. Its neighbours that return 400 or 404 (validation,
// environment gates) do not count.
const REJECTS_CALLER =
  /\bnew\s+(?:Unauthorized|Forbid|Challenge)(?:Object)?Result\b|\bStatusCodes\s*\.\s*Status40[13]\w*|\bthrow\s+new\s+(?:Unauthorized|Forbidden)\w*Exception\b/;

const AUTH_FILTER_BASE = /^(?:AuthorizeAttribute|IAuthorizationFilter|IAsyncAuthorizationFilter|IAuthorizeData)$/;
const HTTP_VERB = /^Http(Get|Post|Put|Patch|Delete|Head|Options)$/;

let memo = { texts: null, index: null };

function projectIndex(texts) {
  if (memo.texts === texts) return memo.index;
  const classes = new Map();
  const methodsByName = new Map();
  const files = [];
  for (const text of texts) {
    const parsed = parseCSharp(text);
    const file = { text, masked: parsed.masked, parsed };
    files.push(file);
    for (const m of parsed.methods) m.file = file;
    for (const c of parsed.classes) {
      // Partial classes are one class: attributes on any part apply to all of it.
      const prev = classes.get(c.name);
      if (prev) {
        prev.attrs.push(...c.attrs);
        prev.bases.push(...c.bases);
        prev.rejects = prev.rejects || c.rejects;
      } else classes.set(c.name, { name: c.name, attrs: [...c.attrs], bases: [...c.bases], rejects: c.rejects });
    }
    for (const m of parsed.methods) {
      if (!methodsByName.has(m.name)) methodsByName.set(m.name, []);
      methodsByName.get(m.name).push(m);
    }
  }
  const index = {
    files,
    byText: new Map(files.map((f) => [f.text, f])),
    classes,
    methodsByName,
    globals: projectGlobals(files),
    authAttributes: new Map(),
    callSites: new Map(),
  };
  index.authorizingHelpers = authorizingHelpers(index);
  memo = { texts, index };
  return index;
}

// The chain of classes from `name` up through bases this project declares.
function classChain(index, name) {
  const chain = [];
  const seen = new Set();
  let cur = name;
  while (cur && !seen.has(cur) && index.classes.has(cur)) {
    seen.add(cur);
    const c = index.classes.get(cur);
    chain.push(c);
    cur = c.bases[0];
  }
  return chain;
}

// An attribute protects when it is [Authorize] or a project class that is one: derives from
// AuthorizeAttribute, or implements an authorization filter, directly or through its own bases.
function isAuthAttribute(index, attr) {
  if (attr.name === "Authorize") return true;
  if (attr.name === "TypeFilter" || attr.name === "ServiceFilter") {
    const t = /typeof\s*\(\s*([\w.]+)/.exec(attr.raw);
    return Boolean(t && isAuthClass(index, t[1].split(".").pop()));
  }
  return isAuthClass(index, attr.name + "Attribute") || isAuthClass(index, attr.name);
}

function isAuthClass(index, name) {
  if (index.authAttributes.has(name)) return index.authAttributes.get(name);
  index.authAttributes.set(name, false); // cycle guard
  const c = index.classes.get(name);
  const yes = Boolean(c && (c.rejects || c.bases.some((b) => AUTH_FILTER_BASE.test(b) || isAuthClass(index, b))));
  index.authAttributes.set(name, yes);
  return yes;
}

// Project-wide switches. Each is matched on code with strings and comments masked.
function projectGlobals(files) {
  const masked = files.map((f) => f.masked).join("\n");
  const fallback =
    /\bFallbackPolicy\s*=[^;]{0,400}?(?:RequireAuthenticatedUser|RequireClaim|RequireRole|RequireUserName|\.DefaultPolicy\b)/.test(masked) ||
    /\bSetFallbackPolicy\s*\([^;]{0,400}?(?:RequireAuthenticatedUser|RequireClaim|RequireRole|RequireUserName|\.DefaultPolicy\b)/.test(masked);
  const controllers =
    /\bMapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization\s*\(/.test(masked) ||
    /\bFilters\s*\.\s*Add\s*(?:<\s*AuthorizeFilter\s*>\s*\(|\(\s*(?:new\s+AuthorizeFilter\b|typeof\s*\(\s*AuthorizeFilter\s*\)))/.test(masked);
  return { fallback, controllers };
}

// ---------------------------------------------------------------------------------------------
// Controllers
// ---------------------------------------------------------------------------------------------

function joinRoute(prefix, template) {
  if (template != null && /^~?\//.test(template)) return "/" + template.replace(/^~?\/+/, "").replace(/\/+$/, "");
  const parts = [prefix, template].filter((p) => p != null).map((p) => p.replace(/^~?\/+|\/+$/g, "")).filter(Boolean);
  return "/" + parts.join("/");
}

function templateOf(attr) {
  const first = attr.args.find((a) => !a.name || a.name === "template");
  if (!first) return null;
  return first.literal != null ? first.literal : `{${first.raw}}`;
}

function controllerRoutes(text, parsed, index) {
  const out = [];
  for (const cls of parsed.classes) {
    const actions = cls.methods.filter((m) => m.attrs.some((a) => HTTP_VERB.test(a.name) || a.name === "Route" || a.name === "AcceptVerbs"));
    if (!actions.length) continue;
    const chain = classChain(index, cls.name);
    const chainAttrs = chain.length ? chain.flatMap((c) => c.attrs) : cls.attrs;
    const routeOwner = chain.find((c) => c.attrs.some((a) => a.name === "Route")) || cls;
    const classRoute = routeOwner.attrs.find((a) => a.name === "Route");
    const area = chainAttrs.find((a) => a.name === "Area");
    const controllerName = cls.name.replace(/Controller$/, "");
    const classAnon = chainAttrs.some((a) => a.name === "AllowAnonymous");
    const classAuth = chainAttrs.find((a) => isAuthAttribute(index, a));

    for (const m of actions) {
      const tokens = (t) =>
        t == null
          ? t
          : t
              .replace(/\[controller\]/gi, controllerName)
              .replace(/\[action\]/gi, m.name.replace(/Async$/, ""))
              .replace(/\[area\]/gi, area ? templateOf(area) || "" : "");
      const prefix = tokens(classRoute ? templateOf(classRoute) : null);
      // No route on the class and none on the action: conventionally routed, which with the default
      // pattern every template ships is /{controller}/{action}.
      const conventional = prefix == null ? `${controllerName}/${m.name.replace(/Async$/, "")}` : null;
      const verbs = m.attrs.filter((a) => HTTP_VERB.test(a.name) || a.name === "AcceptVerbs");
      const routeAttrs = m.attrs.filter((a) => a.name === "Route");
      const endpoints = [];
      const verbOf = (a) => {
        if (a.name !== "AcceptVerbs") return { method: HTTP_VERB.exec(a.name)[1].toUpperCase() };
        const named = a.args.filter((x) => x.literal != null && !x.name).map((x) => x.literal.toUpperCase());
        return named.length === 1 ? { method: named[0] } : { method: "ANY", methodSpec: `methods=[${named.join(", ")}]` };
      };
      for (const v of verbs) {
        const t = v.name === "AcceptVerbs" ? (v.args.find((x) => x.name === "Route") || {}).literal ?? null : templateOf(v);
        if (t != null || !routeAttrs.length) endpoints.push({ ...verbOf(v), template: t, at: v });
        else for (const r of routeAttrs) endpoints.push({ ...verbOf(v), template: templateOf(r), at: v });
      }
      if (!verbs.length) for (const r of routeAttrs) endpoints.push({ method: "ANY", template: templateOf(r), at: r });

      const anonymous = classAnon || m.attrs.some((a) => a.name === "AllowAnonymous");
      const own = m.attrs.find((a) => isAuthAttribute(index, a));
      const auth = own || classAuth;
      for (const e of endpoints) {
        out.push({
          method: e.method,
          route: e.template == null && conventional ? "/" + conventional : joinRoute(prefix, tokens(e.template)),
          declaration: e.at.raw,
          methodSpec: e.methodSpec,
          context: e.at.raw,
          line: e.at.line,
          kind: "controller",
          anonymous,
          auth: auth ? `an [${auth.name}] attribute` : null,
          body: m.bodyStart >= 0 ? text.slice(m.bodyStart, m.bodyEnd + 1) : null,
        });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Minimal APIs
//
// A route's protection can sit in four places, and real apps use all of them:
//   - chained on the call:            app.MapGet("/x", h).RequireAuthorization();
//   - on its group, as a chain or as a statement of its own (Bitwarden):
//                                     var g = app.MapGroup("/x"); g.RequireAuthorization(policy);
//   - at the call site of the method that maps it, which returns the group (eShop):
//                                     orders.MapOrdersApiV1().RequireAuthorization();
//   - inside a project helper that does one of the above to its parameter (Bitwarden):
//                                     endpoints.MapGroup("/leases").WithPamDefaults().MapLeaseEndpoints();
// So a route's receiver is resolved back through local variables and, where it is the parameter
// of the method mapping it, through every call site of that method. A route is protected only when
// every path to it is: one call site without RequireAuthorization is an open route.
// ---------------------------------------------------------------------------------------------

const MAP_VERB = /\.\s*Map(Get|Post|Put|Delete|Patch|Methods)\s*(?=\()/g;
// Any Map* call ends a receiver's conventions: MapGet returns the route, MapGroup a subgroup, and a
// project's MapOrdersApi() whatever it built. `app.MapOrdersApi().RequireAuthorization()` protects
// what MapOrdersApi returned, not app -- reading it as app's would pass every route on app.
const ROUTE_MAPPING = /^Map/;
const MAX_DEPTH = 5;

function lineAt(text, i) {
  return text.slice(0, i).split("\n").length;
}

function matchOpen(masked, close, openCh, closeCh) {
  let depth = 0;
  for (let k = close; k >= 0; k--) {
    if (masked[k] === closeCh) depth++;
    else if (masked[k] === openCh && --depth === 0) return k;
  }
  return -1;
}

// Where the receiver expression of `.Name(` (the dot at `dot`) starts: back over `a.b(...).c<T>()`.
function receiverStart(masked, dot) {
  let k = dot - 1;
  let start = dot;
  for (;;) {
    while (k >= 0 && /\s/.test(masked[k])) k--;
    if (masked[k] === ")") {
      const open = matchOpen(masked, k, "(", ")");
      if (open < 0) return start;
      k = open - 1;
      while (k >= 0 && /\s/.test(masked[k])) k--;
      if (masked[k] === ">") {
        const lt = matchOpen(masked, k, "<", ">");
        if (lt < 0) return start;
        k = lt - 1;
      }
    }
    if (k < 0 || !/\w/.test(masked[k])) return start;
    while (k >= 0 && /\w/.test(masked[k])) k--;
    start = k + 1;
    let j = k;
    while (j >= 0 && /\s/.test(masked[j])) j--;
    if (masked[j] !== ".") return start;
    k = j - 1;
  }
}

// `base.Seg(args).Seg<T>(args).Prop` from `from`: the base identifier and each segment's extent.
function parseChain(masked, from, to) {
  const m = /^\s*(\w+)/.exec(masked.slice(from, to));
  if (!m) return { base: null, segments: [], end: from };
  return { base: m[1], ...segmentsFrom(masked, from + m[0].length, to) };
}

// The `.Seg(args)` calls that follow position `k`, as in what is chained after a call's `)`.
function segmentsFrom(masked, k, to) {
  const segments = [];
  for (;;) {
    let j = k;
    while (j < to && /\s/.test(masked[j])) j++;
    if (masked[j] !== ".") break;
    j++;
    while (j < to && /\s/.test(masked[j])) j++;
    const id = /^\w+/.exec(masked.slice(j, to));
    if (!id) break;
    j += id[0].length;
    while (j < to && /\s/.test(masked[j])) j++;
    if (masked[j] === "<") {
      const gt = matchClose(masked, j, "<", ">");
      if (gt < 0) break;
      j = gt + 1;
      while (j < to && /\s/.test(masked[j])) j++;
    }
    if (masked[j] === "(") {
      const close = matchClose(masked, j, "(", ")");
      if (close < 0) break;
      segments.push({ name: id[0], argsFrom: j + 1, argsTo: close, at: j });
      k = close + 1;
    } else {
      segments.push({ name: id[0], argsFrom: -1, argsTo: -1, at: j });
      k = j;
    }
  }
  return { segments, end: k };
}

function firstArg(file, seg) {
  if (seg.argsFrom < 0) return null;
  const [a, b] = splitTopLevel(file.masked, seg.argsFrom, seg.argsTo)[0];
  let q = a;
  while (/\s/.test(file.masked[q])) q++;
  while (file.masked[q] === "@" || file.masked[q] === "$") q++;
  const lit = literalAt(file.text, file.masked, q);
  if (lit != null) return lit;
  const raw = file.text.slice(a, b).trim();
  return raw ? `{${raw}}` : null;
}

const OPEN = () => ({ prefix: [], auth: null, anonymous: false });

// What a chain of conventions does: MapGroup adds a prefix, RequireAuthorization (or a project
// helper that calls it) protects, AllowAnonymous opens. Stops at the first call that maps a route,
// since what follows that applies to the route, not to this receiver.
function applySegments(index, file, segments, state, label) {
  for (const seg of segments) {
    if (seg.name === "MapGroup") {
      state.prefix.push(firstArg(file, seg));
      continue;
    }
    if (ROUTE_MAPPING.test(seg.name)) break;
    if (seg.name === "RequireAuthorization") state.auth = state.auth || `RequireAuthorization() on ${label}`;
    else if (index.authorizingHelpers.has(seg.name)) state.auth = state.auth || `${seg.name}() on ${label}, which requires authorization`;
    else if (seg.name === "AllowAnonymous") state.anonymous = true;
  }
  return state;
}

function scopeAt(file, pos) {
  let best = null;
  for (const m of file.parsed.methods) {
    if (m.bodyStart >= 0 && m.bodyStart <= pos && pos <= m.bodyEnd && (!best || m.bodyStart > best.bodyStart)) best = m;
  }
  return best ? { from: best.bodyStart, to: best.bodyEnd, method: best } : { from: 0, to: file.masked.length, method: null };
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Conventions applied to a name as statements of their own: `group.RequireAuthorization(policy);`.
// Conventions on a group apply to every endpoint in it, whichever order they are written in.
function statementConventions(index, file, scope, name, state, label) {
  const re = new RegExp(`(?<![\\w.])${esc(name)}\\s*\\.`, "g");
  re.lastIndex = scope.from;
  let m;
  while ((m = re.exec(file.masked)) && m.index < scope.to) {
    const before = file.masked.slice(Math.max(scope.from, m.index - 40), m.index);
    if (/\b(?:var|new)\s+$|[\w>]\s+$/.test(before) && !/\b(?:return|await)\s+$/.test(before)) continue; // a declaration
    // Only what is applied to the name itself: `g.MapGroup("x").RequireAuthorization()` protects the
    // new subgroup, not g, and `g.MapGet(...).RequireAuthorization()` protects that one route.
    const { segments } = parseChain(file.masked, m.index, scope.to);
    const own = segments.findIndex((sg) => ROUTE_MAPPING.test(sg.name));
    applySegments(index, file, own < 0 ? segments : segments.slice(0, own), state, label);
  }
  return state;
}

function resolveName(index, file, scope, name, pos, depth) {
  // The last assignment to the name in scope before its use.
  const re = new RegExp(`(?<![\\w.])${esc(name)}\\s*=(?![=>])`, "g");
  re.lastIndex = scope.from;
  let m;
  let last = null;
  while ((m = re.exec(file.masked)) && m.index < pos) last = m;
  let state;
  if (last) {
    const from = last.index + last[0].length;
    state = resolveExpr(index, file, scope, from, statementEnd(file.masked, from), depth);
  } else if (scope.method && scope.method.params.includes(name)) {
    state = resolveCallSites(index, scope.method, name, depth);
  } else {
    state = OPEN();
  }
  return statementConventions(index, file, scope, name, state, "its group");
}

function resolveExpr(index, file, scope, from, to, depth) {
  const chain = parseChain(file.masked, from, to);
  if (!chain.base) return OPEN();
  const state = depth > MAX_DEPTH ? OPEN() : resolveName(index, file, scope, chain.base, from, depth + 1);
  return applySegments(index, file, chain.segments, { ...state, prefix: [...state.prefix] }, "its group");
}

// A route mapped on a method's parameter is protected only if every call of that method is.
function resolveCallSites(index, method, param, depth) {
  // Only the receiver (`this`) is reached through `x.Method()`; another parameter is passed in, and
  // following arguments is past what this reads. Unknown is open, which reports rather than passes.
  if (method.thisParam !== param) return OPEN();
  const key = method.name;
  if (!index.callSites.has(key)) {
    const sites = [];
    const re = new RegExp(`\\.\\s*${esc(key)}\\s*(?:<[^<>()]*>\\s*)?\\(`, "g");
    for (const f of index.files) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(f.masked))) sites.push({ file: f, dot: m.index, open: m.index + m[0].length - 1 });
    }
    index.callSites.set(key, sites);
  }
  const sites = index.callSites.get(key).filter((s) => !(s.file === method.file && s.dot > method.bodyStart && s.dot < method.bodyEnd));
  if (!sites.length) return OPEN();
  const states = sites.map((s) => {
    const scope = scopeAt(s.file, s.dot);
    const start = receiverStart(s.file.masked, s.dot);
    const state = resolveExpr(index, s.file, scope, start, s.dot, depth + 1);
    // Conventions chained after the call apply to what it returns, which is the group it mapped.
    const close = matchClose(s.file.masked, s.open, "(", ")");
    const after = segmentsFrom(s.file.masked, close + 1, statementEnd(s.file.masked, close + 1));
    applySegments(index, s.file, after.segments, state, `the call to ${key}()`);
    return state;
  });
  return {
    prefix: states[0].prefix,
    auth: states.every((s) => s.auth) ? states[0].auth : null,
    anonymous: states.some((s) => s.anonymous),
  };
}

// Project helpers that apply RequireAuthorization to their `this` parameter, directly or through
// another such helper: Bitwarden's WithPamDefaults(). Found to a fixed point.
function authorizingHelpers(index) {
  const helpers = new Set();
  const candidates = [];
  for (const f of index.files) for (const m of f.parsed.methods) if (m.thisParam && m.bodyStart >= 0) candidates.push(m);
  for (let changed = true; changed; ) {
    changed = false;
    for (const m of candidates) {
      if (helpers.has(m.name)) continue;
      const scope = { from: m.bodyStart, to: m.bodyEnd, method: m };
      const state = { prefix: [], auth: null, anonymous: false };
      statementConventions({ authorizingHelpers: helpers }, m.file, scope, m.thisParam, state, "");
      if (state.auth && !state.anonymous) {
        helpers.add(m.name);
        changed = true;
      }
    }
  }
  return helpers;
}

function handlerAuth(index, file, seg) {
  // The handler is the last argument: a lambda, whose attributes are written on it, or a method
  // group, whose attributes are on the method.
  const args = splitTopLevel(file.masked, seg.argsFrom, seg.argsTo);
  const [a, b] = args[args.length - 1];
  const handler = file.masked.slice(a, b);
  const out = { auth: null, anonymous: false, body: null };
  const lambdaAttrs = attributesAt(file.text, file.masked, a).attrs;
  const group = /^\s*(?:[\w.]+\.)?(\w+)\s*$/.exec(handler);
  const attrs = group ? (index.methodsByName.get(group[1]) || []).flatMap((m) => m.attrs) : lambdaAttrs;
  // Its body, for a check written inside it: the lambda's own, or the method's when one method has
  // that name -- two would leave which one runs undecided.
  if (!group) out.body = file.text.slice(a, b);
  else {
    const methods = (index.methodsByName.get(group[1]) || []).filter((m) => m.bodyStart >= 0);
    if (methods.length === 1) out.body = methods[0].file.text.slice(methods[0].bodyStart, methods[0].bodyEnd + 1);
  }
  for (const attr of attrs) {
    if (attr.name === "AllowAnonymous") out.anonymous = true;
    else if (isAuthAttribute(index, attr)) out.auth = out.auth || `an [${attr.name}] attribute on the handler`;
  }
  return out;
}

function minimalRoutes(index, file) {
  const out = [];
  MAP_VERB.lastIndex = 0;
  let m;
  while ((m = MAP_VERB.exec(file.masked))) {
    const dot = m.index;
    const open = dot + m[0].length;
    const close = matchClose(file.masked, open, "(", ")");
    if (close < 0) continue;
    const seg = { name: `Map${m[1]}`, argsFrom: open + 1, argsTo: close };
    const scope = scopeAt(file, dot);
    const state = resolveExpr(index, file, scope, receiverStart(file.masked, dot), dot, 0);
    const own = { prefix: [], auth: null, anonymous: false };
    applySegments(index, file, segmentsFrom(file.masked, close + 1, statementEnd(file.masked, close + 1)).segments, own, "the endpoint");
    const handler = handlerAuth(index, file, seg);
    let method = m[1].toUpperCase();
    let methodSpec;
    if (m[1] === "Methods") {
      const args = splitTopLevel(file.masked, open + 1, close);
      const verbs = args[1] ? [...new Set((file.text.slice(...args[1]).match(/\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/gi) || []).map((v) => v.toUpperCase()))] : [];
      method = verbs.length === 1 ? verbs[0] : "ANY";
      methodSpec = `methods=[${verbs.join(", ")}]`;
    }
    // Unlike a controller's "/x", a minimal API's leading slash is relative to its group.
    const template = (firstArg(file, seg) || "").replace(/^\/+/, "");
    out.push({
      method,
      route: joinRoute(state.prefix.filter((p) => p != null).map((p) => p.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/"), template),
      declaration: file.text.slice(dot + 1, open + 1),
      methodSpec,
      context: file.text.slice(dot + 1, open + 1),
      line: lineAt(file.text, dot),
      kind: "minimal",
      anonymous: state.anonymous || own.anonymous || handler.anonymous,
      auth: own.auth || handler.auth || state.auth,
      body: handler.body,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------------------------

export const csharpAdapter = {
  name: "C#",
  extensions: [".cs"],
  comments: C_COMMENTS,
  idiom: "`[Authorize]` on the controller or action, `.RequireAuthorization()` on the endpoint or its group, or a FallbackPolicy requiring an authenticated user",

  routes(text, texts = [text]) {
    const index = projectIndex(texts);
    const file = index.byText.get(text);
    return [...controllerRoutes(text, file.parsed, index), ...minimalRoutes(index, file)];
  },

  globalAuth(all, texts = [all]) {
    return projectIndex(texts).globals.fallback ? "a fallback authorization policy requiring an authenticated user" : null;
  },

  family: "brace",
  handlerBodies(r) {
    return [r.body];
  },

  routeAuth(r, all, texts = [all]) {
    if (r.auth) return r.auth;
    if (r.kind === "controller" && projectIndex(texts).globals.controllers) return "authorization required on every controller";
    return null;
  },
};
