// Kotlin adapter for the authentication check: Spring and Ktor. See authentication.mjs for the rules
// every adapter follows; this file only answers "where are the routes" and "is this one protected".
//
// Spring in Kotlin is Spring: `@GetMapping("/owners/{id}")` under a class `@RequestMapping`, with
// Kotlin's own array syntax (`value = ["/a", "/b"]`). A route is protected by
//   - `@PreAuthorize` / `@Secured` / `@RolesAllowed` on the handler or its class;
//   - an annotation of the project's own that an `@Aspect` enforces by answering 401 or 403 --
//     kotlin-spring-realworld's `@ApiKeySecured`, which `@ApiKeySecured(mandatory = false)` turns off;
//   - the security configuration's path rules, taken in order as Spring takes them, so a route
//     under `permitAll()` stays open even when `anyRequest().authenticated()` follows it.
//
// Ktor declares routes as nested blocks, and nesting decides both the path and the protection:
//     authenticate { route("articles") { get("feed") { ... } } }
// A route is protected when any `authenticate` around it is required. That is Ktor's own rule, read
// from its AuthenticationInterceptors: a nested block collects the providers of every enclosing one,
// and the request is let through unauthenticated only when none of them is required -- so
// `authenticate(optional = true)` inside a required block does not open it. Routes declared in an
// extension function (`fun Routing.users() { ... }`) are judged at every place it is called; one
// unprotected call is an open route.
//
// Not read: HandlerInterceptor and servlet-filter authentication registered by hand, Spring's
// functional router DSL (`router { GET("/x", handler) }`), and Ktor's `route(path, HttpMethod.X)`.

import { lineAt, matchClose, splitTopLevel, literalAt, literalsIn, maskKotlin } from "./auth-parse.mjs";

const C_COMMENTS = { line: /^\s*\/\//, blockStart: /^\s*\/\*/, blockEnd: /\*\//, codeAfterEnd: true };

const MODIFIER = /^(?:public|private|internal|protected|open|override|abstract|final|suspend|inline|data|sealed|annotation|enum|companion|inner|operator|infix|tailrec|external|const|lateinit|value)$/;

// ---------------------------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------------------------

function annotationsOf(text, masked) {
  const out = [];
  const re = /@(?:\w+:)?([\w.]+)/g;
  let m;
  while ((m = re.exec(masked))) {
    const name = m[1].split(".").pop();
    let end = m.index + m[0].length;
    let k = end;
    while (k < masked.length && (masked[k] === " " || masked[k] === "\t")) k++;
    const args = [];
    if (masked[k] === "(") {
      const close = matchClose(masked, k, "(", ")");
      if (close > 0) {
        for (const [a, b] of splitTopLevel(masked, k + 1, close)) {
          const raw = masked.slice(a, b);
          const named = /^\s*(\w+)\s*=(?!=)\s*/.exec(raw);
          const from = a + (named ? named[0].length : raw.length - raw.trimStart().length);
          args.push({ name: named ? named[1] : null, literals: literalsIn(text, masked, from, b), raw: text.slice(from, b).trim() });
        }
        end = close + 1;
        re.lastIndex = end;
      }
    }
    out.push({ name, start: m.index, end, args, line: lineAt(text, m.index), raw: text.slice(m.index, end) });
  }
  return out;
}

// The annotations written directly before `pos`, with only modifiers and whitespace between.
function annotationRun(masked, annotations, pos) {
  const run = [];
  let start = pos;
  for (let i = annotations.length - 1; i >= 0; i--) {
    const a = annotations[i];
    if (a.end > start) continue;
    const between = masked.slice(a.end, start).trim();
    if (between && !between.split(/\s+/).every((w) => MODIFIER.test(w))) break;
    run.unshift(a);
    start = a.start;
  }
  return run;
}

function skipBalanced(masked, k) {
  const open = masked[k];
  const close = { "(": ")", "<": ">", "[": "]", "{": "}" }[open];
  const end = matchClose(masked, k, open, close);
  return end < 0 ? masked.length : end + 1;
}

const NEXT_DECLARATION = /^\s*(?:@|fun\b|val\b|var\b|class\b|object\b|interface\b|private\b|public\b|internal\b|protected\b|data\b|enum\b|sealed\b|abstract\b|open\b|override\b|companion\b|\}|$)/;

// Where a declaration's body is: `{ ... }`, or `= expression` running to the end of its line and any
// line continuing it with `.` or `?.`.
function bodyAfter(masked, k) {
  for (; k < masked.length; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "<" || ch === "[") {
      k = skipBalanced(masked, k) - 1;
      continue;
    }
    if (ch === "{") return { from: k, to: matchClose(masked, k, "{", "}") };
    if (ch === "=" && masked[k + 1] !== "=") {
      let j = k + 1;
      let depth = 0;
      for (; j < masked.length; j++) {
        const c = masked[j];
        if (c === "(" || c === "[" || c === "{") depth++;
        else if (c === ")" || c === "]" || c === "}") {
          if (--depth < 0) break;
        } else if (c === "\n" && depth === 0 && !/^\s*(?:\?\.|\.|\?:|&&|\|\|)/.test(masked.slice(j + 1, j + 40))) break;
      }
      return { from: k + 1, to: j };
    }
    if (ch === "}" || ch === ";") return null;
    if (ch === "\n" && NEXT_DECLARATION.test(masked.slice(k + 1, k + 60))) return null;
  }
  return null;
}

function parseFile(text) {
  const masked = maskKotlin(text);
  const annotations = annotationsOf(text, masked);
  const classes = [];
  const functions = [];
  const re = /\b(class|object|interface|fun)\b/g;
  let m;
  while ((m = re.exec(masked))) {
    const after = masked.slice(m.index + m[0].length, m.index + m[0].length + 200);
    if (m[1] === "fun") {
      const f = /^\s*(?:<[^>]*>\s*)?(?:([\w.]+(?:<[^>]*>)?)\.)?(\w+)\s*\(/.exec(after);
      if (!f) continue;
      const paramsAt = m.index + m[0].length + f[0].length - 1;
      const body = bodyAfter(masked, skipBalanced(masked, paramsAt));
      functions.push({
        name: f[2],
        receiver: f[1] ? f[1].replace(/<.*$/, "").split(".").pop() : null,
        annotations: annotationRun(masked, annotations, lineStartOrModifiers(masked, m.index)),
        start: m.index,
        body,
        line: lineAt(text, m.index),
      });
    } else {
      const c = /^\s*(\w+)/.exec(after);
      if (!c) continue;
      const declStart = lineStartOrModifiers(masked, m.index);
      const head = masked.slice(declStart, m.index);
      const body = bodyAfter(masked, m.index + m[0].length + c[0].length);
      classes.push({
        name: c[1],
        isAnnotation: /\bannotation\s*$/.test(head),
        annotations: annotationRun(masked, annotations, declStart),
        body,
        start: m.index,
        line: lineAt(text, m.index),
      });
    }
  }
  for (const f of functions) f.cls = classes.filter((c) => c.body && c.body.from < f.start && f.start < c.body.to).sort((a, b) => b.body.from - a.body.from)[0] || null;
  return { masked, annotations, classes, functions };
}

// Back from a declaration keyword over the modifiers in front of it.
function lineStartOrModifiers(masked, pos) {
  let k = pos;
  for (;;) {
    let j = k - 1;
    while (j >= 0 && /\s/.test(masked[j])) j--;
    let w = j;
    while (w >= 0 && /\w/.test(masked[w])) w--;
    const word = masked.slice(w + 1, j + 1);
    if (word && MODIFIER.test(word)) k = w + 1;
    else return k;
  }
}

// ---------------------------------------------------------------------------------------------
// Spring
// ---------------------------------------------------------------------------------------------

const MAPPING = /^(Get|Post|Put|Patch|Delete|Request)Mapping$/;
const AUTH_ANNOTATION = /^(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)$/;
const OPEN_EXPRESSION = /^\s*["']?\s*(?:permitAll(?:\(\))?|isAnonymous\(\))\s*["']?\s*$/;
const REJECTS_CALLER =
  /\bSC_(?:UNAUTHORIZED|FORBIDDEN)\b|\bHttpStatus\s*\.\s*(?:UNAUTHORIZED|FORBIDDEN)\b|\bHttpStatusCode\s*\.\s*(?:Unauthorized|Forbidden)\b|\b(?:Unauthori[sz]ed|AccessDenied|Forbidden|Authentication)\w*Exception\b|\bstatus\s*=\s*40[13]\b|\bsendError\s*\(\s*40[13]\b/;
const SWITCHED_OFF = /^(?:mandatory|required|enabled|enforced?|active)$/;

function mappingPaths(a) {
  const pos = a.args.filter((x) => !x.name || x.name === "value" || x.name === "path").flatMap((x) => x.literals);
  return pos.length ? pos : [null];
}

function mappingVerb(a) {
  const verb = MAPPING.exec(a.name)[1];
  if (verb !== "Request") return { method: verb.toUpperCase() };
  const m = a.args.find((x) => x.name === "method");
  const verbs = m ? [...m.raw.matchAll(/RequestMethod\s*\.\s*(\w+)/g)].map((v) => v[1]) : [];
  return verbs.length === 1 ? { method: verbs[0] } : { method: "ANY", methodSpec: verbs.length ? `methods=[${verbs.join(", ")}]` : undefined };
}

function joinPath(parts) {
  return "/" + parts.filter((p) => p != null).map((p) => p.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/");
}

function annotationProtects(index, a) {
  if (AUTH_ANNOTATION.test(a.name)) {
    const expr = a.args[0];
    return expr && OPEN_EXPRESSION.test(expr.raw) ? null : `a @${a.name} annotation`;
  }
  if (index.enforced.has(a.name)) {
    const off = a.args.some((x) => x.name && SWITCHED_OFF.test(x.name) && x.raw === "false");
    return off ? null : `@${a.name}, which an aspect enforces`;
  }
  return null;
}

function springRoutes(index, file) {
  const out = [];
  for (const fn of file.parsed.functions) {
    const mappings = fn.annotations.filter((a) => MAPPING.test(a.name));
    if (!mappings.length) continue;
    const cls = fn.cls;
    const classMapping = cls && cls.annotations.find((a) => a.name === "RequestMapping");
    const prefix = classMapping ? mappingPaths(classMapping)[0] : null;
    const auth =
      fn.annotations.map((a) => annotationProtects(index, a)).find(Boolean) ||
      (cls && cls.annotations.map((a) => annotationProtects(index, a)).find(Boolean)) ||
      null;
    for (const a of mappings) {
      for (const p of mappingPaths(a)) {
        const { method, methodSpec } = mappingVerb(a);
        const route = joinPath([prefix, p]);
        out.push({
          method,
          methodSpec,
          route,
          declaration: a.raw,
          context: a.raw,
          line: a.line,
          kind: "spring",
          framework: "Spring",
          auth: auth || securityRuleFor(index, method, route),
          body: fn.body && fn.body.to > fn.body.from ? file.text.slice(fn.body.from, fn.body.to + 1) : null,
        });
      }
    }
  }
  return out;
}

// Annotations an aspect enforces by turning the caller away: the pointcut names the annotation and
// the aspect's code answers 401 or 403.
function enforcedAnnotations(files) {
  const declared = new Set();
  for (const f of files) for (const c of f.parsed.classes) if (c.isAnnotation) declared.add(c.name);
  const enforced = new Set();
  for (const f of files) {
    for (const c of f.parsed.classes) {
      if (!c.body || !c.annotations.some((a) => a.name === "Aspect")) continue;
      const body = f.text.slice(c.body.from, c.body.to);
      if (!REJECTS_CALLER.test(body)) continue;
      for (const m of body.matchAll(/@(?:annotation|within)\s*\(\s*([\w.]+)\s*\)|execution\s*\(\s*@([\w.]+)/g)) {
        const name = (m[1] || m[2]).split(".").pop();
        if (declared.has(name)) enforced.add(name);
      }
    }
  }
  return enforced;
}

// The security configuration's authorization rules, in the order Spring applies them.
function securityRules(files) {
  const rules = [];
  const ACCESS = /^(permitAll|anonymous|authenticated|fullyAuthenticated|rememberMe|denyAll|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|access|hasIpAddress)$/;
  for (const f of files) {
    const { text, masked } = f;
    // Kotlin DSL: authorize("/api/**", permitAll), authorize(HttpMethod.GET, "/x", authenticated),
    // authorize(anyRequest, authenticated).
    for (const m of masked.matchAll(/(?<![\w.])authorize\s*\(/g)) {
      const open = m.index + m[0].length - 1;
      const close = matchClose(masked, open, "(", ")");
      const args = splitTopLevel(masked, open + 1, close);
      if (args.length < 2) continue;
      const access = /^\s*(\w+)/.exec(masked.slice(...args[args.length - 1]));
      if (!access || !ACCESS.test(access[1])) continue;
      const method = /HttpMethod\s*\.\s*(\w+)/.exec(masked.slice(args[0][0], args[args.length - 2][1]));
      const target = masked.slice(...args[args.length - 2]);
      const patterns = /\banyRequest\b/.test(target) ? "any" : literalsIn(text, masked, ...args[args.length - 2]);
      rules.push({ method: method ? method[1].toUpperCase() : null, patterns, access: access[1], at: m.index });
    }
    // Chained: .requestMatchers("/a").permitAll(), .anyRequest().authenticated().
    for (const m of masked.matchAll(/\.\s*(requestMatchers|antMatchers|mvcMatchers|regexMatchers|pathMatchers|anyRequest|anyExchange)\s*\(/g)) {
      const open = m.index + m[0].length - 1;
      const close = matchClose(masked, open, "(", ")");
      const access = /^\s*\.\s*(\w+)\s*\(/.exec(masked.slice(close + 1, close + 80));
      if (!access || !ACCESS.test(access[1])) continue;
      const any = m[1] === "anyRequest" || m[1] === "anyExchange";
      const method = /HttpMethod\s*\.\s*(\w+)/.exec(masked.slice(open, close));
      rules.push({
        method: method ? method[1].toUpperCase() : null,
        patterns: any ? "any" : literalsIn(text, masked, open + 1, close),
        regex: m[1] === "regexMatchers",
        access: access[1],
        at: m.index,
      });
    }
  }
  return rules.filter((r) => r.patterns === "any" || r.patterns.length);
}

function antToRegex(pattern) {
  const body = pattern
    .replace(/[.+^$|()[\]\\]/g, "\\$&")
    .replace(/\{[^}]*\}/g, "[^/]+")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/\/\u0000/g, "(?:/.*)?")
    .replace(/\u0000/g, ".*");
  return new RegExp(`^${body}/?$`);
}

function securityRuleFor(index, method, route) {
  if (!index.rules.length) return null;
  const probe = route.replace(/\{[^}]*\}/g, "x");
  for (const rule of index.rules) {
    if (rule.method && method !== "ANY" && rule.method !== method) continue;
    let hit = rule.patterns === "any";
    if (!hit) {
      hit = rule.patterns.some((p) => {
        try {
          return (rule.regex ? new RegExp(p) : antToRegex(p)).test(probe);
        } catch {
          return false;
        }
      });
    }
    if (!hit) continue;
    return rule.access === "permitAll" || rule.access === "anonymous" ? null : `a security rule requiring ${rule.access}`;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Ktor
// ---------------------------------------------------------------------------------------------

const KTOR_BLOCK = /(?<![\w.])(routing|route|resource|location|authenticate|get|post|put|patch|delete|head|options|webSocket|sse)\s*(?:<\s*([\w.]+)\s*>)?\s*(\()?/g;
const KTOR_VERB = /^(get|post|put|patch|delete|head|options|webSocket|sse)$/;

// Every routing block in a file: `routing { }`, `install(Routing) { }`, `route(...) { }`,
// `authenticate(...) { }` and the verbs, each with the extent of its lambda.
function ktorBlocks(file) {
  const { text, masked } = file;
  const blocks = [];
  KTOR_BLOCK.lastIndex = 0;
  let m;
  while ((m = KTOR_BLOCK.exec(masked))) {
    let k = m.index + m[0].length;
    let args = [];
    let argsFrom = -1;
    let argsTo = -1;
    if (m[3]) {
      const close = matchClose(masked, k - 1, "(", ")");
      if (close < 0) continue;
      argsFrom = k;
      argsTo = close;
      args = splitTopLevel(masked, k, close);
      k = close + 1;
    }
    while (k < masked.length && (masked[k] === " " || masked[k] === "\t")) k++;
    if (masked[k] !== "{") continue;
    const end = matchClose(masked, k, "{", "}");
    if (end < 0) continue;
    const kind = m[1];
    const block = { kind, from: k, to: end, at: m.index, line: lineAt(text, m.index), typed: m[2] ? m[2].split(".").pop() : null };
    if (kind === "authenticate") {
      const raw = masked.slice(argsFrom, argsTo);
      block.optional = /\boptional\s*=\s*true\b|AuthenticationStrategy\s*\.\s*Optional\b/.test(raw);
    } else if (kind === "resource" || kind === "location") {
      // resource<Login> { get { } post { } }: a typed route scope, its path on the class.
      if (!block.typed) continue;
      block.kind = "route";
    } else if (kind === "route" || KTOR_VERB.test(kind)) {
      const pathArg = args.find(([a, b]) => !/^\s*\w+\s*=/.test(masked.slice(a, b)) || /^\s*path\s*=/.test(masked.slice(a, b)));
      // A path that is not a literal -- webSocket(path) { } in a helper -- is kept as the expression,
      // so the route is reported rather than lost.
      block.path = pathArg ? literalsIn(text, masked, ...pathArg)[0] ?? `{${text.slice(...pathArg).trim()}}` : null;
    } else if (kind === "routing" && m[3]) continue;
    blocks.push(block);
  }
  // `install(Routing) { ... }`, the form before Ktor 1.x's `routing { }`.
  for (const im of masked.matchAll(/\binstall\s*\(\s*Routing\s*\)\s*\{/g)) {
    const from = im.index + im[0].length - 1;
    blocks.push({ kind: "routing", from, to: matchClose(masked, from, "{", "}"), at: im.index });
  }
  return blocks;
}

const enclosing = (blocks, pos) => blocks.filter((b) => b.from < pos && pos < b.to).sort((a, b) => a.from - b.from);

// What surrounds a position: path prefix, whether a required authenticate is around it, and the
// extension function it sits in when no routing block does.
function contextAt(index, file, pos, depth) {
  const around = enclosing(index.blocks.get(file), pos);
  const prefix = around.filter((b) => b.kind === "route").map((b) => b.path ?? (b.typed ? index.resources.get(b.typed) ?? `{${b.typed}}` : null));
  const required = around.some((b) => b.kind === "authenticate" && !b.optional);
  const inRouting = around.some((b) => b.kind === "routing");
  if (required || inRouting || depth > 4) return { prefix, auth: required ? "an enclosing authenticate block" : null };
  // Inside `fun Route.users() { ... }`: judged where it is called.
  const fn = file.parsed.functions.find((f) => f.body && f.body.from < pos && pos < f.body.to && /^(?:Route|Routing)$/.test(f.receiver || ""));
  if (!fn) return { prefix, auth: null };
  const sites = callSites(index, fn);
  if (!sites.length) return { prefix, auth: null };
  const outer = sites.map((s) => contextAt(index, s.file, s.pos, depth + 1));
  return {
    prefix: [...outer[0].prefix, ...prefix],
    auth: outer.every((o) => o.auth) ? `${outer[0].auth}, around every call of ${fn.name}()` : null,
  };
}

function callSites(index, fn) {
  if (index.callSites.has(fn)) return index.callSites.get(fn);
  const sites = [];
  const re = new RegExp(`(?<![\\w])${fn.name}\\s*\\(`, "g");
  for (const f of index.files) {
    for (const m of f.masked.matchAll(re)) {
      if (f === fn.file && m.index >= fn.start && m.index <= (fn.body ? fn.body.from : fn.start)) continue; // the declaration
      if (/\bfun\s+(?:[\w.<>]+\.)?$/.test(f.masked.slice(Math.max(0, m.index - 60), m.index))) continue;
      sites.push({ file: f, pos: m.index });
    }
  }
  index.callSites.set(fn, sites);
  return sites;
}

function ktorRoutes(index, file) {
  const out = [];
  for (const b of index.blocks.get(file)) {
    if (!KTOR_VERB.test(b.kind)) continue;
    // A route is declared in a routing scope, never inside a handler: `head { title(...) }` in a
    // GET handler is kotlinx.html, and was read as a HEAD route on two ktor-samples.
    const around = enclosing(index.blocks.get(file), b.at);
    if (around.some((o) => KTOR_VERB.test(o.kind))) continue;
    const inScope =
      around.some((o) => o.kind === "routing" || o.kind === "route" || o.kind === "authenticate") ||
      file.parsed.functions.some((f) => f.body && f.body.from < b.at && b.at < f.body.to && /^(?:Route|Routing)$/.test(f.receiver || ""));
    if (!inScope) continue;
    const ctx = contextAt(index, file, b.at, 0);
    const own = b.typed ? index.resources.get(b.typed) ?? `{${b.typed}}` : b.path;
    const method = b.kind === "webSocket" || b.kind === "sse" ? "GET" : b.kind.toUpperCase();
    out.push({
      method,
      route: joinPath([...ctx.prefix, own]),
      declaration: file.text.slice(b.at, b.from),
      context: file.text.slice(b.at, b.from),
      line: b.line,
      kind: "ktor",
      framework: "Ktor",
      auth: ctx.auth,
      body: b.to > b.from ? file.text.slice(b.from, b.to + 1) : null,
    });
  }
  return out;
}

// @Resource("/articles") class Articles -- Ktor's typed routes, and @Location before them.
function resourcePaths(files) {
  const out = new Map();
  for (const f of files) {
    for (const c of f.parsed.classes) {
      const a = c.annotations.find((x) => x.name === "Resource" || x.name === "Location");
      if (a && a.args[0]?.literals[0] != null) out.set(c.name, a.args[0].literals[0]);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The project
// ---------------------------------------------------------------------------------------------

let memo = { texts: null, index: null };

function projectIndex(texts, ctx = {}) {
  if (memo.texts === texts) return memo.index;
  const rels = ctx.rels || texts.map((_, i) => `file${i}.kt`);
  const files = texts.map((text, i) => {
    const parsed = parseFile(text);
    const f = { text, masked: parsed.masked, parsed, rel: rels[i] };
    for (const fn of parsed.functions) fn.file = f;
    return f;
  });
  const index = {
    files,
    byRel: new Map(files.map((f) => [f.rel, f])),
    byText: new Map(files.map((f) => [f.text, f])),
    enforced: enforcedAnnotations(files),
    rules: securityRules(files),
    resources: resourcePaths(files),
    callSites: new Map(),
  };
  index.blocks = new Map(files.map((f) => [f, ktorBlocks(f)]));
  memo = { texts, index };
  return index;
}

export const kotlinAdapter = {
  name: "Kotlin",
  extensions: [".kt"],
  comments: C_COMMENTS,
  idiom:
    "`authenticate { }` around the Ktor routes, or `@PreAuthorize` on the Spring handler, or a security rule requiring authentication for its path",
  idioms: {
    Ktor: "`authenticate { }` around the routes",
    Spring: "`@PreAuthorize` on the handler or its class, or a security rule requiring authentication for its path",
  },

  routes(text, texts = [text], ctx = {}) {
    const index = projectIndex(texts, ctx);
    const file = (ctx.rel && index.byRel.get(ctx.rel)) || index.byText.get(text);
    return [...springRoutes(index, file), ...ktorRoutes(index, file)];
  },

  globalAuth() {
    // Spring's rules are judged per route, in order; Ktor has no global authentication.
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
