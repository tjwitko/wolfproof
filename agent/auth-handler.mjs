// Authentication written inside a route's handler, in every language the check reads.
//
// The adapters judge what protects a route from the outside: a decorator, middleware, an attribute,
// a group, a security rule. A handler that checks its own caller -- a webhook comparing a key with
// FixedTimeEquals, a page that sends a visitor without a session to the sign-in page -- was reported
// as open to anyone, in Bitwarden, ktor-samples and a Flask service alike (docs/candidate-rules.md #25).
//
// Crediting protection is the dangerous direction: a gate that invents a check is worse than one that
// misses it. So a handler counts only for a guard of one shape, and every part of the shape is needed:
//
//   - **At the top level of the handler.** A check nested inside another branch protects one path.
//   - **Evidence in its condition** of one of three kinds:
//       a secret checked -- a constant-time comparison, or a call verifying a signature or token;
//       a credential compared -- a credential-named value against a configured or credential-named one,
//         never against a literal (`sortKey != "date"` is validation, not authentication);
//       the caller's identity -- a session, principal, signed-in user or role.
//     A name in the condition assigned earlier in the handler is read through its assignment, so
//     `valid = compare_digest(...)` then `if not valid:` is the same guard.
//   - **A branch that refuses and ends the request** -- returns, throws, aborts or halts with a refusal
//     (401, 403, 400, 404, a redirect, an exception) -- or an if/else that ends the handler, with the
//     refusal on one side and the work on the other.
//
//   - **Before any work.** Every top-level statement ahead of the guard reads (an assignment to a
//     name), logs, or is a branch that only refuses. A branch that does work and returns -- CTFd's
//     email confirmation, which marks the account verified before its sign-in check -- is a path the
//     guard never sees.
//   - **Refusing the caller who fails.** `if current_user.is_authenticated: return redirect(...)`
//     names the caller and turns away the signed-in one; the condition's direction is read, not only
//     its evidence.
//
// Everything else is not credited, and the route stays open: a check behind a helper the handler
// calls, a guard after the work, a refusal that does not end the request.

// --- masking -------------------------------------------------------------------------------------

/** String contents blanked, positions and newlines kept: structure can be read without literals. */
function maskStrings(text, family) {
  const out = text.split("");
  const blank = (a, b) => {
    for (let k = a; k < b; k++) if (out[k] !== "\n") out[k] = " ";
  };
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    const triple = family === "python" && (text.startsWith('"""', i) || text.startsWith("'''", i));
    if (triple) {
      const q = text.slice(i, i + 3);
      const end = text.indexOf(q, i + 3);
      const stop = end < 0 ? text.length : end + 3;
      blank(i + 3, stop - 3);
      i = stop;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      // A Rust or C# lifetime/char is too short to matter; Kotlin and PHP `$` templates stay masked.
      let k = i + 1;
      while (k < text.length && text[k] !== c && !(text[k] === "\n" && c !== "`")) {
        if (text[k] === "\\") k++;
        k++;
      }
      blank(i + 1, Math.min(k, text.length));
      i = k + 1;
      continue;
    }
    i++;
  }
  return out.join("");
}

function closeOf(masked, open) {
  const pairs = { "(": ")", "{": "}", "[": "]" };
  const want = pairs[masked[open]];
  let depth = 0;
  for (let k = open; k < masked.length; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    else if (ch === ")" || ch === "}" || ch === "]") {
      depth--;
      if (depth === 0) return ch === want ? k : -1;
    }
  }
  return -1;
}

// --- work before the guard ------------------------------------------------------------------------
//
// A guard protects the route only if nothing ahead of it has acted. What may come first: reading
// something into a name, a log line or flash message, and a branch that only refuses. Anything else
// -- a call, a field written, a loop, a branch that does work and returns -- is work, and a guard
// after it is not credited. Unknown statements count as work: a missed guard leaves a route open,
// which a reviewed finding settles; an invented one hides it.

const SEP = String.raw`\s*(?:\?\.|\.|::|->)\s*`;
// `log(...)`, `logger.info(...)`, `_logger.LogWarning(...)`, `console.log(...)`, `Log::warning(...)`,
// `flash(...)` -- not `login_user(...)`.
const QUIET_CALL = new RegExp(
  String.raw`^\s*(?:await\s+)?(?:\$?[\w$]+(?:\s*\(\s*\))?${SEP})*(?:[\w$]*_)?(?:[Ll]og|[Ll]ogger|[Ll]ogging|LOG|flash)(?:[A-Z]\w*)?(?:${SEP}\w+)?\s*\(`,
);
const COMPOUND = /^\s*(?:if|else|elif|elsif|unless|for|foreach|while|do|try|catch|except|finally|with|switch|match|case|begin|loop|select|go)\b/;
const BARE_RETURN = /^\s*(?:return|break)\b\s*(?:@\w+)?\s*(?:nil|null|None|false|undefined)?\s*;?\s*$/;

// A JavaScript destructuring declaration, `const { newPassword, currentPassword } = request.body` or
// `let [first] = rows`, with renames, nesting, rest and a TypeScript type after it. It reads into
// names as `const x = ...` does. Counted as work, it put fastify/demo's `PUT /update-password` open:
// its handler destructures the body and the session user before checking the current password.
// A default with a call in it (`{ limit = compute() }`) is still work, since the call may act.
const DESTRUCTURE = /^\s*(?:const|let|var)\s+[{[][^()]*[}\]]\s*(?::\s*[\w$.<>[\]\s,|]+)?$/;

/** Assignment to a plain name (`x = ...`, `val x: T = ...`, `a, b := ...`, `$x = ...`), or to Flask's `g`. */
function plainAssignment(m) {
  let depth = 0;
  for (let k = 0; k < m.length; k++) {
    const ch = m[k];
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    else if (ch === "=" && depth === 0) {
      if (m[k + 1] === "=" || m[k + 1] === ">" || "=!<>".includes(m[k - 1] || "")) {
        if (m[k + 1] === "=") k++;
        continue;
      }
      const lhs = m.slice(0, k).replace(/:$/, "").replace(/\[\]/g, "").replace(/^\s*g\s*\.\s*(?=\w+\s*$)/, "");
      return (/^\s*[\w$@\s,:<>?]+$/.test(lhs) && /[\w$]\s*$/.test(lhs)) || DESTRUCTURE.test(lhs);
    }
  }
  return false;
}

// A response header set (`WWW-Authenticate` beside a 401), or an error answered: neither acts.
const RESPONSE_ONLY =
  /^\s*(?:[\w$]+\s*(?:\?\.|\.|->)\s*)*(?:Header\s*\(\s*\)\s*\.\s*(?:Set|Add)|setHeader|set_header|AddHeader|addHeader|header)\s*\(|\bModelState\s*\.\s*AddModelError\s*\(|\b(?:ServerError|InternalServerError|StatusInternalServerError)\b|\bstatus\s*\(\s*5\d\d\b/;
// A call named for reading or checking, alone as a statement: `comment.LoadIssue(ctx)`,
// `repository.MustOwner(ctx)`, `CheckRepoScopedToken(...)`. Reading ahead of a guard is what an
// assignment does too; a call named for anything else may write.
const READ_CALL = new RegExp(
  String.raw`^\s*(?:await\s+)?(?:\$?[\w$]+(?:\s*\(\s*\))?${SEP})*(?:[\w$]+_)?(?![\w$]*(?:[Cc]reate|[Uu]pdate|[Dd]elete|[Ss]ave|[Ii]nsert|[Rr]emove|[Ww]rite|[Ss]end|[Ss]et[A-Z_]|[Aa]dd[A-Z_]|[Pp]ut[A-Z_]))(?:[Gg]et|[Ll]oad|[Ff]ind|[Ff]etch|[Rr]ead|[Ll]ookup|[Mm]ust|[Cc]heck|[Ee]nsure|[Rr]equire|[Aa]ssert|[Vv]erify|[Vv]alidate)(?:[A-Z_]\w*)?\s*\(`,
);

/** A statement that does nothing a caller could want done: a log line, a string, `pass`, a brace. */
function quietStatement(m) {
  if (!m.trim() || /^\s*(?:[{}]|pass|;)\s*$/.test(m) || /^\s*["'`]/.test(m) || QUIET_CALL.test(m)) return true;
  // A read call counts only when the call is the whole statement, not `load(x).delete()`.
  const r = READ_CALL.exec(m);
  if (!r) return false;
  const close = closeOf(m, r.index + r[0].length - 1);
  return close >= 0 && /^\s*;?\s*$/.test(m.slice(close + 1));
}

/** A branch's statements at its own top level, as source text. */
function pieces(branch, family) {
  let text = branch;
  let masked = maskStrings(text, family === "python" ? "python" : "brace");
  const open = /^\s*\{/.exec(masked);
  if (open) {
    const close = closeOf(masked, open[0].length - 1);
    text = text.slice(open[0].length, close < 0 ? text.length : close);
    masked = masked.slice(open[0].length, close < 0 ? masked.length : close);
  }
  const out = [];
  let depth = 0;
  let start = 0;
  for (let k = 0; k <= masked.length; k++) {
    const ch = masked[k];
    if (ch && "([{".includes(ch)) depth++;
    else if (ch && ")]}".includes(ch)) depth--;
    else if (k === masked.length || (depth <= 0 && (ch === ";" || ch === "\n"))) {
      const s = text.slice(start, k);
      // A chained call on the next line continues the statement.
      if (/^\s*\??\./.test(masked.slice(start, k)) && out.length) out[out.length - 1] += s;
      else if (s.trim()) out.push(s);
      start = k + 1;
    }
  }
  return out;
}

/** Does the branch do nothing but refuse: refusals, log lines, a bare return? */
function refusesOnly(branch, family) {
  return pieces(branch, family).every((s) => {
    const m = maskStrings(s, family === "python" ? "python" : "brace");
    if (COMPOUND.test(m)) return false;
    return quietStatement(m) || BARE_RETURN.test(m) || REFUSAL.test(s) || RESPONSE_ONLY.test(m);
  });
}

// --- top-level statements ------------------------------------------------------------------------
//
// Each family yields { guards, assigns }: a guard is { cond, branches: [text...], ends, last }, where
// `ends` says the guard's refusing branch must end the request itself and `last` that it is the
// handler's final statement (an if/else whose other side does the work).

const ASSIGN_BRACE =
  /^\s*(?:(?:val|var|let|const|final|auto)\s+|(?:[\w.<>?[\],\s]+?\s+)(?=\w+\s*=[^=>]))?\$?(\w+)\s*(?::\s*[\w.<>?]+\s*)?(?::=|=)(?!=)\s*([\s\S]*)$/;

// The names a destructuring declaration binds, each with the property it reads:
// `const { user } = request.session` binds `user` to `request.session.user`, as
// `const user = request.session.user` would. Without it a guard on `user` had nothing to read
// through, so the destructured form of a session check left its route open where the plain form
// protected it. A nested pattern binds nothing here; its names stay unknown.
function destructured(m, t) {
  const eq = /^\s*(?:const|let|var)\s+([{[])/.exec(m);
  if (!eq) return [];
  const open = eq[0].length - 1;
  const close = closeOf(m, open);
  if (close < 0) return [];
  const rest = /^\s*(?::\s*[\w$.<>[\]\s,|]+?)?\s*=(?![=>])\s*/.exec(m.slice(close + 1));
  if (!rest || !DESTRUCTURE.test(m.slice(0, close + 1 + rest[0].indexOf("=")))) return [];
  const rhs = t.slice(close + 1 + rest[0].length).trim().replace(/;$/, "");
  const out = [];
  let depth = 0;
  let from = open + 1;
  const entries = [];
  for (let k = open + 1; k < close; k++) {
    if ("([{".includes(m[k])) depth++;
    else if (")]}".includes(m[k])) depth--;
    else if (m[k] === "," && depth === 0) {
      entries.push(m.slice(from, k));
      from = k + 1;
    }
  }
  entries.push(m.slice(from, close));
  entries.forEach((e, i) => {
    const entry = e.trim();
    if (!entry) return;
    const spread = /^\.\.\.\s*([\w$]+)$/.exec(entry);
    if (spread) return out.push([spread[1], rhs]);
    if (eq[1] === "[") {
      const n = /^([\w$]+)\s*(?:=.*)?$/s.exec(entry);
      return n && out.push([n[1], `${rhs}[${i}]`]);
    }
    const kv = /^([\w$]+)\s*(?::\s*([\w$]+))?\s*(?:=.*)?$/s.exec(entry);
    if (kv) out.push([kv[2] || kv[1], `${rhs}.${kv[1]}`]);
  });
  return out;
}

function braceStatements(body) {
  const masked = maskStrings(body, "brace");
  const open = openingBrace(masked);
  if (open < 0) return { guards: [], assigns: new Map() };
  const close = closeOf(masked, open);
  const end = close < 0 ? masked.length : close;
  const guards = [];
  const assigns = new Map();
  // Split the block's top level into statements: at `;`, at a newline where nothing is open (Kotlin,
  // Go, JavaScript without semicolons), and after a `}` that closes a block at depth 0.
  const stmts = [];
  let start = open + 1;
  let depth = 0;
  for (let k = open + 1; k < end; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
      if (depth === 0 && ch === "}") {
        // An `else`, `catch` or chained call after the block continues the statement, and so does
        // the `=` of a destructuring pattern, or its TypeScript type: `const { email } =
        // request.session.user` is one statement, not a block and then an orphan `= ...`.
        const rest = masked.slice(k + 1, k + 40);
        if (/^\s*(?:else\b|catch\b|finally\b|\)|\.|,|\?\?|\?:|=(?![=>])|:)/.test(rest)) continue;
        stmts.push([start, k + 1]);
        start = k + 1;
      }
    } else if (depth === 0 && (ch === ";" || ch === "\n")) {
      // Go's `if err := load(); err != nil {`: the `;` is inside the if's header.
      if (ch === ";" && /^\s*(?:if|for|switch|select)\b[^{]*$/.test(masked.slice(start, k))) continue;
      if (ch === "\n") {
        // A line ending in an operator, or followed by one, continues.
        const before = masked.slice(start, k).trimEnd();
        const after = masked.slice(k + 1, k + 40).trimStart();
        if (!before || /[=+\-*/%&|<>?:,.(!]$/.test(before) || /^(?:[.?:&|+\-*/]|else\b|\?\?|\?:)/.test(after) || /^(?:if|else if|while|for)\b[^{]*$/.test(withoutParens(before.trim()))) continue;
      }
      stmts.push([start, k]);
      start = k + 1;
    }
  }
  if (start < end) stmts.push([start, end]);
  const live = stmts.filter(([a, b]) => masked.slice(a, b).trim());
  let work = false;
  live.forEach(([a, b], n) => {
    const m = masked.slice(a, b);
    const t = body.slice(a, b);
    const isLast = n === live.length - 1;
    const iff = /^\s*if\b\s*/.exec(m);
    if (iff) {
      // A later arm of an if/else-if chain runs only when the earlier conditions failed; an earlier
      // arm that did work is a path around it.
      let chainWork = work;
      for (const g of ifChain(body, masked, a + m.indexOf("if") + 2, b)) {
        guards.push({ ...g, last: isLast, afterWork: chainWork });
        if (!refusesOnly(g.branches[0], "brace")) chainWork = true;
        if (g.branches[1] !== undefined && !refusesOnly(g.branches[1], "brace")) chainWork = true;
      }
      work = chainWork;
      return;
    }
    let quiet = quietStatement(m) || plainAssignment(m) || /^\s*(?:var\s+\w+(?:\s+[\w.*[\]]+)?|defer\b.*)\s*$/.test(m);
    // `x ?: return ...`, `x ?? throw ...`: the left side is the condition, refused when it is null.
    const coalesce = /(\?:|\?\?)\s*(return\b|throw\b|run\s*\{|abort\b)/.exec(m);
    if (coalesce) {
      guards.push({ cond: t.slice(0, coalesce.index), branches: [t.slice(coalesce.index + coalesce[1].length)], ends: true, last: isLast, positive: true, afterWork: work });
    }
    // PHP's abort_unless(cond, 403) and abort_if, Laravel's throw_unless/throw_if.
    const pa = /^\s*(abort_unless|abort_if|throw_unless|throw_if)\s*\(/.exec(m);
    if (pa) {
      const o = a + pa[0].length - 1;
      const c = closeOf(masked, o);
      const inner = body.slice(o + 1, c < 0 ? b : c);
      const comma = splitTop(masked.slice(o + 1, c < 0 ? b : c));
      guards.push({ cond: inner.slice(0, comma[0]), branches: [`abort(${inner.slice(comma[0] + 1)})`], ends: true, last: isLast, self: true, positive: /unless/.test(pa[1]), afterWork: work });
      quiet = true;
    }
    if (SELF_REFUSING.test(t)) {
      guards.push({ cond: t, branches: [], ends: true, last: isLast, self: true, selfRefusing: true, afterWork: work });
      quiet = true;
    }
    const as = ASSIGN_BRACE.exec(m);
    if (as && !/^\s*(?:return|throw|if|while|for)\b/.test(m)) assigns.set(as[1], t.slice(m.indexOf(as[2])));
    for (const [name, value] of destructured(m, t)) assigns.set(name, value);
    if (!quiet) work = true;
  });
  return { guards, assigns };
}

/** Text with every parenthesised part removed: an if's header without its condition. */
function withoutParens(s) {
  let t = s;
  for (let prev; prev !== t; ) {
    prev = t;
    t = t.replace(/\([^()]*\)/g, "");
  }
  return t;
}

/**
 * The brace that opens the handler's block: the body's first character, or the first `{` after a
 * parameter list, an arrow, a generic, a return type or a throws clause -- not a destructuring
 * pattern among the parameters (`({ body }, res) => {`).
 */
function openingBrace(masked) {
  if (/^\s*\{/.test(masked)) return masked.indexOf("{");
  for (let k = masked.indexOf("{"); k >= 0; k = masked.indexOf("{", k + 1)) {
    const before = masked.slice(Math.max(0, k - 200), k);
    if (/(?:\)|=>|->|>)\s*$/.test(before) || /\)\s*(?::\s*\??[\w\\.<>[\]|?, ]+|throws\s+[\w.,\s]+|use\s*\([^)]*\))\s*$/.test(before)) return k;
  }
  return masked.indexOf("{");
}

/**
 * A method's source from `from` (its annotations) through the `}` closing its block, or null for one
 * without a block (abstract, an interface's). For readers that know where a handler is declared and
 * not where its body ends.
 */
export function methodBlock(text, from) {
  const masked = maskStrings(text, "brace");
  for (let k = from; k < masked.length && k < from + 4000; k++) {
    if (masked[k] === ";") return null;
    if (masked[k] !== "{") continue;
    const before = masked.slice(from, k);
    if (!/\)\s*(?::\s*\??[\w.<>[\]?, ]+)?\s*(?:throws\s+[\w.,\s]+)?$/.test(before)) continue;
    const close = closeOf(masked, k);
    return close < 0 ? null : text.slice(from, close + 1);
  }
  return null;
}

/** Index of the first top-level comma in a masked argument list. */
function splitTop(masked) {
  let depth = 0;
  for (let k = 0; k < masked.length; k++) {
    const ch = masked[k];
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    else if (ch === "," && depth === 0) return [k];
  }
  return [masked.length];
}

/** `if (c) X else if (d) Y else Z` from `at` (just after `if`): one guard per condition. */
function ifChain(body, masked, at, end) {
  const out = [];
  let k = at;
  while (k < end && /\s/.test(masked[k])) k++;
  let cond;
  if (masked[k] === "(") {
    const c = closeOf(masked, k);
    if (c < 0) return out;
    // `(a) || b {` in Go: the condition runs on to the block.
    const after = masked.slice(c + 1, c + 20);
    if (/^\s*(?:&&|\|\||and\b|or\b)/.test(after)) {
      const brace = masked.indexOf("{", c);
      cond = body.slice(k, brace);
      k = brace;
    } else {
      cond = body.slice(k + 1, c);
      k = c + 1;
    }
  } else {
    const brace = masked.indexOf("{", k);
    if (brace < 0 || brace > end) return out;
    cond = body.slice(k, brace);
    k = brace;
  }
  const [then, next] = branchAt(body, masked, k, end);
  const branches = [then];
  let rest = masked.slice(next, end);
  const els = /^\s*else\b/.exec(rest);
  if (els) {
    let e = next + els[0].length;
    const elseIf = /^\s*if\b/.exec(masked.slice(e, end));
    if (elseIf) {
      out.push({ cond, branches, ends: true, hasElse: true });
      out.push(...ifChain(body, masked, e + elseIf[0].length, end));
      return out;
    }
    const [other] = branchAt(body, masked, e, end);
    branches.push(other);
    out.push({ cond, branches, ends: true, hasElse: true });
    return out;
  }
  out.push({ cond, branches, ends: true, hasElse: false });
  return out;
}

/** A branch from `k`: a `{ block }`, or one statement up to `;`, a newline, or `else`. */
function branchAt(body, masked, k, end) {
  while (k < end && /\s/.test(masked[k])) k++;
  if (masked[k] === "{") {
    const c = closeOf(masked, k);
    const stop = c < 0 ? end : c + 1;
    return [body.slice(k, stop), stop];
  }
  let depth = 0;
  for (let j = k; j < end; j++) {
    const ch = masked[j];
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    else if (depth === 0 && (ch === ";" || ch === "\n")) return [body.slice(k, j + 1), j + 1];
    if (depth === 0 && /\belse\b/.test(masked.slice(j, j + 4)) && /\s/.test(masked[j - 1] || " ") && j > k) return [body.slice(k, j), j];
  }
  return [body.slice(k, end), end];
}

function pythonStatements(body) {
  const lines = body.split("\n");
  // The body starts after the signature's closing `:`; its statements share the first indentation.
  let i = 0;
  const masked = maskStrings(body, "python").split("\n");
  for (; i < lines.length; i++) if (/^\s*(?:async\s+)?def\b/.test(masked[i])) break;
  let depth = 0;
  for (; i < lines.length; i++) {
    for (const ch of masked[i]) {
      if ("([{".includes(ch)) depth++;
      else if (")]}".includes(ch)) depth--;
    }
    if (depth <= 0 && /:\s*$/.test(masked[i])) break;
  }
  i++;
  while (i < lines.length && !lines[i].trim()) i++;
  if (i >= lines.length) return { guards: [], assigns: new Map() };
  const indent = /^\s*/.exec(lines[i])[0].length;
  const ind = (n) => /^\s*/.exec(lines[n])[0].length;
  const blockFrom = (n) => {
    // The lines indented past `indent` after line n.
    const out = [];
    for (let j = n + 1; j < lines.length; j++) {
      if (lines[j].trim() && ind(j) <= indent) return [out.join("\n"), j];
      out.push(lines[j]);
    }
    return [out.join("\n"), lines.length];
  };
  const tops = [];
  for (let j = i; j < lines.length; j++) if (lines[j].trim() && ind(j) === indent) tops.push(j);
  // Lines that start a statement, for telling work from reading: not a docstring's inside, not the
  // closing bracket of a call spread over lines.
  const starts = tops.filter((j) => masked[j].trim() && !/^\s*[)\]}]/.test(masked[j]));
  const guards = [];
  const assigns = new Map();
  let work = false;
  starts.forEach((j) => {
    const line = lines[j];
    const isLast = j === tops[tops.length - 1];
    const n = tops.indexOf(j);
    const iff = /^\s*if\s+([\s\S]*?):\s*(.*)$/.exec(line);
    if (iff) {
      const [blk, after] = iff[2].trim() ? [iff[2], j + 1] : blockFrom(j);
      const branches = [blk];
      const els = after < lines.length && /^\s*else\s*:\s*(.*)$/.exec(lines[after] || "");
      if (els && ind(after) === indent) branches.push(els[1].trim() ? els[1] : blockFrom(after)[0]);
      // An `elif` continues the chain; its own condition is judged when its line is reached.
      const elif = after < lines.length && /^\s*elif\b/.test(lines[after] || "");
      guards.push({ cond: iff[1], branches, ends: true, hasElse: Boolean(els) || elif, last: isLast || (Boolean(els) && n >= tops.length - 2), afterWork: work });
      if (!branches.every((b) => refusesOnly(b, "python"))) work = true;
      return;
    }
    const elif = /^\s*elif\s+([\s\S]*?):\s*(.*)$/.exec(line);
    if (elif) {
      const [blk] = elif[2].trim() ? [elif[2]] : blockFrom(j);
      guards.push({ cond: elif[1], branches: [blk], ends: true, hasElse: true, last: isLast, afterWork: work });
      if (!refusesOnly(blk, "python")) work = true;
      return;
    }
    // The `else` of an `if` already read; an `except` or `finally` follows a `try`, which is work.
    const els = /^\s*else\s*:\s*(.*)$/.exec(line);
    if (els) {
      if (!refusesOnly(els[1].trim() ? els[1] : blockFrom(j)[0], "python")) work = true;
      return;
    }
    const as = /^\s*(\w+)\s*(?::\s*[\w.[\]]+\s*)?=(?!=)\s*(.+)$/.exec(line);
    if (as) assigns.set(as[1], as[2]);
    if (!(quietStatement(masked[j]) || plainAssignment(masked[j]))) work = true;
  });
  return { guards, assigns };
}

function rubyStatements(body) {
  const lines = body.split("\n");
  const first = lines.findIndex((l, n) => n > 0 && l.trim());
  if (first < 0) return { guards: [], assigns: new Map() };
  const indent = /^\s*/.exec(lines[first])[0].length;
  const ind = (n) => /^\s*/.exec(lines[n])[0].length;
  const guards = [];
  const assigns = new Map();
  const tops = [];
  for (let j = first; j < lines.length; j++) if (lines[j].trim() && ind(j) === indent && !/^\s*(?:end|else|elsif)\b/.test(lines[j])) tops.push(j);
  let work = false;
  tops.forEach((j, n) => {
    const line = lines[j];
    const isLast = n === tops.length - 1;
    // `halt 401 unless ok`, `return redirect('/login') if session[:user].nil?`
    const mod = /^\s*(.+?)\s+(if|unless)\s+(.+)$/.exec(line);
    if (mod && !/^\s*(?:if|unless)\b/.test(line)) {
      guards.push({ cond: mod[3], branches: [mod[1]], ends: true, last: isLast, positive: mod[2] === "unless", afterWork: work });
      if (!refusesOnly(mod[1], "ruby")) work = true;
      return;
    }
    const iff = /^\s*(if|unless)\s+(.+)$/.exec(line);
    if (iff) {
      const out = [];
      let j2 = j + 1;
      const then = [];
      const other = [];
      let into = then;
      for (; j2 < lines.length; j2++) {
        if (ind(j2) === indent && /^\s*end\b/.test(lines[j2])) break;
        if (ind(j2) === indent && /^\s*else\b/.test(lines[j2])) { into = other; continue; }
        into.push(lines[j2]);
      }
      out.push({ cond: iff[2], branches: [then.join("\n"), ...(other.length ? [other.join("\n")] : [])], ends: true, hasElse: other.length > 0, last: isLast, positive: iff[1] === "unless", afterWork: work });
      guards.push(...out);
      if (!out[0].branches.every((b) => refusesOnly(b, "ruby"))) work = true;
      return;
    }
    const as = /^\s*@?(\w+)\s*=(?!=)\s*(.+)$/.exec(line);
    if (as) assigns.set(as[1], as[2]);
    const m = maskStrings(line, "brace");
    if (!(quietStatement(m) || plainAssignment(m))) work = true;
  });
  return { guards, assigns };
}

// --- evidence -------------------------------------------------------------------------------------

// A secret checked: a constant-time comparison in any language, or a call whose name says it
// verifies a signature, token, key or password. Not `verify(` alone: `verifyCaptcha`, `verifyEmail`
// and `verifyCode` check something other than who is calling.
const SECRET_CHECK =
  /\b(?:compare_digest|timingSafeEqual|ConstantTimeCompare|MessageDigest\s*\.\s*isEqual|secure_compare|FixedTimeEquals|hash_equals|constant_time_compare|safeEqual|password_verify|check_password_hash|checkpw|BCrypt\s*\.\s*Verify|bcrypt\s*\.\s*compare(?:Sync)?)\s*\(|\b\w*(?:[Vv]erify|[Vv]alidate|[Cc]heck|is[A-Z]\w*)\w*(?:Signature|Hmac|HMAC|Token|Webhook|ApiKey|Secret|Password|Jwt|JWT)\w*\s*\(|\b\w*(?:verify|validate|check)_\w*(?:signature|hmac|token|webhook|api_key|secret|password|jwt)\w*\s*\(|\bhmac\s*\.\s*(?:compare_digest|Equal)\s*\(/;

const SIGNED = /\bhmac\s*\.\s*(?:new|New)\s*\(|\bcreateHmac\s*\(|\bHMACSHA\d+\b|\bhash_hmac\s*\(|OpenSSL::HMAC|Mac\s*\.\s*getInstance|signature/i;

// The caller's identity: a session, a principal or signed-in user, a role.
const IDENTITY =
  /\bcurrent_user\b|\brequest\s*\.\s*user\b|\bg\s*\.\s*user\b|\breq\s*\.\s*user\b|\bisAuthenticated\b|\bis_authenticated\b|\bis_anonymous\b|\bUser\s*\.\s*(?:Identity|IsInRole|FindFirst|Claims|HasClaim)\b|\bHttpContext\s*\.\s*User\b|\b_?[cC]urrentContext\s*\.\s*\w+\s*\(|\bGet(?:Proper)?UserId\s*\(\s*User\b|\bGetUserByPrincipalAsync\s*\(\s*User\b|\bAuthorizeAsync\s*\(\s*User\b|\bgetUserPrincipal\s*\(|\bisUserInRole\s*\(|\bSecurityContextHolder\b|\bprincipal\b|\bauth\s*\(\s*\)\s*->\s*(?:check|user|id|guest)\b|\bAuth\s*::\s*(?:check|user|id|guest)\b|\$request\s*->\s*user\s*\(|\$this\s*->\s*getUser\s*\(|\bisGranted\s*\(|\bsessions\s*\.\s*get\b|\bcall\s*\.\s*principal\b|\blogged_in\?|\buser_signed_in\?|\bhas_perms?\s*\(|\bis_staff\b|\bis_superuser\b|\bhasRole\s*\(|\bhasAuthority\s*\(|\bIsInRole\s*\(|\b(?:[Ii]s_?)?(?:[Ss]igned_?[Ii]n|[Ll]ogged_?[Ii]n)\b|\bIsSigned\b/;

// A keyed session read is the caller's identity only when the key names the caller: Flask's
// `session.get("user_id")`, Rails' `session[:user_id]`, `"uid" in session`, `$_SESSION['user']`,
// Express's `req.session.userId`. A session also holds sign-in flow state -- CTFd's OAuth
// `session["nonce"] != state`, its git setup's `session.get("setup_git_device")` -- and a check of
// that says nothing about who is calling. A key that is not a literal says nothing either. Ktor's
// typed `call.sessions.get<T>()` has no key and stays in IDENTITY above.
const SESSION_READ =
  /\bsession\s*(?:\.\s*get\s*\(\s*|\[\s*)(:\w+|"[^"]*"|'[^']*')|("[^"]*"|'[^']*')\s+(?:not\s+)?in\s+session\b|\$_SESSION\s*\[\s*("[^"]*"|'[^']*')|\b(?:req|request)\s*\.\s*session\s*(?:\.\s*get\s*\(\s*("[^"]*"|'[^']*')|\.\s*(\w+)|\[\s*("[^"]*"|'[^']*'))/g;
const CALLER_WORD =
  /^(?:user|users|userid|uid|id|account|member|login|logged|signed|auth|authenticated|principal|identity|role|roles|admin|email|username|owner|customer|staff|superuser|passport)$/;

/** Does a key name the caller? Split on `_`, `-`, `:` and camel case: `_user_id`, `userId`, `:uid`. */
function namesCaller(key) {
  const words = key.replace(/^["':]|["']$/g, "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/);
  return words.some((w) => CALLER_WORD.test(w));
}

function sessionIdentity(text) {
  for (const m of text.matchAll(SESSION_READ)) {
    const key = m.slice(1).find((x) => x !== undefined);
    if (key && namesCaller(key)) return true;
  }
  return false;
}

// A call whose name says it authenticates or authorizes the caller (Gitea's LFS handlers:
// `authenticated := authenticate(ctx, repo, rv.Authorization, ...)`). Weaker than the evidence above --
// it is a name -- so it counts only with a refusal that says the caller is not allowed: 401, 403, or
// the sign-in page. Not 400 or 404.
const AUTH_CALL =
  /\b\w*(?:[Aa]uthenticat|[Aa]uthoriz|[Cc]heckAuth|[Rr]equireAuth|[Hh]asPermission|has_permission|[Cc]an[A-Z]\w*Access)\w*\s*\(/;
const DENIED =
  /\b40[13]\b|Unauthorized|Forbidden|\bForbid\s*\(|\bChallenge\s*\(|AccessDenied|PermissionDenied|NotAuthorized|AuthenticationException|UNAUTHORIZED|FORBIDDEN|HTTP_40[13]|\blog_?in\b|[Ll]ogin\b/;

// Statements that refuse by themselves when the caller is not allowed.
const SELF_REFUSING =
  /^\s*(?:\$this\s*->\s*(?:authorize|denyAccessUnlessGranted)\s*\(|Gate\s*::\s*authorize\s*\(|authorize\s*!?\s*\()/;

// A credential-named value. Bare `key` counts, and keys whose prefix names a credential; a sort,
// cache, partition or idempotency key does not.
const CREDENTIAL_NAME =
  /(?:api|access|webhook|secret|signing|auth|admin|private|shared|internal|service|client|master)_?key|^key$|token|secret|password|passwd|signature|credential|authorization|apikey/i;
// Where a configured secret comes from.
const CONFIGURED = /\b(?:os\s*\.\s*(?:environ|getenv)|getenv|process\s*\.\s*env|env\s*\(|config\s*\(|ENV\s*\[|[Ss]ettings\b|_?[Cc]onfig(?:uration)?\b|[Oo]ptions\b|System\s*\.\s*getenv|Environment\s*\.\s*GetEnvironmentVariable|@Value|app\s*\.\s*config)/;
const CONFIRMATION = /confirm|repeat|retype|again/i;
const LITERAL_OR_EMPTY = /^\s*(?:null|None|nil|undefined|NULL|true|false|True|False|-?\d+|"[^"]*"|'[^']*'|`[^`]*`|\[\s*\]|\{\s*\}|string\s*\.\s*Empty)\s*$/;

function operandNames(s) {
  // Identifiers, and the contents of string literals (a header named in a call).
  return [...s.matchAll(/[A-Za-z_$][\w$]*|"([^"]*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2] ?? m[0]);
}

/** Does the condition compare a credential with something that is not a literal? */
function comparesCredential(cond) {
  const masked = maskStrings(cond, "brace");
  for (const op of masked.matchAll(/===?|!==?|<>|\.equals\s*\(|\bequals\s*\(|\bis\s+not\b|\bnot\s+in\b/g)) {
    // The operands: the text either side of the operator up to the next boolean connective.
    const left = cond.slice(0, op.index).split(/&&|\|\||\band\b|\bor\b|\(\s*$/).pop();
    let right = cond.slice(op.index + op[0].length).split(/&&|\|\||\band\b|\bor\b/)[0];
    if (/equals\s*\($/.test(op[0])) right = right.replace(/\)\s*$/, "");
    if (LITERAL_OR_EMPTY.test(left) || LITERAL_OR_EMPTY.test(right.replace(/\)+\s*$/, ""))) continue;
    const namesL = operandNames(left);
    const namesR = operandNames(right);
    // A password against its confirmation, or two fields of one object: validation, not a caller
    // proving who they are (dvcsharp-api's password reset compared exactly this).
    if ([...namesL, ...namesR].some((n) => CONFIRMATION.test(n))) continue;
    if (namesL[0] && namesL[0] === namesR[0] && namesL.length > 1 && namesR.length > 1) continue;
    const credL = namesL.some((n) => CREDENTIAL_NAME.test(n));
    const credR = namesR.some((n) => CREDENTIAL_NAME.test(n));
    if ((credL && credR) || (credL && CONFIGURED.test(right)) || (credR && CONFIGURED.test(left))) return true;
  }
  return false;
}

// --- refusal --------------------------------------------------------------------------------------

const REFUSAL =
  /\babort\b|\bhalt\b|\braise\b|\bthrow\b|\bdie\s*\(|\b(?:Unauthorized|Forbidden|Forbid|Challenge|BadRequest\w*|NotFound\w*|ValidationProblem)\s*\(|\bnew\s+(?:BadRequest|NotFound|Unauthorized|Forbid|Challenge)\w*\b|\bStatusCode\s*\(\s*(?:\(int\)\s*HttpStatusCode\s*\.\s*\w+|4\d\d)|\bstatus(?:_code|Code)?\s*[=(:]\s*4\d\d\b|\bHttpStatus(?:Code)?\s*\.\s*(?:Unauthorized|Forbidden|BadRequest|NotFound|UNAUTHORIZED|FORBIDDEN|BAD_REQUEST|NOT_FOUND)\b|\bHTTP_40[0134]\b|\bStatus(?:Unauthorized|Forbidden|BadRequest|NotFound)\b|\bredirect\w*\s*\(|\bredirect_to\b|\brespondRedirect\s*\(|\bsendError\s*\(|\.\s*status\s*\(\s*4\d\d|\bsendStatus\s*\(\s*4\d\d|\bhttp\s*\.\s*Error\s*\(|,\s*4\d\d\s*\)?\s*;?\s*$|\b(?:return|respond)\b[^\n]*\b40[0134]\b/m;

/** The branch's last statement ends the request. */
function endsRequest(branch) {
  const t = branch.replace(/^\s*\{|\}\s*$/g, "").trim();
  const stmts = t.split(/;|\n/).map((s) => s.trim()).filter(Boolean);
  const last = stmts[stmts.length - 1] || "";
  return /^(?:return\b|throw\b|raise\b|abort\b|halt\b|die\b|exit\b|abort\s*\(|halt\s*\()/.test(last) || /\breturn@\w+/.test(t) || /^(?:abort|halt)\b/.test(last);
}

// --- the judgement --------------------------------------------------------------------------------

// --- the condition's shape -------------------------------------------------------------------------
//
// A refusal guarded by `!valid || other` happens whenever the check fails; one guarded by
// `!valid && other` only when something else holds too. Jellyfin's splashscreen refuses when the
// feature is off AND the caller is not an admin, so with it on the route is public. Which connective
// covers every failure depends on the side that refuses: the `if` side refuses when the condition
// holds (an OR of failures covers them all), the `else` side when it does not (an AND of passes).

function stripParens(s) {
  let t = s.trim();
  for (;;) {
    if (!t.startsWith("(")) return t;
    const close = closeOf(maskStrings(t, "brace"), 0);
    if (close !== t.length - 1) return t;
    t = t.slice(1, -1).trim();
  }
}

/** Split a condition at its top-level connectives: { ops: Set("and"|"or"), terms }. */
function connectives(cond) {
  const m = maskStrings(cond, "brace");
  const ops = new Set();
  const terms = [];
  let depth = 0;
  let start = 0;
  for (let k = 0; k < m.length; k++) {
    const ch = m[k];
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    if (depth !== 0) continue;
    const two = m.slice(k, k + 2);
    const word = /^(?:and|or)\b/.exec(m.slice(k, k + 4));
    if ((two === "&&" || two === "||") || (word && /\s/.test(m[k - 1] || " "))) {
      ops.add(two === "&&" || word?.[0] === "and" ? "and" : "or");
      terms.push(cond.slice(start, k));
      k += two === "&&" || two === "||" ? 1 : word[0].length - 1;
      start = k + 1;
    }
  }
  terms.push(cond.slice(start));
  return { ops, terms };
}

/**
 * Does a refusal on this condition cover every caller the evidence rejects? `refuseWhen` is "true"
 * when the refusing side runs on the condition holding, "false" when it runs on it failing.
 */
function covers(cond, refuseWhen, assigns, depth = 0) {
  if (depth > 6) return null;
  let t = stripParens(cond);
  const neg = /^(?:!|not\s+)\s*(\([\s\S]*\))$/.exec(t);
  if (neg && closeOf(maskStrings(neg[1], "brace"), 0) === neg[1].length - 1) {
    return covers(neg[1], refuseWhen === "true" ? "false" : "true", assigns, depth + 1);
  }
  const { ops, terms } = connectives(t);
  if (ops.size === 0) {
    const kind = evidenceOf(t, assigns);
    // The refusing side must run for the caller who fails the check, not the one who passes it.
    return kind && failing(t, assigns) === (refuseWhen === "true") ? kind : null;
  }
  if (ops.size > 1) return null;
  const op = [...ops][0];
  if ((refuseWhen === "true") !== (op === "or")) return null;
  for (const term of terms) {
    const kind = covers(term, refuseWhen, assigns, depth + 1);
    if (kind) return kind;
  }
  return null;
}

// --- the condition's direction ----------------------------------------------------------------------
//
// Is a term true when the caller fails the check? `!valid`, `user == null`, `token != expected`,
// `current_user.is_anonymous` are; `valid`, `user != null`, `token == expected`,
// `current_user.is_authenticated` are not. Read from the term's negations, its comparison, and words
// that name an anonymous caller; a name assigned earlier is read through its assignment.

const ANONYMOUS = /\bis_?[Aa]nonymous\b|\bIsAnonymous\b|\bisGuest\b|\bis_guest\b|\bguest\s*\(|\bguest\?/;
const NULLISH = /^\s*(?:null|None|nil|undefined|NULL|false|False|FALSE)\s*$/;
const TRUE = /^\s*(?:true|True|TRUE)\s*$/;
// Checks for a value that is not there: `.nil?`, `string.IsNullOrEmpty(key)`, PHP's `empty($user)`.
const ABSENT_CHECK = /\.\s*(?:nil|blank|empty)\?|\.\s*(?:isEmpty|isBlank|IsEmpty)\b|\bIsNullOr(?:Empty|WhiteSpace)\s*\(|\bis_?[Nn]ull\s*\(|^\s*empty\s*\(/;

/** The term's top-level comparison: { equal, left, right }, or null for none. */
function comparison(t) {
  const m = maskStrings(t, "brace");
  let depth = 0;
  for (let k = 0; k < m.length; k++) {
    const ch = m[k];
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    if (depth !== 0) continue;
    const rest = m.slice(k);
    const op =
      /^(?:===|!==|==|!=|<>)/.exec(rest) ||
      (/\s/.test(m[k - 1] || "") && /^(?:is\s+not|not\s+in|is|in)(?=\s)/.exec(rest)) ||
      /^\.\s*equals\s*\(/.exec(rest);
    if (!op) continue;
    const equal = !/^(?:!|<>|is\s+not|not\s+in)/.test(op[0]);
    let right = t.slice(k + op[0].length);
    if (/equals/.test(op[0])) right = right.replace(/\)\s*$/, "");
    return { equal, left: t.slice(0, k), right };
  }
  return null;
}

function failing(term, assigns, depth = 0) {
  let t = stripParens(term);
  let neg = false;
  for (let m; (m = /^(?:!|not\s+)\s*/.exec(t)); ) {
    neg = !neg;
    t = stripParens(t.slice(m[0].length));
  }
  t = t.replace(/^\s*await\s+/, "");
  let fails;
  const cmp = comparison(t);
  if (cmp) {
    const lit = NULLISH.test(cmp.right) || NULLISH.test(cmp.left) ? "absent" : TRUE.test(cmp.right) || TRUE.test(cmp.left) ? "present" : "value";
    // `x == null` fails; `x == true` and `token == expected` pass.
    fails = lit === "absent" ? cmp.equal : !cmp.equal;
  } else if (/^[A-Za-z_$][\w$]*$/.test(t.trim()) && assigns.has(t.trim()) && depth < 4) {
    const via = failing(assigns.get(t.trim()), assigns, depth + 1);
    if (via === null) return null;
    fails = via;
  } else {
    fails = ANONYMOUS.test(t) || ABSENT_CHECK.test(t);
  }
  return fails !== neg;
}

function evidenceOf(cond, assigns) {
  // A name in the condition, assigned earlier at the top level, is read through its assignment, and
  // the names in that through theirs, as far as failing() follows them. One step stopped at
  // fastify/demo's `user = findByEmail(email)`, where `email` comes from the session user, though
  // the same check written in one line was credited. A name after `.`, `->` or `::` is a property
  // or a method, not the local of that name: ktor-samples' public profile page reads
  // `dao.user(it.user)`, and taking `.user` for its session `user` credited the page with a check.
  let expanded = cond;
  const seen = new Set();
  let frontier = cond;
  for (let depth = 0; depth < 4 && frontier; depth++) {
    let next = "";
    for (const name of new Set(frontier.match(/(?<![\w$.]|->|::)[A-Za-z_$][\w$]*/g) || [])) {
      if (seen.has(name) || !assigns.has(name)) continue;
      seen.add(name);
      next += `\n${assigns.get(name)}`;
    }
    expanded += next;
    frontier = next;
  }
  // A signature when an HMAC is computed or a signature named; otherwise a secret compared.
  if (SECRET_CHECK.test(expanded)) return SIGNED.test(expanded) ? "signature" : "secret";
  if (comparesCredential(expanded)) return "credential";
  if (IDENTITY.test(expanded) || sessionIdentity(expanded)) return "identity";
  if (AUTH_CALL.test(expanded)) return "authcall";
  return null;
}

const REASONS = {
  signature: "a request signature verified in the handler",
  secret: "a secret checked in the handler",
  credential: "a credential checked in the handler",
  identity: "the caller checked in the handler",
  authcall: "the caller checked in the handler",
};

/**
 * What protects a route from inside its handler, or null. `bodies` are the handler's source with
 * comments removed (one route may run several, as Express's middleware chain does); `family` is
 * "python", "ruby" or "brace".
 */
export function handlerGuard(bodies, family) {
  for (const body of bodies) {
    if (!body) continue;
    const { guards, assigns } = family === "python" ? pythonStatements(body) : family === "ruby" ? rubyStatements(body) : braceStatements(body);
    for (const g of guards) {
      if (g.afterWork) continue;
      if (g.selfRefusing) return REASONS.identity;
      // A branch that refuses must end the request, or be one side of an if/else that ends the
      // handler -- the other side doing the work. Its condition must then refuse every failure.
      for (const [i, b] of g.branches.entries()) {
        if (!REFUSAL.test(b) || !(endsRequest(b) || (g.hasElse && g.last) || g.self)) continue;
        const onTrue = (i === 0) !== Boolean(g.positive);
        const kind = covers(g.cond, onTrue ? "true" : "false", assigns);
        if (kind === "authcall" && !DENIED.test(b)) continue;
        if (kind) return REASONS[kind];
      }
    }
  }
  return null;
}

export const _internals = { braceStatements, pythonStatements, rubyStatements, comparesCredential, evidenceOf };
