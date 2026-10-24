// Injection through a project helper: the one-hop sinks of docs/candidate-rules.md #22.
//
// Open-source Semgrep's taint analysis stays inside one function. WebGoat's SQL lessons show what that
// misses: the handler takes `@RequestParam String account` and calls `injectableQuery(account)` in the
// same class, and only the helper builds the query and runs it. The request never meets the sink in
// one function, so the taint rules are silent, and the pattern advisories that see the construction
// cannot say where its input came from.
//
// So the project's own helpers are summarised first, then called sinks:
//
//   1. Summary rules. Each blocking taint rule is copied with its sources replaced by the parameters
//      of whatever function encloses them. A result names a function and a parameter that reaches a
//      shell, SQL, an evaluator, an outbound host or a file path. The rule's sanitizers still apply, so
//      a helper that validates its argument first is not a sink.
//   2. Helper-call rules. Each summary becomes a sink: a call to that function, with the argument in
//      that position. The rule's own request sources stay, so a finding is still request data reaching
//      something that injects it -- one call further away.
//   3. Repeated, a call further each time, to a small bound: WebGoat needs one hop, helpers of helpers
//      need more, and every pass costs a Semgrep run. Passes after the first scan only the files that
//      mention a summarised helper by name.
//
// Rule 3 of authentication.mjs holds here too: a false positive is worse than a miss. Resolution is by
// name, which is where false positives would come from, so a call only BLOCKS when the name cannot
// mean something else:
//   - called bare or through self/this in the file that defines it, every definition of that name in
//     the file being a summarised sink -- or called bare anywhere when the project defines the name
//     once;
//   - called through the class or module that defines it (`User.authenticate(...)`), under the same
//     condition on that file's definitions.
// A call through any other receiver (`$obj.query(x)`) could be anyone's `query`, and is an advisory.

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";
import YAML from "yaml";

const RULES_DIR = fileURLToPath(new URL("./sast-rules/", import.meta.url));

export const MAX_HOPS = 3;

// What a function definition looks like, per Semgrep language, with $F its name and $P a parameter.
// Each was checked against real Semgrep before it was written down.
const DEFINITIONS = {
  python: ["def $F(..., $P, ...):\n  ...", "async def $F(..., $P, ...):\n  ..."],
  javascript: ["function $F(..., $P, ...) { ... }", "class $C { ... $F(..., $P, ...) { ... } ... }", "$F = (..., $P, ...) => $BODY"],
  typescript: ["function $F(..., $P, ...) { ... }", "class $C { ... $F(..., $P, ...) { ... } ... }", "$F = (..., $P, ...) => $BODY"],
  java: ["$RET $F(..., $T $P, ...) { ... }"],
  csharp: ["$RET $F(..., $T $P, ...) { ... }"],
  kotlin: ["fun $F(..., $P: $T, ...) { ... }", "fun $F(..., $P: $T, ...) = $E"],
  go: ["func $F(..., $P $T, ...) { ... }", "func ($R $RT) $F(..., $P $T, ...) { ... }"],
  ruby: ["def $F(..., $P, ...)\n  ...\nend", "def self.$F(..., $P, ...)\n  ...\nend"],
  php: ["function $F(..., $P, ...) { ... }"],
  rust: ["fn $F(..., $P: $T, ...) { ... }"],
  c: ["$RET $F(..., $T $P, ...) { ... }"],
  cpp: ["$RET $F(..., $T $P, ...) { ... }"],
};

const LANG_OF_EXT = {
  ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".cs": "csharp", ".kt": "kotlin", ".go": "go",
  ".rb": "ruby", ".php": "php", ".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
  ".hpp": "cpp", ".hh": "cpp",
};

// A separator Semgrep passes through a message untouched and no identifier contains.
const SEP = "~~";

export function loadTaintRules() {
  const out = [];
  for (const file of ["python", "javascript", "java", "csharp", "kotlin", "go", "ruby", "php", "rust", "c"]) {
    const doc = YAML.parse(readFileSync(path.join(RULES_DIR, `${file}.yaml`), "utf8"));
    for (const r of doc.rules) if (r.mode === "taint" && r.severity === "ERROR") out.push(r);
  }
  return out;
}

const paramSources = (languages) => [
  {
    "pattern-either": languages.flatMap((l) => DEFINITIONS[l] || []).map((def) => ({
      patterns: [{ "pattern-inside": def }, { pattern: "$P" }],
    })),
  },
];

function summaryRule(id, base, sinks) {
  return {
    id,
    mode: "taint",
    languages: base.languages,
    severity: "INFO",
    message: `summary${SEP}$F${SEP}$P`,
    metadata: { category: base.metadata?.category },
    "pattern-sources": paramSources(base.languages),
    "pattern-sinks": sinks,
    ...(base["pattern-sanitizers"] ? { "pattern-sanitizers": base["pattern-sanitizers"] } : {}),
  };
}

/** Summary rules for the first pass: each blocking taint rule with a function's parameters as sources. */
export function summaryRules(taintRules) {
  return taintRules.filter((r) => r.languages.some((l) => DEFINITIONS[l])).map((r) => summaryRule(`${r.id}--summary`, r, r["pattern-sinks"]));
}

export function writeRules(rules) {
  const dir = mkdtempSync(path.join(tmpdir(), "sast-hops-"));
  const file = path.join(dir, "rules.yaml");
  writeFileSync(file, YAML.stringify({ rules }, { lineWidth: 0 }));
  return { file, done: () => rmSync(dir, { recursive: true, force: true }) };
}

// ---------------------------------------------------------------------------------------------
// Where a summarised function is defined, and which argument position reaches the sink.
// ---------------------------------------------------------------------------------------------

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function paramList(text, open) {
  let depth = 0;
  for (let k = open; k < text.length; k++) {
    const ch = text[k];
    if (ch === "(" || ch === "[" || ch === "{" || ch === "<") depth++;
    else if (ch === ")" || ch === "]" || ch === "}" || ch === ">") {
      if (ch === ">" && text[k - 1] === "-") continue; // `->` is not a bracket
      if (--depth === 0) return { inner: text.slice(open + 1, k), close: k };
    }
  }
  return null;
}

function splitParams(inner) {
  const out = [];
  let depth = 0;
  let start = 0;
  for (let k = 0; k < inner.length; k++) {
    const ch = inner[k];
    if ("([{<".includes(ch)) depth++;
    else if (")]}>".includes(ch) && !(ch === ">" && inner[k - 1] === "-")) depth--;
    else if (ch === "," && depth === 0) {
      out.push(inner.slice(start, k));
      start = k + 1;
    }
  }
  if (inner.slice(start).trim()) out.push(inner.slice(start));
  return out.map((s) => s.trim());
}

const DEF_KEYWORD = /\b(?:def|function|fun|func|fn)\s+(?:self\.)?(?:\([^)]*\)\s*)?[\w$.]*\s*$/;
const BODY_AFTER = /^\s*(?:throws\s+[\w.,\s]+)?\s*(?::\s*[\w.<>?\[\], |&*]+)?\s*(?:->\s*[\w.<>?\[\], &*]+)?\s*(?:where\b[^{]*)?(?:\{|=>|=(?!=)|:)/;
const SELF_PARAM = /^(?:self|cls|&\s*self|&\s*mut\s+self|mut\s+self)\b/;

/** Every definition of `name` in `text`: offset, line, its parameters, and the class around it. */
export function definitionsIn(text, name) {
  const out = [];
  const re = new RegExp(`(?<![\\w$])${esc(name)}\\s*(?:<[^<>()]*>)?\\s*\\(`, "g");
  let m;
  while ((m = re.exec(text))) {
    const open = m.index + m[0].length - 1;
    const list = paramList(text, open);
    if (!list) continue;
    const lineStart = text.lastIndexOf("\n", m.index) + 1;
    const before = text.slice(lineStart, m.index);
    const after = text.slice(list.close + 1, list.close + 200);
    if (!DEF_KEYWORD.test(before) && !BODY_AFTER.test(after)) continue;
    // A call followed by a block (`if (check(x)) {`) is not a definition.
    if (!DEF_KEYWORD.test(before) && /\b(?:if|while|for|switch|catch|return|new|else)\b|[=(,!&|]\s*$/.test(before)) continue;
    const params = splitParams(list.inner);
    const cls = [...text.slice(0, m.index).matchAll(/\b(?:class|object|module|struct|impl)\s+([A-Z]\w*)/g)].pop()?.[1] || null;
    out.push({ offset: m.index, line: text.slice(0, m.index).split("\n").length, params, cls, classMethod: /\bself\.\s*$/.test(before) });
  }
  return out;
}

function locate(text, name, param, sinkOffset) {
  const defs = definitionsIn(text.slice(0, sinkOffset), name);
  const word = new RegExp(`(?<![\\w$])${esc(param)}(?![\\w$])`);
  for (let i = defs.length - 1; i >= 0; i--) {
    const d = defs[i];
    const at = d.params.findIndex((p) => word.test(p));
    if (at < 0) continue;
    const shift = SELF_PARAM.test(d.params[0] || "") ? 1 : 0;
    if (at < shift) return null;
    return { ...d, index: at, shift };
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Calls to a summarised helper, as Semgrep patterns, by how surely they reach that helper.
// ---------------------------------------------------------------------------------------------

const args = (n) => [...Array.from({ length: n }, (_, i) => `$A${i}`), "$X", "..."].join(", ");

function callForms(lang, s) {
  const F = s.name;
  const own = args(s.index - s.shift); // as called with a receiver: self is not an argument
  const all = args(s.index);
  const mod = path.basename(s.file).replace(/\.[^.]+$/, "");
  const bare = [];
  const qualified = [];
  const receiver = [];
  switch (lang) {
    case "python":
      if (!s.shift) bare.push(`${F}(${all})`);
      else bare.push(`self.${F}(${own})`, `cls.${F}(${own})`);
      if (s.shift && s.cls) qualified.push(`${s.cls}.${F}(${own})`);
      if (!s.shift && /^[A-Za-z_]\w*$/.test(mod)) qualified.push(`${mod}.${F}(${all})`);
      receiver.push(`$O.${F}(${s.shift ? own : all})`);
      break;
    case "java":
    case "csharp":
    case "kotlin":
      bare.push(`${F}(${all})`, `this.${F}(${all})`);
      if (s.cls) qualified.push(`${s.cls}.${F}(${all})`);
      receiver.push(`$O.${F}(${all})`);
      break;
    case "javascript":
    case "typescript":
      bare.push(`${F}(${all})`, `this.${F}(${all})`);
      receiver.push(`$O.${F}(${all})`);
      break;
    case "go":
      bare.push(`${F}(${all})`);
      receiver.push(`$O.${F}(${all})`);
      break;
    case "ruby":
      bare.push(`${F}(${all})`, `self.${F}(${all})`);
      if (s.cls) qualified.push(`${s.cls}.${F}(${all})`);
      receiver.push(`$O.${F}(${all})`);
      break;
    case "php":
      bare.push(`${F}(${all})`, `$this->${F}(${all})`, `self::${F}(${all})`, `static::${F}(${all})`);
      if (s.cls) qualified.push(`${s.cls}::${F}(${all})`);
      receiver.push(`$O->${F}(${all})`);
      break;
    case "rust":
      if (!s.shift) bare.push(`${F}(${all})`);
      else bare.push(`self.${F}(${own})`);
      if (s.cls) qualified.push(`${s.cls}::${F}(${all})`, `Self::${F}(${all})`);
      receiver.push(`$O.${F}(${s.shift ? own : all})`);
      break;
    case "c":
    case "cpp":
      bare.push(`${F}(${all})`);
      break;
  }
  return { bare, qualified, receiver };
}

/** What a qualified call names before the dot: the defining class, or for a Python function its module. */
export function qualifierOf(s) {
  if (s.lang === "python" && !s.shift) return path.basename(s.file).replace(/\.[^.]+$/, "");
  return s.cls;
}

const sinkOf = (patterns) => [{ patterns: [{ "pattern-either": patterns.map((p) => ({ pattern: p })) }, { "focus-metavariable": "$X" }] }];

/**
 * The rules for one pass after the first: for every new summary, request data reaching a call to it
 * (a finding), and a function's parameter reaching a call to it (the next pass's summary).
 */
export function hopRules(summaries, taintRulesById, hop) {
  const rules = [];
  const meta = new Map();
  let n = 0;
  for (const s of summaries) {
    const base = taintRulesById.get(s.base);
    if (!base) continue;
    const forms = callForms(s.lang, s);
    for (const [form, patterns] of Object.entries(forms)) {
      if (!patterns.length) continue;
      const id = `hop${hop}-${n++}`;
      meta.set(id, { summary: s, form });
      rules.push({
        id,
        mode: "taint",
        languages: base.languages,
        severity: form === "receiver" ? "WARNING" : "ERROR",
        message: "helper call",
        metadata: { category: base.metadata?.category },
        "pattern-sources": base["pattern-sources"],
        "pattern-sinks": sinkOf(patterns),
        ...(base["pattern-sanitizers"] ? { "pattern-sanitizers": base["pattern-sanitizers"] } : {}),
      });
      // Helpers of helpers follow only calls that resolve: a summary built on `$obj.query(x)` would
      // make every caller of every `query` a sink.
      if (form !== "receiver") {
        const sid = `hop${hop}-${n++}--summary`;
        meta.set(sid, { summary: s, form });
        rules.push(summaryRule(sid, base, sinkOf(patterns)));
      }
    }
  }
  return { rules, meta };
}

// ---------------------------------------------------------------------------------------------
// Reading results
// ---------------------------------------------------------------------------------------------

/** A summary from a summary rule's result, located in its file, or null. */
export function toSummary(result, base, via, readText) {
  const [, name0, param] = String(result.extra?.message || "").split(SEP);
  if (!name0 || !param) return null;
  const name = name0.split(".").pop();
  if (!/^[A-Za-z_]\w*$/.test(name)) return null;
  const lang = LANG_OF_EXT[path.extname(result.path)];
  if (!lang) return null;
  const text = readText(result.path);
  if (text == null) return null;
  const def = locate(text, name, param, result.start.offset);
  if (!def) return null;
  return {
    key: `${base}|${result.path}|${def.offset}|${def.index}`,
    base,
    category: result.extra?.metadata?.category,
    lang,
    name,
    param,
    file: result.path,
    defLine: def.line,
    defOffset: def.offset,
    index: def.index,
    shift: def.shift,
    cls: def.cls,
    sinkAt: `${result.path}:${result.start.line}`,
    via, // the summary this one reaches through, for helpers of helpers
  };
}

export { LANG_OF_EXT, SEP };
