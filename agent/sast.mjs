// Static analysis for injection: request data reaching a shell, a SQL statement or an evaluator.
//
// An outside review found nothing here looked for it, and a probe confirmed it: a Flask service with
// a command injection and a SQL injection was blocked only because a route lacked authentication.
// ruff runs with `--select F` -- undefined names -- and no security rules.
//
// Semgrep, with this project's own rules in agent/sast-rules/, not the registry's: the registry rules
// are under a licence that restricts redistribution, and fetching them at run time would make the gate
// depend on a network it often does not have. The rules are few and specific on purpose:
//
// - ERROR rules are taint rules and BLOCK. They fire only when data from an HTTP request reaches the
//   sink inside one function. Measured before anything was allowed to block: zero hits across 9,940
//   files of real code -- every deliverable and control repository on the development machine, 4,593
//   files of installed Python packages, and 5,066 of installed JavaScript including Express itself.
// - WARNING rules are pattern rules and are ADVISORY: a SQL statement built by formatting, a shell
//   command built from a non-literal. They see the construction without knowing where its input came
//   from, which is also how they catch what the taint rules cannot.
// - Open-source Semgrep's taint analysis stays inside one function. Request data passed to a project
//   helper that injects it is followed by sast-hops.mjs: the helpers are summarised in the first pass,
//   and later passes treat calls to them as sinks, blocking only where the call cannot mean another
//   function (see that file, and docs/candidate-rules.md #22).
//
// Two ways a project could hide code from the scan, both closed: files are passed to semgrep
// explicitly, from the same walk every other validator uses, because given a directory it obeys the
// project's .semgrepignore and a probe with `src/` in one scanned nothing; and `--disable-nosem`,
// because an inline `# nosemgrep` is a suppression the code's author writes -- the .gitleaksignore
// defect in another form.
import { readdirSync, readFileSync, statSync } from "fs";
import { spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

import { SKIP_DIRS } from "./skip-dirs.mjs";
import { isDeclaredFixture } from "./fixture-markers.mjs";
import { taskWantsErrorDistinction } from "./code-quality.mjs";
import { MAX_HOPS, LANG_OF_EXT, loadTaintRules, summaryRules, hopRules, toSummary, definitionsIn, qualifierOf, writeRules } from "./sast-hops.mjs";

const RULES = fileURLToPath(new URL("./sast-rules/", import.meta.url));
export const SAST_EXT = new Set([".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".cs", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".php", ".kt"]);
const LANGUAGE = {
  ".py": "Python", ".go": "Go", ".java": "Java", ".rb": "Ruby", ".cs": "C#", ".rs": "Rust",
  ".c": "C/C++", ".h": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".cxx": "C/C++", ".hpp": "C/C++", ".hh": "C/C++",
  ".php": "PHP", ".kt": "Kotlin",
};
const MAX_FILE_BYTES = 1024 * 1024;
const CHUNK = 400;
const TIMEOUT_MS = 300_000;

export function sastTargets(projectDir) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !isDeclaredFixture(full)) walk(full);
      } else if (SAST_EXT.has(path.extname(e.name))) {
        try {
          if (statSync(full).size <= MAX_FILE_BYTES) out.push(full);
        } catch {
          /* vanished mid-walk */
        }
      }
    }
  };
  walk(projectDir);
  return out.sort();
}

function semgrepEnv() {
  return { ...process.env, SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0" };
}

function run(files, configs = [RULES]) {
  const r = spawnSync(
    "semgrep",
    ["scan", ...configs.flatMap((c) => ["--config", c]), "--json", "--quiet", "--metrics=off", "--disable-version-check",
     "--disable-nosem", "--no-git-ignore", "--timeout", "30", "--max-target-bytes", String(MAX_FILE_BYTES), ...files],
    // SIGKILL, not the default SIGTERM: spawnSync waits for the child to exit after signalling it, and
    // a wedged child that ignores SIGTERM made a timeout bound nothing once already (#5).
    { encoding: "utf8", env: semgrepEnv(), timeout: TIMEOUT_MS, killSignal: "SIGKILL", maxBuffer: 64 * 1024 * 1024 }
  );
  // Not installed is found by running the scan, not by a `semgrep --version` first: each probe was a
  // full Python start-up, about 2.3s of CPU, and in the unit suite 51 of them were 117s of roughly 412s.
  // The scan's own JSON carries the version.
  if (r.error?.code === "ENOENT") return { missing: true };
  if (r.error || r.signal) {
    return { error: r.error?.code === "ETIMEDOUT" || r.signal ? `semgrep did not finish within ${TIMEOUT_MS / 1000}s` : `semgrep could not be run: ${r.error.message}` };
  }
  let doc;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    return { error: `semgrep exited ${r.status} without a readable result. ${(r.stderr || "").trim().slice(0, 300)}` };
  }
  // A fatal error (bad rules, a crash) reports results it never produced. Per-file problems are
  // level "warn" and are reported separately below.
  const fatal = (doc.errors || []).filter((e) => e.level === "error");
  if (r.status !== 0 && fatal.length) return { error: `semgrep failed: ${fatal[0].message?.slice(0, 300)}` };
  return { doc };
}

const VIA = "\u0000via";
const CATEGORY_ORDER = ["hardcoded credential", "command injection", "SQL injection", "code injection", "SSRF", "path traversal", "format string", "buffer overflow", "XXE", "error distinction", "error detail"];
const REMEDY = {
  "hardcoded credential":
    "Splitting or encoding a credential does not take it out of the source. Read it from the environment " +
    "or a secret manager at run time, and rotate it: it is in the repository's history now.",
  "command injection": "Pass arguments as a list to a call that does not start a shell, and never build a command string from input.",
  "SQL injection": "Use a parameterised query: placeholders in the statement, values passed separately.",
  "code injection": "Parse the input as data — JSON, a number, an allow-list — rather than evaluating it.",
  SSRF:
    "Fix the scheme and host in the code and let request data choose only the path, or check the host " +
    "against an allow-list before connecting -- otherwise the server can be pointed at internal services " +
    "and cloud metadata endpoints.",
  "path traversal":
    "Take only the file name (basename) or look the file up by an ID; joining a request value onto a " +
    "directory does not stop `../`.",
  "format string":
    'Pass the data as an argument to a literal format -- printf("%s", data) -- never as the format itself: ' +
    "%n writes to memory and %x reads it.",
  "buffer overflow": "Use fgets with the buffer's size; gets cannot be told how large the buffer is.",
  "error distinction":
    "A malformed request comes back as 5xx instead of 4xx: the caller is told the service is broken when the " +
    "request was, and a webhook sender seeing 5xx retries a request that can never succeed. Add `except " +
    "HTTPException: raise` before the broad handler, and catch only what you can handle.",
};

// Injection blocks whenever it is found. Error distinction blocks only when the task asks for it --
// the same gate the regex this replaced was under (candidate-rules #3) -- and is otherwise an
// advisory. Error detail is always an advisory: exception text in a response is a disclosure, but a
// small one, and not what the task is judged on.
const ADVISORY_WHY = {
  XXE: " — the parser configuration is the risk, whatever input it is given",
  "error distinction": " — the task does not ask for client errors to be kept distinct",
  "error detail": " — a disclosure rather than a defect, but the caller sees internal detail",
  "SQL injection": " — where the value comes from is not known here",
  "command injection": " — where the value comes from is not known here",
};

function blocks(category, taskText) {
  if (category === "error distinction") return taskWantsErrorDistinction(taskText);
  if (category === "error detail") return false;
  return true;
}

/**
 * Run the rules and classify each result as the gate does: blocking or advisory, with an advisory at
 * a line that already blocks for the same category dropped. sastFailures turns this into messages;
 * the calibration corpus (calibration/run.mjs) counts it per rule, so both see one classification.
 *
 * @returns {{ files: number, version: string|null, couldNotRun?: string[],
 *             findings: { rule: string, category: string, blocking: boolean, at: string }[], unparsed: string[] }}
 */
export function sastScan(projectDir, { taskText = "" } = {}) {
  const files = sastTargets(projectDir);
  if (files.length === 0) return { files: 0, version: null, findings: [], unparsed: [] };

  const notInstalled = () => {
    const langs = [...new Set(files.map((f) => LANGUAGE[path.extname(f)] || "JavaScript/TypeScript"))].join(", ");
    return {
      files: files.length,
      version: null,
      findings: [],
      unparsed: [],
      couldNotRun: [
        `semgrep is not installed, so ${files.length} ${langs} file(s) were not checked for injection. ` +
          `Install it — \`brew install semgrep\` or \`pipx install semgrep\` — and re-run.`,
      ],
    };
  };

  let version = null;
  const results = [];
  const unparsed = new Set();
  // The first pass carries the helper summary rules beside the project's own (#22, sast-hops.mjs).
  const taint = loadTaintRules();
  const summaryConfig = writeRules(summaryRules(taint));
  const summaryResults = [];
  try {
    for (let i = 0; i < files.length; i += CHUNK) {
      const r = run(files.slice(i, i + CHUNK), [RULES, summaryConfig.file]);
      if (r.missing) return notInstalled();
      if (r.error) return { files: files.length, version, findings: [], unparsed: [], couldNotRun: [`${r.error}; nothing was checked for injection.`] };
      version ||= r.doc.version || null;
      for (const x of r.doc.results || []) (String(x.check_id).endsWith("--summary") ? summaryResults : results).push(x);
      for (const e of r.doc.errors || []) if (e.path) unparsed.add(path.relative(projectDir, e.path));
    }
  } finally {
    summaryConfig.done();
  }
  const hops = helperHops(projectDir, files, taint, summaryResults);
  if (hops.error) return { files: files.length, version, findings: [], unparsed: [], couldNotRun: [`${hops.error}; injection through project helpers was not checked.`] };

  const at = (x) => `${path.relative(projectDir, x.path)}:${x.start.line}`;
  // An advisory at a line that already blocks for the same category says nothing the finding does not.
  // Pattern rules (WARNING) see a construction; for injection only the taint rules (ERROR) block.
  const isBlocking = (x) => {
    const category = x.extra?.metadata?.category || "injection";
    if (category === "error distinction" || category === "error detail") return blocks(category, taskText);
    return x.extra?.severity === "ERROR";
  };
  const blocked = new Set(results.filter(isBlocking).map((x) => `${x.extra?.metadata?.category}@${at(x)}`));
  // Findings through a helper: one at a line that already blocks for the same category says nothing
  // new and is dropped; one that blocks silences advisories at its line, as a taint finding does.
  const directlyBlocked = new Set(blocked);
  const viaHelper = hops.findings.filter((h) => !(h.blocking && directlyBlocked.has(`${h.category}@${h.at}`)));
  for (const h of viaHelper) if (h.blocking) blocked.add(`${h.category}@${h.at}`);
  const findings = [];
  for (const x of results) {
    const blocking = isBlocking(x);
    if (!blocking && blocked.has(`${x.extra?.metadata?.category}@${at(x)}`)) continue;
    findings.push({
      rule: String(x.check_id).split(".").pop(),
      category: x.extra?.metadata?.category || "injection",
      blocking,
      message: x.extra?.message,
      at: at(x),
    });
  }
  const seen = new Set();
  for (const h of viaHelper) {
    const key = `${h.category}@${h.at}`;
    if (!h.blocking && blocked.has(key)) continue;
    if (seen.has(`${key}@${h.blocking}`)) continue;
    seen.add(`${key}@${h.blocking}`);
    findings.push(h);
  }
  return { files: files.length, version, findings, unparsed: [...unparsed] };
}

/**
 * Passes after the first: calls to the helpers the summary rules found, a call further each pass.
 * Returns { findings } in the same shape as sastScan's, or { error } when a pass could not run --
 * which is reported as could-not-run, never as a pass, like the first.
 */
function helperHops(projectDir, files, taint, summaryResults) {
  const byId = new Map(taint.map((r) => [r.id, r]));
  const texts = new Map();
  const readText = (f) => {
    if (!texts.has(f)) {
      try {
        texts.set(f, readFileSync(f, "utf8"));
      } catch {
        texts.set(f, null);
      }
    }
    return texts.get(f);
  };
  const rel = (f) => path.relative(projectDir, f);
  const summaries = new Map();
  let fresh = [];
  const add = (s) => {
    if (s && !summaries.has(s.key)) {
      summaries.set(s.key, s);
      fresh.push(s);
    }
  };
  for (const x of summaryResults) add(toSummary(x, String(x.check_id).split(".").pop().replace(/--summary$/, ""), null, readText));

  // Which definitions of a name are summarised sinks, for deciding whether a call resolves.
  const summarisedAt = (s) =>
    new Set([...summaries.values()].filter((o) => o.base === s.base && o.name === s.name && o.index === s.index).map((o) => `${o.file}|${o.defOffset}`));
  const defsInProject = new Map();
  const projectDefs = (s) => {
    const k = `${s.lang}|${s.name}`;
    if (!defsInProject.has(k)) {
      const langs = new Set(byId.get(s.base).languages);
      const defs = [];
      for (const f of files) {
        if (!langs.has(LANG_OF_EXT[path.extname(f)])) continue;
        const text = readText(f);
        if (text && text.includes(s.name)) for (const d of definitionsIn(text, s.name)) defs.push(`${f}|${d.offset}`);
      }
      defsInProject.set(k, defs);
    }
    return defsInProject.get(k);
  };
  const resolves = (s, form, callFile) => {
    if (form === "receiver") return false;
    // SSRF through a helper is an advisory, whatever the call. SSRF is about who controls the host,
    // and a helper that takes a whole URL cannot tell whether its caller fixed one. Measured on the
    // calibration set: SSRF was the only category to block falsely on clean code -- three on Lemmy,
    // a URL built from configuration with request data only in its query, and one fetched from a
    // database row the request picked -- and most of the advisories, against one real finding,
    // WebGoat's SSRF lesson, which stays reported as an advisory.
    if (s.category === "SSRF") return false;
    const done = summarisedAt(s);
    const inFile = projectDefs(s).filter((d) => d.startsWith(`${s.file}|`));
    const fileClean = inFile.length > 0 && inFile.every((d) => done.has(d));
    if (form === "qualified") {
      // `main.ssrf_lab(x)` could be any module named main, and `User.find(x)` any class named User:
      // every definition under that name, wherever it is, has to be a summarised sink.
      const q = qualifierOf(s);
      if (!q) return false;
      const named = new RegExp(`\\b(?:class|object|module|struct|impl)\\s+${q}\\b`);
      const under = projectDefs(s).filter((d) => {
        const f = d.slice(0, d.lastIndexOf("|"));
        return path.basename(f).replace(/\.[^.]+$/, "") === q || named.test(readText(f) || "");
      });
      return fileClean && under.every((d) => done.has(d));
    }
    if (callFile === s.file && fileClean) return true;
    const all = projectDefs(s);
    return all.length === 1 && done.has(all[0]);
  };
  const chain = (s) => {
    const names = [];
    for (let c = s; c; c = c.via) names.push(`${c.name}() at ${rel(c.file)}:${c.defLine}`);
    return names.join(" → ");
  };

  const findings = [];
  for (let hop = 1; hop <= MAX_HOPS && fresh.length; hop++) {
    const current = fresh;
    fresh = [];
    const { rules, meta } = hopRules(current, byId, hop);
    if (!rules.length) break;
    const names = [...new Set(current.map((s) => s.name))];
    const mention = new RegExp(`(?<![\\w$])(?:${names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\s*\\(`);
    const targets = files.filter((f) => {
      const text = readText(f);
      return text != null && mention.test(text);
    });
    if (!targets.length) break;
    let config = writeRules(rules);
    try {
      for (let i = 0; i < targets.length; i += CHUNK) {
        let r = run(targets.slice(i, i + CHUNK), [config.file]);
        // A generated rule Semgrep cannot parse -- a helper named in a way no pattern can spell -- is
        // dropped and the pass re-run, rather than failing the whole check over one helper. Found on
        // NetBox, whose Django migration modules are named 0096_multi_protocol_services.
        for (let retry = 0; retry < 5 && r.error && /Rule parse error in rule \S*?(hop\d+-\d+(?:--summary)?)\b/.test(r.error); retry++) {
          const bad = /Rule parse error in rule \S*?(hop\d+-\d+(?:--summary)?)\b/.exec(r.error)[1];
          const kept = rules.filter((x) => x.id !== bad);
          if (kept.length === rules.length) break;
          rules.splice(0, rules.length, ...kept);
          config.done();
          config = writeRules(rules);
          r = run(targets.slice(i, i + CHUNK), [config.file]);
        }
        if (r.error || r.missing) return { error: r.error || "semgrep could not be run" };
        for (const x of r.doc.results || []) {
          const id = String(x.check_id).split(".").pop();
          const m = meta.get(id);
          if (!m) continue;
          if (id.endsWith("--summary")) {
            // A helper of a helper is only as sure as the call that links them: through an overloaded
            // or twice-defined name, the inner function may not be the one that injects.
            const next = toSummary(x, m.summary.base, m.summary, readText);
            if (next) next.sure = m.summary.sure !== false && resolves(m.summary, m.form, x.path);
            add(next);
            continue;
          }
          const s = m.summary;
          findings.push({
            rule: `${s.base}--via-helper`,
            category: s.category,
            blocking: s.sure !== false && resolves(s, m.form, x.path),
            message: `${byId.get(s.base).message}, through a call to a project helper`,
            at: `${rel(x.path)}:${x.start.line}`,
            via: chain(s),
          });
        }
      }
    } finally {
      config.done();
    }
  }
  return { findings };
}

export function sastFailures(projectDir, { taskText = "" } = {}) {
  const scan = sastScan(projectDir, { taskText });
  if (scan.couldNotRun) return { failures: [], advisories: [], couldNotRun: scan.couldNotRun };

  const blocking = new Map();
  const advisory = new Map();
  for (const f of scan.findings) {
    const target = f.blocking ? blocking : advisory;
    // A helper advisory is unsure of something else -- which function the call reaches -- and says so.
    const key = !f.blocking && f.via ? `${f.category}${VIA}` : f.category;
    if (!target.has(key)) target.set(key, { message: f.message, at: [] });
    target.get(key).at.push(f.via ? `${f.at} (via ${f.via})` : f.at);
  }
  const order = (m) => [...m].sort(([a], [b]) => CATEGORY_ORDER.indexOf(a.replace(VIA, "")) - CATEGORY_ORDER.indexOf(b.replace(VIA, "")));
  const list = (a) => [...new Set(a)].slice(0, 10).join(", ") + (new Set(a).size > 10 ? `, +${new Set(a).size - 10} more` : "");

  const failures = order(blocking).map(
    ([category, { message, at }]) =>
      `sast: ${category} — ${message}: ${list(at)}. ${REMEDY[category] || ""}`.trimEnd()
  );
  const advisories = order(advisory).map(([key, { message, at }]) => {
    const category = key.replace(VIA, "");
    const why = key.endsWith(VIA)
      ? " — the call is through an object whose type is not known here, or the name is defined more than once, so it may reach a different function"
      : ADVISORY_WHY[category] || "";
    return `sast: ${message} (${category}, not blocking${why}): ${list(at)}.`;
  });
  const unparsed = scan.unparsed;
  if (unparsed.length) {
    advisories.push(
      `sast: ${unparsed.length} file(s) could not be fully parsed, so parts of them were not checked — ${unparsed.slice(0, 5).join(", ")}${unparsed.length > 5 ? ", …" : ""}.`
    );
  }
  return { failures, advisories };
}
