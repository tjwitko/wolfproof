// CodeQL, against the project's source. Opt-in: it runs only for `--codeql` (the Action's `codeql`
// input), because the bundle is about 550 MB, a scan takes minutes rather than seconds, and CodeQL's
// licence lets it analyse only open-source code without a GitHub Advanced Security licence
// (docs/candidate-rules.md #17).
//
// The sast check runs Semgrep, whose open-source taint analysis stays inside one function; sast-hops
// follows request data one helper further. CodeQL follows it across functions and files, which is
// what this adds.
//
// What blocks: a result at CodeQL's `error` level from the code-scanning suite, the suite GitHub
// runs by default. Warnings and notes are advisories. A result a review names (lib/reviewed.mjs) is
// listed and does not block, as for sast.
//
// What the project cannot change, the same reasons as sast and trivy:
//   - The scan reads a copy of the project made by the walk every other check uses: SKIP_DIRS and
//     declared fixtures are left out, and symbolic links are not followed. A build also writes into
//     the copy, not the project.
//   - Suppression comments do not count. `// codeql[rule]` is honoured by GitHub's code scanning,
//     not by the CLI, and a result that carries a suppression anyway is counted -- the author of the
//     code clearing their own finding, the `# nosemgrep` case.
//   - CODEQL_*, LGTM_* and SEMMLE_* variables configure the extractors (what is extracted, which
//     files are filtered) and are not passed on. The run says which were dropped.
//   - The suites are named by path inside the bundle, and the scan runs in an empty directory.
//
// Languages that need a build -- Go, Swift, and Java when there is Kotlin -- are built by CodeQL's
// autobuild in the copy, which runs the project's build tooling. That was a choice: without it those
// languages are not analysed at all.

import { spawnSync } from "child_process";
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "fs";
import os from "os";
import path from "path";

import { setting } from "../lib/settings.mjs";
import { SKIP_DIRS } from "./skip-dirs.mjs";
import { isDeclaredFixture } from "./fixture-markers.mjs";
import { lineFingerprint, withIds, applyReviews } from "../lib/reviewed.mjs";

export const SUITE = "code-scanning";

// CodeQL's language for each extension the walk can find. TypeScript is extracted by the
// JavaScript extractor, Kotlin by the Java one.
const EXT_LANGUAGE = {
  ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
  ".ts": "javascript", ".mts": "javascript", ".cts": "javascript", ".tsx": "javascript", ".vue": "javascript",
  ".py": "python",
  ".rb": "ruby", ".erb": "ruby",
  ".rs": "rust",
  ".java": "java", ".kt": "java", ".kts": "java",
  ".cs": "csharp", ".cshtml": "csharp", ".razor": "csharp",
  ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".c++": "cpp", ".h": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
  ".go": "go",
  ".swift": "swift",
};
const WORKFLOW = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)action\.ya?ml$/;

export const LANGUAGE_NAMES = {
  javascript: "JavaScript/TypeScript", python: "Python", ruby: "Ruby", rust: "Rust", java: "Java/Kotlin",
  csharp: "C#", cpp: "C/C++", go: "Go", swift: "Swift", actions: "GitHub Actions",
};
// In the order they are scanned and reported.
const ORDER = Object.keys(LANGUAGE_NAMES);

// Source CodeQL cannot read, so a project with it is told rather than left to assume.
const UNSUPPORTED = { ".php": "PHP", ".scala": "Scala", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".lua": "Lua", ".pl": "Perl" };

const CREATE_TIMEOUT_MS = 30 * 60 * 1000;
const ANALYZE_TIMEOUT_MS = 30 * 60 * 1000;
const SHOWN = 10;

function plural(n, one, many) {
  return n === 1 ? one : many;
}

/** The environment CodeQL runs with, and the variables left out of it. */
export function codeqlEnv(env) {
  const kept = {};
  const dropped = [];
  for (const [k, v] of Object.entries(env)) {
    if (/^(?:CODEQL|LGTM|SEMMLE)_/.test(k)) dropped.push(k);
    else kept[k] = v;
  }
  return { env: kept, dropped: dropped.sort() };
}

/**
 * Copy what the gate's walk sees of `projectDir` into `dest`, and say what is in it: the CodeQL
 * languages found, with each one's build mode, and the source CodeQL cannot read.
 */
export function copyProject(projectDir, dest) {
  const languages = new Set();
  const unsupported = new Set();
  let kotlin = false;
  const walk = (rel) => {
    let entries;
    try {
      entries = readdirSync(path.join(projectDir, rel), { withFileTypes: true });
    } catch {
      return;
    }
    mkdirSync(path.join(dest, rel), { recursive: true });
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      const full = path.join(projectDir, r);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !isDeclaredFixture(full)) walk(r);
        continue;
      }
      if (!e.isFile()) continue;
      try {
        copyFileSync(full, path.join(dest, r));
      } catch {
        continue; // vanished mid-walk
      }
      const ext = path.extname(e.name).toLowerCase();
      if (EXT_LANGUAGE[ext]) languages.add(EXT_LANGUAGE[ext]);
      if (ext === ".kt" || ext === ".kts") kotlin = true;
      if (UNSUPPORTED[ext]) unsupported.add(UNSUPPORTED[ext]);
      if (WORKFLOW.test(r)) languages.add("actions");
    }
  };
  walk("");
  const modes = {};
  for (const l of ORDER.filter((x) => languages.has(x))) {
    modes[l] = l === "go" || l === "swift" || (l === "java" && kotlin) ? "autobuild" : "none";
  }
  return { languages: modes, unsupported: [...unsupported].sort() };
}

function rulesOf(run) {
  const rules = new Map();
  for (const comp of [run.tool?.driver, ...(run.tool?.extensions || [])]) {
    for (const r of comp?.rules || []) if (!rules.has(r.id)) rules.set(r.id, r);
  }
  return rules;
}

function uriOf(loc) {
  return loc?.physicalLocation?.artifactLocation?.uri ?? null;
}

/**
 * The verdict on CodeQL's SARIF, one per language. Pure, so it is tested on real output.
 * @param {{ version?: string, runs: Array<{ language: string, sarif: object }>, lineOf?: (file: string, line: number) => string, reviews?: object[] }} input
 * @returns {{ failures, advisories, couldNotRun, reviewed, ids, blockingIds, findings, files }}
 */
export function judgeCodeqlRuns({ runs, lineOf = () => "", reviews = [] }) {
  const failures = [];
  const advisories = [];
  const couldNotRun = [];
  const results = [];
  const unextracted = new Map(); // language -> Set of files
  const files = {};
  const problems = [];
  let suppressed = 0;
  let version = null;

  for (const { language, sarif } of runs) {
    const run = sarif?.runs?.[0];
    if (!run || !Array.isArray(run.results)) {
      couldNotRun.push(`codeql (${language}): the SARIF has no results list, so ${LANGUAGE_NAMES[language] || language} was not checked.`);
      continue;
    }
    version ||= run.tool?.driver?.semanticVersion || null;
    const rules = rulesOf(run);
    for (const r of run.results) {
      const rule = rules.get(r.ruleId) || {};
      const level = r.level || rule.defaultConfiguration?.level || "warning";
      const loc = r.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri || "?";
      const line = loc?.region?.startLine || 0;
      if (Array.isArray(r.suppressions) && r.suppressions.length) suppressed++;
      results.push({
        language,
        rule: r.ruleId,
        title: rule.shortDescription?.text || rule.name || r.ruleId,
        level,
        blocking: level === "error",
        file,
        line,
        at: `${file}:${line}`,
        where: `${file}:${line}`,
      });
    }
    // Which files were read, from this language's own diagnostics: every database's SARIF repeats
    // the other languages' baselines, so they are taken by this language's prefix.
    const notes = run.invocations?.[0]?.toolExecutionNotifications || [];
    const extracted = new Set();
    for (const n of notes) {
      const id = n.descriptor?.id || "";
      const uris = (n.locations || []).map(uriOf).filter(Boolean);
      if (/\/diagnostics\/successfully-extracted-files$/.test(id)) uris.forEach((u) => extracted.add(u));
      const text = String(n.message?.text || "").trim();
      if (/\/diagnostics\/extraction-(?:errors|warnings)$/.test(id)) {
        if (!unextracted.has(language)) unextracted.set(language, new Set());
        // Go names the file only in the message: "Extraction failed in main.go with error ...".
        const named = uris.length ? uris : [text.match(/^Extraction failed in (.+?) with error\b/)?.[1] || text.split("\n")[0]];
        named.filter(Boolean).forEach((u) => unextracted.get(language).add(u));
      } else if (n.level === "error") {
        // Anything else CodeQL calls an error -- an autobuild step that failed, say -- may mean part
        // of the source was not read, and the run carried on regardless.
        problems.push(`codeql (${language}): CodeQL reported a problem and carried on: ${(text.split("\n")[0] || id).slice(0, 300)} (${id}).`);
      }
    }
    files[language] = extracted.size;
  }

  // IDs as sast's are made: the rule, the file and a hash of the line, numbered when one rule fires
  // twice on identical lines of one file.
  const identified = withIds(results, (f) => `codeql:${f.rule}:${f.file}:${lineFingerprint(lineOf(f.file, f.line))}`);
  const { kept, reviewed } = applyReviews(identified, reviews);

  const group = (list) => {
    const m = new Map();
    for (const f of list) {
      const key = `${f.language}\0${f.rule}`;
      if (!m.has(key)) m.set(key, { ...f, at: [] });
      m.get(key).at.push(f.where);
    }
    return [...m.values()].sort((a, b) => ORDER.indexOf(a.language) - ORDER.indexOf(b.language) || a.rule.localeCompare(b.rule));
  };
  const list = (at) => {
    const u = [...new Set(at)];
    return u.slice(0, SHOWN).join(", ") + (u.length > SHOWN ? `, +${u.length - SHOWN} more` : "");
  };

  for (const g of group(kept.filter((f) => f.blocking))) {
    failures.push(`codeql (${g.language}): ${g.rule} — ${g.title}: ${list(g.at)}. See CodeQL's help for ${g.rule}.`);
  }
  for (const g of group(kept.filter((f) => !f.blocking))) {
    advisories.push(`codeql (${g.language}): ${g.title} (${g.rule}, ${g.level}, not blocking): ${list(g.at)}.`);
  }
  for (const [language, set] of unextracted) {
    const u = [...set].sort();
    advisories.push(
      `codeql (${language}): ${u.length} file(s) could not be fully extracted, so parts of them were not analysed — ${u.slice(0, 5).join(", ")}${u.length > 5 ? ", …" : ""}.`
    );
  }
  advisories.push(...problems);
  if (suppressed) {
    advisories.push(
      `codeql: ${suppressed} result(s) carry a suppression from the code itself and were counted anyway; a review (wolfproof review) is how a finding is accepted.`
    );
  }
  const analysed = runs.filter((r) => !couldNotRun.some((c) => c.startsWith(`codeql (${r.language}):`)));
  if (analysed.length && !kept.some((f) => f.blocking)) {
    const what = analysed.map((r) => `${LANGUAGE_NAMES[r.language] || r.language} (${files[r.language] ?? 0} files)`).join(", ");
    advisories.push(`codeql: CodeQL${version ? ` ${version}` : ""} analysed ${what} with the ${SUITE} suite; nothing at error level.`);
  }
  return {
    failures,
    advisories,
    couldNotRun,
    reviewed,
    ids: identified.map((f) => f.id),
    blockingIds: kept.filter((f) => f.blocking).map((f) => f.id),
    // Every result with its ID, for `wolfproof review --codeql`.
    findings: identified.map(({ id, rule, title, level, blocking, where }) => ({ id, rule, title, level, blocking, where })),
    files,
  };
}

function lastLines(text, n = 3) {
  return String(text || "")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(-n)
    .join(" | ")
    .slice(0, 500);
}

/**
 * Lines a build prints around its error that do not say what went wrong: CodeQL's own "Spawned
 * process exited abnormally" (the build's exit, again), a heading that introduces the next lines
 * (Swift's autobuilder ends "failed to run the build command:"), Maven's help footer, stack frames.
 */
const NOT_A_CAUSE = [
  /Spawned process exited abnormally/,
  /:$/,
  /^(?:To see the full stack trace|Re-run Maven using|For more information about the errors|\[Help \d+\])/,
  /^at\s/,
];

/**
 * Why `codeql database create` failed: the build's own last line that names a cause -- "Could not
 * detect a suitable build command", "xcodebuild requires Xcode", a refused connection -- and
 * otherwise CodeQL's last lines. The scratch copy's path is taken out, so a file is named as it is
 * in the project.
 */
export function createFailure(text, src = null) {
  let all = String(text || "");
  for (const dir of src ? [...new Set([src, realpathOr(src)])] : []) all = all.split(`${dir}/`).join("").split(dir).join(".");
  const build = all
    .split("\n")
    .filter((l) => /\[build-std(?:err|out)\]/.test(l))
    // The build's line, without CodeQL's prefix or the timestamp and [autobuild] tag it nests.
    .map((l) => l.replace(/^.*?\[build-std(?:err|out)\]\s*/, "").replace(/^(?:\[[^\]]*\d{2}:\d{2}:\d{2}[^\]]*\]\s*)?(?:\[autobuild\]\s*)?/, ""))
    .filter((l) => /\b(?:ERROR|error|FATAL|fatal|failed)\b|Exception\b/.test(l))
    // Maven's level tag and its pointer to a help page are not part of the cause.
    .map((l) => l.replace(/^\[(?:ERROR|FATAL)\]\s*/, "").replace(/\s*-> \[Help \d+\]$/, "").trim())
    .filter((l) => l && !NOT_A_CAUSE.some((re) => re.test(l)));
  return (build.length ? build.at(-1) : lastLines(all)).slice(0, 500);
}

function realpathOr(p) {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * Scan the project with CodeQL and judge it. CodeQL is WOLFPROOF_CODEQL when that is set -- the
 * Action sets it to the bundle it installed and verified -- and otherwise the codeql on PATH.
 * @returns {{ ran: string[], failures, advisories, couldNotRun, reviewed, ids, blockingIds, findings }}
 */
export function scanSource(projectDir, { env = process.env, reviews = [], platform = process.platform } = {}) {
  const command = setting(env, "CODEQL") || "codeql";
  const out = { ran: [], failures: [], advisories: [], couldNotRun: [], reviewed: [], ids: null, blockingIds: [], findings: [] };
  const { env: runEnv, dropped } = codeqlEnv(env);
  if (dropped.length) {
    out.advisories.push(
      `codeql: ${dropped.join(", ")} ${plural(dropped.length, "is", "are")} set and not passed to CodeQL, because ${plural(dropped.length, "it", "they")} can change what is extracted.`
    );
  }

  const version = spawnSync(command, ["version", "--format=json"], { encoding: "utf8", env: runEnv, timeout: 60_000 });
  if (version.error?.code === "ENOENT") {
    out.couldNotRun.push(`codeql: ${command === "codeql" ? "codeql is not installed" : `${command} does not exist`}, so the source was not analysed.`);
    return out;
  }
  let info;
  try {
    info = JSON.parse(version.stdout);
  } catch {
    out.couldNotRun.push(`codeql: ${command} did not report its version (${lastLines(version.stderr) || `exit ${version.status}`}), so the source was not analysed.`);
    return out;
  }
  const dist = info.unpackedLocation;

  const work = mkdtempSync(path.join(os.tmpdir(), "wolfproof-codeql-"));
  try {
    const src = path.join(work, "src");
    const empty = path.join(work, "cwd");
    mkdirSync(empty);
    mkdirSync(path.join(work, "db"));
    const { languages, unsupported } = copyProject(projectDir, src);
    if (unsupported.length) {
      out.advisories.push(`codeql: ${unsupported.join(", ")} source is not analysed — CodeQL does not support ${plural(unsupported.length, "it", "them")}. The sast check still reads it.`);
    }
    if (!Object.keys(languages).length) {
      out.advisories.push(`codeql: not checked — nothing here is in a language CodeQL analyses.`);
      out.ids = [];
      return out;
    }

    const runs = [];
    for (const [language, mode] of Object.entries(languages)) {
      const label = `codeql (${language})`;
      const name = LANGUAGE_NAMES[language];
      if (language === "swift" && platform !== "darwin") {
        out.couldNotRun.push(`${label}: CodeQL analyses Swift only on macOS, so the Swift source was not analysed.`);
        continue;
      }
      const suite = path.join(dist, "qlpacks", "codeql", `${language}-queries`);
      let suiteFile = null;
      try {
        const [ver] = readdirSync(suite);
        suiteFile = path.join(suite, ver, "codeql-suites", `${language}-${SUITE}.qls`);
      } catch {
        /* reported below */
      }
      if (!suiteFile || !existsSync(suiteFile)) {
        out.couldNotRun.push(`${label}: the ${SUITE} suite for ${language} is not in ${dist}, so ${name} was not analysed. Install the CodeQL bundle, not the CLI alone.`);
        continue;
      }
      const db = path.join(work, "db", language);
      const created = spawnSync(
        command,
        ["database", "create", db, `--language=${language}`, `--build-mode=${mode}`, `--source-root=${src}`, "--overwrite", "--threads=0", "-q"],
        { cwd: mode === "autobuild" ? src : empty, encoding: "utf8", env: runEnv, timeout: CREATE_TIMEOUT_MS, killSignal: "SIGKILL", maxBuffer: 64 * 1024 * 1024 }
      );
      if (created.error || created.status !== 0) {
        const why = created.error ? created.error.code || created.error.message : createFailure(`${created.stdout || ""}\n${created.stderr || ""}`, src) || `exit ${created.status}`;
        const build = mode === "autobuild" ? "build and " : "";
        out.couldNotRun.push(`${label}: CodeQL could not ${build}extract the ${name} source, so it was not analysed — ${why}`);
        continue;
      }
      const sarifFile = path.join(work, `${language}.sarif`);
      const analysed = spawnSync(
        command,
        ["database", "analyze", db, suiteFile, "--format=sarif-latest", `--output=${sarifFile}`, "--threads=0", "--no-download", "-q"],
        { cwd: empty, encoding: "utf8", env: runEnv, timeout: ANALYZE_TIMEOUT_MS, killSignal: "SIGKILL", maxBuffer: 64 * 1024 * 1024 }
      );
      if (analysed.error || analysed.status !== 0) {
        const why = analysed.error ? analysed.error.code || analysed.error.message : lastLines(analysed.stderr) || `exit ${analysed.status}`;
        out.couldNotRun.push(`${label}: the analysis failed, so ${name} was not checked — ${why}`);
        continue;
      }
      let sarif;
      try {
        sarif = JSON.parse(readFileSync(sarifFile, "utf8"));
      } catch (err) {
        out.couldNotRun.push(`${label}: the analysis finished without readable SARIF (${err.message}), so ${name} was not checked.`);
        continue;
      }
      runs.push({ language, sarif });
      out.ran.push(language);
    }

    const cache = new Map();
    const lineOf = (file, line) => {
      if (!cache.has(file)) {
        let lines = [];
        try {
          if (lstatSync(path.join(src, file)).isFile()) lines = readFileSync(path.join(src, file), "utf8").split("\n");
        } catch {
          /* a file the build generated and removed */
        }
        cache.set(file, lines);
      }
      return cache.get(file)[line - 1] ?? "";
    };
    const judged = judgeCodeqlRuns({ runs, lineOf, reviews });
    out.failures.push(...judged.failures);
    out.advisories.push(...judged.advisories);
    out.couldNotRun.push(...judged.couldNotRun);
    out.reviewed = judged.reviewed;
    // Stale reviews are judged only when every language ran: one that did not could hold the finding.
    out.ids = out.couldNotRun.length ? null : judged.ids;
    out.blockingIds = judged.blockingIds;
    out.findings = judged.findings;
    return out;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
