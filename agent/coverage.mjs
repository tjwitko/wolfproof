// Source in languages no language-aware check reads.
//
// A Rust project exited 0. Each check that reads code said "not checked — no source files in a
// language this check recognises", as one advisory among several, and the verdict line said nothing
// blocking. True, and it reads as a pass: a reader who stops at the verdict has no way to learn that
// none of the code was looked at. The project-wide scans -- secrets, dependencies, infrastructure --
// still apply to such a project, which is why this is a line above the verdict rather than an exit 3:
// the gate ran; it just could not read the code it was given.
//
// Shell is deliberately not listed. Nearly every repository carries scripts, and a line that appears
// everywhere is a line nobody reads. The languages here are the ones a project's application code is
// written in.
import { readdirSync, statSync, lstatSync, accessSync, constants } from "fs";
import path from "path";

import { SKIP_DIRS } from "./skip-dirs.mjs";
import { isDeclaredFixture } from "./fixture-markers.mjs";
import { READ_EXT, TEST_EXT, MAX_FILE_BYTES } from "./source-files.mjs";
import { SAST_EXT, MAX_FILE_BYTES as SAST_MAX_BYTES } from "./sast.mjs";
import { LOCKFILES } from "./lockfiles.mjs";

export const UNREAD_LANGUAGES = {
  ".swift": "Swift",
  ".scala": "Scala",
  ".ex": "Elixir",
  ".exs": "Elixir",
  ".dart": "Dart",
  ".lua": "Lua",
  ".pl": "Perl",
  ".vue": "Vue",
  ".svelte": "Svelte",
};

// The code languages among the extensions the checks do read; configuration and SQL are read too,
// but are not what "most of the source" means.
// Every extension a language-aware check reads. Taken from sast's list rather than kept here: this file
// once called .jsx unread while sast was reading it, which is the drift a second list invites.
const READ_CODE = [...new Set([...READ_EXT, ...SAST_EXT])].filter((e) => ![".sql", ".tf", ".tfvars", ".yaml", ".yml"].includes(e));

// Every extension some check reads, including the configuration ones: a file with one of these that
// is over its limit, or cannot be opened, is skipped by the checks that would have read it.
const READ_ANY = new Set([...READ_EXT, ...SAST_EXT]);

// Two limits, and which applies depends on who reads the file. The checks that read source
// themselves stop at 512 KB, and between them they read the extensions in TEST_EXT (each walker
// keeps its own list, every one a subset of it). Injection reads up to 1 MB, and for C and C++ it
// is the only reader, so a 700 KB C file was read by everything that reads C and is not skipped at
// all -- the first version of this list named it anyway.
const SOURCE_CHECKS = "Authentication, code quality, immutability, retention, secret rotation, the manifest contract and the test check";
const CONFIG_CHECKS = "Immutability, retention, the Kubernetes manifest check and the IAM and manifest contracts";
const limitFor = (ext) => (TEST_EXT.has(ext) ? MAX_FILE_BYTES : SAST_MAX_BYTES);
const limitName = (bytes) => (bytes >= 1024 * 1024 ? `${bytes / (1024 * 1024)} MB` : `${bytes / 1024} KB`);

// The language of each code file some check reads. A check that reads some of these and not others
// cannot vouch for a project holding the others: authentication reads Python and not C#.
export const READ_LANGUAGES = {
  ".py": "Python", ".go": "Go", ".java": "Java", ".rb": "Ruby", ".cs": "C#", ".rs": "Rust",
  ".js": "JavaScript/TypeScript", ".mjs": "JavaScript/TypeScript", ".cjs": "JavaScript/TypeScript",
  ".jsx": "JavaScript/TypeScript", ".ts": "JavaScript/TypeScript", ".tsx": "JavaScript/TypeScript",
  ".c": "C/C++", ".h": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".cxx": "C/C++", ".hpp": "C/C++", ".hh": "C/C++",
  ".php": "PHP", ".kt": "Kotlin",
};

/**
 * `languages` counts every code file by language, read or not. `skipped` lists the files of a kind
 * some check reads that a check which reads that kind did not read: over the limit (`bytes`), or
 * not readable. Each check skipped them quietly, and a project whose only source file was 545 KB
 * was reported by four checks as having no source files at all.
 *
 * `code` is true for a code file that is there and was skipped; the gate reports those as
 * could-not-run (`skippedCodeLine`), and the rest -- YAML, SQL, Terraform, a link to nothing -- stay
 * a line above the verdict (`skippedFilesLine`). `readBy` names the check that did read a file the
 * others skipped: injection, for a file between the two limits.
 *
 * A lockfile is not listed. `pnpm-lock.yaml` has an extension the manifest checks read and is
 * routinely over 512 KB, and the dependency scanner, whose file it is, reads it at any size: the
 * first version of this list called a 624 KB lockfile unread code, on every run.
 * @returns {{ unread: { language: string, files: number }[], unreadFiles: number, readFiles: number, mostlyUnread: boolean, languages: Record<string, number>, skipped: { file: string, bytes: number | null, why: string, code: boolean, readBy: string | null }[] }}
 */
export function sourceCoverage(projectDir) {
  const unread = new Map();
  const languages = {};
  const skipped = [];
  let readFiles = 0;
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
        continue;
      }
      const ext = path.extname(e.name);
      if (READ_ANY.has(ext) && !LOCKFILES.includes(e.name)) {
        const skip = skippedWhy(full, ext);
        if (skip) {
          skipped.push({ file: path.relative(projectDir, full), ...skip });
          continue;
        }
      }
      if (READ_CODE.includes(ext)) readFiles++;
      const language = UNREAD_LANGUAGES[ext];
      if (language) unread.set(language, (unread.get(language) || 0) + 1);
      const any = language || READ_LANGUAGES[ext];
      if (any) languages[any] = (languages[any] || 0) + 1;
    }
  };
  walk(projectDir);
  const list = [...unread].map(([language, files]) => ({ language, files })).sort((a, b) => b.files - a.files);
  const unreadFiles = list.reduce((n, l) => n + l.files, 0);
  skipped.sort((a, b) => a.file.localeCompare(b.file));
  return { unread: list, unreadFiles, readFiles, mostlyUnread: unreadFiles > readFiles, languages, skipped };
}

// Why a check that reads this kind of file did not read this one, or null. The same test every
// source walker applies, without reading the file: its size against the limit, and whether it can
// be opened at all.
function skippedWhy(full, ext) {
  const code = READ_CODE.includes(ext);
  let bytes;
  try {
    bytes = statSync(full).size;
  } catch (e) {
    // A link whose target is not there is not code that went unread: there is nothing to read. It
    // is still named, because a walker that follows links met it and moved on.
    if (e?.code === "ENOENT" && isLink(full)) return { bytes: null, why: "a symbolic link to a file that is not there", code: false, readBy: null };
    return { bytes: null, why: `not readable (${e?.code || e?.message})`, code, readBy: null };
  }
  const limit = limitFor(ext);
  if (bytes > limit) {
    const readBy = limit < SAST_MAX_BYTES && SAST_EXT.has(ext) && bytes <= SAST_MAX_BYTES ? "injection" : null;
    return { bytes, why: `over the ${limitName(limit)} limit`, code, readBy };
  }
  try {
    accessSync(full, constants.R_OK);
  } catch (e) {
    return { bytes, why: `not readable (${e?.code || e?.message})`, code, readBy: null };
  }
  return null;
}

function isLink(full) {
  try {
    return lstatSync(full).isSymbolicLink();
  } catch {
    return false;
  }
}

const kb = (n) => `${Math.round(n / 1024)} KB`;

/** The sentence for code in languages nothing reads, or null. Factory mode's `unread-code` advisory. */
export function unreadLanguagesLine(cov) {
  if (!cov || cov.unreadFiles === 0) return null;
  const what = cov.unread.map((l) => `${l.files} ${l.language}`).join(", ");
  return cov.mostlyUnread
    ? `MOST OF THIS PROJECT'S SOURCE WAS NOT READ: ${what} file(s), against ${cov.readFiles} in languages the checks read. ` +
        `No language-aware check reads these, so the verdict says nothing about that code — only the project-wide scans (secrets, dependencies, infrastructure) apply to it.`
    : `${what} file(s) were not read — no language-aware check reads them, so the verdict says nothing about that code. ` +
        `Only the project-wide scans (secrets, dependencies, infrastructure) apply to it.`;
}

const named = (list) =>
  list
    .slice(0, 5)
    .map((s) => {
      const size = s.bytes !== null && s.why.startsWith("over") ? `${kb(s.bytes)}, ` : "";
      return `${s.file} (${size}${s.why}${s.readBy ? `; within ${s.readBy}'s ${limitName(SAST_MAX_BYTES)}` : ""})`;
    })
    .join(", ") + (list.length > 5 ? `, +${list.length - 5} more` : "");

/**
 * The sentence for code files the source checks did not read, or null. The gate's could-not-run
 * entry, in both modes: a 600 KB server.js with an open DELETE /admin route exited 0 with this as a
 * line above the verdict, and a line is not a verdict. An unreadable Dockerfile is the precedent.
 */
export function skippedCodeLine(cov) {
  const code = (cov?.skipped || []).filter((s) => s.code);
  if (!code.length) return null;
  return (
    `${code.length} code file(s) were not read by the checks that read their language: ${named(code)}. ` +
    `${SOURCE_CHECKS} stop at ${limitName(MAX_FILE_BYTES)}; injection reads up to ${limitName(SAST_MAX_BYTES)} and is the only check that reads C and C++. ` +
    `A check that skipped a file says nothing about its code, and says "no source files" when these were the only ones. ` +
    `Split the file; or, if it is generated or vendored, move it under dist/ or build/, or declare its directory a fixture with a reason.`
  );
}

/**
 * The sentence for the other skipped files -- YAML, SQL and Terraform over the limit or unreadable,
 * a link to nothing -- or null. A line above the verdict, and factory mode's `skipped-files` advisory.
 */
export function skippedFilesLine(cov) {
  const rest = (cov?.skipped || []).filter((s) => !s.code);
  if (!rest.length) return null;
  return (
    `${rest.length} file(s) of a kind the checks read were not read: ${named(rest)}. ` +
    `${CONFIG_CHECKS} read YAML, SQL and Terraform up to ${limitName(MAX_FILE_BYTES)}, so they say nothing about a file over it or one they could not open.`
  );
}

/**
 * Both sentences for both renderers, or null when everything is in a language something reads and
 * no data or configuration file was skipped. Skipped code files are not here: they are could-not-run.
 */
export function coverageLine(cov) {
  const parts = [unreadLanguagesLine(cov), skippedFilesLine(cov)].filter(Boolean);
  return parts.length ? parts.join(" ") : null;
}
