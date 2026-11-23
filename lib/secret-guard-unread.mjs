import { readFileSync } from "fs";
import path from "path";

// What secret-guard's scan does not read. Factory mode blocks a change that writes there, so that
// "the scan found nothing" cannot mean "the scan was not shown it".
//
// Two sources, for two questions. For what is on disk the scan says what it left unread, first-bytes
// skips included, which no name can say (`unread` in its report, reportedUnread below). The list here
// is for a path that is not on disk (what a commit wrote and a later one moved), and for archives,
// which gitleaks does not name at the log level secret-guard reads.
//
// The list comes from the secret-guard that will run (gitleaks/unread-paths.json), so the two cannot
// drift and nothing here parses Go regular expressions. A list that is there and cannot be read is
// could-not-run, exit 3: dropping one pattern would be a place the gate stops looking and says
// nothing about.

/**
 * For a secret-guard from before the file existed. The only copy in wolfproof, and a test fails when
 * it differs from the pinned release's. An older scanner leaves more unread than this says: the text
 * kinds the pinned release reads (lockfiles, go.sum, .svg and the rest) are not on it.
 */
export const FALLBACK_UNREAD = [
  { kind: "rule-file", pattern: "(?:^|/)(?:[^/]*\\.)?gitleaks\\.toml$", flags: "", directories: true },
  { kind: "image", pattern: "\\.(?:bmp|gif|jpe?g|png|tiff?)$", flags: "iu", directories: true },
  { kind: "font", pattern: "\\.(?:eot|[ot]tf|woff2?)$", flags: "iu", directories: true },
  { kind: "binary", pattern: "\\.(?:docx?|xlsx?|pdf|vsidx|suo|wsuo|pdb|exe)$", flags: "iu", directories: true },
  { kind: "go-vendor-list", pattern: "(?:^|/)vendor/modules\\.txt$", flags: "", directories: true },
  { kind: "go-vendor", pattern: "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$", flags: "", directories: true },
  { kind: "node-modules", pattern: "(?:^|/)node_modules(?:/.*)?$", flags: "", directories: true },
  { kind: "bower-components", pattern: "(?:^|/)bower_components(?:/.*)?$", flags: "", directories: true },
  { kind: "virtualenv", pattern: "(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$", flags: "iu", directories: true },
  { kind: "python-lib", pattern: "(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$", flags: "iu", directories: true },
  { kind: "dist-info", pattern: "(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$", flags: "iu", directories: true },
  { kind: "ruby-vendor", pattern: "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$", flags: "", directories: true },
  { kind: "gem", pattern: "\\.gem$", flags: "", directories: true },
  { kind: "git", pattern: "(?:^|/)\\.git$", flags: "", directories: true },
  { kind: "terraform", pattern: "(^|/)\\.terraform/", flags: "", directories: true },
  { kind: "external-modules", pattern: "(^|/)\\.external_modules/", flags: "", directories: true },
  { kind: "node-modules-dir", pattern: "(^|/)node_modules/", flags: "", directories: true },
  { kind: "vendor", pattern: "(^|/)vendor/", flags: "", directories: true },
  { kind: "venv", pattern: "(^|/)\\.venv/", flags: "", directories: true },
  { kind: "pycache", pattern: "(^|/)__pycache__/", flags: "", directories: true },
  { kind: "archive", pattern: "(?:^|/)[^/]*\\.(?:(?:7z|br|bz2|gz|lz4|rar|s2|sz|tar|xz|z[i\\u0130]p|zst|zz)[^/]*|lz|mz)$", flags: "i", directories: false },
];

const compile = (e) => Object.assign(new RegExp(e.pattern, e.flags), { unreadKind: e.kind, unreadDirs: e.directories });

/**
 * The entry that leaves `rel` unread, or undefined: the whole path against every pattern, and its
 * parent directories against those that apply to one. gitleaks does not go into a directory that
 * matches, so logo.png/config.js is unread; an archive goes by a file's own name, so x.gz/a.js is read.
 */
export function unreadMatch(rel, patterns) {
  const whole = patterns.find((re) => re.test(rel));
  if (whole) return whole;
  const parts = rel.split("/");
  for (let i = 1; i < parts.length; i++) {
    const dir = parts.slice(0, i).join("/");
    const hit = patterns.find((re) => re.unreadDirs && re.test(dir));
    if (hit) return hit;
  }
  return undefined;
}

const WHY_UNREAD = {
  directory: "the scan's path allowlist does not go into its directory",
  file: "the scan's path allowlist does not read it",
};

/** In words, what the scan said of an entry of its `unread` list. */
export const unreadWhy = (u) =>
  u.kind === "first-bytes"
    ? `its first bytes are those of a binary format (${u.mime || "application"}), and the scan does not read such a file under any name`
    : WHY_UNREAD[u.kind];

/**
 * A scan's `unread` list, as paths from `root` (the real path of what it scanned):
 * { at(rel) -> the entry that covers rel, or null; entries: [{ rel, kind, mime? }] }, or { error }.
 * An entry the gate cannot place is an error and not a path it stops looking at.
 */
export function reportedUnread(list, root) {
  if (!Array.isArray(list)) return { error: "its list of what it left unread is not a list" };
  const entries = [];
  for (const u of list) {
    if (typeof u?.path !== "string" || !path.isAbsolute(u.path) || !Object.hasOwn({ ...WHY_UNREAD, "first-bytes": 1 }, u?.kind)) {
      return { error: `its list of what it left unread holds an entry the gate cannot read (${JSON.stringify(u).slice(0, 120)})` };
    }
    const rel = path.relative(root, u.path);
    if (!rel || rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
      return { error: `its list of what it left unread names ${JSON.stringify(u.path).slice(0, 120)}, which is not under what it scanned` };
    }
    entries.push({ ...u, rel: rel.split(path.sep).join("/") });
  }
  const files = new Map(entries.filter((e) => e.kind !== "directory").map((e) => [e.rel, e]));
  const dirs = entries.filter((e) => e.kind === "directory");
  return {
    entries,
    at: (rel) => files.get(rel) || dirs.find((d) => rel === d.rel || rel.startsWith(`${d.rel}/`)) || null,
  };
}

/** { patterns: RegExp[], source: "secret-guard" | "fallback", error: string | null } */
export function secretGuardUnread(entry) {
  const fallback = (error = null) => ({ patterns: FALLBACK_UNREAD.map(compile), source: "fallback", error });
  if (!entry) return fallback();
  const file = path.join(path.dirname(entry), "gitleaks", "unread-paths.json");
  const cannot = (why) => fallback(`secret-guard's list of what it does not read (${file}) could not be read: ${why}. What the scan skips is not known, so this run cannot say a change wrote only where it looks`);
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    return err?.code === "ENOENT" ? fallback() : cannot(err?.code || err?.message);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return cannot("it is not JSON");
  }
  if (doc?.schema !== 1) return cannot(`schema ${JSON.stringify(doc?.schema)}, where this version of wolfproof reads schema 1`);
  if (!Array.isArray(doc.entries) || !doc.entries.length) return cannot("it lists nothing");
  const patterns = [];
  for (const [i, e] of doc.entries.entries()) {
    if (typeof e?.kind !== "string" || !e.kind || typeof e.pattern !== "string" || !e.pattern) return cannot(`entry ${i} has no kind or no pattern`);
    if (typeof e.directories !== "boolean") return cannot(`entry ${i} (${e.kind}) does not say whether it applies to directories`);
    if (!["", "i", "iu"].includes(e.flags)) return cannot(`entry ${i} (${e.kind}) has flags ${JSON.stringify(e.flags)}`);
    try {
      patterns.push(compile(e));
    } catch (err) {
      return cannot(`entry ${i} (${e.kind}) does not compile: ${err.message}`);
    }
  }
  return { patterns, source: "secret-guard", error: null };
}
