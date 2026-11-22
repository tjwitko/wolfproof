import { readFileSync } from "fs";
import path from "path";

// What secret-guard's scan does not read, by path. Factory mode blocks a change that writes there,
// so that "the scan found nothing" cannot mean "the scan was not shown it".
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
  { kind: "rule-file", pattern: "(?:^|/)(?:[^/]*\\.)?gitleaks\\.toml$", flags: "" },
  { kind: "image", pattern: "\\.(?:bmp|gif|jpe?g|png|tiff?)$", flags: "i" },
  { kind: "font", pattern: "\\.(?:eot|[ot]tf|woff2?)$", flags: "i" },
  { kind: "binary", pattern: "\\.(?:docx?|xlsx?|pdf|vsidx|suo|wsuo|pdb|exe)$", flags: "i" },
  { kind: "go-vendor-list", pattern: "(?:^|/)vendor/modules\\.txt$", flags: "" },
  { kind: "go-vendor", pattern: "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$", flags: "" },
  { kind: "node-modules", pattern: "(?:^|/)node_modules(?:/.*)?$", flags: "" },
  { kind: "bower-components", pattern: "(?:^|/)bower_components(?:/.*)?$", flags: "" },
  { kind: "virtualenv", pattern: "(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$", flags: "i" },
  { kind: "python-lib", pattern: "(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$", flags: "i" },
  { kind: "dist-info", pattern: "(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$", flags: "i" },
  { kind: "ruby-vendor", pattern: "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$", flags: "" },
  { kind: "gem", pattern: "\\.gem$", flags: "" },
  { kind: "git", pattern: "(?:^|/)\\.git$", flags: "" },
  { kind: "terraform", pattern: "(^|/)\\.terraform/", flags: "" },
  { kind: "external-modules", pattern: "(^|/)\\.external_modules/", flags: "" },
  { kind: "node-modules-dir", pattern: "(^|/)node_modules/", flags: "" },
  { kind: "vendor", pattern: "(^|/)vendor/", flags: "" },
  { kind: "venv", pattern: "(^|/)\\.venv/", flags: "" },
  { kind: "pycache", pattern: "(^|/)__pycache__/", flags: "" },
  { kind: "archive", pattern: "(?:^|/)[^/]*\\.(?:(?:7z|br|bz2|gz|lz4|rar|s2|sz|tar|xz|z[i\\u0130]p|zst|zz)[^/]*|lz|mz)$", flags: "i" },
];

const compile = (e) => Object.assign(new RegExp(e.pattern, e.flags), { unreadKind: e.kind });

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
    if (e.flags !== "" && e.flags !== "i") return cannot(`entry ${i} (${e.kind}) has flags ${JSON.stringify(e.flags)}`);
    try {
      patterns.push(compile(e));
    } catch (err) {
      return cannot(`entry ${i} (${e.kind}) does not compile: ${err.message}`);
    }
  }
  return { patterns, source: "secret-guard", error: null };
}
