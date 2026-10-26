// Reviewed findings: one finding, named by its ID, marked as read and accepted, with a reason.
// docs/candidate-rules.md #24.
//
// A team that had judged a finding acceptable had one way to say so: a fixture marker, which takes a
// whole directory out of every check, future findings included. Inline suppressions stay ignored --
// `# nosemgrep` is the code's author clearing their own finding -- so a review names the finding
// from outside the code, and stops applying when the code it names changes.
//
// Three properties, each the reason for something below:
//   - One entry, one finding. There are no wildcards: an entry that matched every finding of a rule,
//     or every finding under a directory, would be a fixture marker without the marker's visibility.
//   - A reason is required. An entry without one is ignored and reported, like an allowlist entry.
//   - Nothing disappears silently. A reviewed finding is listed with its reason on every run, an
//     entry that matches nothing is an advisory, and an expired entry is listed and not applied.

import { createHash } from "crypto";
import { existsSync, readFileSync } from "fs";
import path from "path";

/** The in-project list. A record, not a control, in the default mode: the code's author can write it. */
export const REVIEW_FILE = ".wolfproof-reviewed.json";

/** The checks whose findings have IDs, and the shape of an ID. */
export const REVIEWABLE_CHECKS = ["sast", "authentication"];
const ID = /^(sast|authentication):\S.*$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The part of a finding's ID that ties it to its code: a short hash of the line, whitespace
 * collapsed so reformatting the indentation does not void a review, and nothing else changed.
 */
export function lineFingerprint(...lines) {
  const norm = lines.map((l) => String(l ?? "").replace(/\s+/g, " ").trim()).join("\n");
  return createHash("sha256").update(norm).digest("hex").slice(0, 8);
}

/**
 * IDs for a list of findings, given each one's base ID. Two findings with the same base -- the same
 * rule on two identical lines of one file -- are told apart by order: the second is `<base>#2`.
 */
export function withIds(items, baseOf) {
  const seen = new Map();
  return items.map((it) => {
    const base = baseOf(it);
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    return { ...it, id: n === 1 ? base : `${base}#${n}` };
  });
}

/** Entries from a parsed review file: { entries, ignored }, an ignored one with why. */
export function parseReviews(value, source) {
  const entries = [];
  const ignored = [];
  const list = value && Array.isArray(value.reviewed) ? value.reviewed : null;
  if (!list) {
    ignored.push({ entry: value, why: 'has no "reviewed" list', source });
    return { entries, ignored };
  }
  for (const e of list) {
    if (!e || typeof e.id !== "string" || !ID.test(e.id.trim())) {
      ignored.push({ entry: e, why: `needs an "id" naming a finding of ${REVIEWABLE_CHECKS.join(" or ")}`, source });
    } else if (typeof e.reason !== "string" || !e.reason.trim()) {
      ignored.push({ entry: e, why: "gives no reason", source });
    } else if (e.expires !== undefined && (typeof e.expires !== "string" || !DATE.test(e.expires))) {
      ignored.push({ entry: e, why: `has an "expires" that is not a date, YYYY-MM-DD`, source });
    } else {
      entries.push({
        id: e.id.trim(),
        reason: e.reason.trim(),
        ...(typeof e.reviewer === "string" && e.reviewer.trim() ? { reviewer: e.reviewer.trim() } : {}),
        ...(e.expires ? { expires: e.expires } : {}),
        source,
      });
    }
  }
  return { entries, ignored };
}

/** The project's own list, or { entries: [], ignored: [] } when there is none. A file that cannot be
 * read applies nothing -- the findings stay -- and says so. */
export function loadProjectReviews(projectDir) {
  const file = path.join(projectDir, REVIEW_FILE);
  if (!existsSync(file)) return { entries: [], ignored: [] };
  let value;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    return { entries: [], ignored: [], error: `${REVIEW_FILE} could not be read (${err.message.split("\n")[0]}), so no review in it was applied` };
  }
  return parseReviews(value, REVIEW_FILE);
}

/** Split entries into those that apply today and those past their date. */
export function activeReviews(entries, today = new Date().toISOString().slice(0, 10)) {
  const active = [];
  const expired = [];
  for (const e of entries) (e.expires && e.expires < today ? expired : active).push(e);
  return { active, expired };
}

/**
 * Apply reviews to one check's findings. `findings` carry an `id`; returns the ones that still
 * count and the ones a review covers, each with the entry that covers it.
 */
export function applyReviews(findings, active) {
  const byId = new Map(active.map((e) => [e.id, e]));
  const kept = [];
  const reviewed = [];
  for (const f of findings) {
    const e = byId.get(f.id);
    if (e) reviewed.push({ ...f, review: e });
    else kept.push(f);
  }
  return { kept, reviewed };
}

/** One line for a reviewed finding, the same in every renderer. */
export function reviewedLine(r) {
  const who = r.review.reviewer ? `, ${r.review.reviewer}` : "";
  const until = r.review.expires ? `, until ${r.review.expires}` : "";
  return `${r.id} — ${r.where} — ${r.review.reason}${who}${until} (${r.review.source})`;
}
