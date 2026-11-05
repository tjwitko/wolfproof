// Known findings: a snapshot of a project's findings, after which a finding in the snapshot is listed
// and does not block, and a finding not in it blocks as before. docs/candidate-rules.md #36.
//
// A repository with history blocks on the first day, for code no change touched. A snapshot lets the
// gate be required there at once: what was already wrong is recorded, and only what a change adds
// blocks. It works through the same IDs a review names a finding by (lib/reviewed.mjs), and differs
// from a review in three ways, each the reason for something below:
//   - It is made by one command, `wolfproof known <project>`, from what the gate finds, and needs no
//     reason per entry: a legacy repository has hundreds.
//   - It only shrinks. The command removes entries that match nothing and never adds one to an
//     existing snapshot, so re-running it after a red build cannot turn it into a mute button.
//   - Some findings never enter it: a hardcoded secret, a check that could not run, a manifest no
//     scanner read, and the checks gated on what the task asks for. Those keep blocking.

import { existsSync, readFileSync } from "fs";
import path from "path";

/** The in-project snapshot. A record, not a control, in the default mode, like the review file. */
export const KNOWN_FILE = ".wolfproof-known.json";

/**
 * The finding families a snapshot can hold: the ID's prefix, and the check whose run decides whether
 * an entry still matches. A family is judged only when that check ran to completion -- an entry for
 * a check that could not run may still name a finding there.
 */
export const KNOWN_FAMILIES = {
  sast: { check: "sast", what: "injection" },
  authentication: { check: "authentication", what: "authentication" },
  codeql: { check: "codeql", what: "CodeQL" },
  dependencies: { check: "check_dependencies", what: "dependency vulnerabilities" },
  identity: { check: "check_auth_posture", what: "workload identity" },
  dockerfile: { check: "dockerfile", what: "Dockerfile base images" },
  presence: { check: "artifact_presence", what: "empty files" },
  quality: { check: "code_quality", what: "test patch targets" },
};

const ID = new RegExp(`^(${Object.keys(KNOWN_FAMILIES).join("|")}):\\S.*$`);

/** The family of an ID: its prefix, or null. */
export const familyOf = (id) => (ID.test(id) ? id.slice(0, id.indexOf(":")) : null);

/**
 * Passed instead of a snapshot's entries by `wolfproof known` when there is no snapshot yet: every
 * blocking finding with an ID counts as known, so one run shows both what the snapshot would hold
 * (the findings set aside) and what it cannot take (the findings still blocking). Never read from a
 * file -- an entry matching everything is exactly what a snapshot must not be able to say.
 */
export const EVERY_FINDING = Object.freeze({ id: "(every finding)", kind: "known", all: true, source: "wolfproof known" });

/** Entries from a parsed snapshot: { entries, ignored }, an ignored one with why. */
export function parseKnown(value, source) {
  const entries = [];
  const ignored = [];
  const list = value && Array.isArray(value.known) ? value.known : null;
  if (!list) {
    ignored.push({ entry: value, why: 'has no "known" list', source });
    return { entries, ignored };
  }
  const seen = new Set();
  for (const e of list) {
    const id = e && typeof e.id === "string" ? e.id.trim() : "";
    if (!familyOf(id)) {
      ignored.push({ entry: e, why: `needs an "id" naming a finding of ${families()}`, source });
    } else if (!seen.has(id)) {
      seen.add(id);
      entries.push({
        id,
        kind: "known",
        ...(typeof e.where === "string" ? { where: e.where } : {}),
        ...(typeof e.message === "string" ? { message: e.message } : {}),
        ...(Array.isArray(e.declared) && e.declared.every((n) => typeof n === "string") ? { declared: [...e.declared] } : {}),
        source,
      });
    }
  }
  return { entries, ignored };
}

function families() {
  const k = Object.keys(KNOWN_FAMILIES);
  return `${k.slice(0, -1).join(", ")} or ${k.at(-1)}`;
}

/** The project's own snapshot, or { entries: [], ignored: [] } when there is none. A file that cannot
 * be read applies nothing -- the findings stay -- and says so. */
export function loadProjectKnown(projectDir) {
  const file = path.join(projectDir, KNOWN_FILE);
  if (!existsSync(file)) return { entries: [], ignored: [] };
  let value;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    return { entries: [], ignored: [], error: `${KNOWN_FILE} could not be read (${err.message.split("\n")[0]}), so no finding in it was set aside` };
  }
  return parseKnown(value, KNOWN_FILE);
}

/** A finding the snapshot covered, as the result document lists it. */
export function knownRecord(r) {
  return { id: r.id, where: r.where, blocking: r.blocking !== false, source: r.review.source, ...(Array.isArray(r.declared) ? { declared: r.declared } : {}) };
}

/** The report's one line for known findings: a count, not a list -- a legacy repository has hundreds. */
export function knownLine(n, sources) {
  return `${n} finding${n === 1 ? "" : "s"} known from the snapshot (${sources.join(", ")}), not blocking — --json lists ${n === 1 ? "it" : "them"}`;
}

/** The advisory for snapshot entries that match no finding of a check that ran. */
export function staleKnownLine(stale) {
  const shown = stale.slice(0, 5).map((e) => e.id);
  return (
    `known: ${stale.length} snapshot entr${stale.length === 1 ? "y matches" : "ies match"} no finding — ` +
    `${shown.join(", ")}${stale.length > 5 ? `, +${stale.length - 5} more` : ""}. The finding was fixed or the code it names ` +
    `changed; \`wolfproof known\` removes ${stale.length === 1 ? "it" : "them"}.`
  );
}

/**
 * One record per finding with an ID, for the result document: where it is, whether it blocks, and
 * whether a review or the snapshot set it aside. What a comment-only reviewer matches to a diff.
 */
export function locate(check, items) {
  return items.map((f) => ({ id: f.id, check, file: f.file ?? null, line: f.line ?? null, blocking: f.blocking !== false }));
}

/** "file:line" split, for checks that keep a location as one string. */
export function splitAt(at) {
  const i = String(at).lastIndexOf(":");
  const n = Number(String(at).slice(i + 1));
  return i > 0 && Number.isInteger(n) ? { file: at.slice(0, i), line: n } : { file: at, line: null };
}
