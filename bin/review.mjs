// wolfproof review: list the findings a review can name, or write one entry. docs/candidate-rules.md
// #24, lib/reviewed.mjs.
//
//   wolfproof review <project-dir> [--codeql]
//       Runs the two checks whose findings have IDs -- injection and authentication -- and lists every
//       finding with its ID, marking the ones already reviewed. With --codeql, CodeQL's results too,
//       as the gate's --codeql runs it. Nothing else is run: no controls, no tests. Exit 0, or 3 when
//       a check could not run (Semgrep or CodeQL missing), as the gate would.
//   wolfproof review <project-dir> <finding-id> --reason "..." [--reviewer <name>] [--expires YYYY-MM-DD]
//                    [--file <path>]
//       Writes one entry to the project's .wolfproof-reviewed.json, or to --file (a list kept outside
//       the project, for --reviewed). An entry for the same ID is replaced. Exit 0, or 2 on a usage
//       error.
//
// Writing does not re-run the checks, which can take minutes: an ID that names no finding is listed
// by the next gate run as matching nothing. The list mode is how to get IDs that do.

import { existsSync, readFileSync, writeFileSync, statSync } from "fs";
import path from "path";

import { sastScan } from "../agent/sast.mjs";
import { authenticationFailures } from "../agent/authentication.mjs";
import { scanSource } from "../agent/codeql.mjs";
import { REVIEW_FILE, parseReviews, loadProjectReviews } from "../lib/reviewed.mjs";

const EXIT = { OK: 0, USAGE: 2, INCOMPLETE: 3 };
const USAGE = `usage: wolfproof review <project-dir> [--codeql]
       wolfproof review <project-dir> <finding-id> --reason "..." [--reviewer <name>] [--expires YYYY-MM-DD] [--file <path>]`;

function option(args, name) {
  const i = args.findIndex((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i < 0) return undefined;
  if (args[i].includes("=")) return args[i].slice(args[i].indexOf("=") + 1);
  return args[i + 1] !== undefined && !args[i + 1].startsWith("--") ? args[i + 1] : null;
}

// Options that take no value, so the argument after one is not read as its value.
const FLAGS = new Set(["--codeql", "--help"]);

function positionals(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      if (!FLAGS.has(args[i]) && !args[i].includes("=") && args[i + 1] !== undefined && !args[i + 1].startsWith("--")) i++;
      continue;
    }
    out.push(args[i]);
  }
  return out;
}

function list(projectDir, out, given = projectDir, codeql = false) {
  const scan = sastScan(projectDir);
  const auth = authenticationFailures(projectDir);
  const reviewed = new Set(loadProjectReviews(projectDir).entries.map((e) => e.id));
  const rows = [
    ...(scan.findings || []).map((f) => ({ id: f.id, blocking: f.blocking, where: f.where, what: `${f.category}: ${f.message}` })),
  ];
  // CodeQL's results, reviewed or not: with no reviews applied, every one is returned in `kept`.
  const q = codeql ? scanSource(projectDir, { reviews: [] }) : null;
  for (const f of q?.findings || []) rows.push({ id: f.id, blocking: f.blocking, where: f.where, what: `${f.rule} (${f.level}): ${f.title}` });
  // Open routes are one finding in the gate's report; here each has its own ID.
  const authIds = auth.ids || [];
  out.push(`project : ${projectDir}`);
  if (scan.couldNotRun) out.push(`!! injection could not be checked: ${scan.couldNotRun.join("; ")}`);
  if (q?.couldNotRun.length) out.push(`!! CodeQL could not analyse everything: ${q.couldNotRun.join("; ")}`);
  out.push("");
  if (!rows.length && !authIds.length) {
    out.push(`No finding of the injection or authentication checks${codeql ? " or CodeQL" : ""} to review.`);
  }
  for (const r of rows) {
    out.push(`${reviewed.has(r.id) ? "reviewed" : r.blocking ? "BLOCKING" : "advisory"}  ${r.id}`);
    out.push(`    ${r.where} — ${r.what}`);
  }
  const where = new Map((auth.located || []).map((r) => [r.id, r.file ? `${r.file}${r.line ? `:${r.line}` : ""}` : null]));
  for (const id of authIds) {
    out.push(`${reviewed.has(id) ? "reviewed" : "BLOCKING"}  ${id}`);
    const at = where.get(id) ? `${where.get(id)} — ` : "";
    if (id.startsWith("authentication:timing:")) out.push(`    ${at}a credential compared with an ordinary equality operator rather than a constant-time one`);
    else if (id.startsWith("authentication:signature:")) out.push(`    a request signature verified with an ordinary equality comparison rather than a constant-time one`);
    else if (id.startsWith("authentication:unset:")) out.push(`    ${at}a credential read from the environment and compared for equality, which succeeds when it is unset`);
    else out.push(`    an endpoint that accepts requests from anyone who can reach the service`);
  }
  if (rows.length || authIds.length) {
    out.push("");
    out.push(`To mark one reviewed: wolfproof review ${given} <id> --reason "why it is acceptable"`);
  }
  return scan.couldNotRun || q?.couldNotRun.length ? EXIT.INCOMPLETE : EXIT.OK;
}

function write(projectDir, id, args, out, err) {
  const reason = option(args, "reason");
  const reviewer = option(args, "reviewer");
  const expires = option(args, "expires");
  const fileArg = option(args, "file");
  const entry = { id, reason: reason ?? undefined, ...(reviewer ? { reviewer } : {}), ...(expires ? { expires } : {}) };
  // The same validation the gate applies, so a written entry is one the gate will honour.
  const { entries, ignored } = parseReviews({ reviewed: [entry] }, "the command line");
  if (!entries.length) {
    err.push(`wolfproof review: this entry ${ignored[0].why}. ${USAGE.split("\n")[1].trim()}`);
    return EXIT.USAGE;
  }
  const file = fileArg ? path.resolve(fileArg) : path.join(projectDir, REVIEW_FILE);
  let doc = { reviewed: [] };
  if (existsSync(file)) {
    try {
      doc = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      err.push(`wolfproof review: ${file} is not valid JSON (${e.message.split("\n")[0]}); fix it before adding to it`);
      return EXIT.USAGE;
    }
    if (!Array.isArray(doc.reviewed)) {
      err.push(`wolfproof review: ${file} has no "reviewed" list`);
      return EXIT.USAGE;
    }
  }
  const { source, ...written } = entries[0];
  const before = doc.reviewed.length;
  doc.reviewed = doc.reviewed.filter((e) => !e || e.id !== written.id);
  doc.reviewed.push(written);
  writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
  // As the user would type it: relative to where they are, when it is under there.
  const shown = path.relative(process.cwd(), file);
  out.push(`${doc.reviewed.length === before ? "replaced" : "added"} in ${shown && !shown.startsWith("..") ? shown : file}:`);
  out.push(`  ${JSON.stringify(written)}`);
  out.push("");
  out.push("The gate lists this finding as reviewed on every run, with the reason, and does not count it.");
  const voids = written.id.startsWith("authentication:") ? "the route's method, path or file changes" : "the line it names changes";
  out.push(`It stops applying when ${voids}` + (written.expires ? ` or after ${written.expires}` : "") + ".");
  if (!fileArg) out.push(`In factory mode, an entry a change adds to ${REVIEW_FILE} blocks unless the pipeline's allowlist approves it.`);
  return EXIT.OK;
}

export async function runReview(args) {
  const out = [];
  const err = [];
  const pos = positionals(args);
  let code;
  if (!pos.length || args.includes("--help")) {
    err.push(USAGE);
    code = pos.length ? EXIT.OK : EXIT.USAGE;
  } else {
    const projectDir = path.resolve(pos[0]);
    if (!existsSync(projectDir) || !statSync(projectDir).isDirectory()) {
      err.push(`wolfproof review: ${pos[0]} is not a directory`);
      code = EXIT.USAGE;
    } else if (pos.length === 1) {
      code = list(projectDir, out, pos[0], args.includes("--codeql"));
    } else if (pos.length === 2) {
      code = write(projectDir, pos[1], args, out, err);
    } else {
      err.push(USAGE);
      code = EXIT.USAGE;
    }
  }
  if (out.length) process.stdout.write(`${out.join("\n")}\n`);
  if (err.length) process.stderr.write(`${err.join("\n")}\n`);
  return code;
}
