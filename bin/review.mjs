// wolfproof review: list the findings a review can name, or write one entry. docs/candidate-rules.md
// #24, lib/reviewed.mjs.
//
//   wolfproof review <project-dir>
//       Runs the two checks whose findings have IDs -- injection and authentication -- and lists every
//       finding with its ID, marking the ones already reviewed. Nothing else is run: no controls, no
//       tests. Exit 0, or 3 when a check could not run (Semgrep missing), as the gate would.
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
import { REVIEW_FILE, parseReviews, loadProjectReviews } from "../lib/reviewed.mjs";

const EXIT = { OK: 0, USAGE: 2, INCOMPLETE: 3 };
const USAGE = `usage: wolfproof review <project-dir>
       wolfproof review <project-dir> <finding-id> --reason "..." [--reviewer <name>] [--expires YYYY-MM-DD] [--file <path>]`;

function option(args, name) {
  const i = args.findIndex((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i < 0) return undefined;
  if (args[i].includes("=")) return args[i].slice(args[i].indexOf("=") + 1);
  return args[i + 1] !== undefined && !args[i + 1].startsWith("--") ? args[i + 1] : null;
}

function positionals(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      if (!args[i].includes("=") && args[i + 1] !== undefined && !args[i + 1].startsWith("--")) i++;
      continue;
    }
    out.push(args[i]);
  }
  return out;
}

function list(projectDir, out) {
  const scan = sastScan(projectDir);
  const auth = authenticationFailures(projectDir);
  const reviewed = new Set(loadProjectReviews(projectDir).entries.map((e) => e.id));
  const rows = [
    ...(scan.findings || []).map((f) => ({ id: f.id, blocking: f.blocking, where: f.where, what: `${f.category}: ${f.message}` })),
  ];
  // Open routes are one finding in the gate's report; here each has its own ID.
  const authIds = auth.ids || [];
  out.push(`project : ${projectDir}`);
  if (scan.couldNotRun) out.push(`!! injection could not be checked: ${scan.couldNotRun.join("; ")}`);
  out.push("");
  if (!rows.length && !authIds.length) {
    out.push("No finding of the injection or authentication checks to review.");
  }
  for (const r of rows) {
    out.push(`${r.blocking ? "BLOCKING" : "advisory"}${reviewed.has(r.id) ? ", reviewed" : ""}  ${r.id}`);
    out.push(`    ${r.where} — ${r.what}`);
  }
  for (const id of authIds) {
    out.push(`BLOCKING${reviewed.has(id) ? ", reviewed" : ""}  ${id}`);
    out.push(`    an endpoint that accepts requests from anyone who can reach the service`);
  }
  if (rows.length || authIds.length) {
    out.push("");
    out.push(`To mark one reviewed: wolfproof review ${projectDir} <id> --reason "why it is acceptable"`);
  }
  return scan.couldNotRun ? EXIT.INCOMPLETE : EXIT.OK;
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
  out.push(`${doc.reviewed.length === before ? "replaced" : "added"} in ${file}:`);
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
      code = list(projectDir, out);
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
