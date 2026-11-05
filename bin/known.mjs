// wolfproof known: snapshot the findings a project has now, so that only new ones block.
// docs/candidate-rules.md #36, lib/known.mjs.
//
//   wolfproof known <project-dir> [task-file] [--codeql] [--file <path>]
//
// With no snapshot yet, runs the gate and writes every blocking finding that has an ID to the
// project's .wolfproof-known.json, or to --file (one kept outside the project, for --known). With
// one, runs the gate against it and removes the entries that match nothing, unless part of the gate
// could not run: then it changes nothing. It never adds an entry to an existing snapshot: a finding
// that appears later blocks until it is fixed or reviewed.
//
// What it cannot take keeps blocking and is listed: a hardcoded secret, a manifest no scanner read,
// the build, the checks gated on the task, and anything from a check that could not run.
//
// Exit 0, 3 when part of the gate could not run (what it could check is still written), 2 on a usage
// error.

import { existsSync, readFileSync, writeFileSync, statSync } from "fs";
import path from "path";

import { KNOWN_FILE, KNOWN_FAMILIES, familyOf, parseKnown } from "../lib/known.mjs";

const EXIT = { OK: 0, USAGE: 2, INCOMPLETE: 3 };
const USAGE = "usage: wolfproof known <project-dir> [task-file] [--codeql] [--file <path>]";

function option(args, name) {
  const i = args.findIndex((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i < 0) return undefined;
  if (args[i].includes("=")) return args[i].slice(args[i].indexOf("=") + 1) || null;
  return args[i + 1] !== undefined && !args[i + 1].startsWith("--") ? args[i + 1] : null;
}

function positionals(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      if (args[i] === "--file") i++;
      continue;
    }
    out.push(args[i]);
  }
  return out;
}

const shown = (file) => {
  const rel = path.relative(process.cwd(), file);
  return rel && !rel.startsWith("..") ? rel : file;
};

/** How many of each family, for the report: "12 injection, 3 dependency vulnerabilities". */
function byFamily(ids) {
  const n = new Map();
  for (const id of ids) n.set(familyOf(id), (n.get(familyOf(id)) || 0) + 1);
  return [...n].map(([f, c]) => `${c} ${KNOWN_FAMILIES[f]?.what || f}`).join(", ");
}

function document(entries) {
  const one = ({ id, where }) => ({ id, ...(where ? { where } : {}) });
  return `${JSON.stringify({ known: entries.map(one) }, null, 2)}\n`;
}

const entries = (n) => `${n} entr${n === 1 ? "y" : "ies"}`;

// The gate is passed in by bin/validate.mjs, which loads this file while its own top-level code is
// still running: importing it back from here would wait on itself. Called from anywhere else (the
// tests), it is imported.
export async function runKnown(args, { env = process.env, gate = null } = {}) {
  const { runGate, UsageError } = gate || (await import("./validate.mjs"));
  const out = [];
  const err = [];
  const pos = positionals(args);
  const fileArg = option(args, "file");
  const done = (code) => {
    if (out.length) process.stdout.write(`${out.join("\n")}\n`);
    if (err.length) process.stderr.write(`${err.join("\n")}\n`);
    return code;
  };
  if (args.includes("--help")) {
    err.push(USAGE);
    return done(EXIT.OK);
  }
  if (!pos.length || pos.length > 2 || fileArg === null) {
    err.push(USAGE);
    return done(EXIT.USAGE);
  }
  const projectDir = path.resolve(pos[0]);
  if (!existsSync(projectDir) || !statSync(projectDir).isDirectory()) {
    err.push(`wolfproof known: ${pos[0]} is not a directory`);
    return done(EXIT.USAGE);
  }
  const file = fileArg ? path.resolve(fileArg) : path.join(projectDir, KNOWN_FILE);
  const exists = existsSync(file);
  let before = [];
  if (exists) {
    let value;
    try {
      value = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      err.push(`wolfproof known: ${shown(file)} is not valid JSON (${e.message.split("\n")[0]}); fix or remove it first`);
      return done(EXIT.USAGE);
    }
    const parsed = parseKnown(value, KNOWN_FILE);
    if (parsed.ignored.length) {
      err.push(`wolfproof known: ${shown(file)} has ${parsed.ignored.length} entr${parsed.ignored.length === 1 ? "y" : "ies"} it cannot read (the first ${parsed.ignored[0].why}); fix or remove ${parsed.ignored.length === 1 ? "it" : "them"} first`);
      return done(EXIT.USAGE);
    }
    before = parsed.entries;
  }

  let result;
  try {
    result = await runGate(pos[0], pos[1], {
      env,
      codeql: args.includes("--codeql"),
      knownMode: exists ? "file" : "every",
      knownFile: exists ? file : null,
    });
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    err.push(`wolfproof known: ${e.message}`);
    return done(EXIT.USAGE);
  }

  out.push(`project : ${projectDir}`);
  out.push(`snapshot: ${shown(file)}`);
  out.push("");

  let after;
  if (!exists) {
    // Every blocking finding the run set aside as known. A reviewed one is not: its review covers it.
    const seen = new Set();
    after = [];
    for (const k of result.known) {
      if (seen.has(k.id)) continue;
      seen.add(k.id);
      after.push({ id: k.id, where: k.where });
    }
    after.sort((a, b) => a.id.localeCompare(b.id));
    if (!after.length) {
      out.push("No blocking finding the snapshot can hold, so nothing was written.");
    } else {
      writeFileSync(file, document(after));
      out.push(`wrote ${after.length} finding${after.length === 1 ? "" : "s"}: ${byFamily(after.map((e) => e.id))}.`);
    }
  } else if (result.incomplete) {
    // Part of the gate could not run, so an entry matching nothing may only mean the scan that finds
    // it did not finish. Nothing is removed, and nothing added: what would have changed is listed.
    after = before;
    const gone = result.staleKnown.filter((e) => before.some((b) => b.id === e.id));
    out.push(`unchanged: part of the gate could not run (listed below), so no entry was removed or added.`);
    if (gone.length) {
      out.push(`${entries(gone.length)} matched no finding in this run (${byFamily(gone.map((e) => e.id))}) and would have been removed:`);
      for (const e of gone.slice(0, 20)) out.push(`  - ${e.id}`);
      if (gone.length > 20) out.push(`  … ${gone.length - 20} more`);
      out.push("Run it again once every check runs.");
    }
  } else {
    // Shrink only: an entry stays unless a check that ran to the end no longer finds it.
    const stale = new Set(result.staleKnown.map((e) => e.id));
    after = before.filter((e) => !stale.has(e.id));
    const gone = before.filter((e) => stale.has(e.id));
    if (!gone.length) {
      out.push(`unchanged: all ${entries(before.length)} still match a finding, or name one a check that did not run could still hold.`);
    } else {
      writeFileSync(file, document(after));
      out.push(`removed ${entries(gone.length)} matching no finding (${byFamily(gone.map((e) => e.id))}); ${after.length} remain.`);
      for (const e of gone.slice(0, 20)) out.push(`  - ${e.id}`);
      if (gone.length > 20) out.push(`  … ${gone.length - 20} more`);
    }
    out.push("New findings are never added to an existing snapshot: each blocks until it is fixed or reviewed.");
  }

  // What still blocks: the findings no snapshot holds, and new ones when the snapshot existed.
  if (result.failures.length) {
    out.push("");
    out.push(
      `still blocking: ${result.failures.length} finding${result.failures.length === 1 ? "" : "s"} the snapshot ${exists ? "does not hold" : "cannot hold"} —`
    );
    for (const f of result.failures) out.push(`  - ${f.split("\n")[0].slice(0, 200)}`);
    if (!exists) out.push("A hardcoded secret, a manifest no scanner read, the build and the checks gated on the task are never snapshotted.");
  }
  if (result.couldNotRun.length) {
    out.push("");
    out.push(`!! ${result.couldNotRun.length} check(s) could not run, so their findings are not in the snapshot:`);
    for (const c of result.couldNotRun) out.push(`   - ${c.slice(0, 300)}`);
    // An existing snapshot never adds, so what these checks find once they run will block. Measured
    // on CTFd: semgrep timed out on the run that made the snapshot and finished on the next.
    if (!exists) out.push("   Once they run, delete the snapshot and make it again to hold their findings too; an existing snapshot never adds one.");
  }
  if (!exists && after.length) {
    out.push("");
    out.push(
      fileArg
        ? `Pass it to the gate with --known=${shown(file)}, or as the Action's \`known\` input.`
        : `Commit ${KNOWN_FILE}. The gate counts these findings and does not block on them; in factory mode, the pipeline's allowlist has to approve this first snapshot, and an entry a later change adds blocks.`
    );
  }
  return done(result.incomplete ? EXIT.INCOMPLETE : EXIT.OK);
}
