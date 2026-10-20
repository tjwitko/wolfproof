#!/usr/bin/env node
// wolfproof — run the full validator suite against a project directory.
//
//   wolfproof <project-dir> [task-file] [--json]
//   wolfproof init ...            set a project up; see bin/init.mjs
//
// Called agent-gate until v1.2.0; that command name is no longer installed since v1.3.0.
//
// Exit codes are the contract and nothing may collapse them:
//   0  nothing blocking
//   1  blocking findings
//   2  usage error
//   3  part of the gate could not run
//
// Exit 3 is the valuable one. "Could not run" is not "passed", and anything consuming this result
// -- a CI job, a required status check, a human reading a summary -- has to be able to tell those
// apart. Two failures here were exactly that confusion: a runner that passed an empty tool registry
// and printed "BLOCKING: none", and a control that connected and was never asked anything for ten
// graded runs while a similarly-named check ran beside it.
import path from "path";
import { readFileSync, realpathSync, existsSync, statSync } from "fs";
import { fileURLToPath } from "url";
import { loadRequirements, checkBaselineInput } from "../lib/requirements.mjs";
import { sourceCoverage, coverageLine } from "../agent/coverage.mjs";
import { splitSentences, unjudgedSentences, alwaysOnCoverage } from "../agent/requirement-sentences.mjs";

import { validateProject, localTools, McpClient } from "../lib/gate-core.mjs";
import { resolveControls, readConfig, CONFIG_FILE } from "../lib/resolve-controls.mjs";
import { toolchain } from "../lib/toolchain.mjs";
import { setting, legacySettingsInUse } from "../lib/settings.mjs";
import {
  resolveBase,
  materializeBase,
  judgeChange,
  declaredOverrides,
  servesHttp,
  readPipelineInput,
  parseAllowlist,
  requirementAtBase,
} from "../lib/factory.mjs";
import { classifyAdvisory, actionFor, ACTIONS, COULD_NOT_RUN, NOT_CHECKED } from "../lib/advisory-classes.mjs";

const EXIT = { CLEAN: 0, BLOCKED: 1, USAGE: 2, INCOMPLETE: 3 };

// Input the gate cannot use. Thrown rather than left to surface as ENOENT, ENOTDIR or EISDIR from
// deep inside -- each of which crashed the process with Node's exit 1, which is this gate's
// "blocked". A mistyped path was reported as a verdict on the project.
export class UsageError extends Error {}

function checkInputs(projectDir, taskFile, baselineFile) {
  if (!existsSync(projectDir)) throw new UsageError(`${projectDir} does not exist`);
  if (!statSync(projectDir).isDirectory()) throw new UsageError(`${projectDir} is not a directory`);
  if (taskFile) {
    if (!existsSync(taskFile)) throw new UsageError(`the task file ${taskFile} does not exist`);
    if (!statSync(taskFile).isFile()) throw new UsageError(`the task file ${taskFile} is not a file`);
  }
  if (baselineFile) {
    const bad = checkBaselineInput(baselineFile);
    if (bad) throw new UsageError(bad);
  }
}

/**
 * The last resort, for anything not foreseen. It returns what to print and the code to exit with,
 * so it can be tested without crashing a process.
 *
 * Exit 3, never Node's default 1. Exit 1 says the gate ran in full and found blocking problems; a
 * gate that fell over did neither. In --json mode it still writes one document, because the Action
 * and the corpus parse stdout, and an empty one made the Action print "? blocking finding(s). The
 * gate ran in full; these are real." -- unless the result was already written, since two documents
 * are as unparseable as none.
 */
export function failClosed(err, { json, wroteResult }) {
  const reason = (err && err.message) || String(err);
  const stderr =
    `wolfproof: the gate itself failed: ${(err && err.stack) || reason}\n` +
    `This is not a verdict on the project. Exit 3: the gate could not run.\n`;
  const stdout =
    json && !wroteResult
      ? `${JSON.stringify({ exitCode: EXIT.INCOMPLETE, incomplete: true, error: `the gate itself failed: ${reason}` })}\n`
      : "";
  return { code: EXIT.INCOMPLETE, stdout, stderr };
}

let wroteResult = false;

/**
 * How many sentences of a requirement text a task-gated check read; of the rest, which an always-on
 * check already blocks on here (`covered`, each with `coveredBy`), and which nothing holds the project
 * to (`unread`, with `notCoveredBecause` where an always-on check would have but cannot here). Null
 * when there is no text. Headings are not counted: they are labels, not requirements.
 */
export function requirementsRead(text, project = {}) {
  if (!text || !text.trim()) return null;
  const sentences = splitSentences(text).filter((s) => !s.heading).length;
  const covered = [];
  const unread = [];
  for (const s of unjudgedSentences(text)) {
    const c = alwaysOnCoverage(s.text, project);
    if (c?.coveredBy) covered.push({ ...s, coveredBy: c.coveredBy });
    else unread.push(c ? { ...s, notCoveredBecause: c.notCoveredBecause } : s);
  }
  return { sentences, read: sentences - covered.length - unread.length, covered, unread };
}

/**
 * The pipeline's own factory inputs, checked before anything runs. A missing, unparseable or
 * in-project allowlist or policy is a usage error: the pipeline is misconfigured, and no verdict on
 * the project should come out of it.
 */
function checkFactoryInputs(projectDir, factory) {
  if (!factory) return { allowlist: { entries: [], ignored: [] }, policy: {} };
  let allowlist = { entries: [], ignored: [] };
  let policy = {};
  if (factory.allowlistFile) {
    const r = readPipelineInput(factory.allowlistFile, "allowlist", projectDir);
    if (r.error) throw new UsageError(r.error);
    allowlist = parseAllowlist(r.value);
  }
  if (factory.policyFile) {
    const r = readPipelineInput(factory.policyFile, "policy", projectDir);
    if (r.error) throw new UsageError(r.error);
    for (const [k, v] of Object.entries((r.value && r.value.advisories) || {})) {
      if (!ACTIONS.has(v)) throw new UsageError(`the policy file says "${k}": "${v}"; each advisory class is "block", "drop" or "incomplete"`);
    }
    policy = r.value || {};
  }
  return { allowlist, policy };
}

export async function runGate(projectDirArg, taskFile, { env = process.env, preCommit = false, baselineFile = null, factory = null } = {}) {
  const projectDir = path.resolve(projectDirArg);
  checkInputs(projectDir, taskFile, baselineFile);
  const { allowlist, policy } = checkFactoryInputs(projectDir, factory);

  // Factory mode needs to know what existed before the change. Resolved first, because the
  // requirements are read as they were there. A base that cannot be established leaves nothing to
  // compare with, which makes the run incomplete -- not blocked, and certainly not clean.
  const factoryFailures = [];
  const factoryCouldNotRun = [];
  const factoryAdvisories = [];
  let base = null;
  if (factory) {
    const b = resolveBase(projectDir, factory.base);
    if (b.error) {
      factoryCouldNotRun.push(
        `factory: ${b.error}, so what predates this change cannot be told apart from what it added. No self-granted exemption was judged, and the requirements were read as they are now.`
      );
    } else {
      const m = materializeBase(projectDir, b.sha);
      if (m.error) factoryCouldNotRun.push(`factory: the base ${b.sha.slice(0, 12)} could not be read — ${m.error}`);
      else base = { ref: factory.base, sha: b.sha, dir: m.dir, empty: m.empty, cleanup: m.cleanup };
    }
  }

  try {
    return await runChecks();
  } finally {
    base?.cleanup();
  }

  async function runChecks() {
    // Several checks are gated on what the task asked for -- immutability, retention, secret rotation
    // and both quality checks stay silent unless the requirement is stated. Without the task text
    // they report "not checked", which is correct and much less useful. The baseline, when there is
    // one, is requirement text from outside the project; see lib/requirements.mjs for why both exist.
    const requirements = loadRequirements(projectDir, taskFile, { preCommit, baselineFile });
    // In factory mode the requirements are the ones that predate the change. A task file the change
    // edited is checked as it was, and the edit blocks: an agent blocked by a requirement can otherwise
    // delete it. One the change added is blocking too -- in a factory, people write the requirements,
    // and a task file that arrived with the code was written by whoever wrote the code.
    if (base) {
      for (const [label, file, key] of [["task file", taskFile, "taskText"], ["baseline", baselineFile, "baselineText"]]) {
        if (!file) continue;
        const at = requirementAtBase(projectDir, base.sha, file);
        if (at.outside) continue;
        if (at.added) {
          factoryFailures.push(
            `factory: the ${label} ${at.rel} was added by this change — it did not exist at the base (${base.sha.slice(0, 12)}). ` +
              `In factory mode the requirements predate the change: they are what the change is judged against, so the change does not get to write them.`
          );
        } else if (at.changed) {
          factoryFailures.push(
            `factory: this change edits the ${label} ${at.rel}, the requirements it is checked against. The code was checked against them as they were at the base ` +
              `(${base.sha.slice(0, 12)}). A requirement is a person's decision; change it on its own, not in the change it would let through.`
          );
          requirements[key] = at.text;
        }
      }
      requirements.text = [requirements.taskText, requirements.baselineText].filter((t) => t.trim()).join("\n\n");
    }
    // When, and with what. osv-scanner answers from a live database, so the same tree and the same
    // pins can give different dependency findings on different days; a report that does not say when it
    // was made cannot be compared with another. The probe runs beside the checks rather than before.
    const scannedAt = new Date().toISOString();
    const tools = toolchain({ env });
    const taskText = requirements.text;

    const { config, error: rawConfigError, file: configFile, note: configNote } = readConfig(projectDir);
    // Factory mode does not read the project's config at all, so a config that cannot be read changes
    // nothing about the run. It is still said.
    const configError = factory ? null : rawConfigError;
    if (factory && rawConfigError) factoryAdvisories.push(`config: ${rawConfigError} Factory mode does not read it.`);
    const controls = resolveControls(projectDir, { config, env, configFile, factory: Boolean(factory) });
    // A control the project tried to choose for itself. The pinned one runs instead, and the attempt
    // blocks: an agent that points secret-guard at an empty directory has not fixed a credential.
    if (factory) {
      for (const o of declaredOverrides(projectDir)) {
        const ran = controls.find((c) => c.name === o.control);
        factoryFailures.push(
          `factory: ${o.file} overrides the ${o.control} control with ${JSON.stringify(o.value)}. In factory mode the pipeline decides what gates ` +
            `the project, so ${ran?.entry ? `the installed control ran instead (${ran.source})` : "the override was not used"}. Remove the override.`
        );
      }
    }

    const registry = new Map();
    const clients = [];
    const unreachable = [];

    // build_check is a local tool rather than an MCP one. It was once omitted for the same reason the
    // MCP tools were: the registry handed to validateProject was empty.
    for (const [name, def] of Object.entries(localTools(projectDir, null))) {
      registry.set(name, { kind: "local", run: def.run });
    }

    for (const c of controls) {
      if (!c.entry) {
        unreachable.push({ name: c.name, provides: c.provides, why: c.error });
        continue;
      }
      try {
        // cwd as well as env: every one of these servers falls back to its startup cwd when its root
        // variable is unset, and callers pass relative targets like ".".
        const client = new McpClient(c.name, "node", [c.entry], { [c.rootVar]: projectDir }, projectDir);
        const tools = await client.init();
        clients.push(client);
        for (const t of tools) {
          if (t.name === "terraform_apply") continue; // never reachable from a validation pass
          registry.set(t.name, { kind: "mcp", server: client, toolName: t.name });
        }
      } catch (err) {
        unreachable.push({ name: c.name, provides: c.provides, why: `${c.source}: ${err && err.message}` });
      }
    }

    const r = await validateProject(projectDir, registry, taskText, { preCommit });
    r.failures.unshift(...requirements.failures);
    r.advisories.unshift(...requirements.advisories);
    if (configNote) r.advisories.unshift(`config: ${configNote}`);
    // Since v1.3.0 only WOLFPROOF_* is read. An AGENT_GATE_* variable left in a pipeline -- a pinned
    // end-of-life date, a hooks path -- has stopped applying, and says so rather than going quiet.
    for (const { name, use } of legacySettingsInUse(env)) {
      r.advisories.unshift(`settings: ${name} is set and no longer read since v1.3.0; set ${use} instead.`);
    }
    for (const c of clients) c.proc?.kill();

    // A server that connected but whose tool the gate never invoked. Not the same as one that could
    // not be reached, and harder to see: identity-guard was spawned by nothing for ten graded runs
    // while every report printed a line called `authentication` -- the in-process route check, a
    // different thing. `provides` is an assertion, not documentation.
    // A tool with nothing to examine did not fail to run. terraform_plan on a project with no
    // Terraform is the common case, and counting it as silent made every such project INCOMPLETE.
    const inapplicable = r.inapplicable || [];
    const outOfScope = new Set(inapplicable.map((i) => i.tool));

    const silent = [];
    for (const c of controls) {
      if (!c.entry || unreachable.some((u) => u.name === c.name)) continue;
      const missing = c.provides.filter(
        (tool) => !outOfScope.has(tool) && !r.ran.some((x) => x === tool || x.startsWith(`${tool}(`))
      );
      if (missing.length) silent.push({ name: c.name, provides: missing });
    }

    // A checker that could not run counts exactly as an unreachable control does. An in-process
    // check is not more trustworthy than an MCP one for being in-process: `build_check` reported
    // blocking "STATIC ERRORS" on any machine without ruff, and read a missing Go toolchain as a
    // pass, and neither showed up here at all.
    const couldNotRun = r.couldNotRun || [];
    const coverage = sourceCoverage(projectDir);
    const alwaysOnContext = { languages: coverage.languages, ran: r.ran, couldNotRun };

    // Factory mode's judgement, after the checks: what the change granted itself, and what every
    // advisory means when nobody reads it. See lib/factory.mjs and lib/advisory-classes.mjs.
    let factoryReport = null;
    if (factory) {
      r.failures.push(...factoryFailures);
      r.advisories.push(...factoryAdvisories);
      couldNotRun.push(...factoryCouldNotRun);
      let judged = { failures: [], notes: [], grants: [], changed: [], newProbeRoutes: [], workflows: [] };
      if (base) {
        judged = judgeChange(projectDir, {
          sha: base.sha,
          baseDir: base.dir,
          allowlist: allowlist.entries,
          secretGuardEntry: controls.find((c) => c.name === "secret-guard")?.entry || null,
          policy,
        });
        r.failures.push(...judged.failures);
      }
      const ctx = { servesHttp: servesHttp(projectDir), couldNotRun: [...couldNotRun] };
      const kept = [];
      const classified = [];
      for (const a of r.advisories) {
        const c = classifyAdvisory(a, ctx);
        const action = actionFor(c, policy);
        classified.push({ id: c.id, class: c.class, action });
        if (action === "block") {
          r.failures.push(
            c.unclassified
              ? `factory: an advisory factory mode cannot classify, so it cannot tell whether it means nothing was checked — ${a}`
              : c.class === NOT_CHECKED
                ? `factory: nothing was checked — ${a}`
                : `factory: blocked by the pipeline's policy (${c.id}) — ${a}`
          );
        } else if (action === "incomplete") {
          couldNotRun.push(`factory: ${a}`);
        } else {
          kept.push(a);
        }
      }
      r.advisories = kept;
      // Code in a language nothing reads. The default mode prints this above the verdict for a reader;
      // here it is a check that could not run against that code, unless the policy accepts it.
      if (coverage.unreadFiles > 0) {
        const action = actionFor({ id: "unread-code", class: COULD_NOT_RUN }, policy);
        classified.push({ id: "unread-code", class: COULD_NOT_RUN, action });
        const line = coverageLine(coverage);
        if (action === "incomplete") couldNotRun.push(`factory: ${line}`);
        else if (action === "block") r.failures.push(`factory: blocked by the pipeline's policy (unread-code) — ${line}`);
      }
      const count = (k) => classified.filter((c) => c.action === k).length;
      factoryReport = {
        base: base ? { ref: base.ref, sha: base.sha, projectExisted: !base.empty } : { ref: factory.base, sha: null },
        allowlist: factory.allowlistFile ? { file: path.resolve(factory.allowlistFile), entries: allowlist.entries.length, ignored: allowlist.ignored } : null,
        policy: factory.policyFile ? path.resolve(factory.policyFile) : null,
        grants: judged.grants.map(({ key, ...g }) => g),
        changedFiles: judged.changed.length,
        newProbeRoutes: judged.newProbeRoutes,
        workflowChanges: judged.workflows,
        notes: judged.notes,
        advisories: { classified, blocked: count("block"), incomplete: count("incomplete"), dropped: count("drop") },
      };
    }

    const incomplete =
      unreachable.length > 0 || silent.length > 0 || couldNotRun.length > 0 || Boolean(configError);
    return {
      factory: factoryReport,
      projectDir,
      taskFile: taskFile || null,
      baseline: requirements.baseline,
      scannedAt,
      // End-of-life dates are judged as of this day instead of the clock when it is set, as the corpus
      // does to keep a frozen verdict from ageing. Recorded so a pinned run does not pass for a live one.
      judgedAsOf: setting(env, "TODAY") || null,
      toolchain: await tools,
      // Which sentences of the requirements switched no check on. A gated-off check says only "not
      // checked", so a requirement nothing recognised was otherwise visible nowhere.
      requirementsRead: {
        task: requirementsRead(requirements.taskText, alwaysOnContext),
        baseline: requirementsRead(requirements.baselineText, alwaysOnContext),
      },
      coverage,
      configError,
      controls,
      ran: r.ran,
      failures: r.failures,
      advisories: r.advisories,
      unreachable,
      silent,
      couldNotRun,
      inapplicable,
      exempt: r.exempt || [],
      incomplete,
      exitCode: incomplete ? EXIT.INCOMPLETE : r.failures.length ? EXIT.BLOCKED : EXIT.CLEAN,
    };
  }
}

function human(result) {
  const out = [];
  out.push(`project        : ${result.projectDir}`);
  out.push(`task text      : ${result.taskFile || (result.baseline ? "NONE — the baseline only" : "NONE — checks gated on the task will report as not checked")}`);
  if (result.baseline) out.push(`baseline       : ${result.baseline}`);
  const taskRead = result.requirementsRead?.task;
  if (taskRead) {
    out.push(
      `task sentences : ${taskRead.sentences}, ${taskRead.read} read by a check, ` +
        `${taskRead.covered.length ? `${taskRead.covered.length} covered by an always-on check, ` : ""}` +
        `${taskRead.unread.length} by none${taskRead.unread.length ? " (--json lists them)" : ""}`
    );
  }
  for (const c of result.controls) {
    const v = c.entry ? (c.version ? `v${c.version}` : "v?").padEnd(8) : "";
    out.push(`control        : ${c.name.padEnd(16)} ${v}${c.entry ? c.source : `NOT RESOLVED — ${c.error}`}`);
  }
  out.push(`validators run : ${result.ran.join(", ")}\n`);

  // Printed before the verdict, deliberately. A reader who stops at "BLOCKING: none" must not be
  // able to miss that a control was absent.
  if (result.configError) out.push(`!! ${result.configError}\n`);
  if (result.unreachable.length) {
    out.push(`!! ${result.unreachable.length} CONTROL(S) COULD NOT BE REACHED — this run is INCOMPLETE`);
    for (const u of result.unreachable) out.push(`   - ${u.name}: ${u.why} — ${u.provides.join(", ")} did NOT run`);
    out.push("");
  }
  if (result.silent.length) {
    out.push(`!! ${result.silent.length} CONTROL(S) CONNECTED AND WERE NEVER CALLED — this run is INCOMPLETE`);
    for (const s of result.silent) out.push(`   - ${s.name} connected, but ${s.provides.join(", ")} was never called`);
    out.push("   A server that starts and is never asked anything reports nothing, which is");
    out.push("   indistinguishable from a server that found nothing.");
    out.push("");
  }
  // A baseline is requirements set from outside the project, by someone who meant every sentence. A
  // sentence of it that no check reads is one the project is not being held to, and the person who
  // wrote it is not the one reading the task file -- so each is printed, above the verdict.
  const baselineUnread = result.requirementsRead?.baseline?.unread || [];
  const baselineCovered = result.requirementsRead?.baseline?.covered || [];
  if (baselineUnread.length) {
    out.push(`!! ${baselineUnread.length} BASELINE SENTENCE(S) NO CHECK READ — the project is not held to these:`);
    for (const s of baselineUnread) out.push(`   - line ${s.line}: ${s.text}${s.notCoveredBecause ? ` (${s.notCoveredBecause})` : ""}`);
    out.push("");
  }
  // Not a warning: each of these is something a check that runs on every project blocks on, and it
  // read this project's code. Listed so the reader can see the baseline was accounted for.
  if (baselineCovered.length) {
    out.push("baseline covered by an always-on check:");
    for (const s of baselineCovered) out.push(`   - line ${s.line}: ${s.text} — ${s.coveredBy}`);
    out.push("");
  }
  // Above the verdict for the same reason as the lines before it: a Rust project exited 0, and the
  // only sign that none of its code was read was one advisory among several.
  const notRead = coverageLine(result.coverage);
  if (notRead) out.push(`!! ${notRead}\n`);

  if (result.couldNotRun.length) {
    out.push(`!! ${result.couldNotRun.length} CHECK(S) COULD NOT RUN — this run is INCOMPLETE`);
    for (const c of result.couldNotRun) out.push(`   - ${c}`);
    out.push("   The code was not checked. That is not the same as the code being fine.");
    out.push("");
  }

  for (const i of result.inapplicable || []) {
    out.push(`not applicable  : ${i.tool} — ${i.why}`);
  }
  for (const e of result.exempt || []) {
    out.push(`exempt          : ${e.path} — ${e.reason} (${e.marker})`);
  }
  if ((result.inapplicable || []).length || (result.exempt || []).length) out.push("");

  // What factory mode compared against and what it decided, above the verdict for the same reason as
  // everything else here. The decisions themselves are in BLOCKING and in the could-not-run list.
  if (result.factory) {
    const f = result.factory;
    const n = (s) => f.grants.filter((g) => g.status === s).length;
    out.push(
      `factory        : base ${f.base.ref}${f.base.sha ? ` (${f.base.sha.slice(0, 12)})` : " — NOT RESOLVED"}; ` +
        `allowlist ${f.allowlist ? f.allowlist.file : "none"}; policy ${f.policy || "none, the defaults"}`
    );
    if (f.grants.length) {
      out.push(`factory grants : ${n("pre-existing")} predate the change, ${n("allowlisted")} allowlisted, ${n("added")} added by it`);
    }
    for (const note of f.notes) out.push(`factory note   : ${note}`);
    for (const i of f.allowlist?.ignored || []) out.push(`factory note   : allowlist entry ignored — it ${i.why}: ${JSON.stringify(i.entry)}`);
    out.push(
      `factory advisories: ${f.advisories.blocked} blocked, ${f.advisories.incomplete} made the run incomplete, ` +
        `${f.advisories.dropped} counted and not blocking (--json lists each with its class)`
    );
    out.push("");
  }

  const qualifier = result.incomplete ? " FROM THE CHECKS THAT RAN (see above)" : "";
  out.push(`BLOCKING        : ${result.failures.length ? result.failures.length : `none${qualifier}`}\n`);
  for (const f of result.failures) out.push(`  - ${f}\n`);
  out.push(`advisory        : ${result.advisories.length || "none"}\n`);
  for (const a of result.advisories) out.push(`  · ${a}\n`);
  return out.join("\n");
}

function machine(result) {
  return JSON.stringify(
    {
      project: result.projectDir,
      taskFile: result.taskFile,
      baseline: result.baseline,
      // Null unless --factory: the base compared against, every self-granted loosening with whether
      // it predates the change, and each advisory's class and what factory mode did with it.
      factory: result.factory,
      scannedAt: result.scannedAt,
      judgedAsOf: result.judgedAsOf,
      // Per requirement text: sentences, how many a check read, and the ones none did.
      requirementsRead: result.requirementsRead,
      notRead: result.coverage.unread,
      coverage: coverageLine(result.coverage),
      exitCode: result.exitCode,
      incomplete: result.incomplete,
      blocking: result.failures.length,
      controls: result.controls.map((c) => ({
        name: c.name,
        provides: c.provides,
        resolvedFrom: c.source,
        version: c.version || null,
        entry: c.entry,
        status: !c.entry
          ? "could-not-run"
          : result.unreachable.some((u) => u.name === c.name) || result.silent.some((s) => s.name === c.name)
            ? "could-not-run"
            : "ran",
        error: c.error || null,
      })),
      // Every tool the checks shell out to, null where it is not on PATH.
      toolchain: result.toolchain,
      validatorsRun: result.ran,
      couldNotRun: result.couldNotRun,
      notApplicable: result.inapplicable,
      exempt: result.exempt,
      findings: result.failures.map((f) => ({ severity: "blocking", message: f })),
      advisories: result.advisories.map((a) => ({ severity: "advisory", message: a })),
    },
    null,
    2
  );
}

const USAGE = `usage: wolfproof <project-dir> [task-file] [--baseline=<file>] [--json] [--pre-commit]
       wolfproof <project-dir> [task-file] --factory --base=<ref> [--allowlist=<file>] [--policy=<file>] ...
       wolfproof init [project-dir] [--hook] [--task <file>] ...   set a project up (--upgrade refreshes it)
       wolfproof --version     this release, its four controls, and the scanners on PATH
       wolfproof --help

exit 0 nothing blocking, 1 blocking findings, 2 usage, 3 part of the gate could not run.

controls resolve from, in order: an env var, ${CONFIG_FILE} in the project,
node_modules, then a sibling checkout. A control that resolves from nowhere exits 3.

--factory is for pipelines where no person reviews the change. Nothing the change grants itself
loosens the gate: controls come only from an env var or node_modules, an exemption or opt-out is
honoured only if it existed at --base or the --allowlist approves it, and an advisory that means
"nothing was checked" blocks. --allowlist and --policy are JSON files outside the project.`;

/**
 * A factory option's value: undefined when absent, null when given without "=value". `--base` is
 * matched whole, so it is never confused with `--baseline`.
 */
function optionValue(args, name) {
  const a = args.find((x) => x === `--${name}` || x.startsWith(`--${name}=`));
  if (a === undefined) return undefined;
  const v = a.slice(`--${name}=`.length);
  return a.startsWith(`--${name}=`) && v ? v : null;
}

async function main() {
  const args = process.argv.slice(2);
  // What you are on, and which controls that brings with it. Answered before anything else, because
  // the first question during an upgrade is whether the upgrade took -- and "the package moved" is
  // not the same answer as "the controls that will run moved". v1.1.1 is the release where they
  // did not.
  if (args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    process.exit(EXIT.CLEAN);
  }
  if (args.includes("--version")) {
    const self = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    console.log(`wolfproof ${self.version}`);
    for (const c of resolveControls(process.cwd())) {
      const v = c.entry ? (c.version ? `v${c.version}` : "v?").padEnd(8) : "".padEnd(8);
      console.log(`  ${c.name.padEnd(16)} ${v}${c.entry ? c.source : `NOT RESOLVED — ${c.error}`}`);
    }
    // The controls are a fraction of what decides a verdict; the scanners they and the checks shell
    // out to are the rest. A missing one is listed as missing -- leaving it out is how a machine
    // without Go came to look like one where Go's checks had passed.
    console.log("tools on PATH");
    for (const [name, v] of Object.entries(await toolchain())) {
      console.log(`  ${name.padEnd(16)} ${v === null ? "not found" : v}`);
    }
    process.exit(EXIT.CLEAN);
  }
  const json = args.includes("--json");
  // Set by the pre-commit hook `wolfproof init` writes. It disables exactly one check, the one
  // whose premise a commit satisfies by existing; everything else runs, and the skip is reported.
  const preCommit = args.includes("--pre-commit");
  const positional = args.filter((a) => !a.startsWith("--"));
  // Requirement text from outside the project, which the project cannot edit. `=` form only: a
  // separate value would be read as the task file.
  const baselineArg = args.find((a) => a.startsWith("--baseline"));
  if (baselineArg !== undefined && !/^--baseline=.+/.test(baselineArg)) {
    console.error("wolfproof: --baseline takes a file: --baseline=<file>");
    process.exit(EXIT.USAGE);
  }
  const baselineFile = baselineArg ? baselineArg.slice("--baseline=".length) : null;
  if (positional.length < 1) {
    console.error(USAGE);
    process.exit(EXIT.USAGE);
  }
  // Factory mode. Its options are refused without it rather than ignored: a pipeline that passes an
  // allowlist and forgets --factory believes it is in a mode it is not in.
  const factoryFlag = args.includes("--factory");
  const factoryOptions = { base: optionValue(args, "base"), allowlist: optionValue(args, "allowlist"), policy: optionValue(args, "policy") };
  const usageExit = (message) => {
    console.error(`wolfproof: ${message}`);
    if (json) process.stdout.write(`${JSON.stringify({ exitCode: EXIT.USAGE, error: message })}\n`);
    process.exit(EXIT.USAGE);
  };
  for (const [name, v] of Object.entries(factoryOptions)) {
    if (v === null) usageExit(`--${name} takes a value: --${name}=<${name === "base" ? "ref" : "file"}>`);
    if (v !== undefined && !factoryFlag) usageExit(`--${name} is a factory-mode option and means nothing without --factory`);
  }
  if (factoryFlag && !factoryOptions.base) {
    usageExit("--factory needs --base=<ref>, the commit the change under test is compared with: a pull request's base, or the commit before a push");
  }
  const factory = factoryFlag
    ? { base: factoryOptions.base, allowlistFile: factoryOptions.allowlist || null, policyFile: factoryOptions.policy || null }
    : null;
  // In --json mode stdout carries exactly one thing: the result document. The validators share
  // their code with the agent loop, which narrates progress to console.log, so a single narration
  // line lands in front of the JSON and makes it unparseable. That is how the corpus first failed
  // on CI -- `[gate] check_dependencies: ... (no lockfile)` wedged ahead of the document, and a
  // SyntaxError pointing at the narration rather than at the gate.
  //
  // Silencing the one line that leaked would leave every other console.log in that shared code one
  // refactor away from doing the same, so stdout is closed to narration for the duration instead.
  // The narration is not discarded -- it goes to stderr, where a human still reads it.
  const narrate = console.log;
  if (json) console.log = (...a) => console.error(...a);
  let result;
  try {
    result = await runGate(positional[0], positional[1], { preCommit, baselineFile, factory });
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    console.log = narrate;
    console.error(`wolfproof: ${err.message}`);
    console.error("usage: wolfproof <project-dir> [task-file] [--baseline=<file>] [--json] [--pre-commit]");
    if (json) process.stdout.write(`${JSON.stringify({ exitCode: EXIT.USAGE, error: err.message })}\n`);
    process.exit(EXIT.USAGE);
  } finally {
    console.log = narrate;
  }
  wroteResult = true;
  process.stdout.write(`${json ? machine(result) : human(result)}\n`);
  process.exit(result.exitCode);
}

// Whether this file was executed rather than imported.
//
// This used `path.resolve(process.argv[1])`, which does not resolve symlinks -- and npm installs a
// bin as a symlink, so `npx agent-gate` had argv[1] pointing at node_modules/.bin/agent-gate while
// import.meta.url pointed at the real file. The comparison was false, main() never ran, and the
// command exited 0 with no output. Silent success, from the entry point of a tool whose whole
// subject is checks that quietly do not run.
//
// Nothing caught it because nothing ran the installed command: the corpus and the GitHub Action
// both invoke `node bin/validate.mjs` by path, which is the one way it worked.
function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    // A path that cannot be resolved is not this file.
    return false;
  }
}

// Anything that escapes main() -- a throw, a rejected promise, an 'error' event nobody listened for
// -- would otherwise end the process with Node's exit 1, which is "blocked".
//
// `init` is handed over before any of that is installed. Setup has its own exit contract -- 70 for
// "failed" -- and the gate's crash handler would turn a setup crash into 3, which means nothing there.
if (invokedDirectly() && process.argv[2] === "init") {
  const { runInit } = await import("./init.mjs");
  await runInit(process.argv.slice(3));
} else if (invokedDirectly()) {
  const json = process.argv.includes("--json");
  const crash = (err) => {
    const r = failClosed(err, { json, wroteResult });
    if (r.stdout) process.stdout.write(r.stdout);
    process.stderr.write(r.stderr);
    process.exit(r.code);
  };
  process.on("uncaughtException", crash);
  process.on("unhandledRejection", crash);
  try {
    await main();
  } catch (err) {
    crash(err);
  }
}
