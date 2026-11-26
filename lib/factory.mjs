// Factory mode: nothing the change under test grants itself loosens the gate.
//
// In the default mode every escape hatch is printed for a reader -- a marker's reason, an opt-out's
// reason, the control a project config pointed at. That is right where a person reviews the change,
// and it is no protection at all where nobody does: in a "dark factory", agents write the code and
// the gate's verdict is the review. Measured on v1.3.1 against test/fixtures/factory-scenario.mjs, a
// project with an open purge endpoint, SQL injection and two hardcoded AWS credentials reached exit 0
// through three things an agent can write: routes renamed under a probe path, a one-line
// .tfguard-fixture, and a .wolfproof.json pointing secret-guard at an empty directory. Every one was
// in the report. Nobody read it.
//
// So factory mode compares the tree under test with a base ref -- what existed before the change --
// and refuses what the change added:
//
//   - Controls come from the pipeline (an environment variable) or the gate's own node_modules, never
//     from the project. A project config that overrides one is a blocking finding.
//   - A self-granted loosening -- every kind the gate or a control honours, listed in GRANT_KINDS --
//     is honoured only if it existed at the base, or the pipeline's allowlist (a file outside the
//     project) approves it. One the change added is a blocking finding.
//   - Code the change put where a check does not look -- under an exemption that predates it, in a
//     directory the checks skip, or moved there from somewhere they do look -- is a blocking finding.
//   - The requirements are read as they were at the base. A change that edits them is blocking.
//   - A credential on a line that a commit of the change added blocks, whether or not a later commit
//     removed it: the scan of the tree does not see it, and the commit still holds it
//     (lib/factory-commits.mjs).
//   - A server written into a test name or test directory, which the authentication check skips, is
//     blocking when code outside the tests runs or imports it.
//   - The pipeline is not the change's to edit: a file under .github/workflows or .github/actions that
//     the change added, edited or deleted is blocking, unless the allowlist approves it.
//   - Nor are the agents' instructions: a file that tells coding agents what to do, which hooks run,
//     which tools load and which commands need no asking (AGENT_FILES), added, edited, renamed or
//     deleted, is blocking, unless the allowlist approves it.
//   - A dependency the change adds needs the pipeline's approval: a new name, a new source, a new
//     install script, a range that takes anything (lib/factory-deps.mjs).
//   - Advisories are classified (lib/advisory-classes.mjs) and none may leave the verdict clean by
//     meaning "nothing was checked".
//
// Blocking rather than exit 3 throughout, except where the base itself cannot be established: the
// change made each of these and can undo it, while exit 3 says "fix the environment", which would
// send it to the wrong owner. A base that cannot be resolved is exit 3, because then nothing can be
// told apart from anything.
//
// What it does not do: measure behaviour. Whether the software does what its user needs is scenario
// validation -- holdout end-to-end checks the agents cannot read -- and wolfproof sits beside it.
import { spawnSync } from "child_process";
import { reportedUnread, secretGuardUnread, unreadMatch, unreadWhy } from "./secret-guard-unread.mjs";
import { REVIEW_FILE, loadProjectReviews } from "./reviewed.mjs";
import { KNOWN_FILE, loadProjectKnown } from "./known.mjs";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, statSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { declaredFixtures, FIXTURE_MARKERS } from "../agent/fixture-markers.mjs";
import { SKIP_DIRS } from "../agent/skip-dirs.mjs";
import { gitIgnoresDir } from "../agent/coverage.mjs";
import { checkAuthentication, TEST_FILE, skippedTestDir } from "../agent/authentication.mjs";
import { CONFIG_FILE, LEGACY_CONFIG_FILE } from "./resolve-controls.mjs";
import { actionFor, FINDING } from "./advisory-classes.mjs";
import { DEP_KINDS, findingLine, inventory, judgeDependencies, parseDepEntry, treeOf, withoutCredentials } from "./factory-deps.mjs";

const MAX_BYTES = 1024 * 1024;

function git(cwd, args, opts = {}) {
  const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...opts });
  return { ok: r.status === 0, out: r.stdout || "", err: (r.stderr || "").trim(), raw: r };
}

// Blobs as text, from one `git cat-file --batch`: [[object name, text]], or null when git failed or
// answered something else. `bytes` is their total size, for the buffer.
const BLOB_GROUP_FILES = 2000;
const BLOB_GROUP_BYTES = 64 * 1024 * 1024;
function blobTexts(cwd, oids, bytes) {
  if (!oids.length) return [];
  const r = spawnSync("git", ["-C", cwd, "cat-file", "--batch"], { input: `${oids.join("\n")}\n`, maxBuffer: bytes + oids.length * 256 + 1024 * 1024 });
  if (r.status !== 0 || !r.stdout) return null;
  const out = [];
  let at = 0;
  for (const oid of oids) {
    const nl = r.stdout.indexOf(10, at);
    const m = nl < 0 ? null : /^([0-9a-f]+) blob (\d+)$/.exec(r.stdout.subarray(at, nl).toString("latin1"));
    if (!m || m[1] !== oid) return null;
    const size = Number(m[2]);
    out.push([oid, r.stdout.subarray(nl + 1, nl + 1 + size).toString("utf8")]);
    at = nl + 1 + size + 1;
  }
  return out;
}

function real(p) {
  try {
    return realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/** Whether `p` is inside `dir` (not equal to it), comparing real paths. */
export function isInside(dir, p) {
  const rel = path.relative(real(dir), real(p));
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

// ---------------------------------------------------------------------------------------------
// The base

/**
 * The commit `ref` names, as seen from the project. { sha } or { error }.
 *
 * A shallow checkout -- actions/checkout fetches depth 1 by default -- has no parent and usually no
 * PR base, and that is the common way this fails. The message says what to fetch.
 */
export function resolveBase(projectDir, ref) {
  if (!ref) return { error: "no base ref was given" };
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]);
  if (!top.ok) return { error: `${projectDir} is not inside a git repository, so there is no history to compare against` };
  const r = git(projectDir, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  if (!r.ok) {
    const shallow = git(projectDir, ["rev-parse", "--is-shallow-repository"]).out.trim() === "true";
    // A relative ref (HEAD~1) cannot be fetched by name; the history it walks has to be deepened.
    // Measured against a depth-1 clone of this repository: `--deepen=1` made HEAD~1 resolve, and
    // `--depth=1 origin <sha>` made a three-commits-older base resolve, with nothing in between.
    const fetch = /[~^]/.test(ref) ? "git fetch --no-tags --deepen=1 origin" : `git fetch --no-tags --depth=1 origin ${ref}`;
    return {
      error:
        `the base ref ${ref} is not in this checkout` +
        (shallow ? ` -- the clone is shallow, so only the commits it was cloned with are present. Fetch the base first: \`${fetch}\`` : ""),
    };
  }
  return { sha: r.out.trim() };
}

/**
 * The project as it was at `sha`, extracted into a temporary directory -- only the project's own
 * subtree when it is a subdirectory of the repository. `empty` when the project did not exist then,
 * in which case everything in it is the change. Call `cleanup()` when done.
 */
export function materializeBase(projectDir, sha) {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-base-"));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  const prefix = git(projectDir, ["rev-parse", "--show-prefix"]).out.trim().replace(/\/$/, "");
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]).out.trim();
  const treeish = prefix ? `${sha}:${prefix}` : sha;
  if (!git(projectDir, ["cat-file", "-e", treeish]).ok) return { dir, empty: true, cleanup };
  // From the repository's top, not the project's directory: run in a subdirectory, git archive takes
  // that directory as a pathspec inside the tree it was given, and archived nothing.
  const archive = spawnSync("git", ["-C", top, "archive", "--format=tar", treeish], { maxBuffer: 1024 * 1024 * 1024 });
  if (archive.status !== 0) {
    cleanup();
    return { error: `git archive of ${treeish} failed: ${String(archive.stderr || "").trim().split("\n")[0]}` };
  }
  const untar = spawnSync("tar", ["-x", "-C", dir], { input: archive.stdout, maxBuffer: 64 * 1024 * 1024 });
  if (untar.status !== 0) {
    cleanup();
    return { error: `extracting the base failed: ${String(untar.stderr || "").trim().split("\n")[0]}` };
  }
  return { dir, empty: false, cleanup };
}

/**
 * What the change did, relative to the project: [{ status: "A"|"M"|"D"|"R", path, from? }]. The
 * working tree against the base, so an uncommitted edit counts, plus untracked files as added.
 */
function nameStatus(out) {
  const changes = [];
  const parts = out.split("\0").filter(Boolean);
  for (let i = 0; i < parts.length; ) {
    const status = parts[i++];
    if (status.startsWith("R") || status.startsWith("C")) {
      const from = parts[i++];
      const to = parts[i++];
      changes.push({ status: status[0], path: to, from });
    } else {
      changes.push({ status: status[0], path: parts[i++] });
    }
  }
  return changes;
}

export function changesSinceBase(projectDir, sha) {
  const diff = git(projectDir, ["diff", "--name-status", "-M", "--relative", "-z", sha]);
  const out = diff.ok ? nameStatus(diff.out) : [];
  for (const f of git(projectDir, ["ls-files", "--others", "--exclude-standard", "-z"]).out.split("\0").filter(Boolean)) {
    out.push({ status: "A", path: f });
  }
  return out;
}

// The workflows, and the local actions they call: a step that says `uses: ./.github/actions/gate` runs
// whatever that directory holds, so editing the action edits the workflow without touching it.
export const PIPELINE_DIRS = [".github/workflows", ".github/actions"];

/**
 * The files under .github/workflows or .github/actions the change added, edited, renamed or deleted,
 * with paths from the repository root. Read at the root rather than the project, because that is the
 * only place GitHub runs workflows from: a project in a subdirectory is built by workflows outside it.
 */
export function workflowChanges(projectDir, sha) {
  const spec = PIPELINE_DIRS.map((d) => `:(top)${d}`);
  const diff = git(projectDir, ["diff", "--name-status", "-M", "-z", sha, "--", ...spec]);
  const out = diff.ok ? nameStatus(diff.out) : [];
  const untracked = git(projectDir, ["ls-files", "--others", "--exclude-standard", "--full-name", "-z", "--", ...spec]);
  for (const f of untracked.out.split("\0").filter(Boolean)) out.push({ status: "A", path: f });
  return out;
}

// ---------------------------------------------------------------------------------------------
// The files that instruct coding agents

/**
 * What counts, each with why. Names are compared without regard to letter case, at any depth: a
 * checkout on a case-insensitive filesystem reads claude.md as CLAUDE.md, and an agent started in
 * packages/api reads the files there. Every name was checked against the tool's own documentation
 * on 2026-11-19 (docs/factory-mode.md names the pages), except two older names their tools' pages
 * no longer mention and older projects still carry: .cursorrules and .github/chatmodes.
 *
 * Not here: a Claude Code plugin's own files (.claude-plugin/, and the agents/, commands/, skills/
 * and hooks/ directories beside it). They instruct agents wherever the plugin is installed, not the
 * agents working in this repository, and in a plugin's repository they are the deliverable.
 *
 * `name`: a file with this name. `dir`: everything under a directory with this name. `under`: a
 * path that follows a directory with the first name.
 */
export const AGENT_FILES = [
  { name: "AGENTS.md", why: "the instructions Codex, Cursor, Copilot, Gemini CLI and Claude Code read, the nearest one to the work first" },
  { name: "AGENTS.override.md", why: "read by Codex before the AGENTS.md beside it" },
  { name: "AGENT.md", why: "the older name of AGENTS.md, which agents.md still tells projects to link to it" },
  { name: "CLAUDE.md", why: "Claude Code's instructions, loaded from the working directory, every directory above it and each subdirectory it works in; Copilot reads the one at the root" },
  { name: "CLAUDE.local.md", why: "loaded by Claude Code beside CLAUDE.md and treated the same way" },
  { name: "GEMINI.md", why: "Gemini CLI's context file, read from the working directory, its parents and its subdirectories; Copilot reads the one at the root" },
  { name: ".mcp.json", why: "the MCP servers Claude Code and VS Code start for the project: the tools the agent is given, and commands run to start them" },
  { name: ".cursorrules", why: "Cursor's older rules file" },
  { dir: ".claude", why: "Claude Code's project directory: settings.json (permission rules, hooks, environment), rules, skills, commands, subagents, output styles and workflows" },
  { dir: ".cursor", why: "Cursor's project directory: rules, hooks.json and the scripts it runs, mcp.json and commands" },
  { dir: ".gemini", why: "Gemini CLI's project directory: settings.json (hooks, MCP servers), commands, a system prompt override and its .env" },
  { dir: ".codex", why: "Codex's project configuration (config.toml)" },
  { dir: ".agents", why: "skills that Copilot and Codex load (.agents/skills)" },
  { under: [".github", "copilot-instructions.md"], why: "Copilot's instructions for the whole repository" },
  { under: [".github", "instructions"], why: "Copilot's path-specific instructions (*.instructions.md)" },
  { under: [".github", "prompts"], why: "Copilot's prompt files" },
  { under: [".github", "agents"], why: "Copilot's custom agents" },
  { under: [".github", "chatmodes"], why: "Copilot's custom chat modes in VS Code, the older form of its custom agents" },
  { under: [".github", "skills"], why: "Copilot's agent skills" },
  { under: [".github", "hooks"], why: "Copilot's hooks, which run commands during an agent's session" },
  { under: [".vscode", "mcp.json"], why: "the MCP servers VS Code's older local agent starts" },
];

/** The AGENT_FILES entry a path (from the repository's top) falls under, or null. */
export function agentFile(rel) {
  const parts = String(rel).normalize("NFC").toLowerCase().split("/");
  const last = parts[parts.length - 1];
  for (const e of AGENT_FILES) {
    if (e.name && last === e.name.toLowerCase()) return e;
    if (e.dir && parts.includes(e.dir.toLowerCase())) return e;
    if (e.under) {
      const [a, b] = e.under.map((x) => x.toLowerCase());
      if (parts.some((p, i) => p === a && parts[i + 1] === b)) return e;
    }
  }
  return null;
}

// `@path` in an instruction file imports another file into what the agent is told (Claude Code, in
// CLAUDE.md, AGENTS.md and rules; Gemini CLI, in GEMINI.md). Outside code spans and fences, as
// Claude Code reads it, and up to four hops.
const IMPORT_HOPS = 4;
const TEXT_FILE = /\.(md|mdc|markdown|txt)$/i;
function importsOf(text) {
  const prose = text.replace(/^(```|~~~)[\s\S]*?^\1[^\n]*$/gm, "").replace(/`[^`\n]*`/g, "");
  const out = [];
  // A path is everything up to the first space, and a backslash before a space keeps the space
  // (Claude Code's memory page, "Import additional files"). Any other character is part of it:
  // @docs/c++/guide.md is one path. Prose puts a full stop or a comma after a path, so the path is
  // tried as written and without it; the caller keeps whichever names a file that is there.
  for (const m of prose.matchAll(/@((?:\\ |[^\s\\]|\\(?! ))+)/g)) {
    const raw = m[1].replace(/\\ /g, " ");
    if (raw.startsWith("~") || raw.startsWith("/")) continue; // outside the repository
    out.push(raw);
    const trimmed = raw.replace(/[.,;:!?)\]]+$/, "");
    if (trimmed && trimmed !== raw) out.push(trimmed);
  }
  return out;
}

const fromTop = (dir, target) => {
  const rel = path.posix.normalize(path.posix.join(dir, target));
  return rel === "." || rel.startsWith("../") || rel === ".." || path.posix.isAbsolute(target) ? null : rel;
};

/**
 * The paths that are not agent files by name and still decide what an agent is told, because an
 * agent file links to them or imports them: Map(path from the top -> the agent file it is reached
 * from). `read(rel)` gives { link } for a symbolic link's target, { text } for a file it read,
 * { dir } for a directory, {} for any other file, or null for a path that is not there.
 * `under(rel)` gives every file and link below a directory, without following a link.
 *
 * A link's target counts whole, so one to a directory covers what is under it. Each hop of a chain
 * of links counts, and imports are followed IMPORT_HOPS deep.
 *
 * What is under a linked directory is read like the agent file that led there, so a link inside it
 * is followed and an import in one of its files counts. Measured on 4a8b674, no finding for any of
 * these: .claude/rules linked to notes, and notes/more linked to a directory the change wrote a
 * file in; the same with a tracked file the change edited; notes/more.md linked to a file; and
 * notes/a.md importing one.
 *
 * Every path is settled first: a link anywhere in it is followed, so "@notes/more/x.md", where
 * notes/more is a link to shared, is shared/x.md. That is the path git tracks and a diff names. On
 * 4a8b674 the path as written was kept, so an edit to shared/x.md was not seen, and with nothing
 * changed at all notes/more/x.md was reported as a file git does not track.
 */
function reachedFrom(paths, read, under, prefetch = null) {
  const reached = new Map();
  // { at, links, there, linked }: `at` is the path with every link in it followed, or null when a
  // link leads out of the repository or the chain is too long; `links` the links passed on the way;
  // `there` whether anything is at the end; `linked` whether the last step was a link.
  const settle = (rel) => {
    const links = [];
    let parts = rel.split("/");
    let at = "";
    let linked = false;
    for (let i = 0; i < parts.length; i++) {
      const here = at ? `${at}/${parts[i]}` : parts[i];
      const got = read(here);
      if (got?.link !== undefined) {
        links.push(here);
        const to = links.length > 16 ? null : fromTop(at, got.link);
        if (!to) return { at: null, links, there: false, linked: true };
        if (i === parts.length - 1) linked = true;
        parts = [...to.split("/"), ...parts.slice(i + 1)];
        at = "";
        i = -1;
        continue;
      }
      if (!got) return { at: [here, ...parts.slice(i + 1)].join("/"), links, there: false, linked };
      at = here;
    }
    return { at, links, there: true, linked };
  };
  // With a reader that pays for each file it reads, as the base's tree does with a git process,
  // everything the walk below will read is asked for first, a hop at a time for every agent file
  // together, so the reader can fetch each hop in one go. This walks the same paths as the loop
  // below and decides nothing: what a path is reached from is still settled there, an agent file at
  // a time. A path this misses is read singly, so only time depends on it.
  if (prefetch) {
    const warmed = new Set();
    let wave = paths.filter((p) => agentFile(p));
    for (let hop = 0; hop <= IMPORT_HOPS && wave.length; hop++) {
      prefetch(wave);
      const files = [];
      for (let i = 0; i < wave.length; i++) {
        const s = settle(wave[i]);
        if (!s.at || !s.there || warmed.has(s.at)) continue;
        warmed.add(s.at);
        if (read(s.at)?.dir) {
          const below = under(s.at);
          prefetch(below);
          wave.push(...below);
        } else if (TEXT_FILE.test(s.at)) files.push(s.at);
      }
      prefetch(files);
      const next = [];
      for (const at of files) {
        const got = read(at);
        if (typeof got?.text !== "string") continue;
        for (const imp of importsOf(got.text)) {
          const to = fromTop(path.posix.dirname(at), imp);
          if (to) next.push(to);
        }
      }
      wave = next;
    }
  }
  for (const start of paths) {
    if (!agentFile(start)) continue;
    const mark = (p) => {
      if (p && !agentFile(p) && !reached.has(p)) reached.set(p, start);
    };
    const seen = new Set();
    let frontier = [start];
    for (let hop = 0; hop <= IMPORT_HOPS && frontier.length; hop++) {
      const next = [];
      // The list grows while it is read: what is under a linked directory joins it at the same hop.
      for (let i = 0; i < frontier.length; i++) {
        const s = settle(frontier[i]);
        // The links from here, each one a path that decides what is read, and where they end: a
        // target that is not there yet counts too, since the change can write it.
        for (const l of s.links) mark(l);
        if (s.links.length) mark(s.at);
        if (!s.at || !s.there || seen.has(s.at)) continue;
        seen.add(s.at);
        const got = read(s.at);
        if (got?.dir) {
          frontier.push(...under(s.at));
          continue;
        }
        if (typeof got?.text !== "string" || !TEXT_FILE.test(s.at)) continue;
        for (const imp of importsOf(got.text)) {
          const to = fromTop(path.posix.dirname(s.at), imp);
          // A file that is there: `@name` in prose is as often a person or a package as a path.
          const t = to && settle(to);
          if (!t?.at || !t.there || (read(t.at)?.dir && !t.linked)) continue;
          for (const l of t.links) mark(l);
          mark(t.at);
          if (hop < IMPORT_HOPS) next.push(to);
        }
      }
      frontier = next;
    }
  }
  return reached;
}

/**
 * Every agent file on disk under `top`, tracked or not and whatever any ignore file says, as paths
 * from the top. Read from the disk and not from `git ls-files`, for two reasons.
 *
 * One: `--exclude-standard` reads the machine's own ignore files. Measured on 53bfaad, ten corpus
 * fixtures hold .claude/settings.local.json; on a machine whose global excludes file ignores that
 * name the listing did not see it, and CI's did, so the same tree gave two verdicts.
 *
 * Two: an ignore rule is the change's to write. Measured on 53bfaad, a change that added ".claude/"
 * to .gitignore and wrote a .claude/settings.json allowing every shell command exited 0. In CI that
 * file is never committed; in a workspace kept between runs it is live for the next agent run. So
 * for these names what is on disk is judged, and factory mode expects a fresh checkout: a file a
 * person keeps there untracked counts as the change's.
 *
 * Not descended into: .git, and the dependency and build trees the checks skip (SKIP_DIRS). An
 * installed node_modules holds other projects' AGENTS.md files by the hundred, none of them this
 * change's. A tracked file there still counts, through the diff.
 *
 * Inside an agent directory only .git is skipped: the agent reads all of .claude, and a skill can be
 * named "build". Measured on 4b4ece2, with .claude/ ignored: .claude/skills/deploy/SKILL.md written
 * by the change was listed, and .claude/skills/build/SKILL.md, .claude/commands/dist/x.md and
 * .claude/rules/venv/x.md were not.
 */
function agentFilesOnDisk(top) {
  const out = [];
  const go = (dir, rel, inside) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === ".git" || (!inside && SKIP_DIRS.has(e.name))) continue;
      const at = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) go(path.join(dir, e.name), at, inside || Boolean(agentFile(at)));
      else if (agentFile(at)) out.push(at);
    }
  };
  go(top, "", false);
  return out;
}

/**
 * The files that instruct coding agents which the change added, edited, renamed or deleted, with
 * paths from the repository's top: [{ status, path, from?, via?, untracked? }]. `via` names the
 * agent file a path is reached from when it is not one by name. Read at the top and not at the
 * project, since an agent working in a subdirectory is told what the files above it say.
 *
 * No listing here reads .git/info/exclude or the user's global excludes file, so the same tree
 * gives the same answer on every machine.
 */
export function agentFileChanges(projectDir, sha) {
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]).out.trim();
  if (!top) return [];
  const list = (args) => git(top, args).out.split("\0").filter(Boolean);
  const diff = git(top, ["diff", "--name-status", "-M", "-z", sha]);
  const changes = diff.ok ? nameStatus(diff.out) : [];
  const seen = new Set(changes.map((c) => c.path));
  const add = (f) => {
    if (seen.has(f)) return;
    seen.add(f);
    changes.push({ status: "A", path: f, untracked: true });
  };
  // Untracked files the tree's own .gitignore files do not ignore: what a link or an import may reach.
  for (const f of list(["ls-files", "--others", "--exclude-per-directory=.gitignore", "--full-name", "-z"])) add(f);
  // And the agent files on disk that git does not track, ignored or not.
  const tracked = new Set(list(["ls-files", "--full-name", "-z"]));
  const onDisk = agentFilesOnDisk(top);
  for (const f of onDisk) if (!tracked.has(f)) add(f);

  // What the agent files reach, in the working tree and as the base had them: an edit to a file the
  // base's CLAUDE.md linked to counts, and so does one to a file the change's CLAUDE.md links to.
  // Each answer is kept: a path is asked about once for each path that runs through it.
  const kept = (read) => {
    const answers = new Map();
    return (rel) => {
      if (!answers.has(rel)) answers.set(rel, read(rel));
      return answers.get(rel);
    };
  };
  const readNow = kept((rel) => {
    try {
      const full = path.join(top, rel);
      const st = lstatSync(full);
      if (st.isSymbolicLink()) return { link: readlinkSync(full).split(path.sep).join("/") };
      if (st.isDirectory()) return { dir: true };
      return st.isFile() && st.size <= MAX_BYTES && TEXT_FILE.test(rel) ? { text: readFileSync(full, "utf8") } : {};
    } catch {
      return null;
    }
  });
  const tree = new Map();
  for (const entry of list(["ls-tree", "-r", "-l", "-z", sha])) {
    const tab = entry.indexOf("\t");
    const [mode, type, oid, size] = entry.slice(0, tab).split(/ +/);
    tree.set(entry.slice(tab + 1), { mode, oid, blob: type === "blob", size: Number(size) || 0 });
  }
  const dirsThen = new Set([...tree.keys()].flatMap((p) => p.split("/").slice(0, -1).map((_, i, a) => a.slice(0, i + 1).join("/"))));
  // The base's links and text files, read with one `git cat-file --batch` for each group asked for
  // and not one git process a file. Measured on 54d6808, agentFileChanges alone, on a change with a
  // diff: 600 tracked .md files in .claude took 10.7 s, and so did 600 under a linked directory;
  // 4,000 took about 90 s through the CLI. A file's type comes from the tree and costs nothing, so
  // its text is read when it is asked for, which is when its imports are.
  const blobs = new Map(); // object name -> its text, or null when git could not give it
  const read1 = (e) => {
    if (!blobs.has(e.oid)) {
      const blob = git(top, ["cat-file", "blob", e.oid]);
      blobs.set(e.oid, blob.ok ? blob.out : null);
    }
    return blobs.get(e.oid);
  };
  const links = [...tree].filter(([, e]) => e.mode === "120000").map(([rel]) => rel);
  let linksRead = false;
  const prefetchThen = (rels) => {
    const want = new Map();
    const ask = (rel) => {
      const e = tree.get(rel);
      if (e && e.blob && (e.mode === "120000" || TEXT_FILE.test(rel)) && !blobs.has(e.oid)) want.set(e.oid, e.size);
    };
    // Every link the base holds, the first time: following a path asks about each part of it.
    if (!linksRead) links.forEach(ask);
    linksRead = true;
    rels.forEach(ask);
    const all = [...want];
    for (let i = 0; i < all.length; ) {
      const group = [];
      let bytes = 0;
      while (i < all.length && group.length < BLOB_GROUP_FILES && (!group.length || bytes + all[i][1] <= BLOB_GROUP_BYTES)) {
        group.push(all[i][0]);
        bytes += all[i][1];
        i++;
      }
      // A group git could not give is left unread, and each of its files is then read singly.
      for (const [oid, text] of blobTexts(top, group, bytes) || []) blobs.set(oid, text);
    }
  };
  const readThen = kept((rel) => {
    const e = tree.get(rel);
    if (!e) return dirsThen.has(rel) ? { dir: true } : null;
    if (e.mode === "120000") {
      const to = read1(e);
      return to === null ? {} : { link: to };
    }
    if (!TEXT_FILE.test(rel)) return {};
    return {
      get text() {
        const text = read1(e);
        return text === null ? undefined : text;
      },
    };
  });
  const underThen = (rel) => [...tree.keys()].filter((p) => p.startsWith(`${rel}/`));
  // What an agent file on disk links to or imports, and git does not track, is the change's too, like
  // an untracked agent file: it is what the next agent run is told, and no diff shows it. Measured on
  // aebaa2b, exit 0 with no finding: the base's CLAUDE.md said "@notes/local.md", the base's
  // .gitignore held "notes/", and the change wrote notes/local.md. A link's target can be a
  // directory, and then every file under it counts.
  //
  // filesUnder lists a link as a file and does not go through it: reachedFrom follows it, and what
  // it leads to is in reachedNow under its own path.
  //
  // Only .git is skipped. The names the tree-wide search skips (SKIP_DIRS) are the wrong filter for
  // a directory an agent file links to, since the agent reads all of it. Measured on 4b4ece2, with
  // .claude/rules linked to an ignored local-rules: local-rules/push.md written by the change was
  // listed, and local-rules/build/push.md and local-rules/dist/x.md were not.
  const filesUnder = (rel) => {
    const out = [];
    const go = (at) => {
      let entries;
      try {
        entries = readdirSync(path.join(top, at), { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (e.name === ".git") continue;
        if (e.isDirectory()) go(`${at}/${e.name}`);
        else out.push(`${at}/${e.name}`);
      }
    };
    go(rel);
    return out;
  };
  const reachedNow = reachedFrom(onDisk, readNow, filesUnder);
  for (const target of reachedNow.keys()) {
    const got = readNow(target);
    if (!got) continue;
    for (const f of got.dir ? filesUnder(target) : [target]) if (!tracked.has(f)) add(f);
  }
  if (!changes.length) return [];
  const reached = new Map([...reachedFrom([...tree.keys()], readThen, underThen, prefetchThen), ...reachedNow]);
  const via = (rel) => {
    if (!rel) return null;
    for (const [target, start] of reached) if (rel === target || rel.startsWith(`${target}/`)) return start;
    return null;
  };
  const out = [];
  for (const c of changes) {
    // `ends`: each end of the change that is an agent file. A rename has two, and the allowlist has
    // to approve every one of them (judgeChange).
    const ends = [c.path, c.from].filter((p) => p && (agentFile(p) || via(p)));
    if (!ends.length) continue;
    const reachedBy = agentFile(c.path) || (c.from && agentFile(c.from)) ? null : via(c.path) || via(c.from);
    out.push({ ...c, ends, ...(reachedBy ? { via: reachedBy } : {}) });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The files a tree holds

function walk(root) {
  const out = [];
  const go = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === ".git") continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) go(full);
      else if (e.isFile()) out.push(path.relative(root, full).split(path.sep).join("/"));
    }
  };
  go(root);
  return out;
}

/**
 * The project's files, as relative paths. In a repository, what git sees -- tracked, plus untracked
 * files that are not ignored -- so an installed node_modules is not read as the project. Otherwise
 * (an extracted base), every file.
 */
export function projectFiles(root) {
  const ls = git(root, ["ls-files", "-co", "--exclude-standard", "-z"]);
  if (ls.ok && git(root, ["rev-parse", "--show-toplevel"]).ok) return ls.out.split("\0").filter(Boolean);
  return walk(root);
}

function readText(root, rel) {
  const full = path.join(root, rel);
  try {
    const st = statSync(full);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const buf = readFileSync(full);
    if (buf.includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// Self-granted loosenings

/**
 * Every way a project can narrow what a check looks at, and what each one narrows. Found by reading
 * every check and control, and each one that is a real escape was confirmed against the gate:
 * gitleaks:allow and a .gitleaksignore carrying the findings' fingerprints each removed both
 * credential findings; an osv-scanner.toml PackageOverrides entry took four blocking CVEs to exit 0;
 * `# noqa` and a ruff.toml extend-exclude each cleared an undefined name.
 *
 * Not here, because nothing honours them: a project .gitleaks.toml (secret-guard passes its own -c),
 * `nosemgrep` and .semgrepignore (sast passes --disable-nosem and its own file list), a pyproject
 * `ignore` for F rules (the gate's --select F wins). A .gitignore hides no file from a check (sast
 * passes --no-git-ignore), with one exception the gate itself honours: a directory it cannot list
 * (`ignored-directory`, see ignoredDirGrants).
 */
export const GRANT_KINDS = {
  "fixture-marker": "a .tfguard-fixture or .identity-exception, which takes a whole directory out of every source check and out of terraform-guard's and identity-guard's scans",
  "identity-guard:allow": "an inline opt-out from one identity-guard rule",
  "gitleaks:allow": "an inline comment gitleaks skips a line for",
  ".gitleaksignore": "fingerprints of credential findings secret-guard then ignores (read at the project root)",
  "osv-scanner.toml": "vulnerabilities or whole packages osv-scanner ignores, beside the lockfile it scans",
  "noqa": "a `# noqa` that hides a Python static-check finding",
  "ruff config": "a ruff.toml, .ruff.toml or pyproject [tool.ruff] section the Python static check reads -- extend-exclude in it hides whole directories",
  "checkov:skip": "an inline checkov skip, hiding findings the pipeline's policy blocks",
  "checkov config": "a .checkov.yaml or .checkov.yml checkov reads, hiding findings the pipeline's policy blocks",
  "changed-under-exemption": "code the change wrote inside a directory an exemption that predates it covers",
  "skipped-location": "code the change wrote where the checks do not look: a directory every source check skips, or a path secret-guard's scan does not read",
  "moved-to-unchecked": "code the change moved from where a check looks to where it does not",
  "server-in-test": "an HTTP server written into a test-named file or a test directory, which the authentication check skips, that code outside the tests runs or imports",
  "workflow-change": "an edit to the pipeline itself: a file under .github/workflows, or under .github/actions where its local actions live, added, changed, renamed or deleted",
  "agent-instructions":
    "an edit to a file that instructs the coding agents working in the repository (AGENT_FILES): what the next run is told, which hooks run, which tools it loads and which commands it may run without asking",
  "reviewed-finding": "an entry in .wolfproof-reviewed.json, which takes one named finding out of the verdict",
  "known-finding": "an entry in .wolfproof-known.json, the snapshot of findings that predate it, which takes one named finding out of the verdict",
  "secret-in-commit":
    "a credential on a line that a commit between the base and the head added, whether or not a later commit removed it (lib/factory-commits.mjs); the allowlist approves the file it is in",
  "ignored-directory":
    "an ignore rule over a directory the gate cannot list, which takes that directory out of could-not-run with no check having read what is in it",
  "known-declared":
    "a package name in the `declared` list of the snapshot's entry for a package.json with no lockfile, the record of what it declared when the snapshot was taken, " +
    "which `wolfproof known` reads to decide whether a lockfile's findings predate the change that commits it",
  // Not loosenings the project grants itself but additions it makes, approved the same way: by an
  // entry that names the package and its ecosystem, never by path and never by "*" (lib/factory-deps.mjs).
  ...DEP_KINDS,
};

const COMMENT_GRANTS = [
  { kind: "gitleaks:allow", re: /gitleaks:allow/, applies: () => true },
  { kind: "identity-guard:allow", re: /identity-guard:allow\b/, applies: () => true },
  { kind: "noqa", re: /#\s*(?:ruff:\s*)?noqa\b/i, applies: (rel) => rel.endsWith(".py") },
  { kind: "checkov:skip", re: /checkov:skip=/i, applies: () => true },
];

const isComment = (line) => !line || /^\s*(#|;|\/\/)/.test(line);

function configLines(kind, rel, text) {
  const out = [];
  const lines = text.split("\n");
  if (kind === "ruff config" && path.posix.basename(rel) === "pyproject.toml") {
    let inRuff = false;
    lines.forEach((l, i) => {
      const t = l.trim();
      if (/^\[/.test(t)) inRuff = /^\[+\s*tool\.ruff\b/.test(t);
      if (inRuff && t && !isComment(t)) out.push({ line: i + 1, text: t });
    });
    return out;
  }
  lines.forEach((l, i) => {
    const t = l.trim();
    if (t && !isComment(t)) out.push({ line: i + 1, text: t });
  });
  return out;
}

function configKind(rel) {
  const base = path.posix.basename(rel);
  if (rel === ".gitleaksignore") return ".gitleaksignore";
  if (base === "osv-scanner.toml") return "osv-scanner.toml";
  if (base === "ruff.toml" || base === ".ruff.toml" || base === "pyproject.toml") return "ruff config";
  if (base === ".checkov.yaml" || base === ".checkov.yml") return "checkov config";
  return null;
}

/**
 * Every self-granted loosening in a tree: [{ kind, key, path, line?, text? }]. `key` is what is
 * compared with the base, so it holds the line's text: the same `gitleaks:allow` on a line whose
 * credential changed is a new grant, because it now covers something else.
 */
export function inventoryGrants(root, files = projectFiles(root)) {
  const grants = [];
  for (const f of declaredFixtures(root)) {
    grants.push({ kind: "fixture-marker", key: `fixture-marker|${f.path}`, path: f.path, text: `${f.marker}: ${f.reason}`, marker: f.marker });
  }
  // One grant per reviewed finding. The key holds the ID and the expiry: a later date on the same
  // finding extends what the change grants itself, so it is a new grant like any other.
  for (const e of loadProjectReviews(root).entries) {
    grants.push({ kind: "reviewed-finding", key: `reviewed-finding|${e.id}|${e.expires || ""}`, path: REVIEW_FILE, text: `${e.id}: ${e.reason}` });
  }
  // One grant per snapshot entry. An entry that was there at the base is a finding that predates the
  // change; one the change adds is the change setting its own finding aside, and blocks.
  for (const e of loadProjectKnown(root).entries) {
    grants.push({ kind: "known-finding", key: `known-finding|${e.id}`, path: KNOWN_FILE, text: e.id });
  }
  for (const rel of files) {
    const kind = configKind(rel);
    if (kind) {
      const text = readText(root, rel);
      if (text !== null) {
        for (const l of configLines(kind, rel, text)) {
          grants.push({ kind, key: `${kind}|${rel}|${l.text}`, path: rel, line: l.line, text: l.text });
        }
      }
    }
    const applicable = COMMENT_GRANTS.filter((c) => c.applies(rel));
    if (!applicable.length) continue;
    const text = readText(root, rel);
    if (text === null) continue;
    if (!applicable.some((c) => c.re.test(text))) continue;
    text.split("\n").forEach((l, i) => {
      for (const c of applicable) {
        if (c.re.test(l)) grants.push({ kind: c.kind, key: `${c.kind}|${rel}|${l.trim()}`, path: rel, line: i + 1, text: l.trim().slice(0, 200) });
      }
    });
  }
  return grants;
}

/** The paths the secret-guard that will run does not read (lib/secret-guard-unread.mjs). */
export function secretGuardAllowlist(secretGuardEntry) {
  return secretGuardUnread(secretGuardEntry).patterns;
}

// Kinds the scan skips for what a file is called, wherever it is. Approving the directory of one
// would approve every file of any name written there later, so the message asks for the file.
const BY_NAME = new Set(["rule-file", "image", "font", "binary", "gem", "archive"]);

/** Where a path sits that some check does not look, or null. */
export function uncheckedLocation(rel, { gitleaksAllow = [] } = {}) {
  const parts = rel.split("/");
  const dirs = parts.slice(0, -1);
  const skipped = dirs.find((d) => SKIP_DIRS.has(d));
  if (skipped) return { where: dirs.slice(0, dirs.indexOf(skipped) + 1).join("/"), why: `every source check skips ${skipped}/` };
  const gl = unreadMatch(rel, gitleaksAllow);
  if (gl) {
    const why =
      gl.unreadKind === "archive"
        ? "secret-guard does not read a file whose name says it is an archive, whatever it holds"
        : `secret-guard's gitleaks allowlist does not scan it (${gl.unreadKind || gl.source})`;
    return { where: dirs.join("/") || ".", why, byName: BY_NAME.has(gl.unreadKind) };
  }
  return null;
}

/**
 * What the change wrote that the tree's scan says it left unread, and the name list does not cover:
 * a file skipped for its first bytes. Called after the checks, because that scan is one of them.
 * Files a commit scan has already reported are not said twice. With no `unread` there is nothing to
 * judge: the run has said why (`secretUnreadUnanswered` from validateProject, or the scan's own failure).
 *
 * @returns {{ failures: string[], unread: object[], error?: string }}
 */
export function unreadWrites(projectDir, { changed = [], unread, allowlist = [], gitleaksAllow = [], reportedByCommits = new Set() }) {
  if (unread === undefined || unread === null) return { failures: [], unread: [] };
  const said = reportedUnread(unread, realpathSync(projectDir));
  if (said.error) return { failures: [], unread: [], error: `secret-guard's scan of the tree: ${said.error}` };
  const hits = [];
  for (const c of changed) {
    if (c.status === "D" || reportedByCommits.has(c.path) || uncheckedLocation(c.path, { gitleaksAllow })) continue;
    const u = said.at(c.path);
    if (u && !allowlisted({ kind: "skipped-location", path: c.path }, allowlist)) hits.push({ path: c.path, why: unreadWhy(u) });
  }
  const failures = hits.length
    ? [
        `factory: ${hits.length} file(s) this change wrote that secret-guard's scan did not read — ${hits.slice(0, 8).map((h) => `${h.path}: ${h.why}`).join("; ")}${hits.length > 8 ? `, +${hits.length - 8} more` : ""}. ` +
          `Nothing read ${hits.length === 1 ? "it" : "them"} for credentials. If it is text, change how it begins; if it is a binary file the pipeline expects, have the pipeline's allowlist approve ${hits.length === 1 ? "the file" : "each file"} by its path (kind "skipped-location").`,
      ]
    : [];
  return { failures, unread: hits };
}

// Files that name a test file without running it as the service: documentation, and the configuration
// of test runners, linters and compilers. package.json is read without its test scripts.
const NOT_A_RUNNER = /\.(?:md|markdown|rst|txt|adoc)$|(?:^|\/)(?:tsconfig|jsconfig)[^/]*\.json$|(?:^|\/)(?:jest|vitest|karma|mocha|playwright|cypress|eslint)\.config\.[^/]+$|(?:^|\/)\.(?:mocharc|eslintrc)[^/]*$|(?:^|\/)(?:pytest\.ini|conftest\.py|tox\.ini|setup\.cfg)$/;

/**
 * The files outside the tests that refer to `rel` -- a start script, a Dockerfile CMD, a Procfile, an
 * import from application code. A server in a test file is ordinary when only tests use it (a stub
 * upstream, an app built inline for supertest); referred to from here, it is the service.
 */
function referencedOutsideTests(root, rel, files) {
  const parts = rel.split("/");
  const noExt = (p) => p.replace(/\.[^./]+$/, "");
  const needles = new Set([noExt(parts[parts.length - 1])]);
  const skipped = skippedTestDir(rel);
  if (skipped) {
    const testDir = skipped.split("/").length - 2;
    needles.add(noExt(parts.slice(testDir).join("/")));
  }
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const res = [...needles].map((n) => new RegExp(`(?<![A-Za-z0-9_])${esc(n)}(?![A-Za-z0-9_-])`));
  const by = [];
  for (const f of files) {
    if (f === rel || authUnchecked(f) || NOT_A_RUNNER.test(f)) continue;
    const fp = f.split("/");
    if (fp[0] === ".github" || fp.some((p) => SKIP_DIRS.has(p))) continue;
    let text = readText(root, f);
    if (!text) continue;
    if (fp[fp.length - 1] === "package.json") {
      try {
        const pkg = JSON.parse(text);
        for (const k of Object.keys(pkg.scripts || {})) if (/^(?:pre|post)?test(?:$|[:-])/.test(k)) delete pkg.scripts[k];
        text = JSON.stringify(pkg);
      } catch {
        /* read as text */
      }
    }
    if (res.some((re) => re.test(text))) by.push(f);
  }
  return by;
}

function authUnchecked(rel) {
  const parts = rel.split("/");
  const testDir = skippedTestDir(rel);
  if (testDir) return `the authentication check skips ${testDir}`;
  if (TEST_FILE.test(parts[parts.length - 1])) return "the authentication check skips files named as tests";
  return null;
}

// ---------------------------------------------------------------------------------------------
// The project's own claims about what gates it

/** Every control a project config file overrides: [{ file, control, value }]. Both names are read. */
export function declaredOverrides(projectDir) {
  const out = [];
  for (const file of [CONFIG_FILE, LEGACY_CONFIG_FILE]) {
    const full = path.join(projectDir, file);
    if (!existsSync(full)) continue;
    let cfg;
    try {
      cfg = JSON.parse(readFileSync(full, "utf8"));
    } catch {
      continue;
    }
    for (const [control, value] of Object.entries((cfg && cfg.controls) || {})) out.push({ file, control, value });
  }
  return out;
}

// Evidence a project starts an HTTP server. Test files and test directories are not evidence: a
// library's tests that stand up an Express app to exercise a client are not a service.
const SERVES_HTTP = [
  /require\(\s*["'](?:express|koa|fastify|@hapi\/hapi|hapi|restify|hono)["']\s*\)|from\s+["'](?:express|koa|fastify|@hapi\/hapi|hapi|restify|hono|@nestjs\/core)["']|\bhttps?\.createServer\s*\(/,
  /\bfrom\s+(?:flask|fastapi|starlette|aiohttp)\b|\bimport\s+(?:flask|fastapi)\b|\bFastAPI\s*\(|\bFlask\s*\(\s*__name__|\bdjango\.urls\b|\bhttp\.server\b|\buvicorn\.run\b/,
  /"net\/http"|\bhttp\.ListenAndServe|\bgin\.(?:Default|New)\(|\becho\.New\(|\bfiber\.New\(|\bchi\.NewRouter\(/,
  /@RestController|@SpringBootApplication|\bextends\s+HttpServlet\b|(?:javax|jakarta)\.ws\.rs/,
  /\bSinatra\b|\bRails\.application\b|require\s+["']sinatra["']/,
  /\bWebApplication\.CreateBuilder\b|\[ApiController\]|\.Map(?:Get|Post|Put|Delete)\s*\(/,
  /\baxum::|\bactix_web\b|\bwarp::|\brocket::/,
  /\bhttplib::Server\b|\bcrow::SimpleApp\b|\bdrogon::app\b/,
];
const CODE_EXT = /\.(?:[mc]?[jt]sx?|py|go|java|rb|cs|rs|c|cc|cpp|cxx|h|hpp)$/;

export function servesHttp(root, files = projectFiles(root)) {
  // Code under a declared fixture is out of scope for every check, so it is not evidence either: a
  // service whose server sits in an honoured exemption is one the authentication check was told to
  // leave alone, and reading it here would block on the exemption the base already granted.
  const exempt = declaredFixtures(root).map((f) => f.path);
  for (const rel of files) {
    if (!CODE_EXT.test(rel)) continue;
    if (exempt.some((d) => under(rel, d))) continue;
    const parts = rel.split("/");
    if (parts.some((p) => SKIP_DIRS.has(p) || p === "test" || p === "tests" || p === "spec") || skippedTestDir(rel)) continue;
    if (TEST_FILE.test(parts[parts.length - 1])) continue;
    const text = readText(root, rel);
    if (text && SERVES_HTTP.some((re) => re.test(text))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// The pipeline's own inputs: an allowlist and a policy, both outside the project

/**
 * A JSON input factory mode reads -- the allowlist or the policy. It must exist, parse, and live
 * outside the project: one the change can edit approves whatever the change likes. Returns
 * { value } or { error } (a usage error: the pipeline's configuration, not the change, is wrong).
 */
export function readPipelineInput(file, label, projectDir) {
  if (!existsSync(file)) return { error: `the ${label} file ${file} does not exist` };
  if (!statSync(file).isFile()) return { error: `the ${label} file ${file} is not a file` };
  if (isInside(projectDir, file)) {
    return { error: `the ${label} file ${file} is inside the project, so the change under test could edit it. In factory mode it must live outside the project` };
  }
  try {
    return { value: JSON.parse(readFileSync(file, "utf8")) };
  } catch (err) {
    return { error: `the ${label} file ${file} could not be parsed as JSON: ${err.message}` };
  }
}

/**
 * The allowlist's usable entries and the ones it ignored. An entry approves grants of its `kind` at
 * its `path` or anywhere under it, and needs a `reason` -- the same rule a fixture marker follows:
 * an approval that does not say what it is for does not exist.
 */
export function parseAllowlist(value) {
  const entries = [];
  const ignored = [];
  for (const e of (value && value.exemptions) || []) {
    // A dependency is approved by name and ecosystem, and `path`, when given, narrows the entry to a
    // manifest or a directory (lib/factory-deps.mjs).
    if (e && typeof e.kind === "string" && Object.hasOwn(DEP_KINDS, e.kind)) {
      const r = parseDepEntry(e);
      if (r.error) ignored.push({ entry: e, why: r.error });
      else entries.push(r.entry);
      continue;
    }
    if (!e || typeof e.kind !== "string" || typeof e.path !== "string") {
      ignored.push({ entry: e, why: "needs a kind and a path" });
    } else if (!(e.kind in GRANT_KINDS) && e.kind !== "*") {
      ignored.push({ entry: e, why: `unknown kind "${e.kind}"` });
    } else if (e.kind === "known-declared") {
      // Never approved (declaredAdded, below), so an entry for it would sit there approving nothing.
      ignored.push({ entry: e, why: `names a kind no allowlist approves: a name added to the declared list of a snapshot entry that existed at the base blocks whatever it says` });
    } else if (!e.reason || !String(e.reason).trim()) {
      ignored.push({ entry: e, why: "gives no reason" });
    } else {
      entries.push({ kind: e.kind, path: e.path.replace(/^\.\/|\/$/g, "") || ".", reason: String(e.reason) });
    }
  }
  return { entries, ignored };
}

function under(p, dir) {
  return dir === "." || p === dir || p.startsWith(`${dir}/`);
}

export function allowlisted(grant, entries) {
  return entries.find((e) => !Object.hasOwn(DEP_KINDS, e.kind) && (e.kind === "*" || e.kind === grant.kind) && under(grant.path, e.path)) || null;
}

// ---------------------------------------------------------------------------------------------
// Requirements as they were

/**
 * The text of a requirement file (the task file, or a baseline inside the project) as it was at the
 * base, and whether the change touched it. { outside } for a file outside the repository, which the
 * change cannot edit and which is read as it is.
 */
export function requirementAtBase(projectDir, sha, file) {
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]);
  if (!top.ok) return { outside: true };
  const root = real(top.out.trim());
  const abs = real(file);
  if (!isInside(root, abs)) return { outside: true };
  const rel = path.relative(root, abs).split(path.sep).join("/");
  const before = git(root, ["show", `${sha}:${rel}`]);
  const now = existsSync(abs) ? readFileSync(abs, "utf8") : null;
  if (!before.ok) return { rel, added: true, text: "" };
  return { rel, text: before.out, changed: now !== before.out };
}

// ---------------------------------------------------------------------------------------------
// The judgement

const short = (sha) => sha.slice(0, 12);

/**
 * Compares the project with its base and returns what factory mode refuses: { failures, notes,
 * grants, changed, newProbeRoutes }. `failures` are blocking findings; `notes` are reported and do
 * not block.
 */
// A checkov skip hides checkov findings, which are advisories: they never block in default mode, and
// in factory mode only when the pipeline's policy says so. Blocking the skip whatever the policy
// says would treat hiding a finding as worse than the finding itself, so an added skip blocks only
// when the findings it hides would: the policy's action for the advisory id of what the file is.
// .checkov.yaml hides the same findings, project-wide, and is judged the same way.
const CHECKOV_GRANTS = new Set(["checkov:skip", "checkov config"]);
const CONFIG_GRANT_FILES = new Set([".checkov.yaml", ".checkov.yml"]);
function checkovAdvisoryId(rel) {
  const base = path.posix.basename(rel);
  if (/^Dockerfile|\.Dockerfile$|\.dockerfile$/i.test(base)) return "dockerfile-checkov";
  if (/\.(tf|tfvars)$/i.test(base) || CONFIG_GRANT_FILES.has(base)) return "checkov";
  return "iac-checkov";
}

/** Whether an added checkov grant blocks under the pipeline's policy, with the advisory id it follows. */
export function checkovGrantBlocks(grant, policy = {}) {
  const id = checkovAdvisoryId(grant.path);
  const action = actionFor({ id, class: FINDING }, policy);
  return { id, blocks: action === "block" || action === "incomplete" };
}

/**
 * Names a change added to the `declared` list of a snapshot entry that was at the base, as grants.
 *
 * The entry for a package.json with no lockfile records what it declared when the snapshot was
 * taken, and `wolfproof known` adds a new lockfile's findings only while the package.json declares
 * nothing else (lib/gate-core.mjs, the relock). The command reads the list from the snapshot as it
 * is on disk, so a change that declares a dependency, commits the lockfile and writes the name into
 * the list is not refused, and the entry's own grant is keyed by its ID, which did not change. Each
 * added name is therefore a grant of its own, and one no allowlist approves: the entry existed at
 * the base, so the snapshot did, and the allowlist approves only the first snapshot. A list the
 * base's entry did not have counts whole, because an entry without one adds nothing. A name
 * removed, or the list removed, grants nothing: the command then refuses more. An entry the change
 * adds is not looked at here; its own grant covers its list.
 */
function declaredAdded(projectDir, baseDir) {
  const base = new Map(loadProjectKnown(baseDir).entries.map((e) => [e.id, e]));
  const out = [];
  for (const e of loadProjectKnown(projectDir).entries) {
    const was = base.get(e.id);
    if (!was || !e.id.startsWith("dependencies:unlocked:") || !Array.isArray(e.declared)) continue;
    const had = new Set(Array.isArray(was.declared) ? was.declared : []);
    for (const name of new Set(e.declared)) {
      if (!had.has(name)) out.push({ kind: "known-declared", key: `known-declared|${e.id}|${name}`, path: KNOWN_FILE, text: `${e.id}: ${name}`, status: "added" });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// A directory the gate cannot list, set aside by an ignore rule the change wrote

/**
 * The ignore files git tracked at `sha`, written under a temporary directory at their paths from
 * the repository's top, and nothing else. Asked there, `git check-ignore` answers from the base's
 * tracked rules, plus .git/info/exclude and the user's global excludes, which it reads from the
 * repository and the configuration as it does anywhere: a change carries neither. A .gitignore that
 * was a symbolic link is left out, as git itself does not follow one.
 */
// A path with no empty, "." or ".." part: one that stays under the directory it is joined onto.
export const plainPath = (rel) => typeof rel === "string" && rel !== "" && !path.isAbsolute(rel) && rel.split(/[\\/]/).every((part) => part !== "" && part !== "." && part !== "..");

function baseIgnoreTree(top, sha) {
  const listed = git(top, ["ls-tree", "-r", "-z", sha]);
  if (!listed.ok) return { error: `git ls-tree of ${short(sha)} failed: ${listed.err.split("\n")[0]}` };
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-base-ignore-"));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  for (const entry of listed.out.split("\0").filter(Boolean)) {
    const tab = entry.indexOf("\t");
    const [mode, type, oid] = entry.slice(0, tab).split(" ");
    const rel = entry.slice(tab + 1);
    if (type !== "blob" || mode === "120000" || path.posix.basename(rel) !== ".gitignore") continue;
    // A tree object can hold a name git never checks out, and `ls-tree -r` prints it as it is.
    // Measured on 7f56106, a base with a tree named ".." and a project in a subdirectory (whose
    // archive is of its own subtree, so `git archive` did not refuse it): .gitignore was written
    // beside the temporary directory.
    if (!plainPath(rel)) {
      cleanup();
      return { error: `${short(sha)} holds an ignore file at ${rel}, a path git does not check out` };
    }
    const blob = spawnSync("git", ["-C", top, "cat-file", "blob", oid], { maxBuffer: 64 * 1024 * 1024 });
    if (blob.status !== 0) {
      cleanup();
      return { error: `reading ${rel} at ${short(sha)} failed: ${String(blob.stderr || "").trim().split("\n")[0]}` };
    }
    mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), blob.stdout);
  }
  return { dir, cleanup };
}

/**
 * The directories the gate could not list and git ignores (`unreadDirs` with `ignored`, from the
 * run's coverage), each as a grant: "pre-existing" when the base's ignore rules already ignored it,
 * "allowlisted" when the pipeline approves the directory by path, and otherwise "added" -- the
 * change's own ignore rule is what set it aside.
 *
 * The gate honours an ignore rule in exactly one place: a directory it cannot list, which git
 * ignores and tracks nothing under, is a line above the verdict where any other is could-not-run
 * (agent/coverage.mjs). Since v1.16.6 factory mode drops that line, so a change that wrote the rule
 * took its own run from exit 3 to exit 0 and nothing named the rule. Measured on v1.16.6: a second
 * commit adding `vendor_src/` to .gitignore, with vendor_src at mode 000, exit 0 with BLOCKING none.
 *
 * Decided by asking git the same question against the base's ignore files, in a temporary tree
 * that holds them and the directory itself (makeInBaseTree), not by whether the change touched one: a pipeline beside a database's volume would otherwise block on every unrelated
 * ignore edit, and a removed negation or a new nested .gitignore would pass. The working tree is
 * what is compared with the base, so an ignore line that is not committed counts like one that is.
 *
 * Blocking, like every other grant: the change wrote the rule and can remove it. `error` instead
 * when the base's ignore files cannot be read or the question cannot be asked of them, which is
 * could-not-run.
 *
 * @returns {{ grants: object[], failures: string[], error?: string }}
 */
/**
 * Make `target` (from the repository's top) a directory in the temporary tree, or say why not.
 *
 * Git applies a directory-only pattern to the path it is asked about only when that path is a
 * directory on disk. Measured on 7f56106 with a base that ignored everything (`*`) and then took
 * every directory back out (the same pattern negated, with a trailing slash): in a tree without
 * vendor_src/ the negation was skipped and `*` won, so `check-ignore -q -- vendor_src/` exited 0
 * there and 1 once the directory existed. A change that removed the negation then read as
 * "pre-existing", exit 0.
 *
 * The tree holds only what baseIgnoreTree wrote, plain directories and .gitignore files, so a
 * plain path cannot leave it through a link. A .gitignore file on the path means the base tracked
 * an ignore file where a directory is now, and removing it would change the rules being asked.
 */
function makeInBaseTree(treeDir, target) {
  if (!plainPath(target)) return `${target}/ is not a path under the repository's top`;
  const parts = target.split(/[\\/]/);
  for (let i = 1; i <= parts.length; i++) {
    const at = parts.slice(0, i).join("/");
    if (parts[i - 1] === ".gitignore" && statSync(path.join(treeDir, at), { throwIfNoEntry: false })?.isFile()) {
      return `the base tracked an ignore file at ${at}, which is a directory now, so its rules cannot be asked about a directory there`;
    }
  }
  try {
    mkdirSync(path.join(treeDir, target), { recursive: true });
  } catch (e) {
    return `${target}/ could not be made in a temporary directory (${e?.code || e?.message})`;
  }
  return null;
}

export function ignoredDirGrants(projectDir, sha, unreadDirs = [], allowlist = []) {
  const dirs = unreadDirs.filter((d) => d.ignored);
  if (!dirs.length) return { grants: [], failures: [] };
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]).out.trim();
  const prefix = git(projectDir, ["rev-parse", "--show-prefix"]).out.trim();
  const gitDir = git(projectDir, ["rev-parse", "--absolute-git-dir"]).out.trim();
  const tree = baseIgnoreTree(top, sha);
  if (tree.error) return { grants: [], failures: [], error: `the base's ignore files could not be read, so whether this change is what ignores ${dirs.map((d) => `${d.dir}/`).join(", ")} is not known — ${tree.error}` };
  const grants = [];
  try {
    for (const d of dirs) {
      const unasked = makeInBaseTree(tree.dir, `${prefix}${d.dir}`);
      if (unasked) return { grants: [], failures: [], error: `whether the ignore rules at the base (${short(sha)}) already ignored ${d.dir}/ could not be asked, so whether this change is what ignores it is not known — ${unasked}` };
      const target = `${prefix}${d.dir}`;
      // The same question the run asked of the working tree (ignoredByGit), of the base's rules.
      const atBase = gitIgnoresDir(["--git-dir", gitDir, "--work-tree", tree.dir, "-C", tree.dir], target);
      // Which rule ignores the directory now: "<file>:<line>:<pattern>\t<path>", the file from the repository's top.
      const now = git(top, ["check-ignore", "-v", "--", target]).out.split("\n")[0];
      const m = /^(.*?):(\d+):(.*)\t/.exec(now);
      const file = m ? (path.isAbsolute(m[1]) && isInside(gitDir, m[1]) ? path.join(".git", path.relative(gitDir, m[1])) : m[1]) : null;
      const rule = m ? { file, line: Number(m[2]), pattern: m[3] } : null;
      const g = { kind: "ignored-directory", key: `ignored-directory|${d.dir}`, path: d.dir, text: rule ? `${rule.file}:${rule.line}: ${rule.pattern}` : "an ignore rule git did not name", ...(rule ? { ignoreFile: rule.file } : {}) };
      const approved = atBase ? null : allowlisted(g, allowlist);
      grants.push({ ...g, status: atBase ? "pre-existing" : approved ? "allowlisted" : "added", ...(approved ? { approvedBy: approved.reason } : {}) });
    }
  } finally {
    tree.cleanup();
  }
  const added = grants.filter((g) => g.status === "added");
  if (!added.length) return { grants, failures: [] };
  const where = added.map((g) => `${g.path}/ (${g.text})`);
  const one = added.length === 1;
  return {
    grants,
    failures: [
      `factory: ${added.length} ignored-directory grant(s) this change added — ${where.slice(0, 8).join(", ")}${where.length > 8 ? `, +${where.length - 8} more` : ""}. ` +
        `Each is ${GRANT_KINDS["ignored-directory"]}, and the ignore rules at the base (${short(sha)}) did not ignore ${one ? "it" : "them"}. ` +
        `In factory mode the change does not get to narrow what checks it: remove the rule and make the director${one ? "y" : "ies"} readable by the user the gate runs as, ` +
        `or have the pipeline's allowlist approve ${one ? "it" : "them"} by path.`,
    ],
  };
}

export function judgeChange(projectDir, { sha, baseDir, allowlist = [], secretGuardEntry = null, policy = {} }) {
  const failures = [];
  const notes = [];
  const gitleaksAllow = secretGuardAllowlist(secretGuardEntry);

  // Self-granted loosenings: pre-existing ones are honoured, allowlisted ones are honoured, the rest
  // were granted by the change.
  const now = inventoryGrants(projectDir);
  const before = new Set(inventoryGrants(baseDir).map((g) => g.key));
  // The allowlist approves snapshot entries only in the change that writes the first snapshot. Once
  // one exists, an entry a change adds is that change setting its own finding aside, and an approval
  // left in place from the first snapshot would let every later change do it.
  const baseSnapshot = existsSync(path.join(baseDir, KNOWN_FILE));
  const grants = now.map((g) => {
    const approved = g.kind === "known-finding" && baseSnapshot ? null : allowlisted(g, allowlist);
    const status = before.has(g.key) ? "pre-existing" : approved ? "allowlisted" : "added";
    return { ...g, status, ...(approved ? { approvedBy: approved.reason } : {}) };
  });
  grants.push(...declaredAdded(projectDir, baseDir));
  const added = grants.filter((g) => {
    if (g.status !== "added" || !CHECKOV_GRANTS.has(g.kind)) return g.status === "added";
    const { id, blocks } = checkovGrantBlocks(g, policy);
    if (!blocks) {
      notes.push(
        `a ${g.kind} this change added, not blocking: ${g.line ? `${g.path}:${g.line}` : g.path}. It hides ${id} findings, which the ` +
          `pipeline's policy does not block, so hiding them is not blocking either.`
      );
    }
    return blocks;
  });
  const byKind = new Map();
  for (const g of added) byKind.set(g.kind, [...(byKind.get(g.kind) || []), g]);
  for (const [kind, list] of byKind) {
    const where = list.map((g) =>
      g.line ? `${g.path}:${g.line}` : g.kind === "fixture-marker" ? `${g.path}/${g.marker}` : g.kind === "reviewed-finding" ? `${g.path} (${g.text.split(": ")[0]})` : g.kind === "known-finding" || g.kind === "known-declared" ? `${g.path} (${g.text})` : g.path
    );
    const it = list.length === 1 ? "it" : "them";
    const remedy =
      kind === "known-declared"
        ? `or review those findings. A lockfile committed with a dependency the list did not hold brings findings that are this ` +
          `change's own, and with the name in the list \`wolfproof known\` adds them to the snapshot as if they predated it. The allowlist ` +
          `does not approve a name added to an entry that existed at the base; a pipeline that keeps its own snapshot passes it with --known.`
        : kind === "known-finding" && baseSnapshot
          ? `or review ${it}. The allowlist approves snapshot entries only in the change that writes the first snapshot, and ${KNOWN_FILE} ` +
            `existed at the base; a pipeline that keeps its own snapshot passes it with --known.`
          : `or have the pipeline's allowlist approve ${it}.`;
    const hiding = kind === "known-declared" ? "what the lockfile's scan finds" : `what ${list.length === 1 ? "it was" : "they were"} hiding`;
    failures.push(
      `factory: ${list.length} ${kind} grant(s) this change added — ${where.slice(0, 8).join(", ")}${where.length > 8 ? `, +${where.length - 8} more` : ""}. ` +
        `Each is ${GRANT_KINDS[kind]}, and none of them existed at the base (${short(sha)}). In factory mode the change does not get ` +
        `to narrow what checks it: remove ${it} and fix ${hiding}, ${remedy}`
    );
  }

  // Code the change wrote where a check does not look.
  const changed = changesSinceBase(projectDir, sha).filter((c) => c.status !== "D");
  const exemptDirs = grants.filter((g) => g.kind === "fixture-marker" && g.status === "pre-existing").map((g) => g.path);
  const isMarker = (rel) => FIXTURE_MARKERS.includes(path.posix.basename(rel));
  const flagged = (kind, rel) => !allowlisted({ kind, path: rel }, allowlist);

  // An allowlisted exemption is approved whole, code written under it included: approving a marker
  // is approving the directory it covers.
  const underExemption = new Map();
  for (const c of changed) {
    if (isMarker(c.path)) continue;
    const dir = exemptDirs.find((d) => under(c.path, d));
    if (!dir || allowlisted({ kind: "fixture-marker", path: dir }, allowlist)) continue;
    if (flagged("changed-under-exemption", c.path)) underExemption.set(dir, [...(underExemption.get(dir) || []), c.path]);
  }
  for (const [dir, files] of underExemption) {
    failures.push(
      `factory: ${files.length} file(s) changed under ${dir}, which an exemption that predates this change takes out of the checks — ` +
        `${files.slice(0, 8).join(", ")}${files.length > 8 ? `, +${files.length - 8} more` : ""}. The exemption existed at the base; this code ` +
        `did not, and nothing has checked it. Move it out of ${dir}, or have the pipeline's allowlist approve ${dir}.`
    );
  }

  const skipped = new Map();
  for (const c of changed) {
    const loc = uncheckedLocation(c.path, { gitleaksAllow });
    if (loc && flagged("skipped-location", c.path)) {
      const k = `${loc.where}|${loc.why}`;
      skipped.set(k, { ...loc, files: [...((skipped.get(k) || {}).files || []), c.path] });
    }
  }
  for (const s of skipped.values()) {
    const list = `${s.files.slice(0, 8).join(", ")}${s.files.length > 8 ? `, +${s.files.length - 8} more` : ""}`;
    failures.push(
      s.byName
        ? `factory: ${s.files.length} file(s) this change wrote under ${s.where === "." ? "the project's top" : s.where}, where ${s.why} — ${list}. ` +
            `Nothing read ${s.files.length === 1 ? "it" : "them"} for credentials. Give a text file a name the scan reads, or have the pipeline's allowlist ` +
            `approve ${s.files.length === 1 ? "the file" : "each file"} by its path (kind "skipped-location").`
        : `factory: ${s.files.length} file(s) this change wrote under ${s.where}, where ${s.why} — ${list}. Nothing checked this code. ` +
            `Put it where the checks look, or have the pipeline's allowlist approve ${s.where}.`
    );
  }

  for (const c of changed.filter((x) => x.status === "R" && x.from)) {
    const fromLoc = uncheckedLocation(c.from, { gitleaksAllow }) || authUnchecked(c.from);
    const toLoc = uncheckedLocation(c.path, { gitleaksAllow });
    const toAuth = authUnchecked(c.path);
    if (fromLoc || (!toLoc && !toAuth)) continue;
    if (!flagged("moved-to-unchecked", c.path)) continue;
    // An unchecked location is already reported above; a move into a test name or test directory
    // narrows only the authentication check, and is reported here.
    if (toLoc) continue;
    failures.push(
      `factory: this change moved ${c.from} to ${c.path}, where ${toAuth}. Moving code out of a check's view is not a fix; ` +
        `move it back, or have the pipeline's allowlist approve ${c.path}.`
    );
  }

  // A server written straight into a test name or test directory. A move there is refused above; one
  // written there from the start was skipped by the authentication check and not flagged at all. Only
  // when something outside the tests runs it: a test that builds a server is ordinary.
  let files = null;
  for (const c of changed.filter((x) => x.status === "A" || x.status === "M")) {
    const why = authUnchecked(c.path);
    if (!why || !CODE_EXT.test(c.path) || uncheckedLocation(c.path, { gitleaksAllow })) continue;
    if (exemptDirs.some((d) => under(c.path, d))) continue;
    const text = readText(projectDir, c.path);
    if (!text || !SERVES_HTTP.some((re) => re.test(text))) continue;
    files ||= projectFiles(projectDir);
    const by = referencedOutsideTests(projectDir, c.path, files);
    if (!by.length || !flagged("server-in-test", c.path)) continue;
    failures.push(
      `factory: ${c.path} builds an HTTP server, and ${by.slice(0, 4).join(", ")}${by.length > 4 ? `, +${by.length - 4} more` : ""} ` +
        `${by.length === 1 ? "refers" : "refer"} to it from outside the tests — but ${why}, so the routes it serves were never judged. ` +
        `Move the server out of the test name, or have the pipeline's allowlist approve ${c.path}.`
    );
  }

  // The pipeline's own definition. A workflow decides which checks run, with what, and what a passing
  // run then does -- deploy, publish, merge -- so a change that edits one, or a local action one
  // calls, has edited its own review.
  const STATUS = { A: "added", M: "changed", D: "deleted", R: "renamed", C: "copied", T: "changed" };
  const workflows = workflowChanges(projectDir, sha).filter(
    (c) => !allowlisted({ kind: "workflow-change", path: c.path }, allowlist) && !(c.from && allowlisted({ kind: "workflow-change", path: c.from }, allowlist))
  );
  if (workflows.length) {
    const what = workflows.map((c) => (c.from ? `${c.from} → ${c.path} (renamed)` : `${c.path} (${STATUS[c.status] || c.status})`));
    failures.push(
      `factory: this change edits the pipeline — ${what.slice(0, 8).join(", ")}${what.length > 8 ? `, +${what.length - 8} more` : ""}. ` +
        `A workflow, and a local action it calls, decides what checks the change and what a passing run then does, so in factory ` +
        `mode the change does not get to edit one. Make the edit in a change a person reviews, or have the pipeline's allowlist approve it (kind "workflow-change", ` +
        `path from the repository root).`
    );
  }

  // The agents' own instructions. A change that edits them changes what the next agent run is told,
  // which hooks run around it, which tools it loads and which commands it may run without asking:
  // the change editing its own supervisor, as a workflow edit is the change editing its own review.
  // Approved when every end that is an agent file is approved. A rename has two ends: measured on
  // 53bfaad with only .claude/commands approved, CLAUDE.md renamed into it (which deletes CLAUDE.md)
  // and a command renamed out of it to .claude/rules both exited 0, because one approved end was enough.
  const approvedAgent = (p) => Boolean(allowlisted({ kind: "agent-instructions", path: p }, allowlist));
  const agentFiles = agentFileChanges(projectDir, sha)
    .filter((c) => !c.ends.every(approvedAgent))
    .map(({ ends, ...c }) => c);
  if (agentFiles.length) {
    const what = agentFiles.map(
      (c) => `${c.from ? `${c.from} → ${c.path} (renamed)` : `${c.path} (${c.untracked ? "on disk, not tracked by git" : STATUS[c.status] || c.status})`}${c.via ? `, which ${c.via} links to or imports` : ""}`
    );
    failures.push(
      `factory: ${agentFiles.length} file(s) that instruct coding agents changed — ${what.slice(0, 8).join(", ")}${what.length > 8 ? `, +${what.length - 8} more` : ""}. ` +
        `These decide what the next agent run in this repository is told, which hooks run around it, which tools it loads and which commands it may run without asking, ` +
        `so in factory mode the change does not get to edit one. Make the edit in a change a person reviews, or have the pipeline's allowlist approve it (kind "agent-instructions", ` +
        `path from the repository root).`
    );
  }

  // Dependencies: what the change adds, against what the base declared (lib/factory-deps.mjs).
  const dependencies = judgeDependencyChange(projectDir, baseDir, { changed, allowlist });
  failures.push(...dependencies.failures);
  grants.push(...dependencies.grants);

  // Routes exempt by name are conventional, not self-granted, and stay exempt. One the change
  // introduced is named, because a purge endpoint renamed to /health is exempt too.
  let newProbeRoutes = [];
  try {
    const was = new Set((checkAuthentication(baseDir).exempt || []).map((r) => `${r.method} ${r.route}`));
    newProbeRoutes = (checkAuthentication(projectDir).exempt || []).filter((r) => !was.has(`${r.method} ${r.route}`));
  } catch {
    /* the authentication check reports its own crash in the run itself */
  }
  for (const r of newProbeRoutes) {
    notes.push(`a route exempt by name that the base did not have: ${r.method} ${r.route} (${r.file}:${r.line})`);
  }

  return { failures, notes, grants, changed, newProbeRoutes, workflows, agentFiles, dependencies: dependencies.report, couldNotRun: dependencies.couldNotRun };
}

// Lockfiles run to megabytes, past what the other checks here read (MAX_BYTES).
const DEP_MAX_BYTES = 64 * 1024 * 1024;
// A symbolic link is not opened, whether the file is one or a directory above it is: what it points
// at may be outside the project, and the rule quotes what it reads. It comes back as unread, with why.
function readDepFile(root, rel) {
  try {
    const parts = rel.split("/");
    for (let n = 1; n <= parts.length; n++) {
      if (lstatSync(path.join(root, ...parts.slice(0, n))).isSymbolicLink()) {
        return { unread: n === parts.length ? "it is a symbolic link, which this rule does not follow" : `${parts.slice(0, n).join("/")} is a symbolic link, which this rule does not follow` };
      }
    }
    const full = path.join(root, rel);
    const st = lstatSync(full);
    if (!st.isFile() || st.size > DEP_MAX_BYTES) return null;
    return readFileSync(full, "utf8");
  } catch {
    return null;
  }
}

/** A tree on disk for lib/factory-deps.mjs: its files, less dependency trees and declared fixtures. */
export function dependencyTree(root) {
  return treeOf(projectFiles(root), (rel) => readDepFile(root, rel), declaredFixtures(root).map((f) => f.path));
}

/**
 * The dependency rule for one change: blocking lines for what nobody approved, a grant for every
 * finding, and could-not-run for a manifest or lockfile that could not be read at either end.
 */
export function judgeDependencyChange(projectDir, baseDir, { changed = [], allowlist = [] } = {}) {
  // Anything the rule did not foresee is could-not-run, by name, and not a gate that fell over.
  let r;
  try {
    const head = inventory(dependencyTree(projectDir));
    const base = inventory(dependencyTree(baseDir));
    r = judgeDependencies(head, base, { changed, allowlist });
  } catch (e) {
    const text = `factory: the dependency rule could not judge this change — ${withoutCredentials((e && e.message) || String(e)).slice(0, 300)}. Whether it adds a dependency nobody approved is not known.`;
    return { failures: [], grants: [], couldNotRun: [text], report: { findings: [], notRead: [], unreadable: [{ path: "", why: "the rule itself failed", text }] } };
  }
  const couldNotRun = r.errors.map(
    (e) => e.text || `factory: ${e.path} at ${e.side} could not be read by the dependency rule — ${e.why}. Whether this change adds a dependency nobody approved is not known.`
  );
  const grants = r.findings.map((f) => ({
    kind: f.kind,
    key: `${f.id}`,
    path: f.manifests[0],
    text: `${f.eco} ${f.package ?? "(registry)"}${f.kind === "dependency-source" ? ` from ${f.sourceShown}` : ""}`,
    status: f.approvedBy ? "allowlisted" : "added",
    ...(f.approvedBy ? { approvedBy: f.approvedBy } : {}),
  }));
  const failures = r.findings.filter((f) => !f.approvedBy).map(findingLine);
  const report = {
    findings: r.findings.map(({ id, sourceKey, ...f }) => ({ ...f, ...(f.approvedBy ? {} : { blocking: true }) })),
    notRead: r.notRead,
    unreadable: r.errors,
  };
  return { failures, grants, couldNotRun, report };
}
