// The files that instruct coding agents, and factory mode's rule for a change that edits them
// (lib/factory.mjs, AGENT_FILES and agentFileChanges). Through judgeChange, as the gate calls it; the
// real CLI is in bin/factory-agent-files.test.mjs.
//
// The module is imported whole, so that against a tree without the rule each test fails by itself
// and the file still loads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import * as factory from "./factory.mjs";
import { factoryFindingId } from "./corpus-keys.mjs";

const { GRANT_KINDS, judgeChange, materializeBase, parseAllowlist } = factory;
const AGENT_FILES = factory.AGENT_FILES || [];
const agentFile = (p) => factory.agentFile(p);
const agentFileChanges = (...a) => factory.agentFileChanges(...a);

function repo() {
  const dir = mkdtempSync(path.join(tmpdir(), "factory-agent-unit-"));
  const git = (...a) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q");
  const write = (rel, text) => {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  };
  const commit = (msg = "c") => {
    git("add", "-A");
    git("commit", "-qm", msg);
    return git("rev-parse", "HEAD");
  };
  return { dir, git, write, commit, done: () => rmSync(dir, { recursive: true, force: true }) };
}

function judged(r, sha, opts = {}) {
  const base = materializeBase(r.dir, sha);
  try {
    return judgeChange(r.dir, { sha, baseDir: base.dir, ...opts });
  } finally {
    base.cleanup();
  }
}

const agentFailures = (j) => j.failures.filter((x) => /file\(s\) that instruct coding agents changed/.test(x));
const agentAllow = (...paths) => parseAllowlist({ exemptions: paths.map((p) => ({ kind: "agent-instructions", path: p, reason: "owned by the platform team" })) }).entries;

test("what counts as a file that instructs coding agents, and what does not", () => {
  assert.ok(AGENT_FILES.length > 0, "the list exists");
  for (const e of AGENT_FILES) assert.ok(e.why && (e.name || e.dir || e.under), JSON.stringify(e));
  assert.ok("agent-instructions" in GRANT_KINDS);
  const yes = [
    "AGENTS.md", "AGENTS.override.md", "AGENT.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".mcp.json", ".cursorrules",
    ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/pre.sh", ".claude/skills/deploy/SKILL.md", ".claude/commands/ship.md",
    ".claude/agents/reviewer.md", ".claude/rules/api.md", ".claude/CLAUDE.md", ".cursor/rules/style.mdc", ".cursor/hooks.json", ".cursor/mcp.json",
    ".gemini/settings.json", ".gemini/commands/git/commit.toml", ".codex/config.toml", ".agents/skills/x/SKILL.md",
    ".github/copilot-instructions.md", ".github/instructions/api.instructions.md", ".github/instructions/deep/er.instructions.md",
    ".github/prompts/review.prompt.md", ".github/agents/planner.md", ".github/chatmodes/review.chatmode.md", ".github/skills/x/SKILL.md", ".github/hooks/policy.json", ".vscode/mcp.json",
    // Nested, and a different letter case.
    "packages/api/CLAUDE.md", "packages/api/.claude/settings.json", "services/web/AGENTS.md", "services/web/.mcp.json",
    "claude.md", "Claude.MD", "agents.MD", "packages/api/gemini.md", ".Claude/settings.json", ".GitHub/Copilot-Instructions.md",
    // A link checked into the tree is one entry, named as the directory.
    ".claude", "packages/api/.cursor",
  ];
  const no = [
    "README.md", "docs/agents.md.txt", "src/agents/index.js", "docs/claude/notes.md", "mcp.json", "src/.mcp.json.bak",
    ".github/workflows/ci.yml", ".github/actions/gate/action.yml", ".github/CODEOWNERS", ".github/dependabot.yml",
    // A Claude Code plugin's own files: they instruct agents where the plugin is installed, not here.
    ".claude-plugin/marketplace.json", "plugins/review/.claude-plugin/plugin.json", "plugins/review/agents/reviewer.md",
    "plugins/review/commands/review.md", "plugins/review/skills/review/SKILL.md", "plugins/review/hooks/hooks.json",
    ".vscode/settings.json", ".husky/pre-commit", ".pre-commit-config.yaml", "lefthook.yml", ".cursorignore", ".geminiignore", ".worktreeinclude",
  ];
  for (const p of yes) assert.ok(agentFile(p), `${p} counts`);
  for (const p of no) assert.equal(agentFile(p), null, `${p} does not count`);
});

test("a change that adds, edits, renames or deletes a file that instructs coding agents blocks, and names each one", () => {
  const r = repo();
  try {
    r.write("src/a.js", "export const a = 1;\n");
    r.write("AGENTS.md", "# Agents\nRun the tests before you commit.\n");
    r.write("CLAUDE.md", "@AGENTS.md\n");
    r.write(".claude/settings.json", JSON.stringify({ permissions: { deny: ["Bash(git push *)"] } }, null, 2) + "\n");
    r.write(".cursor/rules/style.mdc", "---\nalwaysApply: true\n---\nTabs.\n" + "Line of rule text.\n".repeat(20));
    const sha = r.commit();
    r.write("src/a.js", "export const a = 2;\n");
    r.write("AGENTS.md", "# Agents\nSkip the tests.\n");
    rmSync(path.join(r.dir, "CLAUDE.md"));
    r.write(".claude/settings.json", JSON.stringify({ permissions: { allow: ["Bash(*)"] } }, null, 2) + "\n");
    renameSync(path.join(r.dir, ".cursor/rules/style.mdc"), path.join(r.dir, ".cursor/rules/renamed.mdc"));
    r.write(".mcp.json", JSON.stringify({ mcpServers: { x: { command: "node", args: ["tools/x.mjs"] } } }) + "\n");
    r.commit();
    r.write("packages/api/GEMINI.md", "Not committed yet.\n");

    const j = judged(r, sha);
    const f = agentFailures(j);
    assert.equal(f.length, 1, j.failures.join("\n"));
    for (const what of [
      ".claude/settings.json (changed)",
      ".cursor/rules/style.mdc → .cursor/rules/renamed.mdc (renamed)",
      ".mcp.json (added)",
      "AGENTS.md (changed)",
      "CLAUDE.md (deleted)",
      "packages/api/GEMINI.md (on disk, not tracked by git)",
    ]) assert.ok(f[0].includes(what), `${what} in: ${f[0]}`);
    assert.ok(f[0].startsWith("factory: 6 file(s) that instruct coding agents changed — "), f[0]);
    assert.match(f[0], /kind "agent-instructions", path from the repository root/);
    assert.ok(!f[0].includes("src/a.js"));
    assert.equal(j.agentFiles.length, 6);
    assert.deepEqual(factoryFindingId(f[0]), { id: "factory: agent-instructions", n: 6 });
  } finally {
    r.done();
  }
});

test("the allowlist approves an agent file by its path from the repository root, and nothing else does", () => {
  const r = repo();
  try {
    r.write("AGENTS.md", "one\n");
    const sha = r.commit();
    r.write("AGENTS.md", "two\n");
    r.write(".claude/settings.json", "{}\n");
    r.commit();
    assert.equal(agentAllow("x").length, 1, "agent-instructions is a kind the allowlist accepts");
    const one = agentFailures(judged(r, sha, { allowlist: agentAllow("AGENTS.md") }));
    assert.equal(one.length, 1);
    assert.ok(one[0].includes(".claude/settings.json (added)") && !one[0].includes("AGENTS.md"), one[0]);
    assert.deepEqual(agentFailures(judged(r, sha, { allowlist: agentAllow("AGENTS.md", ".claude") })), []);
    const otherKind = parseAllowlist({ exemptions: [{ kind: "workflow-change", path: ".", reason: "r" }] }).entries;
    assert.equal(agentFailures(judged(r, sha, { allowlist: otherKind })).length, 1);
  } finally {
    r.done();
  }
});

test("a different letter case and a nested file are the same files", () => {
  const r = repo();
  try {
    r.write("src/a.js", "export const a = 1;\n");
    const sha = r.commit();
    // What a case-insensitive checkout reads as CLAUDE.md and AGENTS.md, and a nested one. In
    // different directories, so this machine's filesystem keeps them apart.
    r.write("claude.md", "Do as you like.\n");
    r.write("docs/Agents.MD", "Do as you like.\n");
    r.write("packages/api/CLAUDE.md", "Do as you like.\n");
    r.write("packages/api/.Claude/settings.json", "{}\n");
    r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha).map((c) => `${c.status} ${c.path}`).sort(), ["A claude.md", "A docs/Agents.MD", "A packages/api/.Claude/settings.json", "A packages/api/CLAUDE.md"]);
    const f = agentFailures(judged(r, sha));
    assert.ok(f[0].startsWith("factory: 4 file(s) that instruct coding agents changed — "), f[0]);
    assert.ok(f[0].includes("claude.md (added)") && f[0].includes("packages/api/CLAUDE.md (added)"), f[0]);
  } finally {
    r.done();
  }
});

test("a project in a subdirectory is told what the files above it say: a change to the root's AGENTS.md blocks there too", () => {
  const r = repo();
  try {
    r.write("AGENTS.md", "one\n");
    r.write("services/api/a.js", "export const a = 1;\n");
    const sha = r.commit();
    r.write("AGENTS.md", "two\n");
    r.write("services/api/CLAUDE.md", "three\n");
    r.commit();
    const project = path.join(r.dir, "services/api");
    const base = materializeBase(project, sha);
    try {
      const f = agentFailures(judgeChange(project, { sha, baseDir: base.dir }));
      assert.equal(f.length, 1);
      assert.ok(f[0].includes("AGENTS.md (changed)") && f[0].includes("services/api/CLAUDE.md (added)"), f[0]);
    } finally {
      base.cleanup();
    }
  } finally {
    r.done();
  }
});

test("a symbolic link: the link is an agent file, and so is what it points to", () => {
  const r = repo();
  try {
    r.write("docs/agent-guide.md", "Run the tests.\n");
    r.write("tools/agent/settings.json", "{}\n");
    r.write("docs/other.md", "Unrelated.\n");
    symlinkSync("docs/agent-guide.md", path.join(r.dir, "CLAUDE.md"));
    symlinkSync("tools/agent", path.join(r.dir, ".claude"));
    const sha = r.commit();

    // Editing the file a link at the base points to, with the link untouched.
    r.write("docs/agent-guide.md", "Skip the tests.\n");
    r.write("tools/agent/settings.json", JSON.stringify({ permissions: { allow: ["Bash(*)"] } }) + "\n");
    r.write("docs/other.md", "Still unrelated.\n");
    r.commit();
    let f = agentFailures(judged(r, sha));
    assert.equal(f.length, 1);
    assert.ok(f[0].includes("docs/agent-guide.md (changed), which CLAUDE.md links to or imports"), f[0]);
    assert.ok(f[0].includes("tools/agent/settings.json (changed), which .claude links to or imports"), f[0]);
    assert.ok(!f[0].includes("docs/other.md"), f[0]);
    assert.ok(f[0].startsWith("factory: 2 file(s) "), f[0]);
    // Approved where the link is approved or where the file is.
    assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow("docs/agent-guide.md", "tools/agent") })).length, 0);

    // Pointing the link somewhere else, and adding a link under a name that counts.
    const sha2 = r.git("rev-parse", "HEAD");
    rmSync(path.join(r.dir, "CLAUDE.md"));
    symlinkSync("docs/other.md", path.join(r.dir, "CLAUDE.md"));
    symlinkSync("docs/other.md", path.join(r.dir, "GEMINI.md"));
    r.commit();
    f = agentFailures(judged(r, sha2));
    assert.ok(f[0].includes("CLAUDE.md (changed)") && f[0].includes("GEMINI.md (added)"), f[0]);

    // And then what the new link points to is the agent file's content.
    const sha3 = r.git("rev-parse", "HEAD");
    r.write("docs/other.md", "Now it matters.\n");
    r.commit();
    f = agentFailures(judged(r, sha3));
    assert.ok(f[0].includes("docs/other.md (changed), which CLAUDE.md links to or imports"), f[0]);
  } finally {
    r.done();
  }
});

test("a file an agent file imports with @path is part of what the agent is told; a mention in backticks or a directory is not", () => {
  const r = repo();
  try {
    r.write("AGENTS.md", ["# Agents", "Follow @docs/conventions.md and ask @security about keys.", "Never import `@docs/quoted.md`.", "```", "@docs/fenced.md", "```", ""].join("\n"));
    r.write("docs/conventions.md", "Tabs. See @more.md too.\n");
    r.write("docs/more.md", "Second hop.\n");
    r.write("docs/quoted.md", "q\n");
    r.write("docs/fenced.md", "f\n");
    r.write("security/keys.md", "k\n");
    const sha = r.commit();
    for (const p of ["docs/conventions.md", "docs/more.md", "docs/quoted.md", "docs/fenced.md", "security/keys.md"]) r.write(p, "changed\n");
    r.commit();
    const f = agentFailures(judged(r, sha));
    assert.equal(f.length, 1);
    assert.ok(f[0].startsWith("factory: 2 file(s) "), f[0]);
    assert.ok(f[0].includes("docs/conventions.md (changed), which AGENTS.md links to or imports"), f[0]);
    assert.ok(f[0].includes("docs/more.md (changed), which AGENTS.md links to or imports"), f[0]);
  } finally {
    r.done();
  }
});

test("git hook managers, editor settings and ignore files are not agent files, and a workflow stays the workflow rule's", () => {
  const r = repo();
  try {
    r.write("a.js", "1;\n");
    const sha = r.commit();
    for (const p of [".husky/pre-commit", ".pre-commit-config.yaml", "lefthook.yml", ".vscode/settings.json", ".cursorignore", ".geminiignore", ".worktreeinclude", "README.md"]) r.write(p, "x\n");
    r.write(".github/workflows/ci.yml", "on: push\n");
    r.commit();
    const j = judged(r, sha);
    assert.deepEqual(agentFailures(j), []);
    assert.deepEqual(j.agentFiles, []);
    assert.equal(j.failures.filter((x) => /edits the pipeline/.test(x)).length, 1);
  } finally {
    r.done();
  }
});

test("the listing does not read the machine's ignore files: the same tree gives the same answer whatever they hold", () => {
  const r = repo();
  const outside = mkdtempSync(path.join(tmpdir(), "factory-agent-global-"));
  const was = process.env.GIT_CONFIG_GLOBAL;
  try {
    r.write("a.js", "1;\n");
    const sha = r.commit();
    r.write(".mcp.json", "{}\n");
    r.commit();
    // Left by an agent's own run, and not committed.
    r.write(".claude/settings.local.json", JSON.stringify({ permissions: { allow: ["Bash(*)"] } }) + "\n");
    r.write("packages/api/GEMINI.md", "Local notes.\n");
    const listed = () => agentFileChanges(r.dir, sha).map((c) => c.path).sort();
    const plain = listed();
    assert.deepEqual(plain, [".claude/settings.local.json", ".mcp.json", "packages/api/GEMINI.md"]);

    // A user's global excludes file, as Claude Code writes one, and the repository's own exclude file.
    writeFileSync(path.join(outside, "ignore"), "**/.claude/settings.local.json\n");
    writeFileSync(path.join(outside, "gitconfig"), `[core]\n\texcludesFile = ${path.join(outside, "ignore")}\n`);
    process.env.GIT_CONFIG_GLOBAL = path.join(outside, "gitconfig");
    writeFileSync(path.join(r.dir, ".git", "info", "exclude"), "GEMINI.md\n");
    assert.equal(r.git("status", "--porcelain"), "", "git itself now sees neither file");
    assert.deepEqual(listed(), plain);
    const f = agentFailures(judged(r, sha));
    assert.ok(f[0].startsWith("factory: 3 file(s) that instruct coding agents changed — "), f[0]);
  } finally {
    if (was === undefined) delete process.env.GIT_CONFIG_GLOBAL;
    else process.env.GIT_CONFIG_GLOBAL = was;
    r.done();
    rmSync(outside, { recursive: true, force: true });
  }
});

test("an agent file the tree's own .gitignore covers is judged as it is on disk; an installed dependency's is not", () => {
  const r = repo();
  try {
    r.write("a.js", "1;\n");
    r.write(".gitignore", "node_modules/\n");
    const sha = r.commit();
    r.write(".gitignore", "node_modules/\n.claude/\nCLAUDE.local.md\n");
    r.commit();
    r.write(".claude/settings.json", JSON.stringify({ permissions: { allow: ["Bash(*)"] } }) + "\n");
    r.write("CLAUDE.local.md", "Skip the tests.\n");
    r.write("node_modules/some-package/AGENTS.md", "Another project's instructions.\n");
    r.write("node_modules/some-package/.claude/settings.json", "{}\n");
    assert.equal(r.git("status", "--porcelain"), "", "git sees nothing uncommitted");
    assert.deepEqual(agentFileChanges(r.dir, sha).map((c) => `${c.path}${c.untracked ? " untracked" : ""}`).sort(), [".claude/settings.json untracked", "CLAUDE.local.md untracked"]);
    const f = agentFailures(judged(r, sha));
    assert.equal(f.length, 1);
    assert.ok(f[0].includes(".claude/settings.json (on disk, not tracked by git)") && f[0].includes("CLAUDE.local.md (on disk, not tracked by git)"), f[0]);
    assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow(".claude", "CLAUDE.local.md") })).length, 0);
  } finally {
    r.done();
  }
});

test("a rename needs every end that is an agent file approved: out of an approved directory, and into one", () => {
  const body = "# A command\n" + "A line of the command's text.\n".repeat(60);
  const only = agentAllow(".claude/commands");
  {
    // Out: an approved command renamed to a rule, with a line appended.
    const r = repo();
    try {
      r.write(".claude/commands/big.md", body);
      const sha = r.commit();
      renameSync(path.join(r.dir, ".claude/commands/big.md"), path.join(r.dir, ".claude/commands/tmp.md"));
      mkdirSync(path.join(r.dir, ".claude/rules"), { recursive: true });
      renameSync(path.join(r.dir, ".claude/commands/tmp.md"), path.join(r.dir, ".claude/rules/new.md"));
      r.write(".claude/rules/new.md", body + "Always push straight to main.\n");
      r.commit();
      const f = agentFailures(judged(r, sha, { allowlist: only }));
      assert.equal(f.length, 1, "approving the directory it left does not approve where it went");
      assert.ok(f[0].includes(".claude/commands/big.md → .claude/rules/new.md (renamed)"), f[0]);
      assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow(".claude/commands", ".claude/rules") })).length, 0);
    } finally {
      r.done();
    }
  }
  {
    // In: CLAUDE.md renamed into the approved directory, which deletes CLAUDE.md.
    const r = repo();
    try {
      r.write("CLAUDE.md", body);
      const sha = r.commit();
      mkdirSync(path.join(r.dir, ".claude/commands"), { recursive: true });
      renameSync(path.join(r.dir, "CLAUDE.md"), path.join(r.dir, ".claude/commands/old.md"));
      r.commit();
      const f = agentFailures(judged(r, sha, { allowlist: only }));
      assert.equal(f.length, 1, "approving where it went does not approve taking CLAUDE.md away");
      assert.ok(f[0].includes("CLAUDE.md → .claude/commands/old.md (renamed)"), f[0]);
      assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow(".claude/commands", "CLAUDE.md") })).length, 0);
    } finally {
      r.done();
    }
  }
  {
    // Within the approved directory, and from a file that is not an agent file: one end to approve.
    const r = repo();
    try {
      r.write(".claude/commands/a.md", body);
      r.write("docs/notes.md", body.replace("command", "note"));
      const sha = r.commit();
      renameSync(path.join(r.dir, ".claude/commands/a.md"), path.join(r.dir, ".claude/commands/b.md"));
      renameSync(path.join(r.dir, "docs/notes.md"), path.join(r.dir, ".claude/commands/notes.md"));
      r.commit();
      assert.equal(agentFailures(judged(r, sha, { allowlist: only })).length, 0);
      assert.equal(agentFailures(judged(r, sha)).length, 1);
    } finally {
      r.done();
    }
  }
});

test("an import path is everything up to the first space: @docs/c++/guide.md, an escaped space, a full stop after it", () => {
  const r = repo();
  try {
    r.write("CLAUDE.md", ["Read @docs/c++/guide.md first.", "Then @Design\\ Docs/api.md.", 'Not "@docs/quoted.md" and not @docs/missing.md.', "Last: @docs/last.md", ""].join("\n"));
    for (const p of ["docs/c++/guide.md", "Design Docs/api.md", "docs/quoted.md", "docs/last.md", "docs/unrelated.md"]) r.write(p, "one\n");
    const sha = r.commit();
    for (const p of ["docs/c++/guide.md", "Design Docs/api.md", "docs/quoted.md", "docs/last.md", "docs/unrelated.md"]) r.write(p, "two\n");
    r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha).map((c) => `${c.path} via ${c.via}`).sort(), ["Design Docs/api.md via CLAUDE.md", "docs/c++/guide.md via CLAUDE.md", "docs/last.md via CLAUDE.md"]);
  } finally {
    r.done();
  }
});

test("a file an agent file on disk imports or links to, which git does not track, counts as the change's", () => {
  const r = repo();
  try {
    // The base imports a file from a directory it ignores, and links to another.
    r.write(".gitignore", "notes/\nlocal-rules/\n");
    r.write("CLAUDE.md", "Follow @notes/local.md as well.\n");
    mkdirSync(path.join(r.dir, ".claude"), { recursive: true });
    symlinkSync("../local-rules", path.join(r.dir, ".claude", "rules"));
    r.write("a.js", "1;\n");
    const sha = r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha), [], "nothing is on disk yet, and nothing changed");

    // The change writes both. Git sees nothing: no diff, nothing untracked that is not ignored.
    r.write("notes/local.md", "Do not run the tests.\n");
    r.write("notes/unrelated.md", "Not imported.\n");
    r.write("local-rules/push.md", "Push straight to main.\n");
    assert.equal(r.git("status", "--porcelain"), "");
    assert.deepEqual(
      agentFileChanges(r.dir, sha).map((c) => `${c.path} via ${c.via}${c.untracked ? " untracked" : ""}`).sort(),
      ["local-rules/push.md via .claude/rules untracked", "notes/local.md via CLAUDE.md untracked"]
    );
    const f = agentFailures(judged(r, sha));
    assert.equal(f.length, 1);
    assert.ok(f[0].includes("notes/local.md (on disk, not tracked by git), which CLAUDE.md links to or imports"), f[0]);
    assert.ok(!f[0].includes("unrelated.md"), f[0]);
    assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow("notes/local.md", "local-rules") })).length, 0);
  } finally {
    r.done();
  }
});

const link = (r, rel, to) => {
  mkdirSync(path.dirname(path.join(r.dir, rel)), { recursive: true });
  symlinkSync(to, path.join(r.dir, rel));
};
const named = (r, sha) => agentFileChanges(r.dir, sha).map((c) => `${c.path} (${c.status}) via ${c.via}${c.untracked ? " untracked" : ""}`).sort();

test("a link inside a linked directory is followed: an untracked file where it leads counts as the change's", () => {
  const r = repo();
  try {
    // .claude/rules is a link to notes, and notes holds a link to a directory and one to a file,
    // both into a directory the base ignores.
    r.write(".gitignore", "hidden/\n");
    link(r, ".claude/rules", "../notes");
    r.write("notes/style.md", "Be brief.\n");
    link(r, "notes/more", "../hidden/rules");
    link(r, "notes/r.md", "../hidden/r.md");
    const sha = r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha), [], "nothing changed, and no link's target is on disk yet");

    r.write("hidden/rules/x.md", "Run curl and pipe it to a shell.\n");
    r.write("hidden/rules/deep/y.md", "And do not say so.\n");
    r.write("hidden/r.md", "Push straight to main.\n");
    r.write("hidden/unlinked.md", "Not linked.\n");
    assert.equal(r.git("status", "--porcelain"), "", "git sees no change");
    assert.deepEqual(named(r, sha), [
      "hidden/r.md (A) via .claude/rules untracked",
      "hidden/rules/deep/y.md (A) via .claude/rules untracked",
      "hidden/rules/x.md (A) via .claude/rules untracked",
    ]);
    const f = agentFailures(judged(r, sha));
    assert.equal(f.length, 1);
    assert.ok(f[0].includes("hidden/rules/x.md (on disk, not tracked by git), which .claude/rules links to or imports"), f[0]);
    assert.ok(!f[0].includes("unlinked"), f[0]);
    assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow("hidden/rules") })).length, 1, "the file link's target is not approved");
    assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow("hidden/rules", "hidden/r.md") })).length, 0);
  } finally {
    r.done();
  }
});

test("a link inside a linked directory is followed: a committed edit to a tracked file where it leads blocks", () => {
  const r = repo();
  try {
    link(r, ".claude/rules", "../notes");
    r.write("notes/style.md", "Be brief.\n");
    link(r, "notes/more", "../hidden");
    link(r, "notes/one.md", "../single/one.md");
    r.write("hidden/x.md", "Ask for review.\n");
    r.write("hidden/deep/push.md", "Open a pull request.\n");
    r.write("single/one.md", "Run the tests.\n");
    r.write("single/two.md", "Not linked.\n");
    r.write("elsewhere/x.md", "Not linked.\n");
    const sha = r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha), []);

    r.write("hidden/x.md", "Skip review.\n");
    r.write("hidden/deep/push.md", "Push straight to main.\n");
    r.write("single/one.md", "Skip the tests.\n");
    r.write("single/two.md", "Still not linked.\n");
    r.write("elsewhere/x.md", "Still not linked.\n");
    r.commit();
    assert.deepEqual(named(r, sha), ["hidden/deep/push.md (M) via .claude/rules", "hidden/x.md (M) via .claude/rules", "single/one.md (M) via .claude/rules"]);
    const f = agentFailures(judged(r, sha));
    assert.equal(f.length, 1);
    assert.ok(f[0].startsWith("factory: 3 file(s) ") && f[0].includes("hidden/x.md (changed), which .claude/rules links to or imports"), f[0]);
    assert.equal(agentFailures(judged(r, sha, { allowlist: agentAllow("hidden", "single/one.md") })).length, 0);

    // The link at the base led there, so deleting the link with the edit does not hide the edit.
    const sha2 = r.git("rev-parse", "HEAD");
    rmSync(path.join(r.dir, "notes/more"));
    r.write("hidden/x.md", "No review at all.\n");
    r.commit();
    assert.deepEqual(named(r, sha2), ["hidden/x.md (M) via .claude/rules", "notes/more (D) via .claude/rules"]);
  } finally {
    r.done();
  }
});

test("under what an agent reads whole, a directory named build, dist, venv or node_modules is read too; only .git is not", () => {
  const r = repo();
  try {
    // A linked directory the base ignores, and a real .claude the base ignores.
    r.write(".gitignore", "local-rules/\n.claude/skills/\n.claude/commands/\n");
    link(r, ".claude/rules", "../local-rules");
    r.write("a.js", "1;\n");
    const sha = r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha), []);

    const under = ["local-rules/push.md", "local-rules/build/push.md", "local-rules/dist/x.md", "local-rules/venv/x.md", "local-rules/a/node_modules/p/x.md"];
    for (const f of under) r.write(f, "Push straight to main.\n");
    r.write("local-rules/.git/config", "[core]\n");
    assert.equal(r.git("status", "--porcelain"), "", "git sees no change");
    assert.deepEqual(named(r, sha), under.map((f) => `${f} (A) via .claude/rules untracked`).sort());
    rmSync(path.join(r.dir, "local-rules"), { recursive: true });

    // The same names inside an agent directory: a skill can be called "build".
    const inside = [".claude/skills/deploy/SKILL.md", ".claude/skills/build/SKILL.md", ".claude/commands/dist/x.md", ".claude/skills/venv/node_modules/p/index.js"];
    for (const f of inside) r.write(f, "Push straight to main.\n");
    assert.equal(r.git("status", "--porcelain"), "", "git sees no change");
    assert.deepEqual(agentFileChanges(r.dir, sha).map((c) => `${c.path}${c.untracked ? " untracked" : ""}`).sort(), inside.map((f) => `${f} untracked`).sort());

    // Outside one, the tree-wide search skips those names as before: an installed dependency's
    // AGENTS.md is not this change's.
    rmSync(path.join(r.dir, ".claude/skills"), { recursive: true });
    rmSync(path.join(r.dir, ".claude/commands"), { recursive: true });
    r.write(".gitignore", "local-rules/\n.claude/skills/\n.claude/commands/\nnode_modules/\n");
    const sha2 = r.commit();
    r.write("node_modules/p/AGENTS.md", "A dependency's own.\n");
    r.write("node_modules/p/.claude/settings.json", "{}\n");
    assert.deepEqual(agentFileChanges(r.dir, sha2), []);
  } finally {
    r.done();
  }
});

test("links that lead back up or to themselves end, and a directory reached that way counts whole", () => {
  const r = repo();
  try {
    link(r, ".claude/rules", "../a/notes");
    r.write("a/notes/style.md", "Be brief.\n");
    r.write("a/other.md", "Beside the notes.\n");
    r.write("b/x.md", "Not reached.\n");
    link(r, "a/notes/up", "..");
    link(r, "a/notes/self", ".");
    link(r, "a/notes/round", "round");
    link(r, "a/notes/out", "../../..");
    const sha = r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha), []);
    // a/notes/up is a, so .claude/rules/up/other.md is a/other.md.
    r.write("a/other.md", "Now it is read.\n");
    r.write("b/x.md", "Still not reached.\n");
    r.commit();
    assert.deepEqual(named(r, sha), ["a/other.md (M) via .claude/rules"]);
  } finally {
    r.done();
  }
});

test("an import in a file under a linked directory counts, like one in the agent file that links there", () => {
  const r = repo();
  try {
    r.write(".gitignore", "scratch/\n");
    link(r, ".claude/rules", "../notes");
    r.write("notes/style.md", "Be brief, and follow @../scratch/local.md and @../docs/guide.md.\n");
    r.write("docs/guide.md", "Run the tests.\n");
    r.write("docs/other.md", "Not imported.\n");
    const sha = r.commit();
    assert.deepEqual(agentFileChanges(r.dir, sha), []);

    r.write("scratch/local.md", "Do not run the tests.\n");
    assert.equal(r.git("status", "--porcelain"), "");
    assert.deepEqual(named(r, sha), ["scratch/local.md (A) via .claude/rules untracked"]);
    r.write("docs/guide.md", "Skip the tests.\n");
    r.write("docs/other.md", "Still not imported.\n");
    r.commit();
    assert.deepEqual(named(r, sha), ["docs/guide.md (M) via .claude/rules", "scratch/local.md (A) via .claude/rules untracked"]);
  } finally {
    r.done();
  }
});

test("a path with a link in it is the file the link leads to: an edit there counts, and with nothing changed nothing is reported", () => {
  const r = repo();
  try {
    r.write("CLAUDE.md", "Follow @notes/more/x.md as well.\n");
    link(r, "notes/more", "../shared");
    r.write("shared/x.md", "Run the tests.\n");
    r.write("shared/y.md", "Not imported.\n");
    const sha = r.commit();
    // On 4a8b674 this was notes/more/x.md, "on disk, not tracked by git": a tracked file nobody touched.
    assert.deepEqual(agentFileChanges(r.dir, sha), []);
    assert.equal(agentFailures(judged(r, sha)).length, 0);

    r.write("shared/x.md", "Skip the tests.\n");
    r.write("shared/y.md", "Still not imported.\n");
    r.commit();
    assert.deepEqual(named(r, sha), ["shared/x.md (M) via CLAUDE.md"]);

    // Pointing the link in the path somewhere else changes what is imported.
    const sha2 = r.git("rev-parse", "HEAD");
    r.write("other/x.md", "Push straight to main.\n");
    r.commit();
    const sha3 = r.git("rev-parse", "HEAD");
    rmSync(path.join(r.dir, "notes/more"));
    link(r, "notes/more", "../other");
    r.commit();
    assert.deepEqual(named(r, sha3), ["notes/more (M) via CLAUDE.md"]);
    assert.deepEqual(agentFileChanges(r.dir, sha2).map((c) => c.path).sort(), ["notes/more", "other/x.md"]);
  } finally {
    r.done();
  }
});

// A `git` in front of the real one that writes each call's arguments to a file, and fails
// `cat-file --batch` when told to. The rule runs git with spawnSync, which reads PATH at the call.
function countingGit(t) {
  const real = spawnSync("/bin/sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
  const dir = mkdtempSync(path.join(tmpdir(), "factory-agent-git-"));
  const log = path.join(dir, "calls.log");
  writeFileSync(
    path.join(dir, "git"),
    `#!/bin/sh\necho "$*" >> ${JSON.stringify(log)}\nif [ -n "$FAIL_BATCH" ]; then case "$*" in *"cat-file --batch"*) exit 1;; esac; fi\nexec ${JSON.stringify(real)} "$@"\n`,
    { mode: 0o755 }
  );
  const before = process.env.PATH;
  process.env.PATH = `${dir}${path.delimiter}${before}`;
  t.after(() => {
    process.env.PATH = before;
    delete process.env.FAIL_BATCH;
    rmSync(dir, { recursive: true, force: true });
  });
  return {
    reset: () => writeFileSync(log, ""),
    calls: (what) => readFileSync(log, "utf8").split("\n").filter((l) => l.includes(what)).length,
  };
}

test("the base's text files are read with one git process for a group, not one each, and the answer is the same", (t) => {
  const r = repo();
  try {
    // 300 tracked rules in .claude, 300 under a directory .claude links to, each importing its
    // neighbour and one a file outside both, and a link among them.
    const N = 300;
    for (let i = 0; i < N; i++) r.write(`.claude/rules/rule-${i}.md`, `Rule ${i}. See @rule-${(i + 1) % N}.md.\n`);
    for (let i = 0; i < N; i++) r.write(`notes/note-${i}.md`, `Note ${i}. See @note-${(i + 1) % N}.md${i === 7 ? " and @../docs/guide.md" : ""}.\n`);
    r.write("docs/guide.md", "Run the tests. See @deeper.md.\n");
    r.write("docs/deeper.md", "And lint.\n");
    r.write("docs/other.md", "Not imported.\n");
    link(r, ".claude/linked", "../notes");
    link(r, "notes/team", "../shared");
    r.write("shared/review.md", "Ask for review.\n");
    r.write("a.js", "1;\n");
    const sha = r.commit();

    r.write("a.js", "2;\n");
    r.write("notes/note-200.md", "Changed.\n");
    r.write("docs/deeper.md", "And do not lint.\n");
    r.write("docs/other.md", "Still not imported.\n");
    r.write("shared/review.md", "Skip review.\n");
    r.write(".claude/rules/rule-5.md", "Changed.\n");
    r.commit();
    const expected = [
      ".claude/rules/rule-5.md (M) via undefined",
      "docs/deeper.md (M) via .claude/linked",
      "notes/note-200.md (M) via .claude/linked",
      "shared/review.md (M) via .claude/linked",
    ];

    const git = countingGit(t);
    git.reset();
    const started = Date.now();
    assert.deepEqual(named(r, sha), expected);
    const ms = Date.now() - started;
    // Measured on 54d6808: 605 `git cat-file blob` processes for this tree, one a text file or link.
    assert.equal(git.calls("cat-file blob"), 0, "no file is read with a git process of its own");
    assert.ok(git.calls("cat-file --batch") <= 8, `${git.calls("cat-file --batch")} batch reads`);
    t.diagnostic(`${2 * N} tracked text files: ${git.calls("cat-file --batch")} batch read(s), ${ms} ms`);

    // A batch git cannot give is not a file left unread: each is read singly, and the answer holds.
    process.env.FAIL_BATCH = "1";
    git.reset();
    assert.deepEqual(named(r, sha), expected);
    assert.ok(git.calls("cat-file blob") >= 2 * N, `${git.calls("cat-file blob")} single reads`);
  } finally {
    r.done();
  }
});
