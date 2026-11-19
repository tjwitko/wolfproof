// The files that instruct coding agents, and factory mode's rule for a change that edits them
// (lib/factory.mjs, AGENT_FILES and agentFileChanges). Through judgeChange, as the gate calls it; the
// real CLI is in bin/factory-agent-files.test.mjs.
//
// The module is imported whole, so that against a tree without the rule each test fails by itself
// and the file still loads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
    ".github/prompts/review.prompt.md", ".github/agents/planner.md", ".github/skills/x/SKILL.md", ".github/hooks/policy.json", ".vscode/mcp.json",
    // Nested, and a different letter case.
    "packages/api/CLAUDE.md", "packages/api/.claude/settings.json", "services/web/AGENTS.md", "services/web/.mcp.json",
    "claude.md", "Claude.MD", "agents.MD", "packages/api/gemini.md", ".Claude/settings.json", ".GitHub/Copilot-Instructions.md",
    // A link checked into the tree is one entry, named as the directory.
    ".claude", "packages/api/.cursor",
  ];
  const no = [
    "README.md", "docs/agents.md.txt", "src/agents/index.js", "docs/claude/notes.md", "mcp.json", "src/.mcp.json.bak",
    ".github/workflows/ci.yml", ".github/actions/gate/action.yml", ".github/CODEOWNERS", ".github/dependabot.yml",
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
      "packages/api/GEMINI.md (added)",
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
