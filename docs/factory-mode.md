# Factory mode

For a pipeline where agents write the change and no person reviews it. New in v1.4.0.

In the default mode every escape hatch is printed for a reader: a fixture marker and its reason, an
opt-out and its reason, the control a project config pointed at. That is the right design where a
person reviews the change, and no protection where nobody does. Measured on v1.3.1, a project with an
unauthenticated purge endpoint, SQL injection and two hardcoded AWS credentials reached exit 0 through
two files an agent can write: a one-line `src/.tfguard-fixture`, and a `.wolfproof.json` pointing
secret-guard at an empty directory. Both were in the report. In a factory, nothing reads the report.

`--factory` compares the change with a base — the commit before it — and refuses what the change
granted itself:

```bash
wolfproof . task.txt --factory --base=origin/main
```

```yaml
      - uses: tjwitko/wolfproof@v1.16.7
        with:
          task-file: task.txt
          factory: true
```

In the Action the base defaults to the pull request's base, or for a push to the commit before it.
The default `fetch-depth: 1` is enough, because the Action fetches what factory mode needs beside the
head ([what the Action fetches](#what-the-action-fetches)): the base commit, and the commits between
it and the head.

## What it refuses

| the change | default mode | factory mode |
|---|---|---|
| overrides a control in `.wolfproof.json` | the project's control runs, and the report says where it came from | the installed control runs, and the override **blocks** |
| adds an exemption, opt-out or ignore entry ([below](#exemptions-it-judges)) | honoured, and listed | **blocks**, unless it existed at the base or the allowlist approves it |
| writes code under an exemption that predates it | not checked | **blocks**, unless the allowlist approves the exemption |
| writes code where the checks do not look ([below](#where-the-checks-do-not-look)) | not checked | **blocks**, unless the allowlist approves the directory |
| moves code to a test name or test directory, which the authentication check skips (including a .NET `*.Tests` project and the JVM's `src/test`) | not checked | **blocks** |
| writes an HTTP server into a test file that code outside the tests runs ([below](#servers-in-test-files)) | not checked | **blocks**, unless the allowlist approves it |
| edits the task file, or a baseline inside the project | checked against the edited text (the pre-commit hook blocks the edit) | checked against the base's text, and the edit **blocks** |
| adds the task file | read | **blocks**: in a factory the requirements predate the change |
| changes a workflow or local action ([below](#workflows)) | not checked | **blocks**, unless the allowlist approves it |
| changes a file that instructs coding agents ([below](#agent-instructions)) | not checked | **blocks**, naming the file, unless the allowlist approves it |
| leaves an advisory meaning "nothing was checked" | an advisory | **blocks** (see [Advisories](#advisories)) |
| adds a probe route that reads, such as `GET /health` | exempt | still exempt, and **named** in the report |
| adds a credential in one commit and removes it in a later one ([below](#credentials-in-the-changes-commits)) | not checked: the tree is clean | **blocks**, naming the commit, the file and the line, unless the allowlist approves the file |

### Where the checks do not look

`dist/`, `build/`, `venv/`, `node_modules/`, and `vendor/` and the rest of secret-guard's gitleaks
allowlist.

### Servers in test files

A change that writes an HTTP server into a test name or test directory blocks when code outside the
tests runs it — a start script, a Dockerfile `CMD`, a Procfile, an import. A server only the tests
use is an ordinary test.

### Workflows

A change that adds, edits, renames or deletes a file under `.github/workflows/`, or under
`.github/actions/` where local actions live, blocks. A workflow, and a local action it calls,
decides what checks the change and what a passing run then does. A local action kept anywhere else
(`uses: ./tools/deploy`) is not covered.

### Agent instructions

A change that adds, edits, renames or deletes a file that instructs coding agents blocks. Those
files decide what the next agent run in the repository is told, which hooks run around it, which
tools it loads and which commands it may run without asking. A change that edits one has edited its
own supervisor, as a change that edits a workflow has edited its own review. Measured on v1.16.7: a
change that rewrote `AGENTS.md` and added a `.claude/settings.json` allowing every shell command
exited 0 in factory mode.

```text
BLOCKING        : 1
  - factory: 2 file(s) that instruct coding agents changed — .claude/settings.json (added), AGENTS.md (changed). …
```

What counts, at any depth and whatever the letter case:

| file | why |
|---|---|
| `AGENTS.md` | the instructions Codex, Cursor, Copilot, Gemini CLI and Claude Code read, the nearest one to the work first |
| `AGENTS.override.md` | Codex reads it before the `AGENTS.md` beside it |
| `AGENT.md` | the older name of `AGENTS.md`, which agents.md still tells projects to link to it |
| `CLAUDE.md`, `CLAUDE.local.md` | Claude Code's instructions, loaded from the working directory, every directory above it and each subdirectory it works in |
| `GEMINI.md` | Gemini CLI's context file, read from the working directory, its parents and its subdirectories |
| `.mcp.json`, `.vscode/mcp.json` | the MCP servers Claude Code and VS Code start for the project: the tools the agent is given, and commands run to start them |
| everything under `.claude/` | Claude Code's settings (permission rules, hooks, environment), rules, skills, commands, subagents, output styles and workflows |
| everything under `.cursor/`, and `.cursorrules` | Cursor's rules, `hooks.json` and the scripts it runs, `mcp.json` and commands |
| everything under `.gemini/` | Gemini CLI's settings (hooks, MCP servers), commands, a system prompt override and its `.env` |
| everything under `.codex/` | Codex's project configuration |
| everything under `.agents/` | skills that Copilot and Codex load |
| `.github/copilot-instructions.md`, and everything under `.github/instructions/`, `.github/prompts/`, `.github/agents/`, `.github/chatmodes/`, `.github/skills/` and `.github/hooks/` | Copilot's instructions, prompt files, custom agents (and chat modes, their older form), skills and hooks |

Each name was checked against the tool's own documentation on 2026-11-19: Claude Code's memory,
settings and `.claude` directory pages; agents.md; Cursor's rules, hooks and MCP pages; GitHub's
repository instructions page and Copilot customization cheat sheet; VS Code's MCP configuration
reference; Gemini CLI's configuration and custom commands pages; and OpenAI's AGENTS.md guide for
Codex. Two older names are the exception: `.cursorrules`, which Cursor's rules page no longer names,
and `.github/chatmodes/`, which VS Code's custom agents page no longer names. Both are kept because
older projects still carry them and a file there is nothing else.

What decides it:

- **Paths are from the repository's root**, like a workflow's, even when the project is a
  subdirectory: an agent working in `services/api` is told what the `AGENTS.md` above it says.
  `packages/api/CLAUDE.md` counts like the one at the root.
- **Letter case is ignored.** A checkout on a case-insensitive filesystem reads `claude.md` as
  `CLAUDE.md`.
- **A symbolic link counts at both ends.** A link with one of these names blocks when it is added,
  removed or pointed elsewhere. What it points to is an agent file too, a directory included: with
  `CLAUDE.md` linked to `docs/agent-guide.md`, an edit to `docs/agent-guide.md` blocks and is named
  with the link. This holds for a link the base had and for one the change adds.
- **So does a file imported with `@path`** from one of these files, up to four hops, outside code
  spans and fenced blocks, as Claude Code reads imports. The path is everything up to the first
  space (`@docs/c++/guide.md`), and a backslash keeps a space (`@Design\ Docs/api.md`). It counts
  only when it names a file that is there.
- **What is on disk is judged, whatever the ignore rules say.** An agent file that git does not
  track blocks as "on disk, not tracked by git", whether or not an ignore rule covers it. An ignore
  rule is the change's to write: measured on the first version of this rule, a change that added
  `.claude/` to `.gitignore` and wrote a `.claude/settings.json` allowing every shell command exited
  0. In CI that file is never committed; in a workspace kept between runs it is live for the next
  agent run. So **factory mode expects a fresh checkout**. In a workspace a person or an agent has
  worked in, a `CLAUDE.local.md` or a `.claude/settings.local.json` left there counts as the
  change's, and Claude Code writes the second one itself when an approval is saved. Run the gate on
  a fresh checkout, or approve the path.
- **The machine's own ignore files are not read**: neither `.git/info/exclude` nor the user's global
  excludes file. The same tree gives the same answer on every machine.
- **Dependency and build trees are not searched** for untracked agent files: `node_modules/`,
  `.venv/`, `venv/`, `dist/`, `build/`, `.terraform/` and the rest of what the checks skip. An
  installed `node_modules` holds other projects' `AGENTS.md` files. A tracked file there counts.
- **A rename has two ends, and the allowlist has to approve each one that is an agent file.**
  `CLAUDE.md` renamed into an approved `.claude/commands/` still blocks, because it takes
  `CLAUDE.md` away; a command renamed out of it to `.claude/rules/` blocks for where it went.

The allowlist approves a file, or a directory of them, kind `agent-instructions`:

```json
{ "exemptions": [
  { "kind": "agent-instructions", "path": ".claude/skills", "reason": "skills are reviewed by the platform team in CODEOWNERS" }
] }
```

An entry approves every later change to that path, so use one only where a person reviews those
files' changes.

**`wolfproof init` writes two of these files**, `AGENTS.md` and `.mcp.json`, and `wolfproof init
--upgrade` rewrites them, so a factory change that carries its output blocks. It blocked before
this rule as well: the stanza it writes in `AGENTS.md` quotes the `identity-guard:allow` comment,
which factory mode reads as an opt-out the change added. Run `wolfproof init` and its upgrades in a
change a person reviews, outside the factory. A pipeline that must carry it approves
`agent-instructions` for `AGENTS.md` and `.mcp.json` and `identity-guard:allow` for `AGENTS.md`,
and removes the entries afterwards.

Left out, each for a reason:

- **Git hook managers** (`.husky/`, `.pre-commit-config.yaml`, `lefthook.yml`). They run for every
  committer, person or agent, and are build tooling like `package.json` scripts and a `Makefile`:
  code the project runs, which the checks read as code. A hook is also not what gates a factory
  change; the pipeline is.
- **`.vscode/settings.json`.** It can hold agent settings, and it is mostly editor settings that
  change for ordinary reasons. Headless agents do not read it.
- **Ignore files for agents** (`.cursorignore`, `.geminiignore`) and `.worktreeinclude`. They narrow
  what an agent reads or copy files that are already on the machine; they do not tell it to do
  anything.
- **A Claude Code plugin's own files**: `.claude-plugin/`, and the `agents/`, `commands/`,
  `skills/` and `hooks/` directories beside it. They instruct agents wherever the plugin is
  installed, not the agents working in this repository, and in a plugin's repository they are the
  deliverable: counting them would block every change to it. The one case where they are live here,
  a repository that installs its own plugin from a local path, is wired in `.claude/settings.json`,
  which is in the list; later edits to the plugin's files are not seen.
- **Other tools' files** (Windsurf, Cline, Roo, Aider, Continue, Amazon Q, Junie, Kiro, opencode,
  Zed). Their documentation was not checked for this list, so they are not in it.

### Probe routes

Probe names are conventional, so a reading probe route stays exempt in factory mode; factory mode
names one the change added. A write method on a probe path (`POST /health`) is not a probe, and is
checked in both modes.

### Credentials in the change's commits

secret-guard scans the working tree. A change can add a credential in one commit and delete it in a
later commit of the same branch: the tree is clean, and the value is in the branch wherever it was
pushed, and in the target branch's history after a merge commit or a rebase merge. Measured on
v1.16.7 with a base, a commit that adds an AWS access key ID and a commit that removes the line:
factory mode exited 0.

Factory mode scans what each commit between the base and the head added. The files a commit
changed are written, as that commit left them, to a temporary directory, and the pipeline's
secret-guard scans it with the same call it makes for the tree, so the rules are the same. A finding
counts unless a parent of the commit already held it, and blocks:

```text
factory commits: 2 between the base and the head, 1 file(s) they changed scanned for credentials, 1 finding(s)
BLOCKING        : 1
  - factory: 1 credential in the commits of this change — commit e75ce0bbb783 config.js:2 (aws-access-token). …
```

`--json` lists each one under `factory.commits.findings`, with `commit`, `path`, `line`, `rule` and
`status`. The value is never printed.

What decides it:

- **A credential still in the tree is reported twice**: by the tree's scan, and here with the commit
  that added it. Removing the line clears the first and not the second.
- **An exemption is judged as it is in the tree.** A `gitleaks:allow` comment or a `.gitleaksignore`
  entry is honoured when it existed at the base or the allowlist approves it
  ([exemptions it judges](#exemptions-it-judges)). One that exists only in a commit of the change
  hides nothing: the line is scanned and the finding blocks.
- **A commit's message is scanned too.** A credential pasted into one is pushed with the commit.
  The finding names the commit and the line of the message. A message has no path, so only an
  approval of the whole project covers it: `{ "kind": "secret-in-commit", "path": "." }`.
- **A finding is the commit's unless a parent already held it**: unless the lines the finding
  spans, first to last, stand together and in the same order in the parent's scanned copy of the
  file. So a credential the base held, moved within the file, is not the commit's; and a private
  key committed with its lines out of order, then put in order by a later commit, is that later
  commit's, though every line of it was already there. It is decided by the text, so no
  `.gitattributes` or diff setting has a say.
- **Every line counts in a file the parent's scan did not read**: a new file, one that was a
  symbolic link, and one renamed out of a directory secret-guard does not scan.
- **A merge commit is read for what it wrote itself**: lines that none of its parents has. Commits
  merged in from the target branch are not the change's when the base holds them.
- **A file a commit wrote where secret-guard does not scan** (`vendor/`, `node_modules/` and the
  rest of its allowlist) blocks as [code where the checks do not look](#where-the-checks-do-not-look),
  naming the commit, when the tree no longer shows it. The allowlist approves it the same way, kind
  `skipped-location`.
- **The allowlist approves a finding by its file**, kind `secret-in-commit`, path from the project:
  `{ "kind": "secret-in-commit", "path": "test/data", "reason": "generated fixtures, never live keys" }`.
- **Only the project's own files are read**, as in the tree's scan, when the project is a
  subdirectory of the repository.
- **Work that is not committed** is in no commit. The tree's scan reads it.

The remedy for a real credential is to rotate it at the provider, then rewrite the branch so that
no commit carries it. Rewriting alone does not undo the push.

#### What the Action fetches

`actions/checkout` fetches depth 1 by default. For a pull request that is the merge commit and
neither parent's history; for a push it is the pushed head alone. The Action then fetches:

1. **The base commit**, by itself at depth 1 (`git fetch --depth=1 origin <base>`). A push that
   creates a branch has no commit before it, so the base is the head's parent, fetched by deepening
   one level.
2. **The commits between the base and the head**, by deepening the history from where the clone was
   cut: `git fetch --deepen=50 origin <head> <base>`, then 250, then 1250, stopping as soon as no
   commit on either side is one whose parents are missing. Both sides, because the base's own
   history down to the fork point is what tells git where the change starts. Measured on a pull
   request of 4 commits whose base had moved 5 past the fork point, and on a push of 4 commits: both
   were complete after deepening by 6.

The gate does not trust the fetch. It asks whether the commits are all in the checkout, and when
they are not the scan **could not run, exit 3**, with the command to fetch them: never a pass. That
covers a change longer than about 1,500 commits, a fetch that failed, and a run outside the Action
in a shallow clone. `fetch-depth: 0` on `actions/checkout` always works.

Three limits:

- **A file the scanner skips by its name is not read in a commit either**, as it is not in the
  tree: gitleaks' own configuration skips images, PDFs, lockfiles and `go.sum`. Measured: a key in
  `k.png` or `package-lock.json` is not found. And a file renamed from such a name is compared with
  the copy that was never scanned, so a key added as `k.png` and renamed unchanged to `k.txt` by the
  next commit is not reported.
- **A force-push that rewrites the branch takes the commit out of the range.** The gate reads the
  commits between the base and the head it is given. A credential pushed in a commit that was later
  rewritten away was still pushed, and no later run sees it.
- **A push that creates a branch is compared with the head's parent**, the Action's default base
  for that event, so only its last commit is in the range. Set the `base` input to the branch it
  was cut from.

### Exemptions it judges

Each of these is confirmed to loosen a check:

- `.tfguard-fixture` and `.identity-exception` — a whole directory out of every source check
- an entry in `.wolfproof-reviewed.json` — one named finding out of the verdict
  ([reviewed findings](configuration.md#reviewed-findings)); a later `expires` on the same finding is a new entry
- an entry in `.wolfproof-known.json` — one named finding out of the verdict, as a
  [known finding](configuration.md#known-findings). The change that writes the first snapshot adds
  every entry in it, and is the only one the allowlist can approve; removing an entry grants nothing
- a package name added to the `declared` list of a `.wolfproof-known.json` entry that was at the
  base (`known-declared`) — the list is what `wolfproof known` reads before it adds a new lockfile's
  findings, so a name written into it has the command add the findings that dependency brings; no
  allowlist entry approves it, and removing a name grants nothing
- `# identity-guard:allow <rule> <reason>`
- `gitleaks:allow` on a line, and `.gitleaksignore` at the project root
- `osv-scanner.toml` beside a lockfile — an `[[IgnoredVulns]]` or `[[PackageOverrides]]` entry
  (one with `ignore = true` took four blocking CVEs to exit 0)
- `# noqa`, and `ruff.toml`, `.ruff.toml` or a `pyproject.toml` `[tool.ruff]` section
- `checkov:skip=` and `.checkov.yaml` — these block only when the pipeline's policy blocks the
  checkov findings they hide (`checkov`, `iac-checkov` or `dockerfile-checkov`, by file type).
  checkov's findings are advisories, and hiding one that cannot block is not itself blocking:
  under the default policy an added skip is listed in the factory notes instead
- an ignore rule over a directory the gate cannot list (`ignored-directory`) — the one place the
  gate honours `.gitignore`. Such a directory is named above the verdict where any other is exit 3
  ([troubleshooting](troubleshooting.md)), so a rule the change writes would take its own run from
  exit 3 to exit 0. Factory mode asks git whether the ignore files as they were at the base already
  ignored the directory, together with `.git/info/exclude` and the user's global excludes, which a
  change cannot carry. If they did, nothing changes. If only the change's rules ignore it, the
  directory is a grant the change added and blocks, naming the directory and the ignore file, line
  and pattern. It is decided by the answer and not by whether the change touched an ignore file:
  an unrelated line added to the same `.gitignore`, or a pattern moved to another ignore file,
  blocks nothing, and a removed negation or a new nested `.gitignore` does block. So does a rule
  over the directory's contents (`data/postgres/*`) replaced by one over the directory
  (`data/postgres/`): the first never ignored the directory. An ignore line
  that is not committed counts like one that is. The allowlist approves the directory by its path

Not judged, because nothing honours them: a project `.gitleaks.toml`, `nosemgrep` and
`.semgrepignore`. A `.gitignore` hides no file from a check; the directory above is the one thing it
decides.

Each one is compared line by line, so the same `gitleaks:allow` on a line whose credential changed is
a new grant.

### Exit codes in factory mode

A base that cannot be resolved — a ref the checkout does not have — is **exit 3**: with nothing to
compare with, nothing self-granted can be told apart. So is a checkout that does not hold every
commit between the base and the head, or a secret-guard that could not scan them: the change's
commits were not all read. Everything else factory mode refuses is
**exit 1**, because the change made it and can undo it; exit 3 means "fix the environment", which
would send it to the wrong owner.

## Advisories

Every advisory is classified, and none may leave the verdict clean by meaning nothing was checked:

| class | for example | factory mode |
|---|---|---|
| not-checked | "no HTTP routes were identified" in a project that starts an HTTP server; a retention period the task states and nothing here describes; a YAML file a manifest check did not read, because it is a Helm template or does not parse | blocks |
| could-not-run | a Terraform plan that could not authenticate; checkov killed; code in a language no check reads | exit 3 |
| finding | SQL built from a value of unknown origin; a heuristic workload-identity hit | counted, and dropped |
| info | tests ran and passed; no Kubernetes manifests to read | dropped |

Findings are dropped by default because blocking them is what gets a gate switched off: Gitea, a
clean application in the calibration corpus, draws 100 Go SQL advisories. An advisory factory mode
cannot classify blocks, whatever the policy says. `--json` lists each advisory's id, class and
action under `factory.advisories`.

Some lines open with a name the gate did not choose: a Terraform root's path in `checkov (infra): …`,
the kind of template in `iac templates (CloudFormation): …`, the image in `trivy (app:1): …`. That
label is compared with the names the gate wrote in this run and is never read by its brackets, so a
name cannot change the class of the line under it, whatever characters or words it holds. If one
Terraform root's path is another's followed by `): ` and more, a line can be read as being about
either; when the two readings mean different things it blocks as unclassified, and names both roots.

## The allowlist and the policy

Both are JSON files the pipeline supplies, and both must live outside the project — one the change
can edit approves whatever the change likes, so the gate refuses it (exit 2). In the Action they are
inputs, written outside the workspace.

### The allowlist

```json
{ "exemptions": [
  { "kind": "fixture-marker", "path": "test/fixtures", "reason": "deliberately insecure samples for the rule tests" },
  { "kind": "skipped-location", "path": "dist", "reason": "the published build, generated by CI" }
] }
```

An entry approves its `kind` at its `path` or anywhere under it, and needs a `reason`; one without
is ignored and reported. The kinds are the exemptions above plus `changed-under-exemption`,
`skipped-location`, `moved-to-unchecked`, `server-in-test`, `reviewed-finding`, `known-finding`, `ignored-directory`, `agent-instructions` and `workflow-change`, which covers both
`.github/workflows/` and `.github/actions/`. `known-declared` is the one exemption above with no
kind here: an entry naming it is ignored and reported.

A `workflow-change` path is from the repository root, where GitHub reads workflows, even when the
project is a subdirectory:

```json
{ "exemptions": [
  { "kind": "workflow-change", "path": ".github/workflows/release.yml", "reason": "release job maintained by the platform team" }
] }
```

A `reviewed-finding` entry approves every entry a change adds to `.wolfproof-reviewed.json`, so use it
only where a person reviews that file's changes — a CODEOWNERS rule on it, for instance:

```json
{ "exemptions": [
  { "kind": "reviewed-finding", "path": ".wolfproof-reviewed.json", "reason": "the security team owns this file in CODEOWNERS" }
] }
```

Otherwise leave the project's file unapproved and pass reviews from the pipeline's own list,
`--reviewed=<file>`, which the change cannot edit ([Reviewed findings](configuration.md#reviewed-findings)).

The snapshot of known findings is approved differently. A `known-finding` entry for
`.wolfproof-known.json` lets the change that writes the first snapshot through, and nothing else:
once the snapshot exists at the base, an entry a change adds is that change setting its own finding
aside, and blocks whatever the allowlist says, a `*` entry included. The approval can stay in place.
That includes the entries `wolfproof known` adds once when a lockfile is committed for a
`package.json` the snapshot held as having none, so in factory mode that change blocks too. So
does a name a change adds to the `declared` list of that `package.json`'s entry: the command adds a
lockfile's findings only while the `package.json` declares nothing the list does not hold, and it
reads the list from the file the change can write. The pipeline can instead keep the snapshot
itself, `--known=<file>` or the Action's `known` input, which avoids both.

### The policy

```json
{ "advisories": { "sast:sql-string-built": "block", "retention-shorter": "block", "unread-code": "drop" } }
```

The policy maps an advisory id, an id family (`sast` for every `sast:<category>`), or a class name to
`block`, `drop` or `incomplete`, most specific first. The lines the default mode prints above the
verdict are advisories here. Two are could-not-run, so the run exits 3 until the policy accepts
them: `unread-code` for code in a language nothing reads, and `skipped-files` for YAML, SQL and
Terraform files the checks that read them skipped — over 512 KB, unreadable, or a symbolic link to
a file that is not there, whatever the link is named. They have separate ids so an oversized data
file can be accepted without accepting a language unread.

The third, `unread-ignored-dirs`, is information and is dropped by default. It names directories
git ignores that could not be listed, a container's bind mount for one. Git tracks nothing under
such a directory, so a change carries nothing from it, and the line still prints above the verdict.
A pipeline that wants such a directory to hold a run names it:
`{ "advisories": { "unread-ignored-dirs": "incomplete" } }` for exit 3, or `"block"` for exit 1. A
rule for the `could-not-run` class does not reach it. That is for a directory the base already
ignored. One that only the change's own ignore rules ignore blocks as an `ignored-directory` grant
([exemptions it judges](#exemptions-it-judges)), and no policy entry drops that: the allowlist
approves it by path. A code file the
checks for its language skipped is not an advisory and no policy entry reaches it: it is in
could-not-run in both modes, and the run exits 3 until the file is split, moved under `dist/` or
`build/`, or its directory is declared a fixture, each of the last two a grant the allowlist
approves by path.

## What it does not do

- **Measure behaviour.** Whether the software does what its user needs is scenario validation —
  end-to-end checks kept where the agents cannot read them — and wolfproof sits beside it, not in
  place of it. Factory mode answers a narrower question: did the change narrow its own checks?
- **See a commit that is no longer in the branch.** The scan of the change's commits reads the
  commits between the base and the head. A force-push that rewrites the branch takes a commit out of
  that range, though the credential in it was still pushed.
- **Block a reading route renamed to a probe name.** A `GET /health` is exempt by name in either mode,
  whatever it returns; factory mode names one the change added.
- **Judge a server in a test file that nothing in the project runs.** A server written as
  `server.test.js` blocks once a start script, a Dockerfile, a Procfile or application code refers to
  it; one that is run only by something outside the repository looks like any other test.
- **Follow an agent's instructions into the code they run.** A change to `.claude/settings.json`
  blocks; a change to a script one of its hooks runs, or to a local MCP server that `.mcp.json`
  starts, does not, unless the script is under one of the [listed paths](#agent-instructions). The
  same holds for a local action kept outside `.github/actions/`. Nor does it see instructions kept
  outside the repository: a user's own `~/.claude`, an organisation's managed settings.
- **Protect its own invocation.** A change that edits `.github/workflows/` blocks, but only in a run
  that is in factory mode — and a pull request's workflows run as the pull request wrote them, so a
  change that removes `factory: true` is judged in the default mode, which does not check workflows.
  Run the gate from a workflow the change cannot edit — an organisation ruleset's required workflow —
  and the block covers every other workflow, its own invocation included.
- **Hide its rules, or test the running service.** Every rule is open source and documented, blind
  spots included, so an agent iterating against the gate can read what it does not see. And every
  check reads source code: a defect written in a shape no pattern recognises passes, however the
  service behaves.

  The direction chosen for that is a *behavioural holdout*, and it is not built yet. Where a static
  check reads the code, a behavioural holdout runs it: it starts the change's service in a sandbox
  and attacks it from outside, the way a caller would. It sends a request with no credentials to
  every route and expects a 401 or 403; puts injection payloads in each parameter; asks for a path
  containing `../`; and gives every URL parameter the address of a canary that records any
  connection made to it. It judges what the service does — the status code, the data that comes
  back, whether the canary was reached — not what the code looks like, so it catches the defect
  however the code is written. The attacks are held by the pipeline, outside the repository, where
  the agents cannot read them, so there is nothing to tune the code to. It is the security
  counterpart of the scenario validation above, and it would keep this gate's exit contract: a
  service that cannot be started is a check that could not run (exit 3), never a pass.

  A private rule pack — the gate's own rules kept from the agents — was considered and rejected. It
  works against an open-source gate, and it leaks anyway: every finding names its rule and where it
  fired, so an agent that iterates long enough learns the pack one finding at a time.

## The scan-root rule, in both modes

A control that reports scanning less than the project's root — a subdirectory, as in the
`.wolfproof.json` redirect above — is a scan that did not run, in either mode. A result from
secret-guard, identity-guard or dep-audit that names no scan root could not be judged (exit 3):
every release of each reports one. Factory mode refuses the redirect itself, whatever the control
then does.

History: the default mode has caught the secret-guard redirect since v1.4.0. dep-audit always
reported the directory it scanned, but until v1.4.1 the gate did not read it, so the same redirect
aimed at dep-audit hid four high or critical lodash advisories at exit 0. Also since v1.4.1,
`POST /health` running `DELETE FROM users` is checked, and blocks, in both modes.
