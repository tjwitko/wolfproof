# Using wolfproof with a coding agent

This is what the project was built for, and how every graded run in it was produced. The pattern has
two halves, and the split between them is deliberate.

## The controls are MCP tools; the gate is a command

**The four controls are MCP tools.** The agent calls them while it works, for cheap feedback on the
thing it just wrote.

**The gate is a command, not a tool.** The agent runs it and reads the exit code:

```bash
./node_modules/.bin/wolfproof . task.txt
```

**That asymmetry is the whole design.** Across four runs of one task with identical tooling, the
model called `terraform_plan` 3, 1, 4 and 0 times, and never called `check_dependencies` at all. A
tool the model may or may not invoke is not a guardrail. So the controls are available for the
agent's benefit, and the gate runs where the agent cannot route around it — a command in the
transcript, a pre-commit hook, a required check in CI. It spawns the four servers itself, so its
verdict does not depend on which tools the agent chose to call.

## Wiring the MCP tools

`wolfproof init` writes this for you into `.mcp.json`, with absolute paths filled in. You only need
to write it by hand for a client that reads its configuration from somewhere else:

```json
{
  "mcpServers": {
    "terraform-guard": {
      "command": "node",
      "args": ["node_modules/@tjwitko/terraform-guard-mcp/index.mjs"],
      "env": { "TF_WORKING_ROOT": "/abs/path/to/project" }
    },
    "dep-audit": {
      "command": "node",
      "args": ["node_modules/@tjwitko/dep-audit-mcp/index.mjs"],
      "env": { "SCAN_ROOT": "/abs/path/to/project" }
    },
    "secret-guard": {
      "command": "node",
      "args": ["node_modules/@tjwitko/secret-guard-mcp/index.mjs"],
      "env": { "SCAN_ROOT": "/abs/path/to/project" }
    },
    "identity-guard": {
      "command": "node",
      "args": ["node_modules/@tjwitko/identity-guard-mcp/index.mjs"],
      "env": { "SCAN_ROOT": "/abs/path/to/project" }
    }
  }
}
```

If you run one of these servers from an editor on its own, see
[Upgrading → A control wired in on its own](upgrading.md#a-control-wired-in-on-its-own).

## What to put in the agent's instructions

Telling an agent to "run the gate" is not enough; a model that runs it and then describes a refusal
as a pass has satisfied the letter of that. [`templates/AGENTS.md.tmpl`](../templates/AGENTS.md.tmpl)
is the stanza these runs used, and each paragraph in it exists because a run did the thing it
forbids. `wolfproof init` appends it to `AGENTS.md`. To use it elsewhere — `CLAUDE.md` or a system
prompt — copy it and replace `{{VALIDATE_COMMAND}}` with the command above.

The four paragraphs that earn their place:

- **A refusal is not a pass.** If a check refuses, errors, or reports that it did not run, it
  produced no evidence. Say so plainly rather than counting it toward "all checks green".
- **Tests are evidence only when they run and reach the code.** A suite that is never executed, or
  that imports nothing from the project, is not evidence — however many assertions it contains.
- **End the summary with what the gate did not establish.** Exit 0 means nothing is blocking. It
  does not mean everything was checked.
- **An opt-out goes where the gate will record it**, as an `identity-guard:allow <rule> <reason>`
  comment on the line, not as prose in a document the gate never reads.

## The loop that results

1. The agent builds, calling the MCP tools for feedback as it goes.
2. It runs `./node_modules/.bin/wolfproof . task.txt`.
3. **Exit 1** — blocking findings, each with a remediation. It fixes and repeats.
4. **Exit 3** — part of the gate could not run. Not a pass, and the output names which part.
5. **Exit 0** — nothing is blocking. The agent reports what was *not* established alongside that.

Pass the task file. See [The task file](task-file.md).
