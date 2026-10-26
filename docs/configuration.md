# Configuration

## Where the controls come from

Controls resolve in this order, and the run reports which rule won:

1. **Environment variable** — `TFGUARD_SERVER`, `DEPAUDIT_SERVER`, `SECRETGUARD_SERVER`, `IDENTITYGUARD_SERVER`
2. **`.wolfproof.json`** in the project being checked
3. **`node_modules`** — the normal case
4. **A sibling checkout** — for developing the controls themselves

```json
{
  "controls": {
    "terraform-guard": "./vendor/terraform-guard-mcp/index.mjs"
  }
}
```

An environment variable or config entry pointing at a file that does not exist is an **error**, not
a reason to fall through to the next rule. Someone said where the control was and was wrong; quietly
using a different one would hide that.

`.agent-gate.json`, the file's name before v1.2.0, is not read: a project with only that file exits 3
until it is renamed. In [factory mode](factory-mode.md), a control override in `.wolfproof.json`
blocks.

## Test timeout

`WOLFPROOF_TEST_TIMEOUT` sets how long the `tests` check lets the suite run, in whole seconds; the
default is 120. A suite killed at the limit is exit 3, so a suite that needs longer is exit 3 on
every run until this is set. A value that is not a whole number of seconds is exit 3 too, naming the
value, rather than the default used quietly.

For the Action, see [Action reference → Environment](action-reference.md#environment).

## `wolfproof init`

`wolfproof init` writes three files, and **overwrites nothing**:

| | |
| --- | --- |
| `.mcp.json` | the four controls, with absolute entry points and the project as their scan root |
| `AGENTS.md` | the gate stanza (the agent instructions in [`templates/AGENTS.md.tmpl`](../templates/AGENTS.md.tmpl)), with `{{VALIDATE_COMMAND}}` filled in |
| `.git/hooks/pre-commit` | with `--hook`: runs the gate and blocks the commit unless it exits 0 |

An existing `.mcp.json` is merged into, not replaced — your own servers survive, and a control you
have already defined yourself is left as you defined it. An `AGENTS.md` is appended to between
markers, so a second run changes nothing. An existing pre-commit hook is reported and left alone.
`--force mcp|agents|hook` says otherwise, per file.

If `core.hooksPath` is set, `init` refuses rather than writing a hook into `.git/hooks` that would
never run.

`--new <dir>` creates a new project first; otherwise it sets up the current one. After upgrading the
package, `wolfproof init --upgrade` refreshes what it wrote — see [Upgrading](upgrading.md).

Its exit codes: `0` done, `1` left an existing file alone (reported, and `--force` overrides), so a
script can tell "set up" from "already had one", `2` usage error, `70` failed partway — rerun after
fixing the cause, since nothing it writes overwrites.

## The pre-commit hook

`--pre-commit` turns off exactly one check, `uncommitted_work`, and says so in the output. In a hook
its premise is satisfied by the act that invoked it — the work is uncommitted because it is being
committed. Left on, it fails every commit forever, which teaches people to bypass the hook and costs
you the whole thing. The stanza's command keeps that check, because an agent reporting it is done
with work uncommitted has not finished.

## Reviewed findings

A finding you have read and accept can be taken out of the verdict by its ID, with a reason. It stays
in the report: every run lists it as `reviewed`, with the reason, and it does not block.

```bash
wolfproof review .                     # every injection and authentication finding, with its ID
wolfproof review . 'sast:csharp-path-traversal:Jellyfin.Api/Controllers/EnvironmentController.cs:7bb61633' \
  --reason "admin-only endpoint; writes where the admin says, by design" --reviewer tjwitko
```

The second command writes an entry to `.wolfproof-reviewed.json` at the project root:

```json
{ "reviewed": [
  { "id": "sast:csharp-path-traversal:Jellyfin.Api/Controllers/EnvironmentController.cs:7bb61633",
    "reason": "admin-only endpoint; writes where the admin says, by design",
    "reviewer": "tjwitko", "expires": "2027-04-01" }
] }
```

- **One entry, one finding.** An ID names a check, a rule and a file, and for an injection finding a
  hash of its line — for one through a helper, the helper's line too. There are no wildcards; a whole
  directory is a fixture marker's job.
- **A reason is required.** An entry without one, or with an ID or date that is not well-formed, is
  ignored and reported. `expires` is optional; after that date the finding counts again.
- **It stops applying when the code changes.** Moving the line keeps a review; editing it, or the
  helper it goes through, makes it a new finding to review. An authentication review names the
  route, and holds until its method, path or file changes.
- **Nothing goes quiet.** An entry that matches no finding is reported as an advisory, as is one past
  its date, so the file does not keep entries that do nothing.
- **Which findings.** The first version covers the injection (`sast`) and authentication checks.

The file is a record, not a control: whoever writes the code can write it, as with a fixture
marker, and the agent loop refuses to let a model write it. In [factory mode](factory-mode.md), an
entry the change adds blocks unless the pipeline's allowlist approves it (`reviewed-finding`).
`--reviewed=<file>`, and the Action's `reviewed` input, take the same list from outside the project,
in either mode.

## JSON output

`--json` writes one machine-readable document. Even when the gate crashes it exits 3, never Node's
default 1, and still writes one document: `{"exitCode": 3, "incomplete": true, "error": "..."}`. A
usage error writes `{"exitCode": 2, "error": "..."}`.

The report also carries `toolchain` — each scanner on `PATH` and its version — and `scannedAt`, the
time the run started, and `reviewed`: each [reviewed finding](#reviewed-findings) with its ID,
location, reason, reviewer, expiry and the list it came from.
