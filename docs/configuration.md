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

### Finding a finding's ID

The gate's report does not print IDs: it groups findings, several to a line. When a blocking finding
has an ID, the report says where to get it, under the blocking findings:

```text
reviewable      : 3 injection or authentication findings above can be marked reviewed once read — wolfproof review . lists their IDs
```

So run

```bash
wolfproof review <project-dir>
```

It runs only the injection and authentication checks, changes nothing, and prints each finding as two
lines — a status (`BLOCKING`, `advisory` or `reviewed`) followed by the ID, then where the finding is
and what it is:

```text
BLOCKING  sast:python-sql-injection:app.py:5df60c0d
    app.py:18 — SQL injection: request data is built into a SQL statement
```

The ID is everything after the status word, here `sast:python-sql-injection:app.py:5df60c0d`. Copy it
as printed. It has one of two shapes:

| check | ID | example |
|---|---|---|
| injection | `sast:<rule>:<file>:<hash of the line>` | `sast:python-sql-injection:app.py:5df60c0d` |
| authentication | `authentication:<METHOD> <route>:<file>` | `authentication:GET /reports:app.py` |

The last part of an injection ID is a hash of the flagged line, so it cannot be written by hand. Take it
from the list. (`--json` carries the blocking ones too, as `reviewable`.) When two findings would get the same ID (the same rule on two identical lines of one file), the
second gets `#2` on the end.
Advisory findings are listed too, and reviewing one takes it out of the advisories.

### An example

A small Flask service. Both routes check their caller inside the handler — an admin token, a webhook
signature — which the authentication check does not read, and the report's table name is looked up
in a fixed dictionary, which the injection check cannot tell from request data:

```python
REPORTS = {"orders": "orders", "refunds": "refunds"}

@app.get("/reports")
def report():
    if not hmac.compare_digest(request.headers.get("X-Admin-Token", ""), os.environ["ADMIN_TOKEN"]):
        abort(403)
    table = REPORTS[request.args["kind"]]
    return {"rows": db.execute(f"SELECT * FROM {table} ORDER BY created DESC").fetchall()}

@app.post("/hooks/payments")
def payment_hook():
    expected = hmac.new(os.environ["PAYMENTS_SECRET"].encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Signature", "")):
        abort(401)
    return {"ok": True}
```

**1. The gate blocks on all three** (`wolfproof .`, exit 1, explanations trimmed):

```text
BLOCKING        : 2

  - authentication: 2 of 2 endpoint(s) accept requests from anyone who can reach the service — GET /reports (app.py:13), POST /hooks/payments (app.py:21). …

  - sast: SQL injection — request data is built into a SQL statement: app.py:18. Use a parameterised query: …

reviewable      : 3 injection or authentication findings above can be marked reviewed once read — wolfproof review . lists their IDs
```

**2. List the findings by ID**, as the report's last line says:

```text
$ wolfproof review .
project : …/shop

BLOCKING  sast:python-sql-injection:app.py:5df60c0d
    app.py:18 — SQL injection: request data is built into a SQL statement
BLOCKING  authentication:GET /reports:app.py
    an endpoint that accepts requests from anyone who can reach the service
BLOCKING  authentication:POST /hooks/payments:app.py
    an endpoint that accepts requests from anyone who can reach the service

To mark one reviewed: wolfproof review . <id> --reason "why it is acceptable"
```

**3. Review each one you accept, with the reason**, pasting its ID from step 2 in place of `<id>`.
Quote every ID: an authentication ID has a space in it.

```bash
wolfproof review . 'authentication:POST /hooks/payments:app.py' \
  --reason "verifies the provider's HMAC signature in the handler" --reviewer tjwitko
wolfproof review . 'authentication:GET /reports:app.py' \
  --reason "admin token checked in the handler with compare_digest" --reviewer tjwitko
wolfproof review . 'sast:python-sql-injection:app.py:5df60c0d' \
  --reason "the table name comes from the fixed REPORTS dict, never from the request" \
  --reviewer tjwitko --expires 2027-04-30
```

```text
added in .wolfproof-reviewed.json:
  {"id":"authentication:POST /hooks/payments:app.py","reason":"verifies the provider's HMAC signature in the handler","reviewer":"tjwitko"}

The gate lists this finding as reviewed on every run, with the reason, and does not count it.
It stops applying when the route's method, path or file changes.
In factory mode, an entry a change adds to .wolfproof-reviewed.json blocks unless the pipeline's allowlist approves it.
```

The three commands leave this in `.wolfproof-reviewed.json` at the project root, which you commit with
the code:

```json
{
  "reviewed": [
    {
      "id": "authentication:POST /hooks/payments:app.py",
      "reason": "verifies the provider's HMAC signature in the handler",
      "reviewer": "tjwitko"
    },
    {
      "id": "authentication:GET /reports:app.py",
      "reason": "admin token checked in the handler with compare_digest",
      "reviewer": "tjwitko"
    },
    {
      "id": "sast:python-sql-injection:app.py:5df60c0d",
      "reason": "the table name comes from the fixed REPORTS dict, never from the request",
      "reviewer": "tjwitko",
      "expires": "2027-04-30"
    }
  ]
}
```

**4. The gate now passes, and says what it was told** (`wolfproof .`, exit 0):

```text
reviewed        : sast:python-sql-injection:app.py:5df60c0d — app.py:18 — the table name comes from the fixed REPORTS dict, never from the request, tjwitko, until 2027-04-30 (.wolfproof-reviewed.json)
reviewed        : authentication:GET /reports:app.py — GET /reports (app.py:13) — admin token checked in the handler with compare_digest, tjwitko (.wolfproof-reviewed.json)
reviewed        : authentication:POST /hooks/payments:app.py — POST /hooks/payments (app.py:21) — verifies the provider's HMAC signature in the handler, tjwitko (.wolfproof-reviewed.json)

BLOCKING        : none
```

**5. Changing the reviewed line voids its review.** Adding `LIMIT 500` to that query makes it a new
finding, and the old entry is reported as doing nothing (`wolfproof .`, exit 1):

```text
BLOCKING        : 1

  - sast: SQL injection — request data is built into a SQL statement: app.py:18. …

reviewable      : 1 injection or authentication finding above can be marked reviewed once read — wolfproof review . lists its ID

  · review: 1 entry matches no finding, so it does nothing — sast:python-sql-injection:app.py:5df60c0d (.wolfproof-reviewed.json). The code it names has changed or the finding is gone; if the finding comes back with a new ID, review it again.
```

`wolfproof review .` shows its new ID, `sast:python-sql-injection:app.py:cc70db68`, with the two routes
now listed as `reviewed`. Read the line again, review it under the new ID if it is still acceptable,
and delete the old entry.

### The rules

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
in either mode — see [Reviewed findings from outside the workspace](action-reference.md#reviewed-findings-from-outside-the-workspace),
and [factory mode's allowlist](factory-mode.md#the-allowlist) for approving the project's file.

## JSON output

`--json` writes one machine-readable document. Even when the gate crashes it exits 3, never Node's
default 1, and still writes one document: `{"exitCode": 3, "incomplete": true, "error": "..."}`. A
usage error writes `{"exitCode": 2, "error": "..."}`.

The report also carries `toolchain` — each scanner on `PATH` and its version — and `scannedAt`, the
time the run started, and `reviewed`: each [reviewed finding](#reviewed-findings) with its ID,
location, reason, reviewer, expiry and the list it came from; and `reviewable`: the IDs of the
blocking findings a review could name, the ones `wolfproof review` lists as `BLOCKING`.
