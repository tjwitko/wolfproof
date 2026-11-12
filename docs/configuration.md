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

A suite that passes says how long it took, beside the limit:

```text
  · tests: ran under node --test — 19 of 19 passed in 41s (limit 120s).
```

Set the limit from that line, read where the gate runs. A suite killed at the limit says only that it
needed longer, and the same suite does not take the same time in every CI job. On the one run of
this project's own where both printed it, the suite took 232s in the job that gates it and 142s, 160s
and 198s in the jobs that only run `npm test`, on the same commit: 1.2 to 1.6 times as long.

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

It runs only the injection and authentication checks — and CodeQL, with `--codeql`, for a gate run
with `--codeql` — changes nothing, and prints each finding as two lines — a status (`BLOCKING`,
`advisory` or `reviewed`) followed by the ID, then where the finding is and what it is:

```text
BLOCKING  sast:python-sql-injection:app.py:5df60c0d
    app.py:28 — SQL injection: request data is built into a SQL statement
```

The ID is everything after the status word, here `sast:python-sql-injection:app.py:5df60c0d`. Copy it
as printed. It has one of these shapes:

| check | ID | example |
|---|---|---|
| injection | `sast:<rule>:<file>:<hash of the line>` | `sast:python-sql-injection:app.py:5df60c0d` |
| authentication: an open route | `authentication:<METHOD> <route>:<file>` | `authentication:GET /reports:app.py` |
| authentication: a signature compared with `==` | `authentication:signature:<file>:<hash of the line>` | `authentication:signature:hooks.py:c38eafa0` |
| authentication: a credential compared with `==` | `authentication:timing:<file>:<hash of the line>` | `authentication:timing:app.py:a64ea7ba` |
| authentication: a credential that compares equal when unset | `authentication:unset:<variable>` | `authentication:unset:SUPPORT_TOKEN` |
| CodeQL | `codeql:<query>:<file>:<hash of the line>` | `codeql:js/reflected-xss:src/app.js:39f7be0b` |

The last part of an injection ID is a hash of the flagged line, so it cannot be written by hand. Take it
from the list. (`--json` carries the blocking ones too, as `reviewable`.) When two findings would get the same ID (the same rule on two identical lines of one file), the
second gets `#2` on the end.
Advisory findings are listed too, and reviewing one takes it out of the advisories.

### An example

A small Flask service. Both routes check their caller in a helper they call — an admin token, a
webhook signature — and the authentication check reads a handler's own code, not the helpers it
calls ([what it credits](checks.md#authentication-checked-inside-the-handler)). The report's table name
is looked up in a fixed dictionary, which the injection check cannot tell from request data:

```python
REPORTS = {"orders": "orders", "refunds": "refunds"}

def require_admin():
    if not hmac.compare_digest(request.headers.get("X-Admin-Token", ""), os.environ["ADMIN_TOKEN"]):
        abort(403)

def require_payments_signature():
    expected = hmac.new(os.environ["PAYMENTS_SECRET"].encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Signature", "")):
        abort(401)

@app.get("/reports")
def report():
    require_admin()
    table = REPORTS[request.args["kind"]]
    return {"rows": db.execute(f"SELECT * FROM {table} ORDER BY created DESC").fetchall()}

@app.post("/hooks/payments")
def payment_hook():
    require_payments_signature()
    return {"ok": True}
```

**1. The gate blocks on all three** (`wolfproof .`, exit 1, explanations trimmed):

```text
BLOCKING        : 2

  - authentication: 2 of 2 endpoint(s) accept requests from anyone who can reach the service — GET /reports (app.py:24), POST /hooks/payments (app.py:31). …

  - sast: SQL injection — request data is built into a SQL statement: app.py:28. Use a parameterised query: …

reviewable      : 3 injection or authentication findings above can be marked reviewed once read — wolfproof review . lists their IDs
```

**2. List the findings by ID**, as the report's last line says:

```text
$ wolfproof review .
project : …/shop

BLOCKING  sast:python-sql-injection:app.py:5df60c0d
    app.py:28 — SQL injection: request data is built into a SQL statement
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
  --reason "verifies the provider's HMAC signature in require_payments_signature()" --reviewer tjwitko
wolfproof review . 'authentication:GET /reports:app.py' \
  --reason "require_admin() checks the admin token with compare_digest" --reviewer tjwitko
wolfproof review . 'sast:python-sql-injection:app.py:5df60c0d' \
  --reason "the table name comes from the fixed REPORTS dict, never from the request" \
  --reviewer tjwitko --expires 2027-04-30
```

```text
added in .wolfproof-reviewed.json:
  {"id":"authentication:POST /hooks/payments:app.py","reason":"verifies the provider's HMAC signature in require_payments_signature()","reviewer":"tjwitko"}

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
      "reason": "verifies the provider's HMAC signature in require_payments_signature()",
      "reviewer": "tjwitko"
    },
    {
      "id": "authentication:GET /reports:app.py",
      "reason": "require_admin() checks the admin token with compare_digest",
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
reviewed        : sast:python-sql-injection:app.py:5df60c0d — app.py:28 — the table name comes from the fixed REPORTS dict, never from the request, tjwitko, until 2027-04-30 (.wolfproof-reviewed.json)
reviewed        : authentication:GET /reports:app.py — GET /reports (app.py:24) — require_admin() checks the admin token with compare_digest, tjwitko (.wolfproof-reviewed.json)
reviewed        : authentication:POST /hooks/payments:app.py — POST /hooks/payments (app.py:31) — verifies the provider's HMAC signature in require_payments_signature(), tjwitko (.wolfproof-reviewed.json)

BLOCKING        : none
```

**5. Changing the reviewed line voids its review.** Adding `LIMIT 500` to that query makes it a new
finding, and the old entry is reported as doing nothing (`wolfproof .`, exit 1):

```text
BLOCKING        : 1

  - sast: SQL injection — request data is built into a SQL statement: app.py:28. …

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
  helper it goes through, makes it a new finding to review. A review of an open route names the
  route, and holds until its method, path or file changes. A review of an unset credential names the
  variable, and holds every comparison of it, a later one included.
- **Nothing goes quiet.** An entry that matches no finding is reported as an advisory, as is one past
  its date, so the file does not keep entries that do nothing.
- **Which findings.** The first version covers the injection (`sast`) and authentication checks.

The file is a record, not a control: whoever writes the code can write it, as with a fixture
marker, and the agent loop refuses to let a model write it. In [factory mode](factory-mode.md), an
entry the change adds blocks unless the pipeline's allowlist approves it (`reviewed-finding`).
`--reviewed=<file>`, and the Action's `reviewed` input, take the same list from outside the project,
in either mode — see [Reviewed findings from outside the workspace](action-reference.md#reviewed-findings-from-outside-the-workspace),
and [factory mode's allowlist](factory-mode.md#the-allowlist) for approving the project's file.

## Known findings

A repository with history blocks on the first day, for code no change touched: across 34 open-source
applications the gate blocked or was incomplete on every one. Fixing all of it before the gate can be
required is how a gate stays unadopted. A snapshot records what is already there, after which a finding
in the snapshot is counted and does not block, and a finding not in it blocks as before.

```bash
wolfproof known .            # writes .wolfproof-known.json; commit it
```

An Express app with two open routes and an empty file:

```text
$ wolfproof known .
snapshot: .wolfproof-known.json

wrote 3 findings: 2 authentication, 1 empty files.

Commit .wolfproof-known.json. The gate counts these findings and does not block on them; in factory mode, the pipeline's allowlist has to approve this first snapshot, and an entry a later change adds blocks.

$ wolfproof .
known           : 3 findings known from the snapshot (.wolfproof-known.json), not blocking — --json lists them
BLOCKING        : none
```

A change that adds a route blocks on that route alone:

```text
BLOCKING        : 1

  - authentication: 1 of 3 endpoint(s) accept requests from anyone who can reach the service — DELETE /orders/:id (app.js:4). 2 more are open and known from the snapshot.
```

### What a snapshot holds

A finding enters a snapshot only if it blocks and has an ID that survives unrelated edits:

| check | the finding's ID is | survives |
|---|---|---|
| injection (`sast`), CodeQL | the rule, the file, a hash of the line | an edit elsewhere in the file |
| authentication: open routes | the method, the path, the file | any edit that keeps the route |
| authentication: a credential or a signature compared with `==` | the file, a hash of the line | an edit elsewhere in the file |
| authentication: an unset credential | the variable's name | any edit that keeps it |
| dependencies | the ecosystem, the package, the advisory | an upgrade that leaves the advisory open |
| a `package.json` with no lockfile | its path | any edit to it |
| workload identity | identity-guard's rule, the file, a hash of the line | an edit elsewhere in the file |
| Dockerfile base images past end of life | the file, the stage, the image, the product | another release of the same image |
| empty files | the path | — |
| test patch targets that do not exist | the test file, the target | an edit elsewhere in the test |

An entry holds every finding with its ID, and two of these IDs name no single place. An unset
credential's is the variable's name, so the entry holds every comparison of that variable, one a
later change adds included, in any file and in any language. A dependency's is the package and the
advisory, so the entry holds that advisory in every lockfile, one a later change adds included. Every
other ID names the file the finding is in.

Everything else keeps blocking, whatever the snapshot says:

- **A hardcoded secret.** It stays exposed in the repository's history whether or not the gate blocks
  on it, so it is rotated and removed rather than recorded.
- **What was not checked.** A check that could not run makes the run incomplete (exit 3), and a
  manifest no scanner read — a Gradle build or a `Cargo.toml` with no lockfile — says nothing was
  checked. A snapshot can hold neither: there is no finding to hold. A snapshot made while a check
  could not run (a semgrep timeout, say) does not hold that check's findings, and since it never
  adds, they block once the check runs; delete it and make it again on a run where every check
  finishes. A `package.json` with no
  lockfile is the exception, because its direct dependencies are
  [scanned anyway](checks.md#dependencies): the snapshot can hold the missing lockfile, which is then
  an advisory on every run, saying the transitive dependencies are not checked.
- **The build, and the checks gated on the task:** immutability, retention, secret rotation, the IAM
  contract, required artifacts, tests. They judge whether the project meets a stated requirement, and
  they exist because advice did not work where refusal did.

`wolfproof known` lists what still blocks after it writes the snapshot, so it is clear at once what
has to be fixed before the gate can be required.

### The rules

- **It only shrinks.** Run against an existing snapshot, the command removes entries that match no
  finding and never adds one. A finding that appears later blocks until it is fixed or
  [reviewed](#reviewed-findings) with a reason; re-running the command after a red build does not
  clear it. One exception: when a lockfile is committed for a `package.json` the snapshot held as
  having none, the command adds that lockfile's findings, once — they could not be seen before, and
  committing a lockfile should not turn the build red. The entry for the missing lockfile goes, so it
  cannot happen twice for that manifest. The entry records the packages the `package.json` declared
  when it was written (`declared`), and the exception holds only while it declares nothing else: a
  dependency declared since, in the same change as the lockfile or an earlier one, is not one the
  snapshot held, so the command adds nothing for that lockfile, says why, and keeps the entry. Its
  findings block until fixed or reviewed; to have them added, commit the lockfile in a change that
  declares only what the entry lists and run the command again. An entry with no `declared` list,
  one written by hand, adds nothing. The list is read from the snapshot file as it is. In the
  project's own file a name written in by hand is therefore not refused, which is the snapshot being
  a record and not a control: the same hand could have written the finding's entry, and both edits
  are in the diff. [Factory mode](factory-mode.md) refuses the edit itself, and a snapshot kept
  outside the project (`--file`) cannot be edited by the change. Even then, only findings for packages the `package.json` does
  not declare directly are added. A direct dependency was scanned before the lockfile existed, at the
  lowest version its range allows, so a finding it had then is already an entry; one it did not have
  is the change's own (a range lowered in the same change) or a vulnerability only in versions above
  the range's lower bound, and either way it blocks. The transitive findings are added on trust,
  whatever packages the committed lockfile lists: a direct dependency's range lowered in the same
  change can pull in an older, vulnerable package underneath it, and that finding is added. The
  added entries show in the change to `.wolfproof-known.json`, so read it in review. If the
  lockfile's scan fails, nothing is added and the entry is kept; the command says so, and running it
  again once the scan works adds them. A lockfile committed at a workspace root covers every member's
  `package.json`, and holds every member's packages and the root's, so which of its findings are one
  member's cannot be told: nothing is added for a member's entry, the command says so, and the entry
  is kept for you to delete once the lockfile's findings are fixed or reviewed. For the root's own
  entry, every member's direct dependencies count as direct too (the members named by `workspaces`,
  or by `pnpm-workspace.yaml`): they were scanned without a lockfile exactly as the root's were, so
  a finding one has at its locked version blocks rather than being added. Each member is also held
  to its own entry's list, as the root is to its own: the lockfile holds every member's packages,
  so a dependency a member declared since the snapshot would otherwise have its transitive findings
  added through the root's entry. A member that declares a package its entry does not list, one
  whose entry has no list, and one that declares packages and has no entry in the snapshot each
  refuse the lockfile: nothing is added, the command names the member and the packages, and the
  root's entry is kept. A member that declares nothing needs no entry. So keep the members' entries
  until the lockfile's findings have been added for the root, which the command says when it keeps
  one. A member has no entry when it was added after the snapshot, had a lockfile of its own
  then, or sits under a directory the checks skip; the root's lockfile is then refused for as long
  as that member declares anything, and its findings are fixed or reviewed instead. A `!` exclusion
  in `workspaces` is not applied, so a `package.json` it excludes is held to its entry like a
  member. A `workspaces` pattern
  the command cannot resolve (`**`, `?`, braces, brackets; `name` and `packages/*` it can), a
  member it cannot read, or a `pnpm-workspace.yaml` it cannot parse or that has no `packages` list,
  leaves the members unknown, so nothing is added and the entry is kept. A `peerDependency` counts as
  declared, for the entry and for the comparison: npm 7 and later install peers and write them to
  the lockfile, so a peer added with it is the change's own. In
  [factory mode](factory-mode.md) committing the lockfile does turn the build red: the base has a
  snapshot, so the entries the command adds are added grants, and block whatever the allowlist says.
  A pipeline that keeps its own snapshot (`--known=<file>`, or the Action's `known` input) avoids it.
- **A run that did not finish changes nothing.** When part of the gate could not run (exit 3), the
  command leaves an existing snapshot as it is and lists the entries it would have removed: an entry
  matching nothing may only mean the scan that finds it did not finish. The first snapshot is still
  written, holding what the checks that ran found.
- **Nothing goes quiet.** An entry that matches no finding of a check that ran to the end is an
  advisory: the finding was fixed, or the line it names changed. An entry for a check that could not
  run is kept, since that check could still hold the finding. Dependency findings come from two
  scans, the lockfile scan and the scan of a `package.json` with no lockfile, and an advisory's entry
  is judged only when the lockfile scan ran and every manifest of its ecosystem was read; a
  `package.json` that does not parse was not. An entry naming a file no check read — a Dockerfile
  that could not be opened, a source file over 512 KB — is not judged either.
- **A fixed finding stays covered until the command runs.** Its entry matches nothing, and the gate
  says so on every run, but it stays in the file until `wolfproof known` removes it; until then, a
  change that brings the same finding back — the same ID — is set aside like the original. Run the
  command after fixing findings to close that.
- **A dependency advisory is held for the whole project.** Its ID is the ecosystem, the package and
  the advisory, with no file, so one entry covers that advisory in every lockfile, including the
  lockfile of a service added after the snapshot. A different advisory, or a different package,
  blocks.
- **Known findings are counted, not listed.** A legacy repository's snapshot holds hundreds. The
  report prints one line; `--json` lists each under `known`, with where it is.
- **A review wins.** A finding both reviewed and in the snapshot is listed as reviewed, with its
  reason.

Like the review file, `.wolfproof-known.json` is a record, not a control: whoever writes the code
can edit it, the edit is in the diff a reviewer reads, and the agent loop refuses to let a model
write it. In [factory mode](factory-mode.md), each entry a change adds blocks. The pipeline's
allowlist (`known-finding`) can approve the change that writes the first snapshot, and only that
one: once a snapshot exists, nothing approves an entry added to it, or a name added to the
`declared` list of an entry in it (`known-declared`).
`--known=<file>` and the Action's `known` input take a snapshot from outside the project, in either
mode: `wolfproof known . --file <path>` writes one there.

## JSON output

`--json` writes one machine-readable document. Even when the gate crashes it exits 3, never Node's
default 1, and still writes one document: `{"exitCode": 3, "incomplete": true, "error": "..."}`. A
usage error writes `{"exitCode": 2, "error": "..."}`.

The report also carries `toolchain` — each scanner on `PATH` and its version — and `scannedAt`, the
time the run started, and `reviewed`: each [reviewed finding](#reviewed-findings) with its ID,
location, reason, reviewer, expiry and the list it came from; and `reviewable`: the IDs of the
blocking findings a review could name, the ones `wolfproof review` lists as `BLOCKING`.

`known` lists each finding the [snapshot](#known-findings) set aside: its ID, where it is, and the
snapshot it came from, and for a `package.json` with no lockfile the packages it declares
(`declared`). `records` has one entry per finding with an ID — `id`, `check`, `file`,
`line` (null when the finding has no line), `blocking`, `known` and `reviewed` — so a tool can match
findings to the lines a change touched. A finding without an ID is only in `findings`.
