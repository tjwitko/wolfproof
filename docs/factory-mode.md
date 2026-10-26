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
      - uses: tjwitko/wolfproof@v1.11.0
        with:
          task-file: task.txt
          factory: true
```

In the Action the base defaults to the pull request's base, or for a push to the commit before it,
and the Action fetches it: the default `fetch-depth: 1` is enough. Measured on a depth-1 clone of this
repository, fetching the base commit itself at depth 1 is all it takes, with no history in between.

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
| leaves an advisory meaning "nothing was checked" | an advisory | **blocks** (see [Advisories](#advisories)) |
| adds a probe route that reads, such as `GET /health` | exempt | still exempt, and **named** in the report |

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

### Probe routes

Probe names are conventional, so a reading probe route stays exempt in factory mode; factory mode
names one the change added. A write method on a probe path (`POST /health`) is not a probe, and is
checked in both modes.

### Exemptions it judges

Each of these is confirmed to loosen a check:

- `.tfguard-fixture` and `.identity-exception` — a whole directory out of every source check
- an entry in `.wolfproof-reviewed.json` — one named finding out of the verdict
  ([reviewed findings](configuration.md#reviewed-findings)); a later `expires` on the same finding is a new entry
- `# identity-guard:allow <rule> <reason>`
- `gitleaks:allow` on a line, and `.gitleaksignore` at the project root
- `osv-scanner.toml` beside a lockfile — an `[[IgnoredVulns]]` or `[[PackageOverrides]]` entry
  (one with `ignore = true` took four blocking CVEs to exit 0)
- `# noqa`, and `ruff.toml`, `.ruff.toml` or a `pyproject.toml` `[tool.ruff]` section
- `checkov:skip=` and `.checkov.yaml` — these block only when the pipeline's policy blocks the
  checkov findings they hide (`checkov`, `iac-checkov` or `dockerfile-checkov`, by file type).
  checkov's findings are advisories, and hiding one that cannot block is not itself blocking:
  under the default policy an added skip is listed in the factory notes instead

Not judged, because nothing honours them: a project `.gitleaks.toml`, `nosemgrep`, `.semgrepignore`
and `.gitignore`.

Each one is compared line by line, so the same `gitleaks:allow` on a line whose credential changed is
a new grant.

### Exit codes in factory mode

A base that cannot be resolved — a ref the checkout does not have — is **exit 3**: with nothing to
compare with, nothing self-granted can be told apart. Everything else factory mode refuses is
**exit 1**, because the change made it and can undo it; exit 3 means "fix the environment", which
would send it to the wrong owner.

## Advisories

Every advisory is classified, and none may leave the verdict clean by meaning nothing was checked:

| class | for example | factory mode |
|---|---|---|
| not-checked | "no HTTP routes were identified" in a project that starts an HTTP server; a retention period the task states and nothing here describes | blocks |
| could-not-run | a Terraform plan that could not authenticate; checkov killed; code in a language no check reads | exit 3 |
| finding | SQL built from a value of unknown origin; a heuristic workload-identity hit | counted, and dropped |
| info | tests ran and passed; no Kubernetes manifests to read | dropped |

Findings are dropped by default because blocking them is what gets a gate switched off: Gitea, a
clean application in the calibration corpus, draws 100 Go SQL advisories. An advisory factory mode
cannot classify blocks, whatever the policy says. `--json` lists each advisory's id, class and
action under `factory.advisories`.

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
`skipped-location`, `moved-to-unchecked`, `server-in-test`, `reviewed-finding` and `workflow-change`, which covers both
`.github/workflows/` and `.github/actions/`.

A `workflow-change` path is from the repository root, where GitHub reads workflows, even when the
project is a subdirectory:

```json
{ "exemptions": [
  { "kind": "workflow-change", "path": ".github/workflows/release.yml", "reason": "release job maintained by the platform team" }
] }
```

### The policy

```json
{ "advisories": { "sast:sql-string-built": "block", "retention-shorter": "block", "unread-code": "drop" } }
```

The policy maps an advisory id, an id family (`sast` for every `sast:<category>`), or a class name to
`block`, `drop` or `incomplete`, most specific first.

## What it does not do

- **Measure behaviour.** Whether the software does what its user needs is scenario validation —
  end-to-end checks kept where the agents cannot read them — and wolfproof sits beside it, not in
  place of it. Factory mode answers a narrower question: did the change narrow its own checks?
- **Block a reading route renamed to a probe name.** A `GET /health` is exempt by name in either mode,
  whatever it returns; factory mode names one the change added.
- **Judge a server in a test file that nothing in the project runs.** A server written as
  `server.test.js` blocks once a start script, a Dockerfile, a Procfile or application code refers to
  it; one that is run only by something outside the repository looks like any other test.
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
