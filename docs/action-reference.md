# GitHub Action reference

For setting the gate up as a required check, start with the README's
[Use it in CI](../README.md#in-ci); for why CI is the layer that enforces, see [`ci.md`](ci.md).

## Inputs

| input | default | description |
|---|---|---|
| `project` | `.` | Directory to validate |
| `task-file` | *(none)* | The task the code was written to satisfy |
| `baseline` | *(none)* | Requirement sentences the project is held to whatever its task file says — see [Requirements the code's author cannot remove](task-file.md#requirements-the-codes-author-cannot-remove) |
| `terraform-guard` | *(auto)* | Override path to a control server |
| `dep-audit` | *(auto)* | Override path to a control server |
| `secret-guard` | *(auto)* | Override path to a control server |
| `identity-guard` | *(auto)* | Override path to a control server |
| `factory` | `false` | `true` for [factory mode](factory-mode.md) |
| `base` | *(the PR's base, or the commit before a push)* | Factory mode: the commit the change is compared with; fetched if missing |
| `allowlist` | *(none)* | Factory mode: JSON approving specific exemptions |
| `policy` | *(none)* | Factory mode: JSON choosing what each advisory class does |
| `reviewed` | *(none)* | JSON naming [reviewed findings](configuration.md#reviewed-findings), from outside the workspace; either mode |
| `known` | *(none)* | JSON holding a [snapshot of known findings](configuration.md#known-findings), from outside the workspace; either mode |
| `trivy-image` | *(none)* | A container image to scan with Trivy, built or pulled by an earlier step — see [the built image](checks.md#the-built-image-opt-in). Linux runners only |
| `trivy-severity` | `HIGH` | The lowest severity that blocks when a fix exists: `CRITICAL`, `HIGH`, `MEDIUM` or `LOW` |
| `codeql` | `false` | `true` to analyse the source with [CodeQL](checks.md#codeql-opt-in) too. Needs a GitHub Advanced Security licence unless the code is open source on GitHub.com. Linux and macOS runners |

## Outputs

| output | values |
|---|---|
| `outcome` | `clean` \| `blocked` \| `incomplete` |
| `blocking` | number of blocking findings |
| `result` | path to the machine-readable JSON |

`blocked` and `incomplete` both fail the build, and they are reported distinctly on purpose. Use
`outcome` if you want to treat them differently — for example, retrying an `incomplete` run on a
runner that has the missing scanner, which is never the right response to `blocked`.

## Scanning the built image

Build or pull the image in an earlier step and name it. Its vulnerabilities join the one verdict:

```yaml
- run: docker build -t myapp:ci .
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.16.0
- uses: tjwitko/wolfproof@v1.16.0
  with:
    task-file: TASK.md
    trivy-image: myapp:ci
```

The action installs Trivy v0.76.0 itself and checks it against the SHA-256 pinned in `action.yml`,
rather than using `aquasecurity/trivy-action`, whose version tags were force-pushed to
credential-stealing code in March 2026 (CVE-2026-33634). If the install fails, the run is
`incomplete`; a Trivy already on the runner is not used in its place. Each run downloads Trivy's
vulnerability database, about 140 MB. Linux runners only.

## Analysing the source with CodeQL

```yaml
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.16.0
- uses: tjwitko/wolfproof@v1.16.0
  with:
    task-file: TASK.md
    codeql: true
```

Check the licence first. Without GitHub Advanced Security, CodeQL's terms allow it only on code
under an OSI-approved open-source licence, in CI only when that code is on GitHub.com.

The action installs the CodeQL bundle 2.27.3 from `github/codeql-action`'s immutable release and
checks it against the SHA-256 pinned in `action.yml`, a download of about 550 MB on Linux. If the
install fails, the run is `incomplete`; the CodeQL that GitHub's runner images carry is not used in
its place. Go, Swift and Kotlin are built first with CodeQL's autobuild, so the runner needs their
toolchains, as it would for your own build. Each language takes from seconds to minutes, so this
input suits a pull-request workflow better than a pre-commit hook.

## A baseline the project cannot edit

A `baseline` set in a workflow in the same repository is only as protected as that workflow file.
For a requirement every project must meet, set it in a workflow the project cannot edit — one an
organisation ruleset requires, for instance:

```yaml
      - uses: tjwitko/wolfproof@v1.16.0
        with:
          task-file: task.txt
          baseline: |
            Include automated tests that someone else can run.
            A client error must not be reported as a 500.
```

## Reviewed findings from outside the workspace

The project's own `.wolfproof-reviewed.json` changes with the code, by whoever writes the code. For
reviews only the people who own the pipeline can grant, keep the list in a repository or
organisation variable (Settings → Secrets and variables → Actions → Variables) and pass it in; the
Action writes it outside the workspace, where the change cannot edit it:

```yaml
      - uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.16.0
      - uses: tjwitko/wolfproof@v1.16.0
        with:
          reviewed: ${{ vars.WOLFPROOF_REVIEWED }}
```

The variable holds the same JSON as the file, `{"reviewed": [{"id", "reason", ...}]}`. Both lists
apply, and each reviewed finding says which one it came from. See
[Reviewed findings](configuration.md#reviewed-findings) for the format and a worked example.

A snapshot of [known findings](configuration.md#known-findings) can come from outside the workspace
the same way, through the `known` input: `wolfproof known . --file known.json` writes one, and the
variable holds its JSON, `{"known": [{"id", "where"}]}`. The project's own `.wolfproof-known.json`
applies beside it.

## Environment

`WOLFPROOF_TEST_TIMEOUT` sets how long the `tests` check lets the suite run — see
[Configuration](configuration.md#test-timeout). In the Action, set it on the step:

```yaml
      - uses: tjwitko/wolfproof@v1.16.0
        env:
          WOLFPROOF_TEST_TIMEOUT: "300"
```
