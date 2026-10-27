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

## Outputs

| output | values |
|---|---|
| `outcome` | `clean` \| `blocked` \| `incomplete` |
| `blocking` | number of blocking findings |
| `result` | path to the machine-readable JSON |

`blocked` and `incomplete` both fail the build, and they are reported distinctly on purpose. Use
`outcome` if you want to treat them differently — for example, retrying an `incomplete` run on a
runner that has the missing scanner, which is never the right response to `blocked`.

## A baseline the project cannot edit

A `baseline` set in a workflow in the same repository is only as protected as that workflow file.
For a requirement every project must meet, set it in a workflow the project cannot edit — one an
organisation ruleset requires, for instance:

```yaml
      - uses: tjwitko/wolfproof@v1.12.0
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
      - uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.12.0
      - uses: tjwitko/wolfproof@v1.12.0
        with:
          reviewed: ${{ vars.WOLFPROOF_REVIEWED }}
```

The variable holds the same JSON as the file, `{"reviewed": [{"id", "reason", ...}]}`. Both lists
apply, and each reviewed finding says which one it came from. See
[Reviewed findings](configuration.md#reviewed-findings) for the format and a worked example.

## Environment

`WOLFPROOF_TEST_TIMEOUT` sets how long the `tests` check lets the suite run — see
[Configuration](configuration.md#test-timeout). In the Action, set it on the step:

```yaml
      - uses: tjwitko/wolfproof@v1.12.0
        env:
          WOLFPROOF_TEST_TIMEOUT: "300"
```
