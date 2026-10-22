# wolfproof

[![gate](https://github.com/tjwitko/wolfproof/actions/workflows/gate.yml/badge.svg)](https://github.com/tjwitko/wolfproof/actions/workflows/gate.yml)
[![release](https://img.shields.io/github/v/release/tjwitko/wolfproof)](https://github.com/tjwitko/wolfproof/releases/latest)
[![license](https://img.shields.io/github/license/tjwitko/wolfproof)](LICENSE)

*Formerly agent-gate — see [Coming from agent-gate](docs/upgrading.md#coming-from-agent-gate).*

Security scanners find known-bad things: a vulnerable package, a leaked key, request data in a SQL
string. They do not find security that looks done and isn't:

- an API-key check that passes when the key is unset, because `None != None` is false
- a webhook that reads the signature header and never verifies it
- a Deployment that never sets the variable the auth check compares against
- a secret fetched from Secrets Manager and cached forever, so rotating it drops real traffic and
  the revoked key keeps working
- an "immutable" audit log whose only protection is that the API has no delete endpoint

Every file reads as careful, and every scanner passes it. These defects live between files, or
between the code and what it was asked to do. That is where wolfproof looks:

- **Authentication, route by route** — fail-open comparisons, unverified signatures,
  non-constant-time checks, and middleware that looks like auth and isn't.
- **The code against its own deployment** — environment variables the manifests never set, IAM and
  Kubernetes configuration that plans clean and cannot work, workloads that authenticate with a
  credential they hold instead of an identity they have.
- **The code against the task** — when the requirements say records are immutable, retained for
  three years, tokens rotatable, or tests someone else can run, the code is held to it, and its
  author cannot quietly delete the sentence.

It also runs the checks you would expect — injection, dependency CVEs, Terraform policy, hardcoded
secrets — because that floor still matters.

And it never mistakes silence for success. Every run ends **clean**, **blocked**, or
**could-not-run**: a missing scanner, an unreachable control or a test suite that will not start
is exit 3, never a pass.

It was built for code AI agents write. The checks above came out of graded agent runs — work that
passed the usual scanners while its own summary said "production-ready". Nothing in it assumes an
agent, and it works the same on code people wrote.

---

## Quickstart

```bash
npm install --save-dev github:tjwitko/wolfproof#v1.6.0
echo "Build an HTTP service. Ship tests someone else can run." > task.txt   # the requirements, in prose
./node_modules/.bin/wolfproof init --hook --task task.txt                   # agent instructions + pre-commit hook
./node_modules/.bin/wolfproof . task.txt                                    # the verdict
```

Exit **0** clean, **1** blocking findings, **2** usage error, **3** part of it could not run — a
missing scanner, say, which the run names. Work that is not committed is itself a blocking finding,
so on a fresh project commit first and run again.

You will also need the scanners your stack uses — see [Requirements](#requirements).

**Run it by path, not through `npx`.** The path runs the version your project pinned and makes no
network request. `npx` looks up a missing command on the public registry and, in an agent's
non-interactive shell, installs whatever it finds without asking.
[Why this matters](docs/upgrading.md#notes-from-earlier-versions).

To track `main` instead of a release, drop the `#v1.6.0`. `main` moves.

---

## What you get

```
project        : /home/you/webhook-receiver
control        : terraform-guard  node_modules @tjwitko/terraform-guard-mcp
control        : dep-audit        node_modules @tjwitko/dep-audit-mcp
control        : secret-guard     node_modules @tjwitko/secret-guard-mcp
control        : identity-guard   node_modules @tjwitko/identity-guard-mcp
validators run : build_check, terraform_plan(terraform), check_dependencies, immutability, ...

BLOCKING        : 2

  - scan_path: 1 hardcoded credential(s): src/config.js:14 aws-access-key
  - authentication: POST /webhook has no authentication ...

advisory        : 3
  · tests: ran under node --test — 19 of 19 passed.
  ...
```

How to read it:

- **The gate** is what you just ran: `wolfproof <dir> [task-file]`. It produces the verdict.
- **Controls** are four MCP servers, installed with wolfproof, that wrap the scanners: terraform-guard
  (Terraform and checkov), dep-audit (osv-scanner), secret-guard (gitleaks) and identity-guard. Each
  `control` line says where that control was found, so you can see at a glance that all four ran.
- **Validators** are the gate's own in-process checks — tests, authentication, injection, and the
  rest.
- A **blocking** finding fails the run (exit 1). An **advisory** is reported and does not.
- A check that **could not run** is neither: the run exits 3 and names it.

---

## Requirements

**Node.js 20 or newer**, and the scanners for what your project contains. Every project needs the
first row; add the rows for the languages and files you have:

| your project has | install | it runs |
|---|---|---|
| anything | `gitleaks`, `osv-scanner` | hardcoded-credential and dependency-CVE scans |
| Python | `semgrep`, `ruff`; `pytest` if it has tests | injection checks, static checks, the test suite |
| JavaScript / TypeScript | `semgrep` | injection checks; tests run with the project's own tooling |
| Go | `semgrep`, `go`, `docker` | injection checks, the build and the tests |
| Java, Ruby, C#, Rust, C, C++, PHP, Kotlin | `semgrep` | injection checks |
| Terraform | `terraform`; `checkov` optional | plan and policy checks; checkov adds advisories |
| Dockerfile | nothing extra; `checkov` optional | the base-image end-of-life check; checkov adds advisories |

```bash
brew install gitleaks osv-scanner semgrep terraform   # macOS — pick the ones your stack needs
pipx install ruff checkov
python3 -m pip install pytest                         # only if the project has a Python test suite
```

**A missing scanner is never skipped silently.** The run says which check could not run and exits 3.

Install `pytest` with `pip`, not `pipx`: the gate runs `python3 -m pytest`, so the module must be
importable by that interpreter. A `pytest` command on `PATH` is not enough.

---

## The task file

Pass the gate the task the code was written to satisfy. Six checks — immutability, retention, secret
rotation, tests, error distinction, and required artifacts — run only when the task asks for them.
Without a task file they report "not checked".

The task file is prose, not configuration: the requirements as you would write them for a person.

```text
REQUIREMENTS
- Once a message event has been recorded, its contents must stay exactly as received.
- Records are retained for three years.
- Both Slack tokens must be rotatable without redeploying the application.
- Automated tests that someone else can run, covering an event being acknowledged.
```

Each check looks for the shape of a requirement, not a topic. "Records are retained for three years"
switches the retention check on; "keep the records" does not, because there is no period to compare
against. Put each requirement in one sentence, and never write one you don't have — a made-up
requirement holds the code to a standard nobody asked for.

Every run reports how many of the task's sentences a check read, and `--json` lists the ones none
did.

A commit that edits a tracked task file is blocked, so a blocked agent cannot simply delete the
requirement. For requirements every project must meet, there is also a **baseline** kept outside the
project.

→ [The task file](docs/task-file.md): a full example, what switches each check on, baselines.

---

## Where to run it

The gate is a command, so it can run anywhere. There are three places worth running it, and they
build on each other.

### With a coding agent

`wolfproof init` sets up two things for the agent:

- **`.mcp.json`**, so the agent can call the four controls as tools while it works, for quick
  feedback on what it just wrote.
- **A stanza in `AGENTS.md`** that tells it to run the gate, and how to report what it finds.

The agent can choose whether to call a tool, so the tools are only there for its own benefit. Across
four runs of one task, a model called `terraform_plan` 3, 1, 4 and 0 times, and never called
`check_dependencies`. The gate does not depend on those calls: it starts the four controls itself.

The stanza exists because "run the gate" is not enough. Each of its rules was added after a run
broke it — most importantly, **a check that could not run is not a pass**, and **exit 0 means
nothing is blocking, not that everything was checked**.

→ [Using wolfproof with a coding agent](docs/coding-agents.md): the stanza, the MCP configuration, the loop.

### As a pre-commit hook

`wolfproof init --hook` installs a hook that runs the gate on every commit:

```
git commit  ->  wolfproof . task.txt --pre-commit  ->  0  commit proceeds
                                                       1  findings        \
                                                       2  usage error      > commit blocked
                                                       3  could not run   /
```

**Exit 3 blocks.** A commit that nothing checked must not be easier to land than one that failed a
check. For the same reason the hook fails closed: if wolfproof is not installed, it blocks.

`git commit --no-verify` is the deliberate way past, and unlike deleting the hook it leaves a trace.
`--pre-commit` turns off one check, `uncommitted_work` — work being committed is uncommitted by
definition — and says so in the output.

`init` overwrites nothing: it merges into an existing `.mcp.json`, appends to `AGENTS.md` between
markers, and leaves an existing hook alone. → [Configuration](docs/configuration.md#wolfproof-init)

### In CI

This is where the gate actually enforces: a required check, run after the work is finished, on a
machine the agent never touched.

```yaml
name: gate
on: [pull_request]

jobs:
  wolfproof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      # Your project's own dependencies, so the `tests` check can run your suite.
      - run: npm ci --ignore-scripts

      # The scanners, at the versions this release was tested with, each checked after install.
      - uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.6.0

      - uses: tjwitko/wolfproof@v1.6.0
        with:
          project: .
          task-file: task.txt
```

Two of those steps are easy to leave out, and both fail quietly:

- **`npm ci`** (or your language's equivalent). Without it the suite runs with no dependencies and
  every test file fails, which looks like broken tests.
- **`control-tooling`**. It installs the scanner versions this release was tested with and moves
  when you upgrade. A scanner you install yourself stays at whatever version you wrote down.

Keep both `uses:` lines on the same tag. Then make the job a required check in
**Settings → Branches → Branch protection**.

The Action's `outcome` output is `clean`, `blocked` or `incomplete`. Both `blocked` and `incomplete`
fail the build, and they are reported separately so a pipeline can treat them differently.

→ [Action reference](docs/action-reference.md) · [Why CI is the layer that enforces](docs/ci.md)

#### When no person reviews the change

In the default mode, every exemption and opt-out is printed for a reviewer to see. In a pipeline
where agents write the change and nobody reads the report, that protects nothing. **Factory mode**
(`--factory`, or `factory: true` in the Action) compares the change with its base and blocks what
the change granted itself: new exemptions, overridden controls, edits to the task file or workflows,
code moved where the checks do not look.

→ [Factory mode](docs/factory-mode.md)

---

## What it checks

### What scanners miss

Controls that are present and do not work. Each row below blocks.

| concern | blocks on |
|---|---|
| authentication | a route anyone can call, judged route by route; a credential accepted when it is unset, or compared with `==` instead of in constant time; a signature header nothing verifies; a dependency that looks like auth and isn't (`Depends(get_db)`) |
| code against deployment | an environment variable the code requires and no Kubernetes manifest sets; `${...}` that Kubernetes never expands; a container field on the pod spec, which the API server rejects; an IRSA role the ServiceAccount cannot assume; an AWS managed policy that does not exist, which plans clean and fails at apply |
| workload identity | a workload that authenticates with a password, static key or shared token rather than an identity — wherever the credential is stored |
| task requirements | when the task states them: an "immutable" store that can be altered; records deleted before the stated retention period; a secret cached so that it cannot rotate; client errors reported as 500s; tests that fail when run, or do not exist; a deliverable the task names that is not there |
| evidence | a file that exists but is empty, which every check reading it would pass; work not committed; a commit that edits the task file |

Authentication covers Python, JavaScript/TypeScript, Go, Java and Ruby; error distinction covers
Python. The task-gated checks are narrow on purpose — immutability, for instance, only judges a
store that names itself an audit log — because a blocking check that fires on correct code gets
switched off.

### The scanner floor

The checks you would expect, still necessary:

| concern | blocks on |
|---|---|
| injection | request data reaching a shell, SQL, an evaluator, an outbound request's host (SSRF) or a file path — in Python, JavaScript/TypeScript, Go, Java, Ruby, C#, Rust, C, C++, PHP and Kotlin |
| dependencies | high or critical CVEs; dependencies declared with no lockfile the scanner can read |
| secrets | credentials hardcoded in any file, including ones split, joined or encoded |
| infrastructure | Terraform plan and policy violations on AWS, such as a security group or EKS API open to `0.0.0.0/0` |
| containers | a base image past end of life, in any build stage |
| build | syntax errors, undefined names, a Go build that fails |

## What it does not check

So that a clean verdict is read for what it is:

- **Code in other languages.** Swift, Scala and the rest get only the project-wide scans —
  secrets, dependencies, infrastructure. The run says so above the verdict. PHP and Kotlin get the
  injection check and nothing else that reads the code: no authentication check, build or test run.
- **Injection across a function call**, and cross-site scripting, template injection, LDAP
  injection, open redirect and insecure deserialization.
- **Memory safety in C and C++**, beyond `gets()`.
- **Authorisation** — what an authenticated caller may then do.
- **The packages inside a built image** — use Trivy or Grype in CI.
- **Blocking infrastructure policy beyond Terraform on AWS and Kubernetes.** Other clouds and
  formats get advisories only.
- **Requirements nobody stated.**

→ [What it checks, in full](docs/checks.md): languages and frameworks, the four controls, how the
injection rules are calibrated, and every known blind spot.

---

## Exit codes

| code | meaning | what to do |
|---|---|---|
| `0` | nothing blocking | ship it |
| `1` | blocking findings | fix them; they are real |
| `2` | usage error | check the arguments |
| `3` | **part of the gate could not run** | fix the environment, then re-run |

**Exit 3 is the one that matters.** It means the project was not fully checked. It is not a pass,
and it is not a normal failure. Treating it as either is the failure mode this project exists to
remove. A gate that crashes exits 3 too.

`wolfproof init` has its own codes — see [Configuration](docs/configuration.md#wolfproof-init).

---

## Upgrading

1. Check what you are on: `./node_modules/.bin/wolfproof --version` lists the gate, each control and
   each scanner.
2. Move the pin — in CI, **both** `uses:` lines.
3. Run `./node_modules/.bin/wolfproof init --upgrade` to refresh the stanza and hook setup wrote.
4. Run the new version locally before moving the CI pin. A release that closes a gap can turn a
   passing project red on purpose; release notes list these under *expect this to fail*.

→ [Upgrading](docs/upgrading.md): rolling back, Dependabot, coming from agent-gate.

---

## Why this exists

The design comes from a measured experiment: the same task run fifteen times across models, graded
by one frozen gate.

- Twelve runs by a smaller model produced **zero** passes; three frontier-model runs passed on the
  first attempt.
- A control run with the gate available but **unmentioned in the prompt** consulted it zero times
  and finished with six blocking findings. The model did not route around the gate; it never
  reached it.
- Delivering the rules through a file the agent was expected to read worked **two times out of
  four**.

A mechanism that works half the time is a hint, not a control. That is the whole argument for
putting this in CI rather than in a prompt.

Full write-up: [`docs/haiku-experiment.md`](docs/haiku-experiment.md).

---

## Documentation

| page | for |
|---|---|
| [The task file](docs/task-file.md) | writing requirements the checks can read; baselines |
| [Coding agents](docs/coding-agents.md) | the agent stanza, MCP configuration, the build–gate loop |
| [Action reference](docs/action-reference.md) | every Action input and output |
| [Why CI enforces](docs/ci.md) | MCP vs hooks vs required checks; branch protection |
| [Factory mode](docs/factory-mode.md) | pipelines with no human reviewer |
| [What it checks](docs/checks.md) | full coverage, the controls, calibration, blind spots |
| [Configuration](docs/configuration.md) | control resolution, `init`, timeouts, JSON output |
| [Troubleshooting](docs/troubleshooting.md) | what each message means and what to do |
| [Upgrading](docs/upgrading.md) | moving pins, rolling back, coming from agent-gate, version notes |
| [Development](docs/development.md) | tests, the regression corpus, the calibration corpus |

---

## About the name

In the story of the three little pigs, all three houses looked like houses until the wolf came. The
straw and the sticks fell at the first huff; only the third pig's house of brick was wolfproof. A
check that never ran is a straw wall with a green tick on it.

---

## License

[Apache License 2.0](LICENSE) © 2026 Tom Witkowski
