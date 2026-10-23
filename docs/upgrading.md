# Upgrading

The four controls come **with** the gate — `wolfproof` pins them — so upgrading the gate upgrades
them. You only upgrade a control separately if you wired it into an editor on its own.

## 1. See what you are on

```text
$ ./node_modules/.bin/wolfproof --version
wolfproof 1.9.0
  terraform-guard  v1.1.2  node_modules @tjwitko/terraform-guard-mcp
  dep-audit        v1.0.2  node_modules @tjwitko/dep-audit-mcp
  secret-guard     v1.0.2  node_modules @tjwitko/secret-guard-mcp
  identity-guard   v1.0.2  node_modules @tjwitko/identity-guard-mcp
tools on PATH
  node             26.5.1
  go               1.27.1
  terraform        1.15.8
  gitleaks         8.30.1
  osv-scanner      2.4.0
  checkov          3.3.10
  python3          3.14.8
  ruff             0.16.2
  semgrep          1.180.0
  pytest           9.1.1
  docker           29.6.2
```

Run it again afterwards. **"The package moved" and "the controls that will run moved" are different
answers**, and only the second one protects anything. Every gate run prints the version of each
control beside where it was found, in the CLI and in the Action's log alike.

The controls are not all that decides a verdict. The scanners they shell out to are the rest: a
semgrep upgrade moves `sast` findings with no wolfproof change, and osv-scanner answers from a live
database, so the same tree and pins can give different dependency findings on different days.
`--version` lists each one on `PATH`, and `not found` for one that is not — a missing scanner
switches its checks off.

## 2. Move the pin

**GitHub Action** — bump **both** references, which name one repository at one version:

```yaml
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.9.0
- uses: tjwitko/wolfproof@v1.9.0
```

A workflow left at two versions runs one release's gate on another's toolchain. It is an easy one to
miss: a search for `wolfproof@` does not match the first line.

**npm:**

```bash
npm install --save-dev github:tjwitko/wolfproof#v1.9.0
```

## 3. Refresh what setup wrote

```bash
./node_modules/.bin/wolfproof init --upgrade
```

Upgrading the package does not touch what `wolfproof init` wrote into your project, so without this
a project keeps an older release's stanza and hook indefinitely. `--upgrade` refreshes exactly
those, and nothing it did not write:

| | refreshed when | left alone when |
| --- | --- | --- |
| `AGENTS.md` stanza | it sits between wolfproof's markers, or agent-gate's from an earlier version | there are no markers, or the end marker is missing |
| pre-commit hook | it carries the `Installed by wolfproof init` header, or `Installed by agent-gate-init` | anyone else wrote it |
| `.mcp.json` controls | the entry is one setup wrote, or the control is missing | you defined the control yourself |

The task file is read back from what setup wrote, so you do not have to repeat it — and it is not
quietly dropped, which would switch six checks off. Running it twice changes nothing the second
time. It exits **1** if something of its own could not be refreshed, and says what.

`--force` would also refresh these, and would also overwrite a hook you wrote. Use `--upgrade`.

## 4. Run the new version before you gate on it

**An upgrade can turn a passing project red, deliberately.** When a release fixes a check that was
passing something it should not have, projects relying on that gap start failing. Release notes
call these out under *expect this to fail*.

**In v1.7.0: a test suite the gate cannot run is exit 3.** In a Java, Kotlin, C#, Rust, PHP or
Ruby project whose task or baseline asks for tests, the gate now finds the test files, has no
runner for them, and exits 3 — in the default mode, where it used to exit 0 with the suite unrun,
and in factory mode, where it used to exit 1. A Java project used to be blocked for having no tests
at all, because Maven's `src/test/java` was not recognised; it now gets the same exit 3. Projects
with a `package.json`, Python test files or a `go.mod` are not affected: the check picks those
runners first. See [Troubleshooting](troubleshooting.md) for what you can do about it, and what
each option costs.

**In v1.8.0: every test suite is run or reported.** The `tests` check used to pick one runner per
project, and a `package.json` meant JavaScript and nothing else, so a suite in another language
beside it — PHP or Ruby in a Laravel or Rails app with front-end tooling, Python in a service with a
`package.json` for its tooling — was neither run nor flagged. Now each suite is handled: JavaScript,
Python and Go suites run, and a Java, Kotlin, C#, Rust, PHP or Ruby suite is exit 3 as above. A
Laravel or Rails project whose task asks for tests can therefore go from exit 0 to exit 3, and a
project with JavaScript and Python tests now runs both.

**In v1.9.0: tests in Java, Kotlin, C#, Rust, PHP and Ruby run.** These suites were found and
exit 3. Now they run, under Maven or Gradle, `dotnet test`, `cargo test`, PHPUnit or Pest, and RSpec or
Minitest — offline, against dependencies the job installed. A passing suite passes, a failing one
blocks (exit 1), and a project whose dependencies or toolchain are not installed in the job is still
exit 3, now naming the step to add. A PHP project that declares PHPUnit or Pest in `composer.json`
and has no `vendor/` blocks, as a JavaScript project does without `node_modules`. And tests with
nothing that says how to run them — no `pom.xml` or `build.gradle`, a `composer.json` or `package.json`
that declares no runner — are exit 3 in every language; a JavaScript project like that used to pass
on an advisory.

**After v1.9.0: a test run that names no test is exit 3, under every runner.** A run that exited 0
with no summary the gate could read used to pass, with an advisory saying so. That was most often
`go test`, which without `-v` prints no count at all, and the declared runners mocha, ava and tap,
whose summaries no pattern read. `go test` now runs with `-v`, and mocha, ava and tap are read in their
own formats, so their suites are counted; a run that still names no test could not run. tap exits 1
when it generates no coverage report, so a passing tap suite used to block; it now passes.

**After v1.9.0: C#, PHP and Kotlin routes are checked for authentication.** A project whose only
routes are ASP.NET Core, Laravel, Symfony, Spring (Kotlin) or Ktor used to get "not checked" from the
authentication check; its unauthenticated routes now block. The credential-comparison finding reads C# as well, and is
narrower in every language: a name about a credential rather than the credential (`secretId`,
`tokenType`, `passwordResult`, `useResetPassword`, `IS_TOKEN`, an OIDC `idTokenSub`), a property of
an object named for one (`request.email` on a `passwordResetRequest`), a class constant
(`Password::PASSWORD_RESET`), and a password compared with its confirmation are no longer reported.

So run the new version locally first, read what it finds, and move the CI pin once you have — not
the other way round, where the first you hear of it is a red build on someone else's pull request.

## Keeping current

Dependabot's `github-actions` updater opens a pull request when a new tag is published:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

Check that the pull request moves **both** references before merging it.

## A control wired in on its own

If you run one of the four servers directly from an editor rather than through the gate, upgrade it
by its own tag — `npm install github:tjwitko/secret-guard-mcp#vX`, or `git pull && npm ci` in a
checkout — and then **restart the editor's MCP client**. A client starts each server once per
session, so a running editor keeps serving the old code until it is restarted, and nothing about
the upgrade tells you that.

## Rolling back

Pin the previous tag and run `npm install`. The stanza and hook a newer release wrote keep working
with an older gate, with one exception: **below v1.1.3, remove the pre-commit hook**. It passes
`--pre-commit`, which older releases do not know, so they run the uncommitted-work check inside the
hook — where a commit in progress always has uncommitted work — and block every commit.

## Coming from agent-gate

The project was called agent-gate until v1.2.0, and the repository moved from `tjwitko/agent-gate`
to `tjwitko/wolfproof`. Git and install URLs under the old name redirect, and every earlier tag is
here. v1.2.0 still accepted the old names; since v1.3.0 they are gone.

To move a project from agent-gate (v1.1.18 or earlier):

1. **Install wolfproof, then run `wolfproof init --upgrade` straight away.** It replaces the
   `agent-gate` markers, stanza command and hook with `wolfproof` ones and keeps the task file.
   Until you do, a stanza or hook that still says `./node_modules/.bin/agent-gate` finds no such
   command — the hook fails closed with exit 3; it does not let the commit through.
2. **Rename `.agent-gate.json` to `.wolfproof.json`.** A project with only the old file exits 3 and
   says so.
3. **Rename `AGENT_GATE_*` variables to `WOLFPROOF_*`.** An old one left set is reported, not read.
4. **Change both `uses: tjwitko/agent-gate…` lines in your workflows to `tjwitko/wolfproof…`.**
   GitHub does not redirect Actions, so the old path fails with "repository not found".

## Notes from earlier versions

These explain behaviour you may meet in an older project or an older copy of the docs.

- **`npx agent-gate` (up to v1.1.16).** The README recommended `npx agent-gate`, a name that was not
  this project's on npm. Where a command is not installed, npx looks its name up on the public
  registry, and when stdin is not a terminal — as in an agent's shell — npm answers its own install
  prompt with yes. Measured from a directory without it, `npx agent-gate .` and
  `npm exec --no -- agent-gate .` queried the registry and exited 1, the gate's code for blocking
  findings, and `npx --no agent-gate --version` printed npm's version and exited 0. This is why the
  README says to run the gate by path. The name `wolfproof` is held on npm by a placeholder until
  the first release there; `npx wolfproof` prints how to install it and exits 3. Running by path
  runs the version the project pinned, makes no request, and exits 127 when nothing is installed.
- **The hook's install check (up to v1.1.16).** The hook tested for `npx`, which is always there, so
  in a clone without `node_modules` it went on to the public registry and exited 1 — blocked, but
  reported as findings. `init --upgrade` replaces it with one that fails closed with exit 3.
- **Control versions not shown (v1.1.1).** v1.1.1 shipped with terraform-guard a release behind its
  own fixes, and nothing in the output said so. Since then every run prints each control's version.
- **Deliberate breaks.** v1.1.2 started failing S3 buckets with no public access block of their own;
  v1.1.4 started failing services whose only authentication was commented out.
- **Scan roots (v1.4.0, v1.4.1).** See [Factory mode → The scan-root rule](factory-mode.md#the-scan-root-rule-in-both-modes).
