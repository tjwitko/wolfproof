# Troubleshooting

Each entry starts with what you see in the output.

**`exit 3` and "a control could not be reached"** — a control server did not resolve. The message
names which one and what to set. Usually the install did not complete, or an override points
somewhere stale. See [Configuration](configuration.md#where-the-controls-come-from).

**`exit 3` and "COULD NOT RUN"** — a scanner is missing from `PATH`. The message names the binary.
Install it and re-run; the verdict before it was installed proves nothing about your code.

**`exit 3` and "did not finish within 120s and was killed"** — the `tests` check stopped your suite
at its limit. If the suite is simply slow, set `WOLFPROOF_TEST_TIMEOUT` to a number of seconds it
finishes in; if it hangs, a longer limit only makes the wait longer.

**Every test file fails in CI, but passes locally** — the workflow did not install the project's own
dependencies, so the suite could not load its imports. Add `npm ci` (or your language's equivalent)
before the gate step.

**"builds on a base image past end of life"** — the release in a `FROM` line no longer gets security
fixes. The finding names the line, the date it ended and the supported releases. Every stage counts:
a build stage on an unsupported compiler ships its unpatched standard library in the binary. Floating
tags (`node:lts`, `python:3`) and other publishers' images (`bitnami/node`) are not judged; the
dates are refreshed with each release, so a release newer than the table is simply not judged yet.

**`sast: command injection` / `SQL injection` / `code injection`** — data from an HTTP request reaches
a shell, a SQL statement or an evaluator in the same function. The finding names each line and the
fix. The check follows data within a function, not across calls, so a request value passed to a helper
that builds the query shows up as an advisory about the helper instead ("built by string formatting…
not blocking").

**"were not read" or "MOST OF THIS PROJECT'S SOURCE WAS NOT READ" above the verdict** — part of the
project is in a language no language-aware check reads (Swift, Scala, Elixir, Dart, Lua, Perl, Vue,
Svelte). The verdict says nothing about that code: only the project-wide scans —
secrets, dependencies, infrastructure — apply to it, and a requirement like "include unit tests"
cannot be enforced on it.

**Routes "exempt by name"** — the authentication check leaves probe paths (`/health`, `/ping`,
`/metrics`…) and credential-issuing endpoints (`/login`, `/token`…) open, and lists each one it
skipped. The exemption is by path alone, so check the list: a route with one of those names that
reads input or changes state needs authentication like any other.

**"declare dependencies that no scanner read"** — `osv-scanner` reads lockfiles, and of manifests
only `requirements*.txt`, `go.mod` and `pom.xml`. A `package.json`, `Cargo.toml`, `pyproject.toml`,
`Pipfile`, `build.gradle`, `Gemfile` or `composer.json` that declares dependencies is scanned through
its lockfile or not at all, so without one this blocks: the alternative is reporting a dependency
check that looked at nothing as one that passed. The message names each manifest and the command
that writes its lockfile. `bun.lockb` does not count — it is binary and the scanner cannot read it;
`bun install --save-text-lockfile` writes `bun.lock`, which it can.

**`check_dependencies` findings that look wrong** — for the three manifests it does read without a
lockfile, `osv-scanner` resolves the dependency graph to minimum-satisfying versions that no real
install produces. Those findings are reported as advisory rather than blocking, and the message says
so. Commit a lockfile to make the result authoritative.

**Terraform findings about credentials** — a plan needs to authenticate to your cloud provider. With
no credentials the plan-based rules cannot run, and the gate says the configuration is UNSCANNED
rather than clean. The credential-free source scan still runs.

**A check reports "not checked" and you expected it to run** — the task file did not state that
requirement in a form the check reads. See [The task file](task-file.md).

**Different dependency or `sast` findings on the same commit** — the scanners are part of the
verdict. A semgrep upgrade moves `sast` findings with no wolfproof change, and osv-scanner answers
from a live database, so the same tree and pins can give different dependency findings on different
days. `wolfproof --version` lists the scanner versions on `PATH`.
