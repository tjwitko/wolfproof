# Troubleshooting

Each entry starts with what you see in the output.

**`exit 3` and "a control could not be reached"** — a control server did not resolve. The message
names which one and what to set. Usually the install did not complete, or an override points
somewhere stale. See [Configuration](configuration.md#where-the-controls-come-from).

**`exit 3` and "COULD NOT RUN"** — a scanner is missing from `PATH`. The message names the binary.
Install it and re-run; the verdict before it was installed proves nothing about your code.

**`exit 3` and "… could not resolve this project's dependencies, which this check never
downloads"** — the tests run offline, and the job did not install the project's dependencies. Add the
step the message names before the gate: `mvn -B test-compile`, `gradle testClasses`, `dotnet
restore`, `cargo fetch` or `bundle install`. Maven's `dependency:go-offline` alone is often not
enough: it can miss the JUnit provider the test run needs.

**`exit 3` and "the tests are Java and Maven is not installed here"** (or Gradle, the .NET SDK,
cargo, php, bundle) — the toolchain is not on `PATH` in the job. Install it there, for example with
`actions/setup-java`, `actions/setup-dotnet` or `ruby/setup-ruby`.

**`exit 3` and "there is no pom.xml or build.gradle"** (or "composer.json declares neither
phpunit/phpunit nor pestphp/pest", "package.json declares no test runner", "there is no Cargo.toml",
"there is no go.mod", "there is no .sln, .slnx or .csproj") — the project has tests and nothing that
says how to run them. Add the build file, or declare the runner as a dev dependency, so that anyone —
the gate included — can run the suite as delivered.

**`exit 3` and "… exited 0 and reported no test summary"** — the runner ran and named no test, so
nothing is known to have run. For `dotnet test` the usual cause is packages that were never restored:
without them a test project is not recognised as one. Run `dotnet restore` first.

**`exit 3` and "did not finish within 120s and was killed"** — the `tests` check stopped your suite
at its limit. If the suite is simply slow, set `WOLFPROOF_TEST_TIMEOUT` to a number of seconds it
finishes in; if it hangs, a longer limit only makes the wait longer. A run that passes says how long
the suite took (`passed in 41s (limit 120s)`), which is the number to set the limit from.

**Every test file fails in CI, but passes locally** — the workflow did not install the project's own
dependencies, so the suite could not load its imports. Add `npm ci` (or your language's equivalent)
before the gate step.

**"builds on a base image past end of life"** — the release in a `FROM` line no longer gets security
fixes. The finding names the line, the date it ended and the supported releases. Every stage counts:
a build stage on an unsupported compiler ships its unpatched standard library in the binary. Floating
tags (`node:lts`, `python:3`) and other publishers' images (`bitnami/node`) are not judged; the
dates are refreshed with each release, so a release newer than the table is simply not judged yet.

**`sast: command injection` / `SQL injection` / `code injection`** — data from an HTTP request reaches
a shell, a SQL statement or an evaluator. The finding names each line and the fix.

**A `sast` finding that ends `(via injectableQuery() at …)`** — the request value is passed to a
function of your project's that does the injecting: the line named is the call, and the chain after
`via` is the helper, then the helper it calls, if any, ending where the value is used. Fix it in the
helper — a parameterised query, an argument list instead of a shell string — which fixes every caller
at once, or convert the value at the call (`int(...)`, `Integer.parseInt(...)`) if the helper is not
yours to change. A helper that validates its argument before using it is not reported.

**The same, as an advisory: "the call is through an object whose type is not known here…"** — the
call might reach that helper or another function with the same name: a method called on an object
(`repo.find(x)`), a name defined more than once, a call into another Go package, or a JavaScript
helper called through its module (`db.findUser(x)`). Such calls are never blocking. Read the helper
the advisory names; if the call really reaches it, fix it as above. Some of these come from Semgrep
assuming that a function's result carries its argument's taint — a query built with bindings from a
value, an Arel predicate — and are not injections at all. One you have read and accept can be marked
reviewed by its ID ([Reviewed findings](configuration.md#reviewed-findings)).

**A finding you have read and accept** — an admin-only endpoint that writes where the admin says, a
webhook whose signature is checked in a helper it calls — `wolfproof review .` lists each injection and authentication
finding with its ID — the report's `reviewable` line points there ([Finding a finding's
ID](configuration.md#finding-a-findings-id)) — and `wolfproof review . <id> --reason "..."` records it. It is then listed as
`reviewed` on every run instead of blocking, until the line it names changes.

**"review: … matches no finding"** — the code a review named has changed, or the finding is gone. If
the finding came back with a new ID, review it again; otherwise delete the entry.

**"were not read" or "MOST OF THIS PROJECT'S SOURCE WAS NOT READ" above the verdict** — part of the
project is in a language no language-aware check reads (Swift, Scala, Elixir, Dart, Lua, Perl, Vue,
Svelte). The verdict says nothing about that code: only the project-wide scans —
secrets, dependencies, infrastructure — apply to it, and a requirement like "include unit tests"
cannot be enforced on it.

**"source_files: N code file(s) were not read by the checks that read their language", exit 3** —
the files named are over 512 KB (1 MB for C and C++), or could not be opened. Authentication, code
quality, immutability, retention, secret rotation, the manifest contract and the test check skipped
them, and say "no source files" when these were the only ones; injection reads up to 1 MB, and a
file it had within its limit is marked. A file that size is rarely hand-written code: move a
generated or vendored bundle under `dist/` or `build/`, which every check skips, declare its
directory a fixture with a reason, or split it. In factory mode the last two need an allowlist
entry, and no policy entry drops the message.

**"source_files: N directory(ies) could not be listed, so no check read the files in it", exit 3**
— the gate runs as a user who cannot list the directories named, or cannot enter their parent
(`chmod 644` on a directory lets it be listed and not entered). Every check skips such a directory,
so the build check, the dependency search and the secret scan say so too. Make it readable by that
user, or remove it. `node_modules/`, `dist/`, `build/` and the other directories every check skips are not named.
A directory git ignores is not this entry; see the next one. One git tracks anything under, and
any directory outside a git repository, is.

**"N directory(ies) git ignores could not be listed" above the verdict** — most often a
container's bind mount, such as `./data/postgres` in a docker-compose project, owned by the
container's user with mode 700 and listed in `.gitignore`. Nothing in it is in the project's
history, so the gate says it did not read it and the verdict does not change. The exception holds
only inside a git repository, only for a directory `git check-ignore` reports as ignored, and only
while git tracks no file under it. The directory itself has to be ignored: `data/postgres/`. A
rule over what is in it (`data/postgres/*`), or the directory negated after a wider rule (`*`
then `!data/postgres/`), leaves it exit 3, because git still descends into it and a negation can
take a file back out. The project's own ignore rules decide it: `.gitignore`,
`.git/info/exclude` and the user's global excludes. So one ignore line is what moves such a
directory from exit 3 to this line, and code under it that was never committed is not read. Read a
new ignore entry for a directory the gate cannot list as you would a new exemption. In factory
mode the line is the `unread-ignored-dirs` advisory. It is information, so the run does not exit 3
for it and the line still prints above the verdict. A policy entry
`{ "advisories": { "unread-ignored-dirs": "incomplete" } }` makes such a directory exit 3 again, and
`"block"` makes it exit 1.

Nobody reads a new ignore entry in factory mode, so factory mode judges it. That holds only for a
directory the ignore files already ignored at the base, counting `.git/info/exclude` and the
user's global excludes with them. When the change's own ignore rules are what ignore it, the run
is **exit 1**: "N ignored-directory grant(s) this change added", naming the directory and the
ignore file, line and pattern. Remove the rule and make the directory readable, or have the
pipeline's allowlist approve the directory:
`{ "exemptions": [{ "kind": "ignored-directory", "path": "data/postgres", "reason": "…" }] }`.
A change that adds an unrelated line to the same `.gitignore`, or moves the pattern to another
ignore file, is not affected.

**"scan_path: secret-guard could not scan all of the project — it did not read …", exit 3** — the
secret scan reads every file, and the user the gate runs as is not permitted to read the ones
named: a file of mode 000 or another user's, a directory that cannot be entered. It does not matter
whether git ignores the path (an `.env` nobody else may read is still on the disk the scan is
asked about), and it reaches under `dist/` and `build/`, which the other checks skip. Make each
path readable by that user, or remove it. Only one kind of path is set aside: the directory in the
entry above, which git ignores and the gate could not list. A directory that can be listed and not
entered (`chmod 644`) is not that one, because the gate lists it. "the scan stopped before it
finished" in the same entry is gitleaks reaching secret-guard's 120-second limit.

**"file(s) of a kind the checks read were not read" above the verdict** — a YAML, SQL or Terraform
file is over 512 KB, or could not be opened, so immutability, retention, the Kubernetes manifest
check and the IAM and manifest contracts say nothing about it. A symbolic link to a file that is
not there is listed here too, whatever it is named. The line leaves the exit code unchanged. In factory mode it
is the `skipped-files` advisory and makes the run incomplete, exit 3, until the file is fixed or
the policy drops it. A lockfile is never listed here.

**"YAML file(s) were not read"** — a manifest check found a Helm or Go template, or YAML that does
not parse, and names each file with the reason. Render a template (`helm template`) and run the
gate over the output; repair a file that does not parse. `{{` inside a comment or a string does not
make a file a template. In factory mode these block as not-checked.

**"Rails routing is not read"** — this check does not resolve a Rails route to its controller, so the
routes in `config/routes.rb` were not judged at all, protected or not. Check them by hand: each
controller's `before_action`, any `skip_before_action`, and what it inherits. In factory mode the
advisory blocks until the policy drops `auth-rails-unread`.

**Routes "exempt by name"** — the authentication check leaves probe paths (`/health`, `/ping`,
`/metrics`…) and credential-issuing endpoints (`/login`, `/token`…) open, and lists each one it
skipped. The exemption is by path alone, so check the list: a route with one of those names that
reads input or changes state needs authentication like any other.

**Routes that "count as protected by a check inside the handler"** — nothing outside the route
protects it, and its handler checks the caller itself: a secret compared in constant time, a
credential against configuration, a session or role, refused at the top of the handler
([the rule](checks.md#authentication-checked-inside-the-handler)). Read each one listed: a check that
tests the wrong thing, or refuses with a status the client ignores, reads the same.

**A route reported open whose handler does check the caller** — the check is in a helper the handler
calls, after the work (a branch above it that does something and returns counts), behind a condition that lets some callers through (`!featureOn && !isAdmin`
refuses only while the feature is off), or a session key that does not name the caller
(`session["auth"]` counts, `session["s"]` and `session[KEY]` do not). Move the check to the top of the handler, onto the route
(middleware, an attribute, a dependency), or mark the finding reviewed.

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
