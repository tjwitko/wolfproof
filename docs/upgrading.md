# Upgrading

The four controls come **with** the gate — `wolfproof` pins them — so upgrading the gate upgrades
them. You only upgrade a control separately if you wired it into an editor on its own.

## 1. See what you are on

```text
$ ./node_modules/.bin/wolfproof --version
wolfproof 1.16.3
  terraform-guard  v1.1.2  node_modules @tjwitko/terraform-guard-mcp
  dep-audit        v1.0.3  node_modules @tjwitko/dep-audit-mcp
  secret-guard     v1.0.2  node_modules @tjwitko/secret-guard-mcp
  identity-guard   v1.0.3  node_modules @tjwitko/identity-guard-mcp
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
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.16.3
- uses: tjwitko/wolfproof@v1.16.3
```

A workflow left at two versions runs one release's gate on another's toolchain. It is an easy one to
miss: a search for `wolfproof@` does not match the first line.

**npm:**

```bash
npm install --save-dev github:tjwitko/wolfproof#v1.16.3
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

So run the new version locally first, read what it finds, and move the CI pin once you have — not
the other way round, where the first you hear of it is a red build on someone else's pull request.

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

**In v1.10.0: a test run that names no test is exit 3, under every runner.** A run that exited 0
with no summary the gate could read used to pass, with an advisory saying so. That was most often
`go test`, which without `-v` prints no count at all, and the declared runners mocha, ava and tap,
whose summaries no pattern read. `go test` now runs with `-v`, and mocha, ava and tap are read in their
own formats, so their suites are counted; a run that still names no test could not run. tap exits 1
when it generates no coverage report, so a passing tap suite used to block; it now passes.

**In v1.10.0: C#, PHP and Kotlin routes are checked for authentication.** A project whose only
routes are ASP.NET Core, Laravel, Symfony, Spring (Kotlin) or Ktor used to get "not checked" from the
authentication check; its unauthenticated routes now block. The credential-comparison finding reads
these languages as well, and is narrower in every language: a name about a credential rather than the credential (`secretId`,
`tokenType`, `passwordResult`, `useResetPassword`, `IS_TOKEN`, an OIDC `idTokenSub`), a property of
an object named for one (`request.email` on a `passwordResetRequest`), a class constant
(`Password::PASSWORD_RESET`), and a password compared with its confirmation are no longer reported.

**In v1.11.0: identity-guard v1.0.3.** Its HTTP Basic rule no longer blocks a JavaScript,
TypeScript or Kotlin variable named `auth` assigned a parenthesised expression; it needs a credential
tuple, `auth=(user, password)`, in a keyword-argument or statement position.

**In v1.11.0: injection through a project helper blocks.** Request data passed to a function of
the project's that builds it into SQL, a shell command, an evaluator or a file path used to be an
advisory at best, because Semgrep's open-source analysis stays inside one function. When the call can
only reach that function, it now blocks, naming the helper (`via injectableQuery() at ...`). Calls
through an object of unknown type, names defined more than once, and SSRF through any helper are
advisories. The injection check takes longer: 10 to 55 per cent on the calibration applications.

**In v1.12.0: a finding can be marked reviewed.** `wolfproof review .` lists injection and
authentication findings by ID (a blocked report's new `reviewable` line, and `reviewable` in
`--json`, point at it), and `.wolfproof-reviewed.json` (or `--reviewed=<file>`) takes one
finding out of the verdict with a reason, until its line changes. Nothing changes for a project
without one. In factory mode, an entry the change adds blocks unless the allowlist approves it.

**In v1.13.0: authentication checked inside the handler counts.** A route whose own handler
checks its caller — a secret compared in constant time, a credential against configuration, a
session or role — and refuses at the top, is no longer reported as open; each one is listed in an
advisory instead, and a route open before can now pass. A review of one of these routes
(`authentication:METHOD /path:file`) now matches no finding and is reported as doing nothing: delete
it.

It can also go the other way. The Go and JavaScript readers took a route's handlers from the text up
to the first `);`, which Go and semicolon-free JavaScript do not write, so a route could be credited
with the check in the handler of a route declared below it. In an Express app without semicolons,
`app.post('/purge', purge)` followed by `app.post('/webhook', webhook)` passed `/purge` because
`webhook` verifies a signature. Each route is now judged by its own handlers, so a route like
`/purge` is reported open. None of the 29 calibration applications had one.

### In v1.14.0

**v1.14.0 changes how the authentication check reads routes, and verdicts move both ways.** A route
reported open can pass, and a route that passed can block. On the 48 projects pinned in
[`calibration/routes.json`](../calibration/routes.json), v1.14.0 reads 3,748 routes where v1.13.0
read 3,880, reports 1,745 of them open where v1.13.0 reported 1,819, and blocks 29 projects where
v1.13.0 blocked 28. A review of a route that now passes matches no
finding and is reported as doing nothing: delete it.

**Flask's decorators and `before_request` hooks count.** `@login_required` from Flask-Login,
Flask-Security's and Flask-JWT-Extended's decorators, Flask-HTTPAuth's `@auth.login_required`, a
project's own decorator that refuses the caller, and a `before_request` hook that refuses now protect
the routes they run for: 19 of microblog's routes and 3 of Flask's tutorial's now pass. A hook that
lets some paths through (`request.path.startswith("/public")`) leaves open the routes whose full path
it matches, and every route whose full path cannot be read. A full path is read from the blueprint's
`url_prefix`, and for flask-restx from the `Api`'s prefix and the namespace's path. It is also read
for a blueprint registered by a helper, in a loop over a list, or made by a factory (`admin =
make_admin()`, or a factory returning `Blueprint(...)`), and for a rule built from the module's names
(`BASE + "/one"` with `BASE = "/api"`). A conditional rule is either path, where v1.13.0 read
`"/a" if ON else "/b"` as "/a". A rule with a part that is not written out has no known path, where
v1.13.0 read `"/x" + SUFFIX` as "/x"; so has one built from a name written by `+=`, from another
module or from the environment. A hook's path rule is taken to reach such a route, which can be
reported open.

**A Flask hook counts on the app it is installed on, and only where that code runs.** A hook
installed by a function (`def init_app(app)`, `target.before_request(check)`) protects the routes of
whatever each call passes it. A hook on an app imported from another module, or made by a factory
(`app = create_app()`, or one returning `Flask(...)` directly), protects that app's routes, and
those under the directory the app is made in. A hook in an app factory counts though the project
never calls the factory, since Flask's CLI and servers do. A hook in a function nothing calls, or
calls only from such a function, or only stores, no longer counts. Names are read as Python reads
them: a helper's local `app`, or a parameter named like the module's app, no longer stands for the
module's app. A flask-restx `Api` is read where it is mounted, on a parameter or by `init_app` in
another file; one mounted on several blueprints is protected only where each is. Each call of a
factory makes its own blueprint, so a hook on `b1 = make_b()` protects the routes declared on `b1`,
not those of `b2 = make_b()`, and those declared inside the factory only when it runs once. A route
that passed on a hook it is not under can now block.

**A Flask route on a class is judged by a hook, not by its first method.** A flask-restx route,
`@ns.route(...)` on a `Resource` class, was judged by the body of the class's first method, so a
sign-in check in its `get` credited an open `post`. No method counts now: not its body, not
`@login_required` on it, and not `method_decorators`. The route is reported open unless a
`before_request` hook protects it: the app's, or that of the blueprint its `Api` is mounted on
(`Api(bp)`, `api.init_app(bp)`). A hook that lets requests through by endpoint leaves it open, since
its endpoint is not read. A class route that passed can now block: move the check into such a hook,
or mark the finding reviewed once a person has read each method. A `MethodView` registered with
`add_url_rule` is not read as a route by either version.

**A Flask route whose rule is a call is checked.** `@routes.route(org_scoped_rule("/login"))` was
not found, so nothing checked it: 19 of redash's routes. They are now found, shown by the path written
in them, and judged like any other route. A hook's path rule is matched against every path the call
can return, and reaches the route when the call cannot be read. redash has 9 with nothing protecting
them: its LDAP, SAML and remote-user sign-in pages, its invitation, password-reset and verification
pages, and `POST /verification_email/`. A raw-string rule (`r"/x"`) is found as well.

**A check inside a handler counts only before any work, and only against the caller who fails it.**
v1.13.0 credited a check that came after a branch doing work for anyone (CTFd's email confirmation
marks the account verified before its sign-in check), and a check pointing the wrong way (`if
current_user.is_authenticated: return redirect(...)`, which turns away signed-in users). A session
value counts as the caller only when its key names the caller: `session.get("user_id")`,
`session[:user_id]`, `"uid" in session`, `req.session.userId` and `req.session?.user` count, and
Ktor's `call.sessions.get<T>()` is unchanged. Sign-in flow state no longer counts (CTFd's OAuth
callback compares `session["nonce"]` with the `state` parameter), nor does a key that is not a
literal (`session[KEY]`). Four of CTFd's routes and microblog's password-reset request page are now
open for these reasons. A route that passed on such a check can now block: move the check to the top
of the handler or onto the route, or mark the finding reviewed if the route is meant to be public.

In JavaScript, a destructuring is reading, not work: `const { newPassword, currentPassword } =
request.body` ahead of a check no longer makes the check count as after work. A destructured name is
read as the property it takes, and a name in a check is followed through up to four assignments, so
`const { email } = request.session.user`, then `findByEmail(email)`, then `if (!user)` counts as the
caller checked. fastify/demo's `PUT /update-password` stays protected for that reason; v1.13.0
credited it for `newPassword === currentPassword`, which compares two of the caller's inputs, and
v1.14.0 does not.

**A JavaScript or Go handler is the function its route's file names.** A named handler was the first
function of that name anywhere in the project, so a route could be credited with another file's
check; such a route can now block. The name is resolved from the route's file, through its imports or
its package, and a method through the receiver's type. A handler imported from a package, or from a
TypeScript path alias, is not read, so a check inside it is not credited.

**A Fastify `autohooks` file protects the routes it reaches, and only those.** `@fastify/autoload`
applies the hooks in a directory's `autohooks` file to that directory's routes, and to its
subdirectories' with `cascadeHooks`. v1.13.0 read such a hook only by the project-wide rule, which
credited every route in the project when the hook's first 120 characters named authentication, and
none otherwise. fastify/demo protects its 12 API routes from `src/routes/api/autohooks.ts`; 11 of them
were reported open, and all 12 now pass on that hook, while its root page stays open. A hook in an
`autohooks` file no longer credits routes outside its directory, so such a route can now block. Each
rule was checked against Fastify 5.12.7 and @fastify/autoload 6.5.1, on 29 routes in 16 apps: none the
check counts as protected was reached by an anonymous request.

**An HTTP client call is not a route.** In JavaScript and TypeScript, `await api.post("/api/groups",
{...})` was read as an Express route. A call whose value is waited for, or that passes only data after
the path, is no longer a route. That removes 139 calls from the calibration projects, 49 of them
reported open: 37 in redash's Playwright helpers, 6 in the React RealWorld client, 5 in BookStack's
front end, and 1 in Gitea's end-to-end helpers. A project blocked only by such calls can now pass, as
the React RealWorld client does. No route among 611 in Express, Fastify, Hono, juice-shop and the MCP
SDK's examples moved.

**Rails routes are reported as not checked, not as protected.** Lines in `config/routes.rb` were read
as Sinatra routes, and a `before_action :authenticate…` in any controller marked them all protected —
on Mastodon, its public profile page among them. Rails routing is now not read as routes, and an
advisory names the files whose routes were not checked: 9 of Mastodon's routes and 1 of
rubygems.org's. A Rails app that passed on that credit passes in the default mode with the advisory,
and blocks in factory mode, as any not-checked advisory does; a policy can drop `auth-rails-unread`
once a person has judged the routes. A Sinatra `before` filter with a path now protects only the
routes it matches, and a filter counts only on what its own block does.

**A credential compared with `==` blocks when no route is read.** The two comparison findings, a
credential or signature compared with `==` and a credential that is vacuous when its variable is
unset, were dropped from the report of a project with no route read. They are reported again, so a
Rails app with such a comparison blocks: rubygems.org keeps the `path_token ==` finding v1.13.0
blocked on, and dvwa and railsgoat newly block, each on a credential compared with `==`. Comparisons
with an empty string or `None` behind a Python `:`, with a credential's owner, with an action named
after a credential, or with an UPPER_CASE constant the source assigns a string are no longer counted;
these were six of 88 matches, and none was a secret compared.

**The fix for an open route names its framework.** A Flask route was told to add a FastAPI
dependency, and every language's advice named all of that language's frameworks. The advice now names
the fix for the framework each open route is written in, and only forms the check credits. A Flask
route on a class is told about a `before_request` hook, the one form that counts for it. A NestJS
`@UseGuards(...)` written below the route decorator now counts, as one above it did.

### In v1.14.1

**In v1.14.1: a plural, or a setting named after a credential, is not the credential.** v1.14.0
read terraform-guard-mcp's `httpTokens !== "optional"`, which tests the EC2 metadata option
`http_tokens`, as a credential compared with `==`, and blocked on it. A name that ends in a plural
(`tokens`, `secrets`, `keys`, `passwords`) or in `method` or `mode` is no longer counted;
`credentials` still is, being as often one `user:password` string as several. On the 48 projects
pinned in [`calibration/routes.json`](../calibration/routes.json), the four control repositories and
this one, 3 of 100 matches drop, each a setting, and none is added. One verdict moves:
terraform-guard-mcp passes. The MCP SDK still blocks, now on its `client_secret !==` comparison
rather than on `token_endpoint_auth_method === 'none'`.

### In v1.14.2

**In v1.14.2: a credential word inside a longer word is not the credential.** v1.14.1 read
CodeMirror's `c.tokenize != fe`, minified into CTFd's theme bundles, as a token compared with `!=`.
The word now counts only where its part of the name ends: at the end, or before `_`, a digit or a
capital. `tokenValue`, `token_hash`, `TOKEN_VALUE` and `credentials` are read as before; `tokenize`
and `TOKENIZER` are not, and neither is a name run together in lower case, such as `tokenvalue`. On
the same 48 projects, four control repositories and this one, 5 of 97 matches drop, all CTFd's
`tokenize`, and none is added. No verdict moves. CTFd still blocks, and its report now names
`mail_password` instead.

**In v1.14.2: a presence test in minified code is a presence test.** The empty-string test
`mail_password===""&&delete e.mail_password`, minified in CTFd's admin bundle, was read as a
password compared with `===`, because the operand was taken up to the next space and read as
`""&&delete`. The operand now ends at `&&`, `||` or `?` (not `?.`). On the same projects, 1 of 92
matches drops, this one, and none is added. No verdict moves. CTFd still blocks, now naming
`credentials==="include"`.

**In v1.14.2: fetch's credentials mode is not a credential.** `credentials === "include"`,
fetch's option for sending cookies, was read as a credential compared with a hardcoded value. A name
ending in `credentials` compared with one of the three values the Fetch standard allows, `omit`,
`same-origin` or `include`, is no longer counted; compared with anything else, it still is. On the
same projects, 1 of 91 matches drops, this one, and none is added. No verdict moves. CTFd still
blocks, now naming its `password == preset_admin_password` comparison in `CTFd/auth.py`.

**In v1.14.2: a comparison minified behind another is examined.** In code with no spaces, a
credential comparison that followed another in the same run of text was never read:
`credentials==="include"?a:b.password==="hunter"` was one match, about the first comparison, which
is skipped. Each is now examined, so a minified bundle can report one it did not before. On the same
projects, three more comparisons are examined, all in CTFd and none of them a credential, and no
finding or verdict moves.

### In v1.15.0

**In v1.15.0: a credential compared with one character is not counted.** Jellyfin's header
parser reads the `Authorization` header a character at a time into a variable named `token`, and
`token == '"'`, `token == ','` and `token == '='` were each read as a token compared with `==`. A
comparison with one quoted character, or one escape such as `'\''`, is no longer counted: in C#,
Java, C, Go and Rust that is a character, not a credential, and in any language a timing leak of one
character tells an attacker nothing a guess would not. A literal with more after it (`'a' + rest`)
is still read. On the same projects, 5 of 90 matches drop, all Jellyfin's, and none is added. No
finding or verdict moves: Jellyfin's report already named its QuickConnect `secret` comparison.

**In v1.15.0: the built image can be scanned.** Name it — `trivy-image: myapp:ci` in the Action,
`--trivy-image=myapp:ci` on the command line — and Trivy scans its OS and language packages. A
vulnerability at `HIGH` or above with a fixed version blocks (`trivy-severity` moves the line); the
rest are advisories. Nothing changes for a run that names no image. Expect a first run to block:
each of seven images on one machine with packages Trivy could check had at least one, from 2 in
`alpine:latest` to 298 in `node:22`. A scan that cannot run makes the run incomplete (exit 3). The
Action installs Trivy v0.76.0 itself, checked against its SHA-256.

**In v1.15.0: the source can be analysed with CodeQL.** Turn it on — `codeql: true` in the
Action, `--codeql` on the command line — and CodeQL's code-scanning suite runs for each language it
finds; a result at error level blocks, the rest are advisories, and a language it could not analyse
makes the run incomplete. Nothing changes for a run that does not ask for it. Without GitHub
Advanced Security, CodeQL's licence allows this only for open-source code; see
[CodeQL](checks.md#codeql-opt-in). Go, Swift and Kotlin are built first, by CodeQL's autobuild. On
the 13 corpus fixtures it took 10 to 18 seconds each and found one error-level result. The Action
installs the CodeQL bundle 2.27.3 itself, checked against its SHA-256. A CodeQL finding is reviewed
like any other, by ID: `wolfproof review <project> --codeql` lists them.

**In v1.15.0: decorators no longer stall the authentication check.** The pattern for a NestJS
controller-wide guard backtracked exponentially on a guard followed by decorators with spaces after
them and no class: twelve held the gate past 30 seconds, and each one more took eleven times longer.
It now takes linear time and matches the same text. On the same projects no route count, finding or
verdict moves.

### In v1.15.1

**In v1.15.1: a CodeQL build that fails says why.** When CodeQL's autobuild cannot build a
language, the incomplete line now quotes the build's own cause: `xcodebuild` needing Xcode, Gradle
unable to download itself, Maven unable to resolve a dependency. Before, it often quoted a heading
that ended in a colon, or CodeQL's "Spawned process exited abnormally". The verdict is unchanged:
the run is still incomplete (exit 3). Go's extractor can still end on its own summary,
"Extraction failed for all discovered Go projects".

### In v1.16.0

**In v1.16.0: only new findings block, with a snapshot.** `wolfproof known .` writes the blocking
findings a project has now to `.wolfproof-known.json`; committed, those are counted and do not
block, and a finding a later change adds blocks as before. Nothing changes for a project without
one. A hardcoded secret, a manifest no scanner read, the build and the checks gated on the task are
never snapshotted. `--known=<file>` and the Action's `known` input take one from outside the
project; in factory mode, an entry a change adds to the project's file blocks, and the allowlist
(`known-finding`) can approve only the change that writes the first snapshot. See
[Known findings](configuration.md#known-findings).

**In v1.16.0: a `package.json` with no lockfile is scanned anyway.** Its direct dependencies
are checked at the lowest version each range allows, and a high or critical CVE found that way
blocks; the missing lockfile still blocks, as before, because transitive dependencies are not
checked. A project with no lockfile was blocked already, so no verdict moves from clean to blocked,
but the report can list CVEs it did not before. Raising a range's lower bound past the fix clears one.
In the regression corpus, webhook-haiku gains one: uuid 9.0.1 (GHSA-w5hq-g745-h8pq). A snapshot can
hold the missing lockfile; when one is later committed, `wolfproof known` adds its transitive
findings once ([Known findings](configuration.md#known-findings)). Other manifests that need a lockfile
are unchanged.

**In v1.16.0: every credential compared with `==` has an ID.** The authentication check names the
first credential a project compares with an ordinary equality operator, and now gives every one it
finds an ID, as it does an open route. They can be reviewed by ID, so the report's `reviewable`
count includes them and `wolfproof review .` lists them. The finding and the verdict are unchanged:
on the 53 calibration projects, no authentication finding or verdict moved against v1.15.1, and the
rule accepts the same 85 comparisons.

**In v1.16.0: `--json` lists findings one per location.** `records` has one entry per finding
with an ID — `id`, `check`, `file`, `line`, `blocking`, `known`, `reviewed` — and `known` lists the
findings a snapshot set aside. `findings` and `advisories` are unchanged.

**In v1.16.0: the licence is AGPL-3.0-only.** wolfproof is under the GNU Affero General Public
License v3.0 from this release; v1.15.1 and every release before it stay under Apache-2.0. Running
it on your own projects, as a CLI, hook or Action, asks nothing of you. If you ship wolfproof, or run
a modified version as a service for others, the AGPL asks you to publish that source under the AGPL
too.

### In v1.16.1

**In v1.16.1: the dep-audit control is v1.0.3.** Importing dep-audit no longer clears the
importer's environment; up to v1.0.2 it deleted every variable but PATH, HOME and SCAN_ROOT as it
loaded, and now does so only when its server starts. Verdicts do not change: the gate already ran
dep-audit's severity bands in a process of its own, and still does, for a project that hands it an
older dep-audit. Like wolfproof, dep-audit is AGPL-3.0-only from this version.

### In v1.16.2

**In v1.16.2: a range with an `||` alternative that has no lower bound is not checked.** In a
`package.json` with no lockfile, `<2.0.0 || >=3.0.0` was checked at 3.0.0, the lowest bound among
the other alternatives, though it allows every 1.x, and the dependency counted as checked. It is
now listed as not checked, as `<2.0.0` alone already was. The report's wording for these is now
"have no lowest version and were not" (it said "name no version"). A finding that only the higher
version had is no longer reported: raise the range's lower bound, or commit the lockfile, to have
the dependency checked.

**In v1.16.2: `wolfproof known` names its exception when it uses it.** After adding a committed
lockfile's findings, it ended with "New findings are never added to an existing snapshot". That
line now reads "No other new finding is added to an existing snapshot"; a run that adds nothing
still prints the original.

**In v1.16.2: `wolfproof known` keeps a workspace member's entry when the lockfile is committed
at the root.** A `package-lock.json` at the workspace root covers `web/package.json`, so the
member's entry for the missing lockfile matched nothing; the command looked for the lockfile only in
`web/`, found none, and removed the entry with nothing added and nothing said. The root lockfile
holds every member's packages and the root's, and its findings cannot be told apart by member, so
none are added in one member's place: the command now says so and keeps the entry, to delete once
the lockfile's findings are fixed or reviewed. Those findings block, as any new finding does.

**In v1.16.2: prereleases are ordered as semver orders them.** In a `package.json` with no
lockfile, `1.0.0-rc.9 || 1.0.0-rc.10` was checked at rc.10 and `1.0.0-beta.2 || 1.0.0-beta.10` at
beta.10, the alternatives compared as text; both are now checked at the lower one. `>1.2.3-beta`
was checked at 1.2.4, a patch above a version the range allows; it is now checked at 1.2.3. A
finding only the higher version had is no longer reported, and one 1.2.3 has that 1.2.4 does not is
new.

**In v1.16.2: an alias and a direct dependency on the same package are both checked.** In a
`package.json` with no lockfile declaring `"old-lodash": "npm:lodash@^4.17.4"` and
`"lodash": "^4.17.21"`, both were written to the same entry of the scan's lockfile, and only the one
declared last was scanned. Each is now its own entry, as npm writes an alias, so a finding in either
version is reported.

**In v1.16.2: `--json` carries `configError`, and the corpus says why a fixture was INCOMPLETE.**
The JSON document has a `configError` field, the configuration error that made the run incomplete
(`.agent-gate.json` still present, for one) or `null`; it was only in the text report. The corpus
runner prints, under an INCOMPLETE fixture, every control that did not run, every check that could
not, and the configuration error, instead of a line with no reason.

### In v1.16.3

**In v1.16.3: `wolfproof known` counts a workspace's members' direct dependencies as direct when
it adds a root lockfile's findings.** A root `package.json` with `workspaces` and a snapshot entry
for its missing lockfile, once that lockfile was committed, had every finding added that the root
did not declare directly, the members' direct dependencies among them, though those were scanned
without a lockfile exactly as the root's were. Now a finding in any member's direct dependency
blocks, as the root's do, and only packages nothing in the workspace declares directly are added.
The members are read from `workspaces` (an array, or `{ packages: [...] }`) and from
`pnpm-workspace.yaml`; a pattern that is not a path or a `*` glob (`**`, `?`, braces, brackets),
a member that cannot be read, or a `pnpm-workspace.yaml` that does not parse or has no `packages`
list, makes the command add nothing, say so, and keep the entry. A
workspace whose root lockfile was already added by an earlier run is not affected: the command
only adds once.

### After v1.16.3

Six changes of one shape: a part of the gate that could not read its input said "nothing there",
which is the answer that passes. Each now says what it did not read, and nothing is judged over an
input that was not read. Three of them can change a passing project's verdict, two to blocked and
one to could-not-run; they are marked.

**After v1.16.3: a `package.json` that does not parse is unscanned, not "0 checked".** The scan of
a `package.json` with no lockfile reported one that was not JSON as `(0 checked)`, which counted as
read: the dependency family was judged over it, and `wolfproof known` removed the entries its earlier
scan had produced. It is now reported with the other manifests no scanner read, with the reason
(`could not be parsed as JSON`), it blocks like them, and no dependency entry is judged while it
stands. Can turn a passing project red: only one whose `package.json` is not valid JSON.

**After v1.16.3: a Dockerfile that cannot be read is could-not-run.** It was skipped as a file
with no `FROM`: its end-of-life finding left the run with nothing in could-not-run, and its snapshot
entries matched nothing. The run now exits 3 naming the file, and its entries are not judged.

**After v1.16.3: a code file the checks did not read is could-not-run.** Authentication, code
quality, immutability, retention, secret rotation, the manifest contract and the test check stop
reading a source file at 512 KB, and said nothing: a project whose only source file was 600 KB, with
an open `DELETE /admin` route in it, passed, with four checks reporting it had no source files. A
code file over the limit for its language, or one that cannot be opened, now makes the run exit 3,
in the default mode and in factory mode, with a `source_files:` entry naming each file, its size and
the reason. The limit is 512 KB for every language except C and C++, which only injection reads,
up to 1 MB; a file between the two limits is marked as within injection's. A snapshot entry naming
such a file is not judged. Can turn a passing project to exit 3: split the file, or, when it is
generated or vendored, move it under `dist/` or `build/`, or declare its directory a fixture with a
reason. No factory policy drops it; a fixture marker there is a grant the allowlist has to approve.
Of the 34 calibration checkouts, four have such a file and now exit 3: CTFd (six JavaScript
bundles), juice-shop (`three.js`), WebGoat (`ace.js`) and NetBox (a 6 MB table of place codes in a
`.py` file).

**After v1.16.3: a YAML, SQL or Terraform file over 512 KB is named above the verdict.** Immutability,
retention, the Kubernetes manifest check and the IAM and manifest contracts skip one that size, or
one they cannot open, and the "not read" line above the verdict now lists them. The run's exit code
does not change. In factory mode the line is the `skipped-files` advisory, could-not-run by default
like `unread-code`, and a policy can drop it. `--json` lists these and the code files above under
`skippedFiles`, each with `code` true or false. A lockfile the dependency scanner reads
(`pnpm-lock.yaml` is the one with an extension these checks read) is not listed at any size. A
symbolic link to a file that is not there is listed with these files whatever its extension, a link
named `.py` included: it is never the `source_files:` entry a skipped code file gets. So in the
default mode it is a line, and the line does not change the exit code; in factory mode it is
`skipped-files` like the rest, and the run is incomplete, exit 3, until the link is repaired or
removed or the policy drops the advisory. The line is not all a link named `.py` gets: the build
check compiles it by name, cannot open it, and reports a blocking finding in either mode.

**After v1.16.3: dependencies declared indirectly need a lockfile.** A `pyproject.toml` with
`dynamic = ["dependencies"]` (setuptools, reading them from a requirements file), one whose
dependencies are only in `[tool.pdm.dev-dependencies]` or `[tool.uv] dev-dependencies`, and a
`Gemfile` whose only declaration is `gemspec` each read as declaring nothing, so none needed a
lockfile. Each counts as declaring now. Can turn a passing project red: commit the lockfile
(`pip freeze`, `pdm lock`, `uv lock`, `bundle lock`), or hold the finding in a snapshot.

**After v1.16.3: `wolfproof known` counts `peerDependencies` as declared when it adds a lockfile's
findings.** npm 7 and later install peers and write them to the lockfile, so a peer added in the
change that commits the lockfile had its findings added as if they were transitive. The entry
written for a `package.json` with no lockfile now lists its peers, and the relock step compares and
counts them as direct. An entry written by an earlier version for a `package.json` that already had
peers lists none of them, so its relock is refused as "declares packages its entry does not list",
the lockfile's findings block, and the entry is kept: review them, then delete it by hand. The scan
without a lockfile still does not scan peers.

**After v1.16.3: Helm templates and YAML that does not parse are not read as manifests.** The
Kubernetes manifest, manifest-contract and IAM-contract checks read a file that failed to parse as
whatever the parser salvaged, and read `{{ .Values.image }}` as nested mappings rather than as the
unexpanded value it is. Neither is read now, and the checks name the files they did not read. A
file is a template when an unquoted `{{ … }}` stands where YAML expects a key, a value or a list
item, which the parsed document decides: `{{` in a comment, in a quoted or plain string or in a
block of text (a Prometheus rule, an Argo parameter, a container argument, `${{ }}` in a workflow)
is text, and that file is read exactly as before. A variable the code requires is unknown rather
than missing only when a file that was not read could have set it; a file that parsed and holds no
workload changes nothing. A template is checked by rendering it (`helm template`) and running the
gate over the output. A document cut short in a way that still parses is read as it stands; nothing
in its text says it is incomplete.

In factory mode a file that was not read is never information. Each message has its own advisory
id, all of class not-checked, so each blocks until the file is rendered or repaired, or the policy
says otherwise: `k8s-yaml-unread`, `k8s-none-read` (no manifest was read and some YAML was not),
`iam-yaml-unread`, `manifest-contract-unread` and `manifest-contract-no-workload-read`. That
includes a file that is not a manifest and does not parse as YAML, such as a Rails
`config/database.yml` written in ERB: three of the 34 calibration checkouts have a file that does
not parse (juice-shop, Mastodon, RailsGoat), none of them a manifest, and none lost a finding.

**After v1.16.3: in factory mode, a name added to a snapshot entry's `declared` list blocks.** The
entry for a `package.json` with no lockfile lists what it declared when the snapshot was taken, and
`wolfproof known` adds a new lockfile's findings only while the `package.json` declares nothing
else. The command reads the list from the snapshot file as it is, so a change that declared a
dependency, committed the lockfile and wrote the name into the list in `.wolfproof-known.json` was
refused nothing, and factory mode did not see the edit: the entry's grant is its ID, which had not
changed. Each name a change adds to the list of an entry that was at the base is now a grant of its
own, `known-declared`, listed in `--json` under `factory.grants`, and it blocks whatever the
allowlist says; an allowlist entry of that kind is ignored and reported. A name removed, the list
removed, and the list of an entry the change itself adds grant nothing more than before. The
command never adds a name to a list, so only a change that edits one by hand is affected. The
default mode is unchanged: there the project's snapshot is a record the change can edit, this line
of it included, and the edit is in the diff a reviewer reads. A snapshot kept outside the project
(`wolfproof known . --file <path>`, then `--known=<file>`) cannot be edited by the change in either
mode.

**After v1.16.3: `wolfproof known` holds each workspace member to its own entry before it adds a
root lockfile's findings.** The refusal for a dependency declared since the snapshot compared only
the root `package.json` with the root's entry. A member's names counted as direct and were compared
with nothing, so a change that declared express in `packages/web/package.json` and committed the
root lockfile had the finding in qs, which express brings in, added through the root's entry. Now
the root lockfile adds nothing while any member declares a package its own entry does not list, has
an entry with no list, or declares packages and has no entry at all; the command names each member
and its packages, and the root's entry is kept. This can refuse a lockfile an earlier version added
findings for, and then those findings block. Two cases to expect. A member's entry deleted by hand
before the root's lockfile was added: restore it from the snapshot's history, or fix or review the
findings. A member the snapshot never held as having no lockfile (it was added since, it had its
own lockfile then, or it is under a skipped directory): the root lockfile is refused while that
member declares anything. The message for a member's kept entry now says not to
delete it before the lockfile's findings have been added for the root. `--json` consumers: a
refused root entry in `relocked` carries `member: true` when a member is among the reasons, and a
member's entry carries `root` naming the root `package.json` whose entry is still held.

**After v1.16.3: in factory mode, a name the project chooses no longer decides what a line under
it means.** Some lines open with a label the gate did not choose: a Terraform root's path in
`checkov (infra): …`, in the plan's line and in the resource census; the kind of template checkov
reported on in `iac templates (CloudFormation): …`; the image in `trivy (app:1): …`. Factory mode
read that label up to the first `)`, and it went wrong in two directions. For a root with `)` in
its name, `net (prod)` for one, every such line was an advisory it could not classify: a scan that
found nothing blocked (exit 1), and so did a checkov that could not run, which is exit 3 for any
other root. And a label written like the end of one message and the start of another chose the
line's class. With a directory called `a): 0 finding(s) in your own configuration (b`, a checkov
that did not run there read as its "found nothing" line, which is information: exit 0 where every
other root gets exit 3. Its findings read the same way, so a policy that blocks checkov's findings
(`"checkov": "block"`) let them through with exit 0. The label is now compared with the names the
gate wrote in this run, the roots it scanned, the kinds checkov reported and the image it was given,
and is never read by its brackets. Verdicts move both ways, in factory mode only. A project blocked
only by a bracket in a name goes to exit 0, or to exit 3 where the tool could not run. A could-not-run
or a finding that a name was hiding is exit 3 again, or blocks under a policy that blocks it. Can
turn a passing project red: only one with two Terraform roots where one's path is the other's
followed by `): ` and more, so that a line could be about either and the two readings differ. That
line blocks as unclassified and names both roots; rename one directory. The printed lines are
unchanged, and so is the default mode.

**After v1.16.3: the gate leaves no Python bytecode in the project.** The build check's
`python3 -m py_compile` wrote `__pycache__/` beside every Python file it compiled, and the test
check's pytest wrote one for each module the suite imported. On a checkout that does not ignore
`__pycache__/`, the next `--factory` run read those as files the change wrote where no source
check looks and blocked: "1 file(s) this change wrote under __pycache__". A machine with
`PYTHONDONTWRITEBYTECODE` set never saw the pytest half, and Apple's `/usr/bin/python3`, which
keeps its bytecode under `~/Library/Caches`, saw neither. Now `py_compile` writes to a temporary
directory that is removed afterwards (`PYTHONPYCACHEPREFIX`, or the one already set in the
environment), and pytest and the `pytest --version` probes run with `PYTHONDONTWRITEBYTECODE=1`,
which the suite's own subprocesses inherit. A `__pycache__/` an earlier run left is still there and
still blocks in factory mode: delete it once. Not covered: Python before 3.8 does not read
`PYTHONPYCACHEPREFIX`, so `py_compile` there writes beside the source as before; and pytest still
writes `.pytest_cache/`, which holds its own `.gitignore` and is not one of the directories factory
mode blocks on.

**After v1.16.3: a checkov that is installed and cannot run is no longer called "not installed".**
The Dockerfile, template and Terraform checks each ran `checkov --version` before the scan and read
any failure of it as absence. They now start the scan and nothing else; checkov is absent when the
scan cannot be started and nothing on `PATH` is named `checkov`. With checkov working, nothing a run
reports has changed. With no checkov, a Dockerfile and a CloudFormation, ARM or Bicep template still
get "checkov is not installed", could-not-run in factory mode.

With no checkov, a Terraform project's run has one new line: "checkov: not installed, so its
rules did not run over the Terraform here (.). checkov is optional for Terraform, and what it finds
there is advisory." It is said once, naming every Terraform root. Until now such a run said nothing
about checkov outside the toolchain report, which is in `--json` and `--version` only. The line is
information, advisory id `checkov-absent`: no verdict moves on it in either mode, and a policy that
blocks checkov's findings does not reach it. A pipeline that requires checkov on Terraform can map
`checkov-absent` to `incomplete` in its policy.

What else changes is the install that is there and fails. One whose Python has lost the module: for
a Dockerfile and a template the advisory now reads "checkov did NOT run to completion (exit 1, no
output)", could-not-run as before, and for Terraform, where that install was read as absent and
nothing was said, the run now reports "checkov (.): produced no output (exit 1)" with what checkov
printed. One the system cannot start at all, which is what a pipx or venv install becomes when its
Python is upgraded or removed (a script whose `#!` line names an interpreter that is gone, or a link
to a file that is gone): all three checks report "checkov did NOT run to completion
(/home/me/.local/bin/checkov is on PATH and could not be started: its #! line names
/home/me/.local/pipx/venvs/checkov/bin/python, which does not exist)". Both are could-not-run, so in
factory mode a Terraform project with such an install is exit 3 where it was judged as if checkov
were absent. Repair or remove the install.

Also: "dockerfile: checkov's output could not be parsed" had no class, so factory
mode blocked on it (exit 1) as an unclassified advisory. It is could-not-run, exit 3, like the same
message for templates and Terraform. A gate run starts checkov one time fewer per check that uses it.

**After v1.16.3: C# tests with no project file say so where the .NET SDK is missing too.** With no
`.sln`, `.slnx` or `.csproj` to build them with, the test check said "there is no .sln, .slnx or
.csproj" on a machine with the SDK and "the .NET SDK is not installed here" on one without, because it
asked for the SDK first. It now settles what to build first, as it does for every other language, so
the message names what the project lacks on both. The verdict is the same either way: could not run,
exit 3. With a project file and no SDK the message is unchanged.

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
