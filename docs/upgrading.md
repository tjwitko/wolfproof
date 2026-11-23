# Upgrading

The four controls come **with** the gate — `wolfproof` pins them — so upgrading the gate upgrades
them. You only upgrade a control separately if you wired it into an editor on its own.

## 1. See what you are on

```text
$ ./node_modules/.bin/wolfproof --version
wolfproof 1.17.0
  terraform-guard  v1.1.3  node_modules @tjwitko/terraform-guard-mcp
  dep-audit        v1.0.4  node_modules @tjwitko/dep-audit-mcp
  secret-guard     v1.0.4  node_modules @tjwitko/secret-guard-mcp
  identity-guard   v1.0.4  node_modules @tjwitko/identity-guard-mcp
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
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.17.0
- uses: tjwitko/wolfproof@v1.17.0
```

A workflow left at two versions runs one release's gate on another's toolchain. It is an easy one to
miss: a search for `wolfproof@` does not match the first line.

**npm:**

```bash
npm install --save-dev github:tjwitko/wolfproof#v1.17.0
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

### In v1.16.4

Fifteen changes. The first seven share one shape: a part of the gate that could not read its input
said "nothing there", which is the answer that passes. Each now says what it did not read, and
nothing is judged over an input that was not read. The rest are about `wolfproof known`, factory
mode, checkov, C# tests, the `tests` line and signature IDs.

These can turn a passing project red. Each note says how, and what to do:

- **Exit 1, in either mode:** an `authentication:signature:<Language>` entry in a snapshot or review
  file, from before each comparison had its own ID; a `package.json` that is not valid JSON;
  dependencies declared indirectly with no lockfile; a lockfile hand-off `wolfproof known` now
  refuses, for a snapshot entry with no list of peers or for a workspace member.
- **Exit 3, in either mode:** a code file the checks did not read; a Dockerfile that cannot be read.
- **Factory mode only:** YAML the manifest checks did not read, Helm templates among it; a large
  YAML, SQL or Terraform file, or a broken symbolic link (`skipped-files`); a name added by hand to
  a snapshot entry's `declared` list; two Terraform roots whose names make a line readable as
  either; a checkov that is installed and cannot start.

**In v1.16.4: a `package.json` that does not parse is unscanned, not "0 checked".** The scan of
a `package.json` with no lockfile reported one that was not JSON as `(0 checked)`, which counted as
read: the dependency family was judged over it, and `wolfproof known` removed the entries its earlier
scan had produced. It is now reported with the other manifests no scanner read, with the reason
(`could not be parsed as JSON`), it blocks like them, and no dependency entry is judged while it
stands. Can turn a passing project red: only one whose `package.json` is not valid JSON.

**In v1.16.4: a Dockerfile that cannot be read is could-not-run.** It was skipped as a file
with no `FROM`: its end-of-life finding left the run with nothing in could-not-run, and its snapshot
entries matched nothing. The run now exits 3 naming the file, and its entries are not judged.

**In v1.16.4: a code file the checks did not read is could-not-run.** Authentication, code
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

**In v1.16.4: a YAML, SQL or Terraform file over 512 KB is named above the verdict.** Immutability,
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

**In v1.16.4: dependencies declared indirectly need a lockfile.** A `pyproject.toml` with
`dynamic = ["dependencies"]` (setuptools, reading them from a requirements file), one whose
dependencies are only in `[tool.pdm.dev-dependencies]` or `[tool.uv] dev-dependencies`, and a
`Gemfile` whose only declaration is `gemspec` each read as declaring nothing, so none needed a
lockfile. Each counts as declaring now. Can turn a passing project red: commit the lockfile
(`pip freeze`, `pdm lock`, `uv lock`, `bundle lock`), or hold the finding in a snapshot.

**In v1.16.4: `wolfproof known` counts `peerDependencies` as declared when it adds a lockfile's
findings.** npm 7 and later install peers and write them to the lockfile, so a peer added in the
change that commits the lockfile had its findings added as if they were transitive. The entry
written for a `package.json` with no lockfile now lists its peers, and the relock step compares and
counts them as direct. An entry written by an earlier version for a `package.json` that already had
peers lists none of them, so its relock is refused as "declares packages its entry does not list",
the lockfile's findings block, and the entry is kept: review them, then delete it by hand. The scan
without a lockfile still does not scan peers.

**In v1.16.4: Helm templates and YAML that does not parse are not read as manifests.** The
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

**In v1.16.4: in factory mode, a name added to a snapshot entry's `declared` list blocks.** The
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

**In v1.16.4: `wolfproof known` holds each workspace member to its own entry before it adds a
root lockfile's findings.** The refusal for a dependency declared since the snapshot compared only
the root `package.json` with the root's entry. A member's names counted as direct and were compared
with nothing, so a change that declared express in `packages/web/package.json` and committed the
root lockfile had the finding in qs, which express brings in, added through the root's entry. Now
the root lockfile adds nothing while any member declares a package its own entry does not list, has
an entry with no list, or declares packages and has no entry at all; the command names up to five
such members, with up to ten of each one's packages, counts the rest, and keeps the root's entry. This can refuse a lockfile an earlier version added
findings for, and then those findings block. Two cases to expect. A member's entry deleted by hand
before the root's lockfile was added: restore it from the snapshot's history, or fix or review the
findings. A member the snapshot never held as having no lockfile (it was added since, it had its
own lockfile then, or it is under a skipped directory): the root lockfile is refused while that
member declares anything. The message for a member's kept entry now says not to
delete it before the lockfile's findings have been added for the root. `--json` consumers: a
refused root entry in `relocked` carries `member: true` when a member is among the reasons, and a
member's entry carries `root` naming the root `package.json` whose entry is still held.

**In v1.16.4: in factory mode, a name the project chooses no longer decides what a line under
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

**In v1.16.4: the gate leaves no Python bytecode in the project.** The build check's
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

**In v1.16.4: a checkov that is installed and cannot run is no longer called "not installed".**
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

**In v1.16.4: C# tests with no project file say so where the .NET SDK is missing too.** With no
`.sln`, `.slnx` or `.csproj` to build them with, the test check said "there is no .sln, .slnx or
.csproj" on a machine with the SDK and "the .NET SDK is not installed here" on one without, because it
asked for the SDK first. It now settles what to build first, as it does for every other language, so
the message names what the project lacks on both. The verdict is the same either way: could not run,
exit 3. With a project file and no SDK the message is unchanged.

**In v1.16.4: the `tests` line says how long the suite took.** A suite that passes is reported as
`tests: ran under node --test — 19 of 19 passed in 41s (limit 120s).`: the time, and the limit
`WOLFPROOF_TEST_TIMEOUT` or its default gave it. Each suite of a project with several has its own
line and its own time. The verdict is unchanged, and so is the finding for a suite that fails. If you
read the line with a pattern that ends at `passed.`, it no longer matches. The line now differs from
run to run, so two runs' advisories are no longer equal as text.

**In v1.16.4: each signature compared with `==` has its own ID.** The authentication check's
finding for a request signature compared with an ordinary equality operator had one ID per language,
`authentication:signature:Python`, so a snapshot or a review that held one such comparison held every
one a later change added in that language: a second webhook verified the same way passed. Each
comparison now has an ID of its own, `authentication:signature:<file>:<hash of the line>`, like a
credential's, and the finding names where they are, `(hooks.py:12, billing.py:40)`. Whether a project
has the finding is decided as before. Can turn a passing project red: one whose snapshot or review
file holds the old language ID. That entry now matches no finding, and the gate says so, so each
comparison blocks until it is fixed or reviewed by its new ID (`wolfproof review .` lists them).
`wolfproof known` will not add them to an existing snapshot; delete it and run the command again to
take in what is there now, and read the diff. `wolfproof review` also says what voids an entry by what
its ID names: a line for a comparison, the variable for an unset credential, and a route only for an
open route, where it said "the route's method, path or file" for every authentication ID.

### In v1.16.5

Nine changes. Two are the gate's own: a directory it cannot list, and a workspace member it cannot
read or a pattern it cannot resolve, now say so instead of reading as empty. Six come with the four
controls' patch releases, and one with the end-of-life data.

These can turn a passing project red. Each note says how, and what to do:

- **Exit 1, in either mode:** a credential in a project the gate is given through a symbolic link;
  a Python HTTP Basic tuple whose parts are calls; a Dockerfile on Go 1.2 to 1.9, Python 2.1 to 2.5
  or Ruby 1.8; a root lockfile that `wolfproof known` now refuses for a workspace that names members
  with an extglob or has one it cannot read.
- **Exit 3, in either mode:** a directory the gate's user cannot list or enter, unless git ignores it
  and tracks nothing under it.
- **Factory mode only:** a directory like that which git ignores (`unread-ignored-dirs`), until the
  policy accepts it. This changed twice since: see the notes in v1.16.6 and v1.16.7.

One can turn a red project green: JavaScript or TypeScript that the HTTP Basic rule read as a tuple.

**In v1.16.5: `wolfproof known` refuses a root lockfile when a workspace pattern is an extglob or
a member cannot be read.** Before it adds a root lockfile's findings, the command reads which
members the workspace has, so that their direct dependencies count as direct. Two kinds of input
read as "no member here" and not as "not known":

- **An extglob** (`packages/@(web|api)`, `packages/!(legacy)`, `packages/+(web)`) was taken as a
  directory name and matched nothing. A pattern that opens with `!(` was dropped as an exclusion.
- **A directory a pattern walks that could not be listed, and a member that could not be looked
  into,** for instance for lack of permission.

Either way the member's direct dependencies were not counted, and it was not held to its own
entry. A finding one has at its locked version was added through the root's entry. So was one a
package it declared in the same change brought in: with `packages/@(web|api)` and express added to
`packages/web/package.json` beside the root lockfile, qs's finding was added, where `packages/*`
refuses the lockfile. Each now leaves the members unknown: nothing is added, the command names the
pattern or the directory, and the entry is kept, as for `packages/**`.

Can turn a passing project red, only when the command adds a root lockfile's findings, and only for
a workspace that names members with an extglob or has one it cannot read. Those findings then block
until fixed or reviewed. Write the members as paths or `*` globs. A symbolic link that `*` matches
is now followed, so a member reached through one counts. Through the CLI, a member that cannot be
read usually stops a run earlier (the dependency scan, or the build check, cannot read it either),
so the extglob is the case to expect.

**In v1.16.5: a directory the gate cannot list is could-not-run.** Every check walks the
project, and each read a directory it could not list as an empty one. Two shapes, both reproduced on
v1.16.4 with a project whose only Python file, `lib/secret/b.py`, has a syntax error (exit 1 when
readable):

- **A directory that can be listed and not entered** (`chmod 644 lib`): every check skipped
  `lib/secret/` without a word, the dependency search said "no dependency manifest was found", and
  the run **exited 0**, in the default mode and in factory mode.
- **A directory that cannot be listed** (`chmod 311 lib/secret`): the build check's walk threw.
  The gate caught it as "the gate itself failed", exit 3, and lost the whole run. `wolfproof known`
  did not catch it and ended with Node's exit 1, a code it does not have.

Now each such directory is a `source_files:` entry naming it, could-not-run, exit 3 in either
mode. The build check says it did not syntax-check the files there. When no manifest was found
elsewhere, the dependency search says whether one is there is not known, where it said "not
applicable". A snapshot entry naming a file under such a directory is not judged. `--json` lists
the directories under `unreadDirectories`. Directories every check skips (`node_modules/`,
`dist/`, `build/` and the rest) are not named.

One exception: inside a git repository, a directory `git check-ignore` reports as ignored, with no
file under it that git tracks, is a line above the verdict, not could-not-run. The case is a
docker-compose bind mount such as `./data/postgres`, owned by the container's user with mode 700
and ignored: without the exception every run of that project would exit 3, and the only way out was
`sudo chmod` or moving the volume. In factory mode the line is the `unread-ignored-dirs` advisory,
could-not-run unless the policy accepts it (no longer so: see the notes in v1.16.6 and
v1.16.7). `unreadDirectories` marks each such directory
`ignored: true`. A directory git tracks anything under, and any directory outside a git repository,
is could-not-run as above.

`wolfproof known` now exits 3 if anything escapes it, with "the command itself failed" and the
reason, as the gate does.

Can turn a passing project to exit 3: only one with a directory the gate's user cannot list or
enter, other than one git ignores. Make it readable by that user, or remove it. In factory mode an
ignored one is exit 3 too, until the policy accepts `unread-ignored-dirs`. Later versions changed
the factory-mode part: see the notes in v1.16.6 and v1.16.7.

**In v1.16.5: the controls are terraform-guard v1.1.3, dep-audit v1.0.4, secret-guard v1.0.3
and identity-guard v1.0.4.** Each now compares real paths when it checks that a path stays inside
the project. Each compared the text of the path, so a symbolic link inside the project that leads out
of it passed, and a project reached through a link was misjudged. The notes below say what that, and
each control's other change, does to a run. terraform-guard, secret-guard and identity-guard are
AGPL-3.0-only from these versions, as wolfproof and dep-audit already were.

**In v1.16.5: a project named through a symbolic link has its credentials scanned.** gitleaks
scans nothing when the last part of the path it is given is a link to a directory. The gate hands
secret-guard the project path as given, so `wolfproof ./link-to-project` reported no hardcoded
credential whatever the project held. Reproduced on v1.16.4: a project holding a GitHub token
exits 1 when named directly and **0 when named through a link**. secret-guard now scans the real
directory, and both exit 1. A link earlier in the path, such as macOS's `/tmp`, was not affected.

**In v1.16.5: the HTTP Basic rule reads the credential tuple in Python files only.**
`auth=(user, password)` is Python syntax. In JavaScript and TypeScript `(a, b)` is the comma
operator, and v1.16.4 blocked some of it as Basic authentication. A file with
`const a = 1, auth = (b, c);` and `auth = (console.log("x"), process.env.TOKEN);` exits 1 on v1.16.4
with two "workload identity" findings, and 0 now. The `HTTPBasicAuth` and `BasicAuth` classes and an
`Authorization: Basic` header are still read in every language. In Python the tuple's parts may now
hold calls, so `auth=(str(os.getenv("U")), p)` blocks, where v1.16.4 passed it.

**In v1.16.5: dep-audit counts more Python dependencies as direct.** It reads `requirements.txt`
and `pyproject.toml` entries as PEP 508. Before, these were classed as transitive:

- CRLF line endings;
- a marker with no version;
- a version in parentheses;
- a URL reference;
- extras, single quotes and inline arrays in `pyproject.toml`.

Names are compared after PEP 503 normalisation (`python_jose` is `python-jose`). The gate's verdict
does not read this field: the change shows in `check_dependencies`' own result, `direct: true`, as an
editor or the agent loop receives it. Poetry's `[tool.poetry.dependencies]` is still not read.

**In v1.16.5: a scan path or working directory through a symbolic link out of the root is
refused.** secret-guard, dep-audit and identity-guard refuse a path whose real location is outside
`SCAN_ROOT`, and terraform-guard one outside `TF_WORKING_ROOT`. Each now also refuses a path that
does not exist, as outside the root when it lies below a link that leaves it. Before, the text of
the path decided. The gate names `.` and the Terraform directories its own walk finds, and the walk
does not follow a link to a directory. So the gate's verdicts do not move: a project whose `infra`
is a link to Terraform outside it reports "no Terraform configuration was found" before and after.
A caller that names its own path, such as an editor or the agent loop's model, can now be refused.

**In v1.16.5: `terraform_plan` refuses a `var_file` outside the working root.** It joined
`var_file` onto the working directory unchecked. terraform quotes a var file's lines in its parse
errors, and `terraform_plan` returns up to 4,000 characters of the error, so a file outside the root
could be read back through it. `var_file` is now resolved relative to `working_dir` and must stay
inside `TF_WORKING_ROOT`, so a shared `../env/prod.tfvars` inside the root still works. The gate
never passes a `var_file`, so only a direct caller sees this.

Can turn a passing project red: one named through a link that holds a hardcoded credential, and a
Python file that passes Basic authentication as a tuple whose parts are calls. Can turn a red one
green: JavaScript or TypeScript that the HTTP Basic rule read as a tuple.

**In v1.16.5: the end-of-life data names older releases.** The refresh from endoflife.date on
2026-11-17 added Python 2.1 to 2.5, Go 1.2 to 1.9 and Ruby 1.8, and changed no date it already
held. The Dockerfile check judges a base image only by a release the data names, and said nothing
about one it did not. So `FROM golang:1.9`, `FROM python:2.5-slim` and `FROM ruby:1.8` passed, while
`golang:1.10` and `python:2.6` were blocked as end of life. All five now block. Can turn a passing
project red: only one whose Dockerfile is on one of those releases.

### In v1.16.6

**In v1.16.6: factory mode no longer exits 3 for a directory git ignores that it cannot list.**
In v1.16.5 the `unread-ignored-dirs` advisory was could-not-run in factory mode. A pipeline that
runs beside a container's bind mount, such as an ignored `./data/postgres` owned by the container's
user, exited 3 on every change until its policy dropped the advisory. It is now information,
dropped by default, as the default mode already treated it. Git tracks nothing under such a
directory, so a change carries nothing from it. The line still prints above the verdict, and
`--json` still lists the directory under `unreadDirectories` with `ignored: true`; the advisory's
entry under `factory.advisories.classified` now has class `info`.

A policy entry for the id still decides: `"unread-ignored-dirs": "incomplete"` restores exit 3, and
`"block"` is exit 1. A policy's rule for the `could-not-run` class no longer reaches it. So a
pipeline whose policy says `"could-not-run": "block"`, and which relied on that to stop at such a
directory, needs the entry by id. A directory git tracks anything under, and any directory outside
a git repository, is could-not-run in both modes as before.

Can turn a red project green: only in factory mode, one with an ignored directory the gate's user
cannot list. Cannot turn a passing project red.

### In v1.16.7

**In v1.16.7: factory mode blocks a directory it cannot list when the change's own ignore rule
is what ignores it.** v1.16.6 made the `unread-ignored-dirs` line information in factory mode. So
a change that added the ignore line itself took its own run from exit 3 to exit 0, and nothing
named the line: a project with an unlistable `vendor_src/`, and a commit adding `vendor_src/` to
`.gitignore`, exited 0 with no blocking finding, where the same run without that line exited 3.

Factory mode now asks git whether the ignore files as they were at the base already ignored the
directory. `.git/info/exclude` and the user's global excludes count with them, since a change
cannot carry either. A directory they ignored is as v1.16.6 left it: information, dropped, the line
above the verdict. One that only the change's rules ignore is an `ignored-directory` grant the
change added, **exit 1**, like every other exemption a change gives itself:

```
factory: 1 ignored-directory grant(s) this change added — vendor_src/ (.gitignore:1: vendor_src/). …
```

The pipeline's allowlist approves the directory by path, with kind `ignored-directory`. No policy
entry drops it. `--json` lists each such directory under `factory.grants`, with `status`
`pre-existing`, `allowlisted` or `added` and the `ignoreFile` that ignores it now. The default mode
is unchanged.

Can turn a passing factory run red, exit 1: only when the gate cannot list a directory, git
ignores it and tracks nothing under it, and the ignore rules at the base did not ignore it. That
is a change that adds the ignore line, adds a nested `.gitignore` that ignores it, or removes a
negation that kept it from being ignored (`!vendor_src/`, or `!*/` after a `*`), committed or not.
Not affected: a directory already ignored at the base, whatever else the change does to ignore
files, including an unrelated line in the same file or the pattern moved to another one; and a
directory only `.git/info/exclude` or a global exclude ignores. With no base to compare with the
run is exit 3 as before, and no grant is judged. It is also exit 3, "factory: … is not known",
when the base's rules cannot be asked: the base tracked a `.gitignore` file where the directory is
now, or holds an ignore file at a path git does not check out.

**In v1.16.7: a directory the gate cannot list counts as ignored only when git ignores the
directory itself.** Since v1.16.5 the gate asked `git check-ignore -- dir/`, which also answers
"ignored" when the rules ignore what is in the directory and not the directory. Git descends into
such a directory, and a negation can take a file back out. With `*`, `!vendor_src/` and `!*.js` in
`.gitignore`, `git status` lists `vendor_src/v.js` as untracked, and the gate still named an
unlistable `vendor_src/` above the verdict as one "git ignores" and exited 0. It now asks with and
without the trailing slash and takes the directory as ignored only when both say so.

Can turn a passing run red, **exit 3**, in both modes: only for a directory the gate cannot list
whose ignore rule is over its contents (`data/postgres/*`, `data/postgres/**`), or which is
negated after a wider rule (`*` then `!data/postgres/`). It is could-not-run, like any other
directory that cannot be listed. Ignore the directory itself instead: `data/postgres/`. In factory
mode that edit is an `ignored-directory` grant the change adds, exit 1, because the base's rules
did not ignore the directory; the pipeline's allowlist approves it by path. Not affected: a rule
that names the directory (`data/postgres/`, `data/postgres`, `data/`, `data/*`), with or without
other negations elsewhere.

### In v1.17.0

**In v1.17.0: factory mode scans the change's commits for credentials.** secret-guard reads the
working tree, so a credential one commit added and a later commit of the same change removed was in
no tree the gate compared: on v1.16.7, a base, a commit adding an AWS access key ID and a commit
removing the line exited 0 in factory mode. Factory mode now scans what each commit between the
base and the head added, and each commit's message, with the pipeline's own secret-guard and the same rules, and a finding
blocks, naming the commit, the file and the line. A `gitleaks:allow` or `.gitleaksignore` entry is
honoured when it existed at the base or the allowlist approves it, as in the tree. The Action now
fetches the commits between the base and the head as well as the base
([what it fetches](factory-mode.md#what-the-action-fetches)).

Can turn a passing factory run red. **Exit 1**: a commit of the change added a credential, though
the tree no longer holds it, or wrote a file under `vendor/` or another directory secret-guard does
not scan. A credential still in the tree is now reported twice. Rotate it and rewrite the branch,
or have the allowlist approve the file, kind `secret-in-commit`. **Exit 3**: the checkout does not
hold every commit between the base and the head. That is a run outside the Action in a shallow
clone, or a change longer than about 1,500 commits; `fetch-depth: 0` fixes both. The default mode
is not affected.

**In v1.17.0: factory mode blocks a change to a file that instructs coding agents.** Factory
mode blocked a change under `.github/workflows/` and had no rule for `AGENTS.md`, `CLAUDE.md`,
`.claude/`, `.mcp.json`, `.cursor/`, `.github/copilot-instructions.md`, `GEMINI.md` and the rest of
[the list](factory-mode.md#agent-instructions). A change that edits one changes what the next agent
run is told, which hooks run, which tools it loads and which commands it may run without asking: on
v1.16.7, a change that rewrote `AGENTS.md` and added a `.claude/settings.json` allowing every shell
command exited 0. Such a change now blocks, naming each file, at any depth and whatever the letter
case, and so does a change to a file one of them links to or imports. An agent file on disk that git
does not track counts too, whatever the ignore rules say, so factory mode expects a fresh checkout.

Can turn a passing factory run red, **exit 1**: any factory change that adds, edits, renames or
deletes one of those files, the output of `wolfproof init` and `wolfproof init --upgrade` included.
Make such edits in a change a person reviews, or have the allowlist approve the path, kind
`agent-instructions`. The default mode is not affected.

**In v1.17.0: a gate that cannot start exits 3, not 1.** The crash handler was installed by
the CLI's own code, which runs only after every module it imports has loaded. So a failure before
then ended with Node's exit 1, which is "blocked": on v1.16.7, a copy of the package whose
dependencies are not installed exits 1 from every command, and under Node 20 so does an exception
thrown while the modules are being read. The handler is now in place before anything of the package
that can fail to load is loaded. The gate, `wolfproof known` and `wolfproof review` exit 3 with
"could not start" and the reason, and in `--json` mode the gate writes
`{"exitCode": 3, "incomplete": true, "error": "the gate could not start: ..."}`; `wolfproof init`
exits 70, its own code for failed. `wolfproof review` had no handler at all, and a throw that
escapes it is now exit 3 too. One that arrives after it has begun to exit leaves the code it chose
and its output whole, and is said on stderr, as for the gate and `wolfproof known` (below).

If a job treated exit 1 from a broken installation as findings, it now sees exit 3. Under Node 20 a
module preloaded with `--import` can still throw before any line of the CLI has run, in its first
few milliseconds, and that is still Node's exit 1; under Node 22 no such moment was found.

**In v1.17.0: `--json` through a pipe is written whole.** The gate wrote its result and then
ended the process. A write to a pipe is asynchronous on macOS and Linux, so a document larger than
the pipe's buffer was cut there: on v1.16.7 on macOS, a 417,136-byte document reached `spawnSync`,
a shell's `$(...)` or `| jq` as 65,536 bytes that do not parse, with the exit code of a finished
run. Redirected to a file it was whole, which is why the Action, which redirects, never showed it.
The process now ends when stdout and stderr have handed everything over, on every exit: a verdict,
a usage error, a crash, `wolfproof review` and `wolfproof known`. Exit codes are unchanged, and a
reader that closes early still gets the code.

No verdict changes. A script that read `--json` through a pipe and fell back on a parse error now
gets the document.

**In v1.17.0: a failure after the gate has begun to exit is said on stderr.** With the change
above, an exception or rejection that arrived while the verdict was being written out was dropped:
a clean run exited 0 with no trace of it, and `wolfproof known` printed "Exit 3: it did not finish"
and exited with the code it already had. Both now write two lines to stderr, the failure and the
exit code that stands, and the process ends when they have been read. The exit code is the one
already chosen and stdout still holds one document. No verdict changes.

The gate has no time limit of its own on its output: a reader that keeps the pipe open and stops
reading makes it wait, as any program waits on a full pipe. Set your own limit on the call if you
cannot wait.

**In v1.17.0: an option the command does not define is a usage error.** Each command picked
out the options it knew and stepped over any other. On v1.16.7, on a clean project,
`wolfproof <project> --factroy` ran the default mode and exited 0, `--json=1` wrote the report as
text, and `wolfproof known <project> --json` wrote its snapshot. Each is now exit 2, naming the
option and the nearest one the command has, as `wolfproof init` already did: the gate,
`wolfproof known` and `wolfproof review`, for an option that is not theirs, for one that takes no
value and was given one, and for one written with a single dash. In `--json` mode the gate writes
`{"exitCode": 2, "error": "unknown option ..."}`. It is asked before anything else, so
`wolfproof --version --no-such-flag` is exit 2 as well.

Can turn a passing run into **exit 2**: any call that passes an option the command does not have.
The Action and the hook `wolfproof init` writes pass none. A directory whose name begins with a
dash has to be given as `./-name`.

**In v1.17.0: a credential that holds "true", "false" or "null" is reported.** The gate now
pins secret-guard v1.0.4. gitleaks' built-in allowlist dismisses any secret matching
`(?i)^true|false|null$`, which reads as "starts with true, or contains false, or ends with null",
in any letter case and for every rule. Measured on v1.16.7, one committed file per project: a
generated RSA private key exited 1, and the same key with `fAlSe` in its body exited 0; a
36-character GitHub token in a comment exited 1, and one with `False` in it exited 0; a
connection-string password starting `True` exited 0, and so did one ending `Null`. Each of those
is now exit 1. A password that is exactly `false` is still dismissed, exit 0 before and after.

secret-guard reads the default rules from its own copy of gitleaks 8.30.1's, with that one entry
anchored. So the rules are gitleaks 8.30.1's whatever gitleaks binary is installed: a newer
binary no longer brings newer rules, and 8.30.1 is the one to install.

Can turn a passing run red, **exit 1**: a credential with one of those words in it, which was in
the tree all along. Rotate it.

**In v1.17.0: a secret scan that did not happen, or did not read everything, is exit 3.** Up to
secret-guard v1.0.3 each of these came back as a clean scan, and v1.0.4 makes each an error:

- **A configuration gitleaks cannot load.** A clean project with `SECRET_GUARD_CONFIG` naming a
  file that is not there exited 0 on v1.16.7 with nothing scanned. It is now exit 3, naming the
  file.
- **A file or directory the scanner may not read.** gitleaks walks past it and reports on the
  rest. A tracked file of mode 000 holding a password exited 1 on v1.16.7 only because git could
  not read it either and called it uncommitted work, and exited 0 with `--pre-commit`. Both are
  now exit 3, and the line names the file from the project's top:
  "scan_path: secret-guard could not scan all of the project — it did not read config.yaml
  (permission denied)".
- **A scan gitleaks does not finish** within secret-guard's 120 seconds, which reported the part
  it had reached.

One path is set aside, so that v1.16.5's rule holds: a directory git ignores that the gate could
not list itself, such as a container's bind mount. The scanner did not read it either, the line
above the verdict already says so, and the verdict is as it was, exit 0 before and after. In
factory mode a directory only the change's own ignore line ignores is still
[the grant the change added](factory-mode.md#exemptions-it-judges), exit 1. The gate reads the
list of unread paths secret-guard sends with its error and sets the error aside only when every
path on it lies in such a directory.

Nothing else is set aside, and each of these, measured, went from exit 0 on v1.16.7 to exit 3:

- a file git ignores that cannot be read, such as an `.env` of mode 000. Ignored or not, it is on
  the disk the scan is asked about;
- a directory git ignores that can be listed and not entered (mode 444), with files in it. The gate
  lists it, so it is not in the line above the verdict;
- a directory that cannot be listed under `dist/`, which the other checks skip and the secret scan
  reads. One under `node_modules/` is not reported: gitleaks does not walk there.

Outside a git repository nothing is ignored, so a directory that cannot be listed adds a
`scan_path` entry to those the run already had; the exit code was 3 and is 3.

When the scan found credentials as well, they block as before and what was not read is a
could-not-run entry beside them, so the run is exit 3 where it was exit 1. In factory mode the
scan of [the change's commits](factory-mode.md#credentials-in-the-changes-commits) is held to the
same rule: a scan that says it left some of them unread is exit 3.

Can turn a passing run into **exit 3**: a project holding anything the user the gate runs as cannot
read, apart from the ignored directory above, or a `SECRET_GUARD_CONFIG` that does not load. Make
the path readable by that user, or remove it.

### After v1.17.0

**After v1.17.0: the secret scan reads text files it used to skip.** The secret-guard this release
pins takes out of gitleaks' default path allowlist the entries that hid text: lockfiles, `go.mod`,
`go.sum`, `go.work`, `.svg`, the gradle and maven wrappers, any `.js` named for a library such as
`bootstrap.js`, `javascript.json`, `verification-metadata.xml`, `.refactorlog`, `.gltf`, `.socket`,
`.bin` and `.v2`. In `go.sum`, `generic-api-key` skips a line of exactly the form
`<module> <version> h1:<hash>`; every other rule reads it, and a password on any other line is
reported. On the 35 calibration projects the findings went from 451 to 452, none lost, and the new
one is a commented-out API key in a file named for a library.

Can turn a passing run red, **exit 1**: a credential in one of those files. Measured, v1.17.0 against
this version, in default mode and in factory mode:

| The change | default | factory |
|---|---|---|
| an AWS access key ID in `go.sum` | 0 to 1 | 0 to 1 |
| a GitHub token in a comment in `art.svg` | 0 to 1 | 0 to 1 |
| the same in `bootstrap.js`, or a file named for angular, jquery, plotly or swagger-ui | 0 to 1 | 0 to 1 |
| the same under `bower_components/`, `env/lib64/` or `lib/python3.11/`, which stay unread | 0 | 0 to 1 |
| `go.sum` with a key, renamed to `config.js`, then deleted, in three commits | 0 | 0 to 1 |
| `package-lock.json` edited, no credential | 0 | 0 |

**After v1.17.0: factory mode blocks a write where the secret scan still does not look.** Its list
now comes from the pinned secret-guard (`gitleaks/unread-paths.json`): third-party trees, images,
fonts, Office files, PDFs, `.exe`, gems, rule files and archives. A list that is there and cannot be
read is exit 3. Default mode is unchanged by this.

Can turn a passing factory run red, **exit 1**: a change that adds, edits or renames a file to such
a path. Text holding a token named `logo.png` or `data.zip` was 0 and is 1, and so is the same file
renamed to `config.js` and deleted. So is a real image. Over the last 100 commits of wolfproof and of
the four controls (446 commits, since three have fewer), 2 would have blocked on this rule alone,
both edits to secret-guard's own `gitleaks/default.gitleaks.toml`. Approve a path with the kind
`skipped-location`, by the file's path for a kind skipped by its name.

gitleaks takes a file for an archive when its **name holds** an archive's ending, so
`app.browser.js`, `deploy.target.yaml` and `messages.pt.br.json` are unread and block as well. So does
a file under a directory named like an unread file, such as `logo.png/config.js`.

**After v1.17.0: factory mode blocks a file the scan skipped for its first bytes.** gitleaks skips text
that begins like a binary format under any name, and two letters are enough: `settings.env` with
`MZ_REGION=maputo` on line 1 and a token on line 2 was exit 0 in both modes. secret-guard now reports what
it left unread. In factory mode that write is **exit 1**, kind `skipped-location`, and so is a real
binary with no telling name. Default mode still exits 0 for it.

**After v1.17.0: a project under a path the scan will not enter is exit 3.** gitleaks tests the whole
path, so a checkout at `.../vendor/app`, `.../node_modules/app` or `.../env/lib/app` was read as nothing and
reported clean. Can turn a passing run into **exit 3**, in both modes. Move the checkout.

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
