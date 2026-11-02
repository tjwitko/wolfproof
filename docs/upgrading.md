# Upgrading

The four controls come **with** the gate — `wolfproof` pins them — so upgrading the gate upgrades
them. You only upgrade a control separately if you wired it into an editor on its own.

## 1. See what you are on

```text
$ ./node_modules/.bin/wolfproof --version
wolfproof 1.14.2
  terraform-guard  v1.1.2  node_modules @tjwitko/terraform-guard-mcp
  dep-audit        v1.0.2  node_modules @tjwitko/dep-audit-mcp
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
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.14.2
- uses: tjwitko/wolfproof@v1.14.2
```

A workflow left at two versions runs one release's gate on another's toolchain. It is an easy one to
miss: a search for `wolfproof@` does not match the first line.

**npm:**

```bash
npm install --save-dev github:tjwitko/wolfproof#v1.14.2
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

### After v1.14.2

**After v1.14.2: a credential compared with one character is not counted.** Jellyfin's header
parser reads the `Authorization` header a character at a time into a variable named `token`, and
`token == '"'`, `token == ','` and `token == '='` were each read as a token compared with `==`. A
comparison with one quoted character, or one escape such as `'\''`, is no longer counted: in C#,
Java, C, Go and Rust that is a character, not a credential, and in any language a timing leak of one
character tells an attacker nothing a guess would not. A literal with more after it (`'a' + rest`)
is still read. On the same projects, 5 of 90 matches drop, all Jellyfin's, and none is added. No
finding or verdict moves: Jellyfin's report already named its QuickConnect `secret` comparison.

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
