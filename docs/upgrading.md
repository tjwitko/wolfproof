# Upgrading

The four controls come **with** the gate — `wolfproof` pins them — so upgrading the gate upgrades
them. You only upgrade a control separately if you wired it into an editor on its own.

## 1. See what you are on

```text
$ ./node_modules/.bin/wolfproof --version
wolfproof 1.13.0
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
- uses: tjwitko/wolfproof/.github/actions/control-tooling@v1.13.0
- uses: tjwitko/wolfproof@v1.13.0
```

A workflow left at two versions runs one release's gate on another's toolchain. It is an easy one to
miss: a search for `wolfproof@` does not match the first line.

**npm:**

```bash
npm install --save-dev github:tjwitko/wolfproof#v1.13.0
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

**After v1.13.0: the fix for an open route names its framework.** A Flask route was told to add a
FastAPI dependency, and every language's advice named all of that language's frameworks. The advice
now names the fix for the framework each open route is written in, and only forms the check
credits. A NestJS `@UseGuards(...)` written below the route decorator now counts,
as one above it did. A Flask route on a class (`@ns.route` on a flask-restx `Resource`) is told
about a `before_request` hook, on the app or on the blueprint its `Api` is mounted on, the one form
that counts for it, not a check at the top of the view.

**After v1.13.0: Flask's decorators and `before_request` hooks count.** `@login_required` from
Flask-Login, Flask-Security's and Flask-JWT-Extended's decorators, Flask-HTTPAuth's
`@auth.login_required`, a project's own decorator that refuses the caller, and a `before_request` hook
that refuses now protect the routes they run for. A hook that lets some paths through
(`request.path.startswith("/public")`) leaves open the routes whose full path it matches, read with
their blueprint's `url_prefix` and, for flask-restx, the `Api`'s prefix and the namespace's path, and
every route whose full path cannot be read. A blueprint registered by a helper function, in a loop over
a list, or made by a factory now has a known full path, so such a hook can protect its routes; and a
blueprint registered on a helper's parameter is read as what the helper is called with, not as a
module-level name the parameter shadows, which credited routes the hook lets through. A Flask route open before can now pass, and a review
of one now matches nothing and is reported as doing nothing: delete it.

**After v1.13.0: a JavaScript or Go handler is the function its route's file names.** A named
handler was the first function of that name anywhere in the project, so a route could be credited with
another file's check; such a route can now block. The name is resolved from the route's file, through
its imports or its package, and a method through the receiver's type. A handler imported from a
package, or from a TypeScript path alias, is not read, so a check inside it is not credited.

**After v1.13.0: a Flask rule built from a module's names has a known path.** `@app.get(BASE +
"/one")` with `BASE = "/api"` now has the full path `/api/one`, so a hook's path rule is matched against
it rather than taken to reach it: a route open before can now pass. A name written by `+=`, from
another module, or from the environment still has no known path.

**After v1.13.0: a Flask hook counts only where the code installing it runs.** A `before_request`
hook in a function nothing calls, or calls only from such a function, or only stores, was credited,
and no longer is: a route that passed on it can now block. A hook in an app factory still counts
though the project never calls the factory, since Flask's CLI and servers do.

**After v1.13.0: names are read as Python reads them, and an Api where it is mounted.** A Flask name
was the first assignment of it anywhere in its file, so a helper's local `app` could stand for the
module's app and credit the module's routes with a hook the helper put on its own blueprint; such a
route can now block. A flask-restx `Api` mounted on a parameter or by `init_app` in another file is now
read, so a blueprint hook can protect its routes; one mounted on several blueprints is protected only
where each is.

**After v1.13.0: a Flask rule is read as a literal only when it is one.** `@app.get("/a" if ON else
"/b")` was read as "/a", and `@app.get("/x" + SUFFIX)` as "/x", so a hook letting "/b" or "/x/c"
through was credited on a route Flask serves to anyone. A conditional rule is now either path, and one
with a part not written out has no known path, so a hook's path rule is taken to reach it: such a route
can now be reported open. A factory or name choosing between two blueprints with a conditional
expression now stands for both.

**After v1.13.0: an app or blueprint made by a factory is known.** A hook on `app = create_app()`
imported from wsgi.py now protects that app's routes, a route declared there has a full path, and a
blueprint assigned from a factory (`admin = make_admin()`) has the prefix it is registered with, as
does a factory returning `Blueprint(...)` or `Flask(...)` directly. A route open before can now pass.
Each call of a factory makes its own blueprint: a hook put on one call's result (`b1 = make_b()`)
protects the routes declared on that name, not those of `b2 = make_b()`, and those declared inside the
factory only when it runs once.

**After v1.13.0: a Flask hook installed by a function counts, and one never installed does not.** A
`before_request` hook inside `def init_app(app)`, or added with `target.before_request(check)`, now
protects the routes of whatever each call passes it, and a hook on an app imported from another module
protects that app's routes; an app's hook reaches the routes under the directory the app is made in.
A hook in a function nobody calls, on a parameter named like the module's app, was credited and no
longer is: a route that passed on it can now block.

**After v1.13.0: a Flask route whose rule is a call is checked.** A route written as
`@routes.route(org_scoped_rule("/login"))` was not found, so nothing checked it: 19 of redash's. It is
now found, shown by the path written in it, and judged like any other route, so one with nothing
protecting it is reported open and a project can start to block on it; redash has 8, its sign-in,
invitation and password-reset pages and `POST /verification_email/`. A hook's path rule is matched
against each path the call can return, every branch of it, and reaches the route when the call
cannot be read. A raw-string rule (`r"/x"`) is now found as well.

**After v1.13.0: a Python route on a class is not judged by its first method.** A flask-restx route,
`@ns.route(...)` on a `Resource` class, was judged by the body of the class's first method, so a
sign-in check in its `get` credited an open `post`. A route on a class is now judged by none of its
methods: not by their bodies, not by `@login_required` on a method, and not by `method_decorators`.
It is reported open unless a `before_request` hook protects it: the app's, or that of the blueprint
its `Api` is mounted on (`Api(bp)`, `api.init_app(bp)`). A hook that lets requests through by endpoint
leaves it open, since its endpoint is not read, and one that lets them through by path leaves it open
when the path matches its full path. A class route that passed on
its first method's check can now block: move the check into such a hook, or mark the finding
reviewed once a person has read each method. A `MethodView` registered with `add_url_rule` is not
read as a route by either version, so nothing changes for it. It moved no route on the calibration
applications or on five real Flask applications.

**After v1.13.0: Rails routes are reported as not checked, not as protected.** Lines in
`config/routes.rb` were read as Sinatra routes, and a `before_action :authenticate…` in any controller
marked them all protected — on Mastodon, its public profile page among them. Rails routing is now not
read as routes, and an advisory names the files whose routes were not checked. A Rails app that passed
on that credit passes in the default mode with the advisory, and blocks in factory mode, as any
not-checked advisory does; a policy can drop `auth-rails-unread` once a person has judged the routes.
A Sinatra `before` filter with a path now protects only the routes it matches, and a filter counts
only on what its own block does.

**After v1.13.0: a credential compared with `==` blocks when no route is read.** The two comparison
findings, a credential or signature compared with `==` and a credential that is vacuous when its
variable is unset, were dropped from the report of a project with no route read. Once Rails routing
stopped being read, rubygems.org lost the `path_token ==` finding v1.13.0 blocked on. They are reported
again, so a Rails app with such a comparison blocks as it did, and a project whose routes are not read
at all can now block on one: of the 72 projects compared, dvwa and railsgoat newly block, each on a
credential compared with `==`. Comparisons with an empty string or `None` behind a Python `:`, with a
credential's owner, with an action named after a credential, or with an UPPER_CASE constant the source
assigns a string are no longer counted; these were six of 88 matches and none was a secret compared.

**After v1.13.0: a check inside a handler counts only before any work, and only against the caller
who fails it.** v1.13.0 credited a check that came after a branch doing work for anyone (CTFd's email
confirmation marks the account verified before its sign-in check), and a check pointing the wrong way
(`if current_user.is_authenticated: return redirect(...)`, which turns away signed-in users). Both are
now reported open. A route that passed on such a check can now block: move the check to the top of
the handler, or onto the route, or mark the finding reviewed if the route is meant to be public.

**After v1.13.0: a JavaScript destructuring is reading, not work.** `const { newPassword,
currentPassword } = request.body` ahead of a check made the check count as after work, so it was not
credited. A destructured name is now also read as the property it takes, and a name in a check is
followed through up to four assignments, so `const { email } = request.session.user` then
`findByEmail(email)` then `if (!user)` counts as the caller checked, as the one-line form did.
fastify/demo's `PUT /update-password` is credited again, for that reason. v1.13.0 credited it for
`newPassword === currentPassword`, which compares two of the caller's inputs, and no longer does. Of
3,748 routes on 72 projects, no other verdict moved.

**After v1.13.0: a Fastify `autohooks` file protects the routes it reaches, and only those.**
`@fastify/autoload` applies the hooks in a directory's `autohooks` file to that directory's routes, and
to its subdirectories' with `cascadeHooks`. Such a hook was read only by the project-wide rule, which
credited every route in the project when the hook's first 120 characters named authentication, and
nothing otherwise: fastify/demo protects its 12 API routes from `src/routes/api/autohooks.ts`, and all
were reported open. They now pass, its root page stays open, and a hook in an `autohooks` file no longer
credits routes outside its directory, so such a route can now block. Each rule was checked against
Fastify 5.12.7 and @fastify/autoload 6.5.1 on 29 routes in 16 apps; none counted as protected was reached. A
session read with optional chaining, `req.session?.user`, counts as the caller again, as in v1.13.0.

**After v1.13.0: a session value counts as the caller only when its key names the caller.**
`session.get("user_id")`, `session[:user_id]`, `"uid" in session` and `req.session.userId` still count.
A check of sign-in flow state held in the session no longer does: CTFd's OAuth callback compares
`session["nonce"]` with the `state` parameter, and that says nothing about who is calling. A key that
is not a literal (`session[KEY]`) no longer counts either. Ktor's typed `call.sessions.get<T>()` is
unchanged. A route that passed on such a check can now block.

**After v1.13.0: an HTTP client call is not a route.** In JavaScript and TypeScript,
`await api.post("/api/groups", {...})` was read as an Express route and reported open: 37 in
redash's Playwright helpers, 6 in the React RealWorld client, 1 in Gitea's end-to-end helpers. A call
whose value is waited for, or that passes only data after the path, is no longer a route. A project
blocked only by such calls can now pass, and a review of one now matches nothing and is reported as
doing nothing: delete it. No other route moved: not among 611 in Express, Fastify, Hono, juice-shop
and the MCP SDK's examples, nor among the 1,967 other calibration routes.

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
