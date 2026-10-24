# What wolfproof checks, and what it does not

The README has the summary. This page has the full detail: what each check blocks on, what it
reports without blocking, what it covers, and the measured failure it exists because of.

The checks fall into two groups:

- **[What scanners miss](#what-scanners-miss)** — controls that are present and do not work. These
  defects live between files, or between the code and what it was asked to do, so a scanner reading
  one file for a known-bad pattern passes them.
- **[The scanner floor](#the-scanner-floor)** — injection, dependency CVEs, secrets,
  infrastructure policy, base images and the build. The checks you would expect, still necessary.

A check that could not run — a scanner missing, a control unreachable — makes the whole run exit 3,
never a pass. Code in a language nothing reads is named above the verdict.

## What scanners miss

These checks are narrow on purpose. A blocking check that fires on correct code gets switched off,
and then it protects nothing, so each one judges a specific failure shape and reports an answer it
cannot determine as an advisory, not a pass.

### Authentication

Validator: `authentication`.

**Blocks on:**

- a route anyone can call, judged route by route rather than for the project as a whole
- a credential read from the environment and compared with `==` or `!=`, so that when the variable
  is unset the check is vacuous and the endpoint opens (`None != None` is false; so is
  `undefined !== undefined`)
- a credential or signature compared with `==` instead of in constant time
- a signature header that the route accepts and nothing in the project verifies
- a dependency that looks like authentication and isn't — `Depends(get_db)` on every route
  authenticates none of them

**Reports without blocking:** routes exempt by name — probes such as `/health` and credential-issuing
endpoints such as `/login` — each one listed.

**Covers:** Python (FastAPI, Flask), JavaScript/TypeScript (Express, Fastify, NestJS), Go
(`net/http`, chi, gin, echo, gorilla), Java (Spring), Ruby (Sinatra, Rails), C# (ASP.NET Core
controllers and minimal APIs), PHP (Laravel, Symfony), Kotlin (Spring, Ktor).

In C#, a route counts as protected by `[Authorize]` in any form on the action or anywhere in its
controller's class chain, by an attribute class of the project's that derives from
`AuthorizeAttribute` or turns the caller away with 401 or 403, by `RequireAuthorization()` on the
endpoint, on its group, or on the call of the method that mapped it, by `MapControllers().RequireAuthorization()`
or a global `AuthorizeFilter` (controllers only), and by a `FallbackPolicy` that requires an
authenticated user. `[AllowAnonymous]` or `.AllowAnonymous()` overrides all of them, as it does in
ASP.NET, and the finding marks such a route "declared anonymous". `UseAuthorization()` and a
`DefaultPolicy` protect nothing on their own. Not read: authorization written inside the handler,
Razor Pages, gRPC services and SignalR hubs.

In PHP, a Laravel route counts as protected by middleware on the route, on a group around it, on the
group that includes its route file, or in its controller's constructor. A middleware name is resolved
through the project's aliases and groups (the HTTP Kernel or `bootstrap/app.php`) and counts when it
is Laravel's own (`auth`, `auth.basic`, `can`, `verified`, `signed`) or a class of the project's
that answers 401 or 403, throws an authentication or authorization exception, or redirects to the
login page; `withoutMiddleware` takes one away. A Symfony route counts as protected by
`#[IsGranted]` on the action or controller, `$this->denyAccessUnlessGranted()` in the action, or an
`access_control` rule in `security.yaml`. Not read: plain PHP pages served without a router (DVWA),
Slim, and Symfony's YAML and docblock routing.

In Kotlin, a Spring route counts as protected by `@PreAuthorize`, `@Secured` or `@RolesAllowed` on the
handler or its class, by an annotation of the project's that an `@Aspect` enforces with 401 or 403
(unless the use says `mandatory = false`), or by the security configuration's path rules, taken in
order as Spring takes them. A Ktor route counts as protected when any `authenticate { }` around it is
required, which is Ktor's own rule: `authenticate(optional = true)` nested inside a required block
does not open it. Routes in a `fun Route.x()` are judged at every call. Not read: hand-registered
interceptors and filters, Spring's functional router, and Ktor's `method(HttpMethod.X) { handle { } }`.

**Why it exists:** "no endpoint authenticates" appeared in five of five preserved reviews and was
still unfixed six runs later. Per route, because one real run authenticated POST and left GET open,
which any project-level "is there auth here" check passes. The unset-credential rule came from a
webhook receiver that authenticated both routes, passed the earlier version of this check, and
served every stored callback to an unauthenticated request.

### Code against its own deployment

Validators: `manifest_contract`, `k8s_manifest`, `iam_contract`.

**Blocks on:**

- an environment variable the code requires — read with no default — that no Kubernetes manifest
  sets
- `${...}` interpolation in a manifest, which Kubernetes never expands and applies as literal text
- a container field such as `resources` placed on the pod spec, which the API server rejects
- an application that serves a health endpoint from containers that declare no probe
- an IRSA role that the annotated ServiceAccount cannot assume; an IRSA annotation that is not a
  role ARN; a trust policy that names a ServiceAccount that does not exist; an annotation naming a
  role the project does not define
- an attached AWS managed policy that does not exist, which `terraform plan` cannot see because it
  does not resolve managed-policy ARNs — the plan is clean and `apply` fails

**Reports without blocking:** a manifest that pulls in a whole ConfigMap or Secret with `envFrom`,
whose keys cannot be checked; a managed-policy name this check does not recognise and cannot show is
a near miss for a real one.

**Covers:** Kubernetes YAML and Terraform on AWS, against the application source beside them.

**Why it exists:** each artifact is correct on its own terms, and the defect exists only in the gap.
A webhook receiver's Deployment set four variables and not the two API keys its code compared
callers against, so applying its manifests as written produced an open endpoint. Another shipped
`arn:aws:iam::${var.account_id}:role/...` as an IRSA annotation, so the role binding could never
resolve. Both plans were clean.

### Workload identity

Control: identity-guard.

**Blocks on:** a workload that authenticates with something it holds — a password, a static cloud
key, a shared token — rather than with an identity, wherever the credential is stored. A password
fetched from a secret manager is still a password.

**Reports without blocking:** heuristic findings.

**Covers:** application code, Kubernetes manifests and Dockerfiles.

**Why it exists:** a secret scanner asks whether a credential-shaped string is present. This asks
whether the workload has an identity to authenticate with, so a file with no credential in it can
still fail — and a connection string a secret scanner rightly ignores as a placeholder is a finding
here, because it is password authentication whatever the value.

### Task requirements

Each of these runs only when the task or a [baseline](task-file.md#a-baseline) states the
requirement. Without it, the check reports "not checked". See [The task file](task-file.md) for the
phrasings that switch each one on.

| requirement | validator | blocks on |
|---|---|---|
| immutability | `immutability` | an audit store whose records can be altered; when the task demands immutability, an audit store that cannot be found |
| retention | `retention` | something configured to delete records sooner than the stated period; a store holding the records that has no deletion protection, so one `terraform destroy` ends the period |
| secret rotation | `secret_rotation` | a secret read once and cached for the life of the process |
| tests | `tests`, `code_quality` | a suite that fails when run; no tests at all; test files that import nothing from the project; `mock.patch` targets that do not exist |
| error distinction | `sast`, `code_quality` | a broad `except Exception` that turns the handler's own 400 into a 500 |
| required artifacts | `artifact_presence` | a deliverable the task names — Terraform, Kubernetes manifests, a Dockerfile — that the project does not contain, judged by content rather than filename |

**Reports without blocking:** a retention period the task states and nothing in the project
describes, or an expiry whose horizon cannot be read; a backup window offered as record retention;
an immutability answer that cannot be determined when the task does not demand it.

A test suite that cannot be started on this machine — no toolchain, dependencies not installed,
killed at the time limit — is neither: the run exits 3. So is a run that exits 0 and names no test:
`dotnet test` on a solution whose packages were never restored builds nothing, tests nothing and
exits 0, and that is not a pass.

The `tests` check handles every suite it finds, each with its own verdict and the full time limit:

| suite | run with |
|---|---|
| JavaScript, with a `package.json` | the runner it declares, or `node --test` |
| JavaScript, without one | `node --test` |
| Python | `python3 -m pytest` |
| Go, with a `go.mod` | `go test -v ./...` |
| Java, Kotlin | `mvn -B -o test` with a `pom.xml`, or `gradle --offline test` with a `build.gradle` |
| C# | `dotnet test --no-restore`, on the solution or each test project |
| Rust | `cargo test --offline --no-fail-fast` |
| PHP | `vendor/bin/phpunit` or `vendor/bin/pest`, whichever `composer.json` declares |
| Ruby | `bundle exec rspec` for `*_spec.rb`, and Minitest for `*_test.rb`, each file loaded directly |

Every runner works offline, against dependencies the project's CI installed: the check never
downloads them, because a Maven plugin, a crate's `build.rs` and an MSBuild target all run code at
build time. Nor does it run a command the project authored — not `./gradlew`, which downloads the
Gradle the project names, and not `npm test`, `rake` or `bin/rails`. A runner the project declares
and has not installed (`jest` in `package.json`, PHPUnit in `composer.json`) blocks: nobody can run
the tests as delivered. Tests with nothing that says how to run them — Java with no `pom.xml` or
`build.gradle`, a `composer.json` or `package.json` that declares no runner, Rust with no
`Cargo.toml`, Go with no `go.mod` — are exit 3 too: the fix is in the project, but no test ran, and a
suite that did not run does not pass. In a Rails or
Laravel app with front-end tooling, the Ruby or PHP suite runs; it is not hidden behind the
`package.json`.

**Covers:** running tests under `node --test`, jest, vitest, pytest, `go test`, Maven, Gradle,
`dotnet test`, `cargo test`, PHPUnit, Pest, RSpec and Minitest. Finding test
files, and whether they assert something, in JavaScript/TypeScript, Python, Go, Ruby, Java, Kotlin,
C#, Rust and PHP — a `test/`, `tests/`, `spec/` or `__tests__` directory (so Maven's
`src/test/java` and .NET's `MyApp.Tests/`), `*Test.java`, `*Test.kt`, `*Spec.kt`, `*Tests.cs`,
`*Test.php`, or a Rust file with `#[test]`. Whether a test imports the project's own code, in
JavaScript/TypeScript, Python and Ruby; a test that imports only other test files does not count.
C and C++ test files are not recognised. Error distinction in Python. Immutability judges only a
store that names itself an audit log.

**Why it exists:** these requirements were stated in the task and missed in run after run.
Across nineteen runs of an "immutable audit log" task, not one deliverable implemented an
immutability control before review; the model reasoned in its own comments that having no delete
endpoint *was* the control. Retention had zero coverage across about sixteen deliverables, and the
one that addressed it offered an RDS backup window, which is not how long a record survives. A
signing secret memoised from Secrets Manager meant that after rotation the provider's real
callbacks got 401 and the retired key got 200. A deliverable that reported "comprehensive test
coverage" failed three of twelve tests when its toolchain was installed — and those three were
exactly the acceptance criteria.

### Evidence and process

Validators: `artifact_presence`, `uncommitted_work`, and the commit gate.

**Blocks on:**

- a file that exists and is empty — a manifest, a Dockerfile, a `.tf` file — which every check
  reading it would otherwise pass
- work that is not committed
- a commit that changes or deletes a tracked task file

**Why it exists:** told to fix findings in its Kubernetes manifests, a model wrote all five back as
empty files; three manifest-aware checks went quiet at once, because they had nothing left to read.
Work never committed was never seen by whatever runs at commit time. And a task file inside the
repository is a requirement its author can delete.

## The scanner floor

### Injection

Validator: `sast`.

**Blocks on:** request data reaching a shell, a SQL statement, an evaluator, the host of an outbound
request (SSRF), a file path (path traversal) or a C format string; any use of `gets()`.

**Blocks through a project helper** too: request data passed to a function of the project's that
injects it, when the call can only reach that function (see "What it does not check" below).

**Reports without blocking:** a query or command built from a value of unknown origin; a non-literal
C format string; an XML parser that resolves external entities (XXE); exception text sent back to
the caller.

**Covers:** Python, JavaScript/TypeScript, Go, Java, Ruby, C#, Rust, C, C++, PHP, Kotlin — Flask,
Django, FastAPI, Express, `net/http`, gin, Spring, servlets, Rails, Sinatra, ASP.NET Core, axum,
actix-web, Laravel, Symfony, plain PHP's superglobals, Ktor; in C, CGI and sockets; in C++,
cpp-httplib, Crow, Drogon.

`sast` runs Semgrep with this project's own rules. Only the rules that trace data from an HTTP
request to the dangerous call block. A URL whose scheme and host are fixed in the code, with request
data only in the path, is not SSRF and is not reported. Neither `.semgrepignore` nor an inline
`# nosemgrep` hides code from it.

**How it is calibrated.** The [calibration corpus](development.md#the-calibration-corpus) holds the
rules to known answers at pinned commits:

- Across sixteen real applications — about 26,700 files, in every language the rules cover except
  C++ — they block twice, both on Jellyfin's admin endpoint that writes a file where the request
  says, which is what the rule describes.
- They find the documented vulnerabilities in the deliberately vulnerable WebGoat (3), RailsGoat
  (6), Juice Shop (11), PyGoat (8) and dvcsharp-api (2).

### Dependencies

Control: dep-audit (`osv-scanner`).

**Blocks on:** high or critical CVEs; a manifest that declares dependencies with no lockfile the
scanner can read.

**Reports without blocking:** CVEs in an unlocked `requirements.txt`, `go.mod` or `pom.xml`, which
the scanner resolves to minimum-satisfying versions no real install produces.

**Covers:** npm, PyPI, Go, Maven, Cargo, RubyGems, Packagist and the rest of
[OSV](https://osv.dev).

### Secrets

Control: secret-guard (`gitleaks`).

**Blocks on:** credentials hardcoded in any file; a credential-named value assembled from literals —
split, joined, reversed, base64- or hex-encoded.

**Covers:** every file; assembly detection in Python, JavaScript/TypeScript, Go, Java, Ruby, C#,
Rust, PHP, Kotlin.

### Infrastructure

Control: terraform-guard (`terraform`, `checkov`).

**Blocks on:** Terraform plan and policy violations on AWS — a security group or EKS API open to
`0.0.0.0/0`, for instance. A plan that cannot authenticate is reported as unscanned, never clean.

**Reports without blocking:** checkov's findings on Terraform for any cloud, CloudFormation, ARM and
Bicep.

**Covers:** blocking: Terraform on AWS; advisory: also CloudFormation, ARM, Bicep.

### Containers

Validator: `dockerfile`.

**Blocks on:** a base image past end of life, in any build stage.

**Reports without blocking:** checkov's Dockerfile rules — no `USER`, no `HEALTHCHECK`.

**Covers:** official `node`, `python`, `golang`, `ruby`, `php`, `debian`, `ubuntu`, `alpine` and
`eclipse-temurin` images, with dates from [endoflife.date](https://endoflife.date). The OS named in a
language image's tag (`-buster`, `-alpine3.18`) is judged too.

**Why it exists:** `FROM node:14` passed until it did, because the only check confirmed the file was
there.

### Build

Validator: `build_check`.

**Blocks on:** syntax errors, undefined names, a Go build that fails.

**Covers:** Python, JavaScript, Go.

## Where the checks live

The checks live in four control servers, each in its own repository and each installed as a
dependency:

| control | checks | backed by |
|---|---|---|
| [terraform-guard](https://github.com/tjwitko/terraform-guard-mcp) | Terraform plan, policy, and source scanning | `terraform`, `checkov` |
| [dep-audit](https://github.com/tjwitko/dep-audit-mcp) | dependency vulnerabilities, direct vs transitive | `osv-scanner` |
| [secret-guard](https://github.com/tjwitko/secret-guard-mcp) | hardcoded credentials | `gitleaks` |
| [identity-guard](https://github.com/tjwitko/identity-guard-mcp) | workload identity posture | — |

Plus in-process validators: `build_check`, `tests`, `immutability`, `authentication`,
`manifest_contract`, `k8s_manifest`, `secret_rotation`, `retention`, `iam_contract`,
`artifact_presence`, `dockerfile`, `sast`, `code_quality`, `artifact_census`, `uncommitted_work`.

## What it does not check

Listed so that a clean verdict is read for what it is.

- **Languages outside the coverage above.** Swift, Scala and the rest get the project-wide scans —
  secrets, dependencies, infrastructure — and nothing that reads the code itself. The run says so
  above the verdict. Rust and C/C++ get the injection check, but there is no authentication check
  for them. PHP pages served directly, without Laravel or Symfony routing, have no routes to read,
  so the authentication check reports that it checked nothing.
- **C and C++ tests.** C and C++ test files are not recognised at all, and nothing reads C or C++ for
  whether tests exist, so a task asking for tests gets only an advisory.
- **Injection through a call that cannot be pinned to one function.** Semgrep's open-source analysis
  stays inside one function, so the project's own helpers are summarised first: a function whose
  parameter reaches a shell, SQL, an evaluator or a file path, after the same sanitizers. Request data
  passed to such a helper blocks when the call can only mean that helper — called bare or through
  self/this in the file that defines it, called through its class or module, or called anywhere when
  the project defines the name once — and up to three calls deep, every link held to the same test.
  A call through an object whose type is not known here, a name defined more than once, and SSRF
  through any helper (whether the caller fixed the host cannot be seen across the call) are
  advisories. Data that only reaches a helper through a call on an object is not followed.
- **Other classes of injection.** Shell, SQL, evaluators, SSRF and path traversal are covered, and
  an XML parser configured to resolve external entities is an advisory. Cross-site scripting is not:
  templates escape by default, so what is worth checking is the escape hatches (`|safe`, `Markup()`,
  `dangerouslySetInnerHTML`, `html_safe`), and that is not written yet. Neither is server-side
  template injection, LDAP injection, open redirect or insecure deserialization.
- **Memory safety in C and C++.** Beyond `gets()`, buffer overflows, use-after-free and integer
  overflow are not checked: the patterns that find them flag most C code, and a check that blocks most
  projects gets switched off. A sanitiser build (`-fsanitize=address`) and a fuzzer find them better.
- **Proof that the Go, Rust, C and C++ rules find injection in real code.** They are tested on
  annotated samples and on real projects with none, which shows they do not over-fire; no
  deliberately vulnerable application in those languages is in the calibration corpus, so nothing
  shows they catch a real one. C++ has no real application in it at all.
- **Request data in a C buffer, used in another function.** Free Semgrep does not follow taint into a
  buffer, so a write into one is reported only when the same function passes it to the dangerous call.
- **Rocket, Warp and other Rust frameworks**, and ASP.NET WebForms. Their request types are not yet
  named as sources.
- **Authorisation.** `authentication` checks that a route requires a caller identity, not what that
  caller may then do.
- **The built image.** A Dockerfile's base image is judged; the packages inside a built image are not
  scanned. That needs a build or a pull, so it is a job for a CI step with Trivy or Grype.
- **Secrets assembled at run time.** gitleaks reads literals, including credentials that only look
  random, and a credential-named value assembled from literals — split, joined, reversed, base64- or
  hex-encoded — is caught too. A key built by a loop, fetched from somewhere unsafe, or held under a
  name that does not say what it is, is not seen.
- **Blocking infrastructure policy beyond Terraform on AWS and Kubernetes.** Terraform for Azure and
  GCP, CloudFormation, ARM and Bicep get checkov's findings as advisories; none of them can block.
  Pulumi programs are not read as infrastructure at all.
- **Requirements nobody stated.** The task-gated checks run only when the task or a baseline states
  the requirement.
- **A commit made with `--no-verify`.** The hook is a convenience. CI with the gate as a required check
  is the enforcement point.
