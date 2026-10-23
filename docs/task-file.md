# The task file

The task file is the requirements the code was written to satisfy. Six checks are gated on what it
asks for — immutability, retention, secret rotation, tests, error distinction, and required
artifacts. Without a task file they report "not checked", which is accurate and much less useful.

## What goes in it

Prose, not configuration. It is the requirements as you would write them for a person, and the
checks read ordinary English — there are no keys, fields or front matter to fill in.

```text
Build and deploy a service that receives our Slack workspace's message events.

WHAT IT NEEDS TO DO
- Receive message events from Slack as they happen, and keep receiving them across a working week.
- Keep every message event received, so that a question raised weeks later can be settled.

REQUIREMENTS
- Once a message event has been recorded, its contents must stay exactly as received.
- Records are retained for three years.
- Both Slack tokens must be rotatable without redeploying the application.

HOW WE WILL JUDGE IT
- Automated tests that someone else can run, covering an event being acknowledged.
- Errors distinguished from faults: Slack refusing our token is not our service failing.

DEPLOYMENT
- AWS, single region. Terraform for all infrastructure. Kubernetes manifests. A Dockerfile.
```

Each gated check is looking for the shape of a requirement, not a topic:

| check | switched on by | stays off for |
| --- | --- | --- |
| immutability | "must not change once written", "an immutable audit log" | "store the events" |
| retention | "retained for three years", "keep every event for 90 days" | a period with no number |
| secret rotation | "the API key must be rotated every 90 days", "tokens must be rotatable" | "use an API key" |
| tests | "automated tests that someone else can run", "include unit tests" | "make it work" |
| error distinction | "a client error must not be reported as a 500" | "handle errors" |
| required artifacts | naming them: "Terraform", "Kubernetes manifests", "a Dockerfile" | "deploy it somehow" |

## Four rules for writing it

**State the requirement, don't gesture at the topic.** The retention check compares a configured
period against the one the task states, so it needs a number to compare against; "keep the records"
gives it nothing and the check stays off.

**Never write a requirement you don't have.** A fabricated one switches a check on and then reports
against a standard nobody asked for, which is worse than the check being off. The parsers are built
to resist it from their side too: "Keep the log short; rotate it every 7 days" once produced a
seven-day retention requirement, and the span a phrase may cross now stops at a semicolon so it no
longer does. That is the direction of the whole design — a check that stays quiet costs you a
finding, and a check that fires on a requirement nobody stated costs you working code.

**Put each requirement in one sentence.** The checks read a sentence at a time, so "The signing
secret is kept in Secrets Manager. It must be rotated every 90 days." does not switch rotation on:
"it" is in a different sentence from the secret. "The signing secret must be rotated every 90
days." does. A line indented under a list item continues that item, so hard-wrapping is safe; any
other line break ends a thought.

**Check which sentences were read.** Every run counts the task's sentences and how many switched a
check on — `task sentences : 18, 9 read by a check, 9 by none` for the webhook task — and `--json`
lists the unread ones with their line numbers, under `requirementsRead`. Most are requirements no
check could hold code to ("accept HTTP callbacks at a public endpoint"); one you expected a check to
read is a phrasing to fix.

If a check reports "not checked" and you expected it to run, the task text is where to look. The
four control repositories each keep one of these at `.github/gate-task.txt` if you want a smaller
worked example: they state tests and error distinction, and deliberately state nothing about
retention or immutability, because they store no records.

## Requirements the code's author cannot remove

The task file usually lives in the repository it describes, so whoever writes the code can edit the
requirement the code is checked against. An agent blocked by "tokens must be rotatable" could delete
the sentence and commit. Two things stop that from being quiet.

### At commit time

A commit that changes or deletes a tracked task file is blocked, and the code is checked against the
requirements as they were. The gate reads the version being committed, not the file on disk, so an
unstaged edit does not loosen it either. Adding a task file is not changing one, so a project's
first commit is unaffected.

To change a requirement on purpose, commit it on its own:

```bash
git commit --no-verify -- task.txt
```

### A baseline

A baseline holds requirements no project gets to opt out of. Pass it as `--baseline=<file>` on the
command line, or as the Action's `baseline` input. Its sentences are added to the task text, so they
switch on the same checks.

A baseline only does its job if it lives somewhere the code's author cannot edit. A baseline inside
the project is reported as such. In CI, that means a workflow the project cannot edit — see
[Action reference](action-reference.md#a-baseline-the-project-cannot-edit).

**Unread baseline sentences are flagged.** A baseline sentence that no check reads is printed with
`!!` above the verdict, in the CLI and the Action's log alike. It is a requirement the project is not
being held to, and whoever wrote the baseline is not the person reading the task file.

**Some sentences are covered by checks that always run.** A baseline may ask for something a check
already blocks on in every project:

| the sentence asks for | covered by |
| --- | --- |
| parameterised queries | `sast` |
| no hardcoded credentials | `scan_path` |
| authentication on every route | `authentication` |
| no high or critical CVEs | `check_dependencies` |

Such a sentence is listed as **covered** rather than unread — but only when that check ran and reads
every language in the project. In a project containing Swift, "use parameterized queries" is listed
as unread, with a note that `sast` reads no Swift; in one containing Rust, "all routes require
authentication" is, because `authentication` reads no Rust.

Covered means the check blocks on what the sentence asks, not that it is on the same topic.
"Passwords are hashed with argon2id" and "authorization enforces least privilege" stay unread.
