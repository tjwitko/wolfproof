// What each advisory the gate can emit means, for factory mode.
//
// In the default mode an advisory is a note for a reader. In factory mode -- a pipeline where agents
// write the change and no person reviews it -- there is no reader, so every advisory has to be one of
// four things, decided here rather than by whoever happens to be looking:
//
//   not-checked    something the project needs checked was not, and the change can make it
//                  checkable: "no HTTP routes were identified" in a service, a retention period the
//                  task states and nothing here describes. The silent-pass pattern in an advisory's
//                  clothes. Blocks.
//   could-not-run  a scanner or the environment kept a check from running: checkov killed, a plan
//                  that could not authenticate. Exit 3, like any check that could not run -- the fix
//                  belongs to whoever owns the pipeline, not to the change.
//   finding        a real observation at lower confidence than a blocking one: a query built from a
//                  value of unknown origin, a heuristic workload-identity hit. Counted, and blocked
//                  or dropped by the pipeline's policy file. Dropped by default, because the
//                  calibration corpus shows what blocking them would cost: Gitea, a clean application,
//                  draws 100 Go SQL advisories.
//   info           a fact that needs no decision: tests ran and passed, there are no Kubernetes
//                  manifests to read, the task states no retention period. Never blocks.
//
// An advisory that matches nothing here is UNCLASSIFIED and blocks: factory mode cannot tell whether
// it means nothing was checked, and guessing "fine" is the failure this whole project is built
// against. So a new message with no class is caught the first time factory mode meets it, not
// waved through. lib/factory.test.mjs holds a real example of every class here, and fails on a
// class without one or an example that lands in a different class.
//
// Matched on the text because the advisories are text everywhere else -- in the report, in the
// Action's log, in the corpus. Each pattern anchors on the message's own prefix and a phrase that
// names its meaning, so a reworded message falls through to UNCLASSIFIED rather than into the wrong
// class.

export const NOT_CHECKED = "not-checked";
export const COULD_NOT_RUN = "could-not-run";
export const FINDING = "finding";
export const INFO = "info";

/** What each class does in factory mode when the policy file does not say otherwise. */
export const DEFAULT_ACTION = { [NOT_CHECKED]: "block", [COULD_NOT_RUN]: "incomplete", [FINDING]: "drop", [INFO]: "drop" };

/**
 * Ordered: the first match wins. `class` is a class name, or a function of the factory context for
 * the few messages whose meaning depends on the project (see auth-no-routes).
 */
export const ADVISORY_CLASSES = [
  // could-not-run
  { id: "check-crashed", class: COULD_NOT_RUN, re: /: the check itself crashed and did not run/ },
  { id: "terraform-plan-unauthenticated", class: COULD_NOT_RUN, re: /^terraform_plan\([^)]*\): the plan could not authenticate/ },
  { id: "checkov-unavailable", class: COULD_NOT_RUN, re: /^checkov \([^)]*\): (?:did NOT run to completion|produced no output|output could not be parsed)/ },
  { id: "iac-checkov-unavailable", class: COULD_NOT_RUN, re: /^iac templates: checkov(?: is not installed| did NOT run to completion|'s output could not be parsed)/ },
  { id: "dockerfile-checkov-unavailable", class: COULD_NOT_RUN, re: /^dockerfile: checkov (?:is not installed|did NOT run to completion)/ },
  { id: "workload-identity-unparseable", class: COULD_NOT_RUN, re: /^workload identity: check_auth_posture returned output that could not be parsed/ },
  // A suite that could not start. Environmental when the same reason is in couldNotRun -- the tests
  // check reports a missing toolchain there -- and otherwise a fact about the project: the task
  // asked for tests and there is nothing that can run them.
  {
    id: "tests-not-executed",
    re: /^tests: NOT EXECUTED — /,
    class: (text, ctx) =>
      (ctx.couldNotRun || []).some((c) => c.startsWith("tests: ") && text.includes(c.slice("tests: ".length))) ? COULD_NOT_RUN : NOT_CHECKED,
  },

  // not-checked
  // Printed for every project with no routes, including a library that serves nothing. That one is a
  // fact; the same sentence about a project that starts an HTTP server is a service whose endpoints
  // no check could find, which is the escape.
  {
    id: "auth-no-routes",
    re: /^authentication: no HTTP routes were identified/,
    class: (text, ctx) => (ctx.servesHttp ? NOT_CHECKED : INFO),
  },
  { id: "auth-only-probes", class: NOT_CHECKED, re: /^authentication: the only routes identified are exempt by name, so nothing was checked/ },
  { id: "retention-not-checked", class: NOT_CHECKED, re: /^retention: NOT CHECKED — / },
  { id: "retention-undetermined", class: NOT_CHECKED, re: /^retention: .* could not be established here/ },
  { id: "rotation-unverifiable", class: NOT_CHECKED, re: /^secret rotation: the task says a secret rotates, but nothing here reads a secret from a managed store/ },
  { id: "dockerfile-unresolved-base", class: NOT_CHECKED, re: /^dockerfile: \d+ base image\(s\) named through a variable with no default/ },
  { id: "manifest-contract-opaque", class: NOT_CHECKED, re: /^manifest contract: envFrom pulls .* so the contract cannot be checked here/ },
  { id: "sast-unparsed", class: NOT_CHECKED, re: /^sast: \d+ file\(s\) could not be fully parsed/ },

  // finding
  { id: "deps-unlocked", class: FINDING, re: /^check_dependencies: \d+ finding\(s\) at or above high severity — NOT BLOCKING/ },
  // One id per sast category, so a policy can block SQL built from strings and drop the rest.
  { id: "sast", class: FINDING, re: /^sast: .*\(([a-z0-9-]+), not blocking/, sub: (m) => m[1] },
  { id: "checkov", class: FINDING, re: /^checkov \([^)]*\): \d+ finding\(s\) in your own configuration/ },
  { id: "iac-checkov", class: FINDING, re: /^iac templates \([^)]*\): checkov reports/ },
  { id: "dockerfile-checkov", class: FINDING, re: /^dockerfile: checkov reports \d+ finding/ },
  { id: "workload-identity-heuristic", class: FINDING, re: /^workload identity: \d+ heuristic finding/ },
  { id: "iam-unverifiable-policy", class: FINDING, re: /^iam: \d+ attached AWS managed policy ARN/ },
  { id: "iam-irsa-unmatched", class: FINDING, re: /^iam: \d+ IRSA annotation/ },
  { id: "resource-census", class: FINDING, re: /^resource census \(/ },
  { id: "retention-backup-only", class: FINDING, re: /^retention: .* is set, and it is not record retention/ },
  { id: "retention-shorter", class: FINDING, re: /^retention: .* which is shorter than the .* the task requires/ },
  { id: "retention-governance-lock", class: FINDING, re: /^retention: Object Lock on .* is in / },
  { id: "retention-kms-deletable", class: FINDING, re: /^retention: KMS key\(s\) / },
  { id: "code-quality-detached-tests", class: FINDING, re: /^code quality: \d+ of \d+ test file\(s\) import/ },
  { id: "rotation-cache", class: FINDING, re: /^secret rotation: a secret is fetched once and cached/ },

  // info
  { id: "auth-probes-listed", class: INFO, re: /^authentication: \d+ route\(s\) exempt by name, not checked/ },
  { id: "auth-no-source", class: INFO, re: /^authentication: not checked — / },
  // Only ever an advisory when the task does not require immutability; when it does, the same
  // undetermined answer is a blocking finding.
  { id: "immutability-not-required", class: INFO, re: /^immutability: / },
  { id: "k8s-none", class: INFO, re: /^kubernetes manifests: not checked — / },
  { id: "manifest-contract-no-workload", class: INFO, re: /^manifest contract: the code requires \d+ environment variable\(s\) and no Kubernetes workload/ },
  { id: "retention-not-required", class: INFO, re: /^retention: not checked — the task states no retention period/ },
  { id: "retention-satisfied", class: INFO, re: /^retention: (?:.* holds records for at least the|.* each at or beyond the|nothing here deletes the records)/ },
  { id: "rotation-not-checked", class: INFO, re: /^secret rotation: not checked — / },
  { id: "code-quality-info", class: INFO, re: /^code quality: (?:no tests found\. The task did not ask|\d+ test file\(s\) found and read|not checked — )/ },
  { id: "artifact-presence-not-checked", class: INFO, re: /^artifact presence: not checked — / },
  { id: "tests-ran", class: INFO, re: /^tests: ran under / },
  // Opt-outs are judged by factory mode itself, against the base ref; this sentence only lists them.
  { id: "workload-identity-allowances", class: INFO, re: /^workload identity: \d+ finding\(s\) were opted out/ },
  { id: "workload-identity-refused-allowance", class: INFO, re: /^workload identity: an opt-out in / },
  { id: "task-file-unstaged", class: INFO, re: /^task file: .* has changes that are not part of this commit/ },
  { id: "baseline-inside-project", class: INFO, re: /^baseline: .* is inside the project/ },
  { id: "config-note", class: INFO, re: /^config: / },
  { id: "settings", class: INFO, re: /^settings: / },
];

export const UNCLASSIFIED = "unclassified";

/**
 * { id, class, unclassified? } for one advisory. `ctx` carries what a few classes depend on:
 * `servesHttp` and `couldNotRun`.
 */
export function classifyAdvisory(text, ctx = {}) {
  const s = String(text);
  for (const c of ADVISORY_CLASSES) {
    const m = c.re.exec(s);
    if (!m) continue;
    const cls = typeof c.class === "function" ? c.class(s, ctx) : c.class;
    return { id: c.sub ? `${c.id}:${c.sub(m)}` : c.id, class: cls };
  }
  return { id: UNCLASSIFIED, class: NOT_CHECKED, unclassified: true };
}

/**
 * The action factory mode takes for a classified advisory: "block", "drop" or "incomplete".
 * The policy maps ids, id families ("sast" for every "sast:<category>") or class names to an action,
 * most specific first. An unclassified advisory blocks whatever the policy says about its class: the
 * policy's author wrote it about messages they knew of.
 */
export function actionFor(classified, policy = {}) {
  if (classified.unclassified) return "block";
  const rules = (policy && policy.advisories) || {};
  const family = classified.id.split(":")[0];
  return rules[classified.id] || rules[family] || rules[classified.class] || DEFAULT_ACTION[classified.class];
}

export const ACTIONS = new Set(["block", "drop", "incomplete"]);
