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
//
// Some messages open with a label the gate did not choose, before the words a pattern reads:
// "checkov (infra): ...", "terraform_plan(infra): ..." and "resource census (infra): ..." name a
// Terraform root, which is a directory name; "iac templates (CloudFormation): ..." names a kind of
// template as checkov's report gives it; "trivy (registry/app:1): ..." names the image the pipeline
// asked for. A pattern cannot find where such a label ends, and both ways of getting it wrong were
// real. Read up to the first ")", a root called "net (prod)" made every line about it unclassified,
// a clean scan and a scanner that could not run alike (exit 1 for both). And a root called
// "a): 0 finding(s) in your own configuration (b" made "did NOT run to completion" and "3
// finding(s)" in it read as the "found nothing" line, which is information and is dropped: a change
// picks its directory names, so a change could turn a checkov that did not run into nothing. Reading
// up to the last ")" instead mends the first and not the second. So the label is not read from the
// text at all. The gate says which labels it wrote (ctx.terraformRoots, ctx.iacTemplateLabels,
// ctx.trivyImages), and classifyAdvisory takes the label off by name before any pattern sees the
// line: see LABELLED.

export const NOT_CHECKED = "not-checked";
export const COULD_NOT_RUN = "could-not-run";
export const FINDING = "finding";
export const INFO = "info";

/** What each class does in factory mode when the policy file does not say otherwise. */
export const DEFAULT_ACTION = { [NOT_CHECKED]: "block", [COULD_NOT_RUN]: "incomplete", [FINDING]: "drop", [INFO]: "drop" };

/** The line the Terraform check writes when no checkov is on PATH (lib/gate-core.mjs, checkovAdvisory). */
export const CHECKOV_ABSENT_RE = /^checkov: not installed, so its rules did not run over the Terraform here \(/;

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
  { id: "dockerfile-checkov-unavailable", class: COULD_NOT_RUN, re: /^dockerfile: checkov(?: is not installed| did NOT run to completion|'s output could not be parsed)/ },
  { id: "workload-identity-unparseable", class: COULD_NOT_RUN, re: /^workload identity: check_auth_posture returned output that could not be parsed/ },
  // The image scan (agent/trivy.mjs). An OS Trivy has no advisories for reads like a clean one, and a
  // warning it carried on past may mean part of the image went unread.
  { id: "trivy-os-unrecognised", class: COULD_NOT_RUN, re: /^trivy \([^)]*\): Trivy does not recognise .* and found no vulnerabilities/ },
  { id: "trivy-os-unscanned", class: COULD_NOT_RUN, re: /^trivy \([^)]*\): Trivy detected .* and did not scan its packages/ },
  { id: "trivy-warned", class: COULD_NOT_RUN, re: /^trivy \([^)]*\): Trivy reported a problem and carried on/ },
  // The source scan (agent/codeql.mjs): an error CodeQL reported and ran past, a failed autobuild
  // step among them, may mean part of the source was not read.
  { id: "codeql-warned", class: COULD_NOT_RUN, re: /^codeql \([^)]*\): CodeQL reported a problem and carried on/ },
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
  // Rails routes exist and nothing judged them: a service, so never only information.
  { id: "auth-rails-unread", class: NOT_CHECKED, re: /^authentication: Rails routing is not read/ },
  { id: "auth-only-probes", class: NOT_CHECKED, re: /^authentication: the only routes identified are exempt by name, so nothing was checked/ },
  { id: "retention-not-checked", class: NOT_CHECKED, re: /^retention: NOT CHECKED — / },
  { id: "retention-undetermined", class: NOT_CHECKED, re: /^retention: .* could not be established here/ },
  { id: "rotation-unverifiable", class: NOT_CHECKED, re: /^secret rotation: the task says a secret rotates, but nothing here reads a secret from a managed store/ },
  { id: "dockerfile-unresolved-base", class: NOT_CHECKED, re: /^dockerfile: \d+ base image\(s\) named through a variable with no default/ },
  { id: "manifest-contract-opaque", class: NOT_CHECKED, re: /^manifest contract: envFrom pulls .* so the contract cannot be checked here/ },
  // A YAML file one of the three manifest readers did not read (agent/yaml-docs.mjs): a Helm or Go
  // template, or a file that does not parse. Never information. Whatever the file holds was judged
  // by nothing, and the change can make it checkable: render the template, repair the file. Five
  // messages, one id each, so none of them can land in the class of the sentence it extends:
  // "no Kubernetes manifests read; 1 YAML file(s) were not read" began with the words k8s-none
  // matched, and a `${TAG}` image under a comment holding `{{` was dropped as information.
  { id: "k8s-yaml-unread", class: NOT_CHECKED, re: /^kubernetes manifests: \d+ YAML file\(s\) were not read — / },
  { id: "k8s-none-read", class: NOT_CHECKED, re: /^kubernetes manifests: not checked — no Kubernetes manifests read; \d+ YAML file\(s\) were not read — / },
  { id: "iam-yaml-unread", class: NOT_CHECKED, re: /^iam: \d+ YAML file\(s\) were not read — / },
  { id: "manifest-contract-unread", class: NOT_CHECKED, re: /^manifest contract: \d+ variable\(s\) the code requires are set by no manifest that was read / },
  { id: "manifest-contract-no-workload-read", class: NOT_CHECKED, re: /^manifest contract: the code requires \d+ environment variable\(s\) and no Kubernetes workload was found to supply them; \d+ YAML file\(s\) were not read / },
  { id: "sast-unparsed", class: NOT_CHECKED, re: /^sast: \d+ file\(s\) could not be fully parsed/ },
  { id: "codeql-unextracted", class: NOT_CHECKED, re: /^codeql \([^)]*\): \d+ file\(s\) could not be fully extracted/ },
  // Past end of service life, the distribution publishes no more advisories; a supported base image
  // makes the image checkable again.
  { id: "trivy-eosl", class: NOT_CHECKED, re: /^trivy \([^)]*\): .* is past its end of service life/ },
  // A package.json the snapshot holds as having no lockfile: its transitive dependencies are still
  // not checked, and committing the lockfile makes them checkable (agent/lockless-npm.mjs).
  { id: "deps-unlocked-known", class: NOT_CHECKED, re: /^check_dependencies: \d+ package\.json file\(s\) with no lockfile are known from the snapshot/ },

  // finding
  { id: "deps-unlocked", class: FINDING, re: /^check_dependencies: \d+ finding\(s\) at or above high severity — NOT BLOCKING/ },
  // One id per sast category, so a policy can block SQL built from strings and drop the rest.
  { id: "sast", class: FINDING, re: /^sast: .*\(([a-z0-9-]+), not blocking/, sub: (m) => m[1] },
  // One id per CodeQL query, as sast has one per category.
  { id: "codeql", class: FINDING, re: /^codeql \([^)]*\): .*\(([\w./-]+), (?:warning|note|none), not blocking\)/, sub: (m) => m[1] },
  // checkov's coverage summaries, emitted when it found nothing too. "0 finding(s)" is information:
  // classed as a finding, a policy blocking checkov findings blocked every project where checkov
  // found none. Before the finding entries, because the first match wins.
  // No checkov on a Terraform project, where it is optional: said once, for all its Terraform roots,
  // and information. Its own id, so a pipeline that requires checkov can make it "incomplete" in its
  // policy; blocking checkov's findings (the `checkov` id) does not reach it.
  { id: "checkov-absent", class: INFO, re: CHECKOV_ABSENT_RE },
  { id: "checkov-summary", class: INFO, re: /^checkov \([^)]*\): 0 finding\(s\) in your own configuration/ },
  { id: "iac-checkov-summary", class: INFO, re: /^iac templates \([^)]*\): checkov reports 0 finding\(s\)/ },
  { id: "checkov", class: FINDING, re: /^checkov \([^)]*\): \d+ finding\(s\) in your own configuration/ },
  { id: "iac-checkov", class: FINDING, re: /^iac templates \([^)]*\): checkov reports/ },
  { id: "trivy-not-blocking", class: FINDING, re: /^trivy \([^)]*\): \d+ more vulnerabilit(?:y does|ies do) not block/ },
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
  { id: "auth-in-handler-listed", class: INFO, re: /^authentication: \d+ route\(s\) count as protected by a check inside the handler/ },
  { id: "auth-no-source", class: INFO, re: /^authentication: not checked — / },
  // Only ever an advisory when the task does not require immutability; when it does, the same
  // undetermined answer is a blocking finding.
  { id: "immutability-not-required", class: INFO, re: /^immutability: / },
  // Each matches its whole sentence and nothing after it. The same words with "N YAML file(s) were
  // not read" appended are k8s-none-read and manifest-contract-no-workload-read, above; anchored at
  // the start alone, these two took those and dropped them.
  { id: "k8s-none", class: INFO, re: /^kubernetes manifests: not checked — no Kubernetes manifests found, in YAML or in Terraform$/ },
  { id: "manifest-contract-no-workload", class: INFO, re: /^manifest contract: the code requires \d+ environment variable\(s\) and no Kubernetes workload was found to supply them$/ },
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
  { id: "trivy-settings", class: INFO, re: /^trivy \([^)]*\): TRIVY_\w+.* (?:is|are) set and not passed to Trivy/ },
  { id: "trivy-scanned", class: INFO, re: /^trivy \([^)]*\): Trivy[\d. ]* (?:scanned .*; nothing at|found no OS packages and no language packages)/ },
  { id: "codeql-settings", class: INFO, re: /^codeql: (?:CODEQL|LGTM|SEMMLE)_\w+.* (?:is|are) set and not passed to CodeQL/ },
  { id: "codeql-scanned", class: INFO, re: /^codeql: CodeQL[\d. ]* analysed .* suite; nothing at error level/ },
  { id: "codeql-none", class: INFO, re: /^codeql: not checked — nothing here is in a language CodeQL analyses/ },
  // The sast check reads PHP, so CodeQL's not reading it leaves nothing unchecked that was checked.
  { id: "codeql-unsupported", class: INFO, re: /^codeql: .* source is not analysed — CodeQL does not support/ },
  { id: "codeql-suppressed", class: INFO, re: /^codeql: \d+ result\(s\) carry a suppression from the code itself/ },
  // Snapshot housekeeping (lib/known.mjs). Neither sets anything aside: the findings an entry names
  // still count, and factory mode judges the entries a change adds as grants.
  { id: "known-stale", class: INFO, re: /^known: \d+ snapshot entr(?:y matches|ies match) no finding/ },
  { id: "known-ignored", class: INFO, re: /^known: (?:an entry in .* so it was ignored|\S+ could not be read)/ },
];

export const UNCLASSIFIED = "unclassified";

/**
 * The messages that open with a label the gate did not choose: the opener, which is followed in the
 * message by the label and "): ", and the field of `ctx` that holds the labels the gate wrote in
 * this run. The patterns above for these messages are written for a label with no ")" in it, and
 * are only ever shown the label "." (classifyAdvisory).
 *
 * "codeql (<language>): ..." is not here: its label is one of CodeQL's own language names, picked by
 * the gate from a fixed list (agent/codeql.mjs, LANGUAGE_NAMES), and none of them holds a ")".
 */
export const LABELLED = [
  { opener: "checkov (", from: "terraformRoots", what: "Terraform root", many: "Terraform roots" },
  { opener: "terraform_plan(", from: "terraformRoots", what: "Terraform root", many: "Terraform roots" },
  { opener: "resource census (", from: "terraformRoots", what: "Terraform root", many: "Terraform roots" },
  { opener: "iac templates (", from: "iacTemplateLabels", what: "kind of template", many: "kinds of template checkov reported on" },
  { opener: "trivy (", from: "trivyImages", what: "image", many: "images scanned" },
];

function matchClass(s, ctx) {
  for (const c of ADVISORY_CLASSES) {
    const m = c.re.exec(s);
    if (!m) continue;
    const cls = typeof c.class === "function" ? c.class(s, ctx) : c.class;
    return { id: c.sub ? `${c.id}:${c.sub(m)}` : c.id, class: cls };
  }
  return null;
}

const unclassified = (why) => ({ id: UNCLASSIFIED, class: NOT_CHECKED, unclassified: true, ...(why ? { why } : {}) });

/**
 * A labelled message, classified by the labels the gate wrote and not by where a ")" falls.
 *
 * Every label of this run that the line opens with is one reading of it. The label the gate wrote
 * the line under is always among them, and a second one is possible only when one label continues
 * another with "): ", which is what a name forged to read like a message does. Each reading is
 * classified with its label replaced by ".", so no pattern sees a character of a name the project
 * chose. One answer from every reading is the answer. Anything else is unclassified, which blocks:
 * two readings that disagree, a reading no pattern matches, a label that is none of this run's, and
 * a caller that did not say which labels there were. So the result is the line's true class or a
 * block, and never a class a name chose.
 */
function classifyLabelled(s, { opener, from, what, many }, ctx) {
  const labels = ctx[from];
  if (!Array.isArray(labels)) {
    return unclassified(`it is labelled with a ${what}, and the ${many} of this run were not given to tell the label from the message`);
  }
  const readings = [];
  for (const name of new Set(labels)) {
    const label = `${opener}${name}): `;
    if (s.startsWith(label)) readings.push({ name, got: matchClass(`${opener}.): ${s.slice(label.length)}`, ctx) });
  }
  if (!readings.length) return unclassified(`its label names no ${what} of this run`);
  const [first, ...rest] = readings;
  if (first.got && rest.every((r) => r.got && r.got.id === first.got.id && r.got.class === first.got.class)) return first.got;
  if (!rest.length) return unclassified();
  return unclassified(
    `its label can be read as more than one ${what} of this run (${readings.map((r) => JSON.stringify(r.name)).join(", ")}), and the readings do not agree on what it means`
  );
}

/**
 * { id, class, unclassified?, why? } for one advisory. `ctx` carries what a few classes depend on:
 * `servesHttp` and `couldNotRun`, and the labels the gate wrote in this run, without which a
 * message that opens with one is unclassified: `terraformRoots` (validateProject returns it),
 * `iacTemplateLabels` (the same) and `trivyImages` (the image the run was asked to scan, or none).
 * `why` is set when the reason is more than "no pattern matches".
 */
export function classifyAdvisory(text, ctx = {}) {
  const s = String(text);
  const labelled = LABELLED.find((l) => s.startsWith(l.opener));
  if (labelled) return classifyLabelled(s, labelled, ctx);
  return matchClass(s, ctx) || unclassified();
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
