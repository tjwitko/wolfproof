// How the regression corpus (corpus/run.mjs) identifies a finding, so a frozen verdict can be compared
// with a new run. Here rather than in the runner so it can be tested: the runner runs the corpus when
// it is loaded, and these decide what counts as drift.

/**
 * A finding's identity is the check that produced it. Message bodies carry counts, paths and prose
 * that move for reasons unrelated to whether the control still fires, so the corpus pins WHICH
 * checks fire and HOW MANY times rather than their wording. Pinning the prose would make every
 * improvement to a remediation message look like a regression, and the remediations have been
 * rewritten repeatedly -- one of them cost a run by naming a setting without naming the block it
 * belongs in.
 */
export function findingId(message) {
  const m = /^([a-z_][a-z_ ]*)\s*(?:\(|:)/i.exec(message.trim());
  return m ? m[1].trim() : message.trim().slice(0, 24);
}

/**
 * A finding's identity and weight in factory mode. Every factory refusal starts "factory:", so
 * findingId alone would fold a self-granted noqa, a control override and an unchecked advisory into
 * one count; this names what was refused instead. Refusals that list grants or files count each one,
 * because "3 checkov:skip grant(s)" turning into 2 is drift, and one message per kind would hide it.
 */
export function factoryFindingId(message) {
  const t = message.trim();
  if (!t.startsWith("factory:")) return { id: findingId(t), n: 1 };
  const rules = [
    [/^factory: (\d+) (.+?) grant\(s\) this change added/, (m) => [`factory: added ${m[2]}`, +m[1]]],
    [/^factory: (\d+) file\(s\) changed under /, (m) => ["factory: changed-under-exemption", +m[1]]],
    [/^factory: (\d+) file\(s\) this change wrote under /, (m) => ["factory: skipped-location", +m[1]]],
    [/^factory: this change moved /, () => ["factory: moved-to-unchecked", 1]],
    [/^factory: this change edits the pipeline/, () => ["factory: workflow-change", 1]],
    [/^factory: the (task file|baseline) .* was added by this change/, (m) => [`factory: ${m[1]} added`, 1]],
    [/^factory: this change edits the (task file|baseline) /, (m) => [`factory: ${m[1]} edited`, 1]],
    [/^factory: nothing was checked — (.*)$/s, (m) => [`factory: nothing checked (${findingId(m[1])})`, 1]],
    [/^factory: blocked by the pipeline's policy \(([^)]+)\)/, (m) => [`factory: policy (${m[1]})`, 1]],
    [/^factory: an advisory factory mode cannot classify/, () => ["factory: unclassified advisory", 1]],
    [/^factory: (\S+) overrides the (\S+) control/, (m) => [`factory: control override (${m[2]})`, 1]],
  ];
  for (const [re, f] of rules) {
    const m = re.exec(t);
    if (m) {
      const [id, n] = f(m);
      return { id, n };
    }
  }
  return { id: t.slice(0, 40), n: 1 };
}
