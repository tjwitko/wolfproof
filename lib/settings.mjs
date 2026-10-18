// Settings read from the environment.
//
// Every setting is WOLFPROOF_<NAME>. The project was agent-gate until v1.2.0 and its variables were
// AGENT_GATE_*; v1.2.0 read both, and since v1.3.0 only the new names are read. A pipeline still
// setting AGENT_GATE_TODAY must not lose its pin silently -- a pin that quietly stops applying is a
// verdict that quietly changes meaning -- so legacySettingsInUse() names each one still set, and the
// gate reports it. An empty value counts as unset.

export const PREFIX = "WOLFPROOF_";
export const LEGACY_PREFIX = "AGENT_GATE_";

/** The value of setting `name` (e.g. "TODAY"), or undefined when it is not set. */
export function setting(env, name) {
  const v = env[`${PREFIX}${name}`];
  return v !== undefined && v !== "" ? v : undefined;
}

/**
 * The AGENT_GATE_* variables set in `env` that are no longer read, each with the name to use instead.
 * One whose WOLFPROOF_* replacement is also set is still listed: it is ignored either way.
 */
export function legacySettingsInUse(env) {
  return Object.keys(env)
    .filter((k) => k.startsWith(LEGACY_PREFIX) && env[k] !== "")
    .sort()
    .map((k) => ({ name: k, use: `${PREFIX}${k.slice(LEGACY_PREFIX.length)}` }));
}
