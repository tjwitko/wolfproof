// Settings read from the environment, under the tool's name and under the name it had before.
//
// The project was agent-gate until v1.2.0, and its variables were AGENT_GATE_*. A pipeline that sets
// AGENT_GATE_TODAY to pin end-of-life dates, or AGENT_GATE_HOOKS_PATH, must not silently lose that
// setting on upgrade -- a pin that quietly stops applying is a verdict that quietly changes meaning.
// So every setting is read as WOLFPROOF_<NAME> first and AGENT_GATE_<NAME> second. An empty value
// counts as unset, the same as before.

export const PREFIX = "WOLFPROOF_";
export const LEGACY_PREFIX = "AGENT_GATE_";

/** The value of setting `name` (e.g. "TODAY"), or undefined when neither spelling is set. */
export function setting(env, name) {
  for (const key of [`${PREFIX}${name}`, `${LEGACY_PREFIX}${name}`]) {
    const v = env[key];
    if (v !== undefined && v !== "") return v;
  }
  return undefined;
}
