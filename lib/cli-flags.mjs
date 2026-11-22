// An option the command does not define is a usage error, not something to step over.
//
// Each command picked out the options it knew with `args.includes("--json")` and the like, and
// treated every other argument beginning "--" as not being there. Measured on c54b4a9, each of
// these on a clean project exited 0:
//
//   wolfproof <project> --json --no-such-flag
//   wolfproof <project> --factroy          the default mode, from a pipeline that asked for factory mode
//   wolfproof <project> --json=1           the report as text, to a caller that parses JSON
//   wolfproof <project> task.txt -j
//   wolfproof known <project> --json       and `wolfproof review <project> --json`
//
// A misspelt option is the one mistake a caller cannot see from the outside: the run succeeds, in a
// mode that was not asked for. `wolfproof init` already refused one.
//
// This file imports nothing, so that loading it cannot be what fails.

/** How many single-character edits turn `a` into `b`, for telling a slip from another word. */
function distance(a, b) {
  let row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const next = [i];
    for (let j = 1; j <= b.length; j++) {
      next[j] = Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    row = next;
  }
  return row[b.length];
}

/**
 * What is wrong with the options in `args`, as sentences without a full stop; empty when nothing is.
 *
 * `flags` take no value and `values` take one. With `separate`, a value may be the argument after
 * the option, as `--file <path>`, and is then not looked at; without it only `--name=value` is a
 * value, which is the gate's form, since a separate one would be read as its task file.
 *
 * Whether a value was given at all is left to the command, which says what the value is. A lone
 * "-" is not an option. Any other argument beginning "-" is, so a directory named that way has to
 * be given as "./-name".
 */
export function optionProblems(args, { flags = [], values = [], separate = false }) {
  const problems = [];
  const defined = [...flags, ...values];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("-") || arg === "-") continue;
    const eq = arg.indexOf("=");
    const name = eq < 0 ? arg : arg.slice(0, eq);
    if (flags.includes(name)) {
      if (eq >= 0) problems.push(`${name} takes no value`);
      continue;
    }
    if (values.includes(name)) {
      // The command's own reading: the next argument is the value unless it is another option.
      if (separate && eq < 0 && args[i + 1] !== undefined && !args[i + 1].startsWith("--")) i++;
      continue;
    }
    const near = defined
      .filter((d) => d.startsWith("--"))
      .map((d) => ({ d, n: distance(name, d) }))
      .filter((x) => x.n <= 2)
      .sort((x, y) => x.n - y.n)[0];
    problems.push(`unknown option ${name}${near ? ` (did you mean ${near.d}?)` : ""}`);
  }
  return problems;
}
