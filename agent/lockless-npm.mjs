// A package.json with no lockfile, scanned anyway. docs/candidate-rules.md #36.
//
// osv-scanner reads npm dependencies only through a lockfile (agent/unscanned-manifests.mjs), so a
// package.json without one was reported as declaring dependencies nothing scanned -- true, and on a
// legacy repository the one finding a snapshot could not hold. This reads the dependencies the
// manifest declares, takes for each the lowest version its range allows, writes them to a lockfile
// in a directory of its own, and has osv-scanner scan that.
//
// What that checks is narrower than a lockfile scan, and every finding and advisory says so:
//   - Direct dependencies only. Nothing names the transitive ones without a lockfile.
//   - The lowest version a range allows, not the one an install picks. `^4.17.4` is checked as
//     4.17.4 when an install would take the newest 4.x, so a finding may be fixed in what actually
//     installs; raising the range's lower bound is the fix either way.
// Nothing from the project is run: the versions are read from the manifest's text.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, readdirSync, existsSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";
import { pathToFileURL } from "url";
import { parse as parseYaml } from "yaml";

// The sections an install reads. peerDependencies are the host's to install, not this package's.
const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"];

const VERSION = /^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** A partial version as numbers, a wildcard part as null: "1.x" -> [1, null, null]. */
function parts(v) {
  const m = VERSION.exec(v);
  if (!m) return null;
  const n = (p) => (p === undefined || /^[xX*]$/.test(p) ? null : Number(p));
  return { major: n(m[1]), minor: n(m[2]), patch: n(m[3]), pre: m[4] || "" };
}

const fmt = (p) => `${p.major ?? 0}.${p.minor ?? 0}.${p.patch ?? 0}${p.pre}`;

// Semver's order: the three numbers, then the prerelease. A prerelease sorts before its release, and
// prerelease identifiers compare field by field, numeric fields as numbers (rc.9 before rc.10),
// a numeric field before an alphanumeric one, and the shorter list first when it is a prefix of the
// other (alpha before alpha.1). Compared as text, rc.10 sorted before rc.9, and `||` picked the
// higher one.
function compare(a, b) {
  const x = parts(a);
  const y = parts(b);
  for (const k of ["major", "minor", "patch"]) if ((x[k] ?? 0) !== (y[k] ?? 0)) return (x[k] ?? 0) - (y[k] ?? 0);
  if (!x.pre || !y.pre) return x.pre ? -1 : y.pre ? 1 : 0;
  const xs = x.pre.slice(1).split(".");
  const ys = y.pre.slice(1).split(".");
  for (let i = 0; i < Math.min(xs.length, ys.length); i++) {
    const [p, q] = [xs[i], ys[i]];
    const [np, nq] = [/^\d+$/.test(p), /^\d+$/.test(q)];
    if (np && nq) {
      if (Number(p) !== Number(q)) return Number(p) - Number(q);
    } else if (np !== nq) {
      return np ? -1 : 1;
    } else if (p !== q) {
      return p < q ? -1 : 1;
    }
  }
  return xs.length - ys.length;
}

/** The lowest version one comparator allows, or undefined for one that sets no lower bound. */
function lower(comparator) {
  const m = /^(\^|~|>=|>|<=|<|=)?\s*(.+)$/.exec(comparator);
  if (!m) return null;
  const [, op = "", v] = m;
  const p = parts(v);
  if (!p) return null;
  if (op === "<" || op === "<=") return undefined;
  if (op === ">") {
    // Past a prerelease, the release itself: `>1.2.3-beta` allows 1.2.3 (and the prereleases between,
    // which this does not reach for), so the scan must not start at 1.2.4.
    if (p.pre) return fmt({ ...p, pre: "" });
    // The next version past it: a patch past a full version, the next minor or major past a partial.
    if (p.patch !== null) return `${p.major}.${p.minor}.${p.patch + 1}`;
    if (p.minor !== null) return `${p.major}.${p.minor + 1}.0`;
    return p.major !== null ? `${p.major + 1}.0.0` : null;
  }
  if (p.major === null) return undefined;
  return fmt(p);
}

/**
 * The lowest version an npm range allows, or null when it has none: a range with no lower bound
 * (`*`, `<=4.17.20`) or one that names no version (a tag like `latest`, a URL, a path,
 * `workspace:`). `||` takes the lowest of its alternatives, so one alternative with no lower bound
 * leaves the whole range none: `<2.0.0 || >=3.0.0` allows every 1.x, and is not 3.0.0.
 */
export function lowestVersion(range) {
  const r = String(range ?? "").trim();
  if (!r || /[:/]/.test(r)) return null;
  let best = null;
  for (const alt of r.split("||")) {
    const a = alt.trim();
    let low;
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(a);
    if (hyphen) {
      low = lower(hyphen[1]);
    } else {
      const comparators = a.replace(/(\^|~|>=|>|<=|<|=)\s+/g, "$1").split(/\s+/).filter(Boolean);
      if (!comparators.length) return null;
      low = undefined;
      for (const c of comparators) {
        const l = lower(c);
        if (l === null) return null;
        if (l !== undefined && (low === undefined || compare(l, low) > 0)) low = l;
      }
    }
    if (low === null || low === undefined) return null;
    if (best === null || compare(low, best) < 0) best = low;
  }
  return best;
}

/** What a package.json declares: [{ name, range, version }], version null where the range has no lowest version. */
export function npmDeclared(text) {
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    return null;
  }
  const out = [];
  const seen = new Set();
  for (const s of SECTIONS) {
    for (const [name, spec] of Object.entries(pkg?.[s] && typeof pkg[s] === "object" ? pkg[s] : {})) {
      if (seen.has(name)) continue;
      seen.add(name);
      // `npm:other@^1` installs `other`: an alias is checked as the package it names, and keeps
      // the name it was declared under (`alias`) so that a direct dependency on the same package,
      // at another version, is checked as well rather than overwritten in the lockfile.
      const alias = /^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/.exec(String(spec));
      const real = alias ? alias[1] : name;
      const range = alias ? alias[2] : String(spec);
      out.push({ name: real, range, version: lowestVersion(range), ...(alias ? { alias: name } : {}) });
    }
  }
  return out;
}

/**
 * The names a package.json declares directly, sorted, or null when it cannot be read. What a
 * snapshot's entry for a package.json with no lockfile records, so that the lockfile committed for it
 * later adds only findings of what was declared then (bin/known.mjs).
 */
export function declaredNames(text) {
  const deps = npmDeclared(text);
  return deps ? [...new Set(deps.map((d) => d.name))].sort() : null;
}

/**
 * The package.json of every workspace member a root manifest in `dir` names: the `workspaces` field
 * (an array, or yarn's `{ packages: [...] }`) and pnpm-workspace.yaml's `packages`, as paths
 * relative to `dir`. A pattern is a path or a glob whose segments are literal or `*`
 * (`packages/*`); anything else (`**`, `?`, `{a,b}`, `[ab]`) is listed in `unresolved` instead of
 * guessed at, and a `!` exclusion is ignored, which can only name more members, never fewer. A file
 * that names members in a form this does not read -- a pnpm-workspace.yaml that does not parse or
 * has no `packages` list, a `workspaces` that is not a list -- is described in `unknown`, since
 * "none found" would be wrong in exactly the case the caller must not get wrong.
 *
 * For `wolfproof known`: a root lockfile holds every member's packages, so when it is committed for a
 * root package.json the snapshot held as having none, the members' direct dependencies have to count
 * as direct too, or their findings would be added as if nothing had declared them.
 */
export function workspaceManifests(dir) {
  const patterns = [];
  const unknown = [];
  const strings = (v) => Array.isArray(v) && v.every((s) => typeof s === "string");
  try {
    const pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
    const ws = pkg?.workspaces;
    if (ws === undefined || ws === null) {
      /* no workspaces field: nothing names members */
    } else if (strings(ws)) patterns.push(...ws);
    else if (strings(ws?.packages)) patterns.push(...ws.packages);
    else unknown.push("package.json's `workspaces` is not a list of patterns");
  } catch {
    /* no root manifest, or unreadable: the caller reads it too and reports that itself */
  }
  // pnpm's file is YAML, and `packages` comes in every form YAML allows a list: block, flow, indented
  // or not. The first version read it line by line and saw no members in `packages: ["a/*"]` or in
  // an unindented `- a/*`, so the members' findings were added as if nothing had declared them.
  let yamlText = null;
  try {
    yamlText = readFileSync(path.join(dir, "pnpm-workspace.yaml"), "utf8");
  } catch (e) {
    if (e?.code !== "ENOENT") unknown.push("pnpm-workspace.yaml could not be read");
  }
  if (yamlText !== null) {
    let doc;
    try {
      doc = parseYaml(yamlText);
    } catch {
      unknown.push("pnpm-workspace.yaml could not be parsed");
      doc = undefined;
    }
    if (doc !== undefined) {
      if (strings(doc?.packages)) patterns.push(...doc.packages);
      else unknown.push("pnpm-workspace.yaml has no `packages` list");
    }
  }
  const manifests = new Set();
  const unresolved = [];
  for (const raw of patterns) {
    const pattern = raw.trim().replace(/\/+$/, "");
    if (!pattern || pattern.startsWith("!")) continue;
    const segments = pattern.split("/").filter((s) => s && s !== ".");
    if (segments.some((s) => s !== "*" && /[*?[\]{}]/.test(s))) {
      unresolved.push(pattern);
      continue;
    }
    let dirs = [dir];
    for (const s of segments) {
      dirs = dirs.flatMap((d) => {
        if (s !== "*") return [path.join(d, s)];
        try {
          return readdirSync(d, { withFileTypes: true })
            .filter((e) => e.isDirectory() && !e.name.startsWith("."))
            .map((e) => path.join(d, e.name));
        } catch {
          return [];
        }
      });
    }
    for (const d of dirs) {
      const m = path.join(d, "package.json");
      if (path.relative(dir, m) !== "package.json" && existsSync(m)) manifests.add(path.relative(dir, m));
    }
  }
  return { manifests: [...manifests].sort(), unresolved, unknown };
}

/**
 * A package-lock.json, version 3, holding exactly these packages at these versions. An alias is
 * written as npm writes one, under the name it was declared with and naming the real package in
 * `name` (osv-scanner 2.4.0 reads it as that package), so `"old-lodash": "npm:lodash@^4.17.4"` and
 * `"lodash": "^4.17.21"` are two entries and both versions are scanned.
 */
export function lockfileFor(deps) {
  const packages = { "": { name: "wolfproof-lockless", version: "0.0.0", dependencies: {} } };
  for (const d of deps) {
    const key = d.alias || d.name;
    packages[""].dependencies[key] = d.alias ? `npm:${d.name}@${d.version}` : d.version;
    packages[`node_modules/${key}`] = { ...(d.alias ? { name: d.name } : {}), version: d.version };
  }
  return { name: "wolfproof-lockless", version: "0.0.0", lockfileVersion: 3, requires: true, packages };
}

/**
 * Scan each package.json in `manifests` (paths relative to the project) as described above.
 * `summarize` is dep-audit's summarizeFindings, so severities are banded exactly as the control
 * bands them. Returns { error } when osv-scanner could not run, or
 * { scanned: [{ manifest, checked, unresolved, declared, findings }] }, findings at or above
 * `threshold`, `declared` the names the manifest declares (declaredNames).
 */
export function scanWithoutLockfile(projectDir, manifests, { summarize, threshold = "high", run = spawnSync } = {}) {
  const work = mkdtempSync(path.join(tmpdir(), "wolfproof-lockless-"));
  try {
    const scanned = [];
    manifests.forEach((manifest, i) => {
      let deps = null;
      try {
        deps = npmDeclared(readFileSync(path.join(projectDir, manifest), "utf8"));
      } catch {
        /* unreadable: reported below as nothing checked */
      }
      const resolved = (deps || []).filter((d) => d.version);
      const entry = {
        manifest,
        checked: resolved.length,
        unresolved: (deps || []).filter((d) => !d.version).map((d) => `${d.name}@${d.range}`),
        declared: [...new Set((deps || []).map((d) => d.name))].sort(),
        findings: [],
      };
      scanned.push(entry);
      if (!resolved.length) return;
      const dir = path.join(work, String(i));
      mkdirSync(dir);
      writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(lockfileFor(resolved)));
      entry.lock = path.join(dir, "package-lock.json");
    });
    if (!scanned.some((s) => s.lock)) return { scanned };
    const r = scanLockfiles(scanned.filter((s) => s.lock).map((s) => s.lock), { summarize, threshold, run });
    if (r.error) return { error: r.error };
    let k = 0;
    for (const s of scanned) {
      if (!s.lock) continue;
      s.findings = r.findings[k++];
      delete s.lock;
    }
    return { scanned };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/**
 * dep-audit's summarizeFindings, run in a node process of its own. Never import dep-audit's entry
 * into the gate: dep-audit up to v1.0.2 deletes every environment variable but PATH, HOME and
 * SCAN_ROOT as it loads (the guardrail of an MCP server, which v1.0.3 applies only when the server
 * starts), and in the gate's process that took TMPDIR, every WOLFPROOF_ setting and the test
 * runner's own variables away from everything that ran after it. The gate pins a later dep-audit,
 * but a project can hand it its own (an env var, .wolfproof.json or its node_modules), so the child
 * process stays for those versions.
 *
 * The returned function summarizes one osv-scanner result; its `many` summarizes several in one
 * process. Both throw when dep-audit could not be run or has no summarizeFindings.
 */
export function childSummarizer(entry, { run = spawnSync } = {}) {
  // The entry is written into the script rather than passed as an argument: dep-audit starts its
  // server when argv[1] is its own path, and a server would wait on stdin for ever.
  const script =
    `const { summarizeFindings } = await import(${JSON.stringify(pathToFileURL(entry).href)});` +
    `if (typeof summarizeFindings !== "function") { process.stderr.write("this dep-audit has no summarizeFindings"); process.exit(3); }` +
    `let s = ""; for await (const c of process.stdin) s += c;` +
    `process.stdout.write(JSON.stringify(JSON.parse(s).map((r) => summarizeFindings(r))));`;
  const many = (results) => {
    const r = run(process.execPath, ["--input-type=module", "-e", script], { input: JSON.stringify(results), encoding: "utf8", maxBuffer: 50 * 1024 * 1024 });
    if (r.error || r.status !== 0) throw new Error(`dep-audit's severity bands could not be read (${r.error?.message || `exit ${r.status}`}): ${String(r.stderr || "").trim().split("\n").slice(-1)[0] || "no output"}`);
    return JSON.parse(r.stdout);
  };
  const one = (result) => many([result])[0];
  one.many = many;
  return one;
}

/**
 * osv-scanner over these lockfiles, in one run, and each one's findings at or above `threshold`,
 * banded by `summarize` (dep-audit's summarizeFindings, or childSummarizer's): { findings: [[...],
 * ...] } in the order given, or { error } when it did not scan or could not be banded.
 */
export function scanLockfiles(locks, { summarize, threshold = "high", run = spawnSync } = {}) {
  const args = ["scan", "source", "--format", "json", ...locks.flatMap((l) => ["-L", l])];
  const r = run("osv-scanner", args, { encoding: "utf8", maxBuffer: 50 * 1024 * 1024 });
  // 0 nothing found, 1 vulnerabilities found; anything else, or no JSON, is not a scan.
  if (r.error || (r.status !== 0 && r.status !== 1)) {
    return { error: `osv-scanner did not scan them (${r.error?.message || `exit ${r.status}`}): ${String(r.stderr || "").trim().split("\n").slice(-1)[0] || "no output"}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {
    return { error: "osv-scanner's output could not be parsed" };
  }
  const bands = ["low", "moderate", "high", "critical"];
  const included = bands.slice(Math.max(0, bands.indexOf(threshold)));
  const each = locks.map((lock) => ({ results: (parsed.results || []).filter((x) => path.resolve(x.source?.path || "") === path.resolve(lock)) }));
  let summaries;
  try {
    summaries = summarize.many ? summarize.many(each) : each.map((e) => summarize(e));
  } catch (err) {
    return { error: err.message };
  }
  return { findings: summaries.map((summary) => included.flatMap((b) => summary[b] || [])) };
}
