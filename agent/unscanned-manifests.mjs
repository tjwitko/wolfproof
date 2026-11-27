// Manifests whose dependencies nothing scanned.
//
// osv-scanner reads lockfiles. Of manifests it reads only requirements*.txt, go.mod and pom.xml;
// every other manifest is read through its lockfile or not at all. So a package.json with
// dependencies and no lockfile is not scanned less accurately, it is not scanned -- and it was
// reported as a dependency check that ran and found nothing. A probe depending on lodash 4.17.4 with
// no lockfile exited 0, with no advisory; the same project with a lockfile blocked on four high
// findings. Deleting the lockfile before committing removed a critical finding rather than
// downgrading it.
//
// Both tables are measured against osv-scanner 2.4.0 -- the version control-tooling pins -- by
// running it over a manifest or lockfile pinning a known-vulnerable package, not taken from its
// documentation. Two results that documentation would not have predicted: bun.lockb, being binary,
// is not read (bun.lock is), and requirements.lock is not read (requirements-lock.txt is, because
// the match is requirements*.txt).
//
// A manifest that declares no dependencies needs no lockfile: there is nothing to scan, and blocking
// a package.json that only holds scripts would teach people to ignore this check.
import { readdirSync, readFileSync, existsSync } from "fs";
import path from "path";
import { parse as parseYaml } from "yaml";

import { SKIP_DIRS } from "./skip-dirs.mjs";
import { uvGlobMatches, workspaceMatches } from "../lib/factory-deps.mjs";
import { readToml } from "../lib/toml.mjs";

const PY_LOCKS = ["poetry.lock", "pdm.lock", "uv.lock", "Pipfile.lock", "pylock.toml"];
const isRequirementsTxt = (name) => /^requirements.*\.txt$/.test(name);

// For each manifest osv-scanner cannot read: the lockfiles it CAN read that cover it, a test for
// whether the manifest declares anything, and the command that writes a lockfile.
export const NEEDS_LOCKFILE = {
  "package.json": {
    ecosystem: "npm",
    locks: ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"],
    declares: (text) => {
      let pkg;
      try {
        pkg = JSON.parse(text);
      } catch {
        // Unreadable is not "declares nothing". It is the one case where saying nothing is a pass.
        return true;
      }
      return ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].some(
        (k) => pkg[k] && typeof pkg[k] === "object" && Object.keys(pkg[k]).length > 0
      );
    },
    fix: "`npm install` writes package-lock.json (yarn, pnpm and `bun install --save-text-lockfile` also work; bun.lockb does not — it is binary and osv-scanner cannot read it)",
    member: npmMember,
  },
  "Cargo.toml": {
    ecosystem: "crates.io",
    locks: ["Cargo.lock"],
    declares: (text) =>
      tomlDeclares(text, (h) => /^(?:workspace\.|target\..+\.)?(?:dev-|build-)?dependencies(?:\..+)?$/.test(h), {
        headerAlone: (h) => /dependencies\..+$/.test(h),
      }),
    fix: "`cargo generate-lockfile` writes Cargo.lock",
  },
  Pipfile: {
    ecosystem: "PyPI",
    locks: ["Pipfile.lock"],
    declares: (text) => tomlDeclares(text, (h) => h === "packages" || h === "dev-packages"),
    fix: "`pipenv lock` writes Pipfile.lock",
  },
  "pyproject.toml": {
    ecosystem: "PyPI",
    locks: PY_LOCKS,
    coveredBy: isRequirementsTxt,
    member: uvMember,
    declares: pyprojectDeclares,
    fix: "`uv lock`, `poetry lock` or `pdm lock` writes a lockfile; or `pip freeze > requirements-lock.txt` (not requirements.lock, which osv-scanner does not read)",
  },
  "build.gradle": { ecosystem: "Maven", locks: ["gradle.lockfile"], declares: gradleDeclares, fix: "`./gradlew dependencies --write-locks` writes gradle.lockfile" },
  "build.gradle.kts": { ecosystem: "Maven", locks: ["gradle.lockfile"], declares: gradleDeclares, fix: "`./gradlew dependencies --write-locks` writes gradle.lockfile" },
  Gemfile: {
    ecosystem: "RubyGems",
    locks: ["Gemfile.lock"],
    // `gemspec` pulls the gem's own dependencies in from its .gemspec: every Ruby library's Gemfile
    // declares that way and little else, and read as declaring nothing it needed no lockfile.
    declares: (text) => /^\s*(?:gem\s+['"]|gemspec\b)/m.test(text),
    fix: "`bundle lock` writes Gemfile.lock",
  },
  "composer.json": {
    ecosystem: "Packagist",
    locks: ["composer.lock"],
    declares: (text) => {
      let c;
      try {
        c = JSON.parse(text);
      } catch {
        return true;
      }
      // `php` and `ext-*` are platform requirements, not packages anything installs or scans.
      const real = (o) => Object.keys(o || {}).filter((k) => k !== "php" && !k.startsWith("ext-"));
      return real(c.require).length + real(c["require-dev"]).length > 0;
    },
    fix: "`composer update --lock` writes composer.lock",
  },
};

// Whether any section accepted by `wanted` holds at least one key. Line-based rather than a TOML
// parser: this needs "is the section empty", and a dependency on a parser for that is a dependency
// that can be missing.
function tomlDeclares(text, wanted, { headerAlone = () => false } = {}) {
  let inWanted = false;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const header = line.match(/^\[\[?\s*([^\]]+?)\s*\]\]?$/);
    if (header) {
      const h = header[1].replace(/["']/g, "");
      inWanted = wanted(h);
      // `[dependencies.serde]` is a dependency even when every key under it is optional.
      if (inWanted && headerAlone(h)) return true;
      continue;
    }
    if (inWanted && /^[\w.\-"']+\s*=/.test(line)) return true;
  }
  return false;
}

function pyprojectDeclares(text) {
  // Poetry and PEP 735 groups, PDM's and uv's development dependencies: any key except the
  // interpreter constraint.
  const poetry = (h) =>
    h === "tool.poetry.dependencies" || h === "tool.poetry.dev-dependencies" ||
    /^tool\.poetry\.group\..+\.dependencies$/.test(h) || h === "tool.pdm.dev-dependencies";
  let section = "";
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/#.*$/, "").trim();
    if (!line) continue;
    const header = line.match(/^\[\[?\s*([^\]]+?)\s*\]\]?$/);
    if (header) {
      section = header[1].replace(/["']/g, "");
      continue;
    }
    if (poetry(section) && /^[\w.\-"']+\s*=/.test(line) && !/^["']?python["']?\s*=/.test(line)) return true;
    if (section === "project.optional-dependencies" || section === "dependency-groups") {
      if (/=\s*\[\s*["']/.test(line)) return true;
      if (/=\s*\[\s*$/.test(line) && arrayHasString(lines, i)) return true;
    }
    if (section === "project" && /^dependencies\s*=/.test(line)) {
      if (/\[\s*["']/.test(line)) return true;
      if (/\[\s*$/.test(line) && arrayHasString(lines, i)) return true;
    }
    // `dynamic = ["dependencies"]`: setuptools reads them from a file named under
    // [tool.setuptools.dynamic], usually a requirements.txt. They are declared, just not here, and
    // read as declaring nothing the manifest needed no lockfile.
    if (section === "project" && /^dynamic\s*=/.test(line)) {
      const body = /\[\s*$/.test(line) ? arrayBody(lines, i) : line;
      if (/["'](?:optional-)?dependencies["']/.test(body)) return true;
    }
    // uv's own list, before dependency-groups: `dev-dependencies = [...]` under [tool.uv].
    if (section === "tool.uv" && /^dev-dependencies\s*=/.test(line)) {
      if (/\[\s*["']/.test(line)) return true;
      if (/\[\s*$/.test(line) && arrayHasString(lines, i)) return true;
    }
  }
  return false;
}

// The lines of a multi-line array opened on line i, up to its close, as one string.
function arrayBody(lines, i) {
  const out = [];
  for (let j = i + 1; j < lines.length; j++) {
    const l = lines[j].replace(/#.*$/, "").trim();
    if (l.startsWith("]")) break;
    out.push(l);
  }
  return out.join(" ");
}

// A multi-line array opened on line i: does it hold a string before it closes?
function arrayHasString(lines, i) {
  for (let j = i + 1; j < lines.length; j++) {
    const l = lines[j].replace(/#.*$/, "").trim();
    if (/^["']/.test(l)) return true;
    if (l.startsWith("]")) return false;
  }
  return false;
}

function gradleDeclares(text) {
  const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  const re = /\bdependencies\s*\{/g;
  let m;
  while ((m = re.exec(code))) {
    let depth = 1;
    let j = m.index + m[0].length;
    const start = j;
    while (j < code.length && depth > 0) {
      if (code[j] === "{") depth++;
      else if (code[j] === "}") depth--;
      j++;
    }
    if (code.slice(start, j - 1).trim()) return true;
  }
  return false;
}

// Whether the directory `root`, which holds a lockfile, names `dir` as a member of its workspace, so
// that the lockfile holds what dir's manifest declares. A lockfile above a manifest that is not its
// workspace's member holds nothing of it: npm, yarn, pnpm and bun run in that directory use its own
// lockfile, or none. A pattern this cannot read (an extglob) is taken to name it, as it was before.
function npmMember(root, dir) {
  const rel = path.relative(root, dir).split(path.sep).join("/");
  const patterns = [];
  const strings = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");
  try {
    const ws = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"))?.workspaces;
    if (strings(ws)) patterns.push(...ws);
    else if (strings(ws?.packages)) patterns.push(...ws.packages);
  } catch {
    /* no root package.json, or not JSON: it names no members */
  }
  try {
    const doc = parseYaml(readFileSync(path.join(root, "pnpm-workspace.yaml"), "utf8"));
    if (strings(doc?.packages)) patterns.push(...doc.packages);
  } catch {
    /* no pnpm-workspace.yaml, or not one this reads */
  }
  const named = patterns.filter((w) => !w.startsWith("!") || w.startsWith("!(")).map((w) => workspaceMatches(w, rel));
  const excluded = patterns.filter((w) => w.startsWith("!") && !w.startsWith("!(")).some((w) => workspaceMatches(w.slice(1), rel) === true);
  return !excluded && named.some((m) => m !== false);
}

// The same for uv: a uv.lock holds the projects its root's [tool.uv.workspace] names as members
// (`members` matched, `exclude` not). poetry.lock, pdm.lock, Pipfile.lock and pylock.toml are a
// project's own and cover only the directory they are in.
function uvMember(root, dir, lock) {
  if (path.basename(lock) !== "uv.lock") return false;
  let text;
  try {
    text = readFileSync(path.join(root, "pyproject.toml"), "utf8");
  } catch {
    return false;
  }
  const t = readToml(text);
  const ws = t.value?.tool?.uv?.workspace;
  if (t.error || !ws || typeof ws !== "object") return false;
  const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);
  const rel = path.relative(root, dir).split(path.sep).join("/");
  return list(ws.members).some((m) => uvGlobMatches(m, rel)) && !list(ws.exclude).some((m) => uvGlobMatches(m, rel, true));
}

/**
 * The lockfile that covers a manifest in `dir`: one in the manifest's directory, or in a directory
 * above it, up to the project root, that holds what the manifest declares (workspaces, npm and Cargo,
 * keep one lockfile at the root for every member), as a path; or null when there is none. Where the
 * ecosystem says which directories a lockfile above holds (`member`), one it does not name is not
 * covered by it. Whatever decides a manifest is covered must
 * find the lockfile the same way: the relock step in lib/gate-core.mjs looked only in the manifest's
 * own directory, so a member's entry went stale and was dropped without its lockfile being scanned.
 */
export function coveringLockfile(projectDir, dir, rule) {
  for (let d = dir; ; d = path.dirname(d)) {
    const locks = rule.locks.filter((l) => existsSync(path.join(d, l)));
    const lock = d === dir || !rule.member ? locks[0] : locks.find((l) => rule.member(d, dir, l));
    if (lock) return path.join(d, lock);
    if (rule.coveredBy) {
      try {
        const other = readdirSync(d).find(rule.coveredBy);
        if (other) return path.join(d, other);
      } catch {
        /* unreadable directory; keep climbing */
      }
    }
    if (path.relative(projectDir, d) === "" || d === path.dirname(d)) return null;
  }
}

const covered = (projectDir, dir, rule) => coveringLockfile(projectDir, dir, rule) !== null;

/**
 * Every manifest under projectDir that declares dependencies osv-scanner cannot read, with no
 * lockfile that it can. Each is a dependency set no scanner looked at.
 */
export function unscannedManifests(projectDir) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        // Fixtures are NOT skipped here. dep-audit's osv-scanner reads the whole tree, fixtures
        // included, so the dependency checks treat it as one unit; exempting a fixture's manifest
        // here would only loosen the check, never correct a false finding.
        if (!SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name));
        continue;
      }
      const rule = NEEDS_LOCKFILE[e.name];
      if (!rule) continue;
      let text;
      try {
        text = readFileSync(path.join(dir, e.name), "utf8");
      } catch {
        text = null;
      }
      if (text !== null && !rule.declares(text)) continue;
      if (covered(projectDir, dir, rule)) continue;
      out.push({
        manifest: path.relative(projectDir, path.join(dir, e.name)),
        ecosystem: rule.ecosystem,
        fix: rule.fix,
      });
    }
  };
  walk(projectDir);
  return out;
}
