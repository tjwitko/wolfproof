// Factory mode: a dependency the change adds needs the pipeline's approval.
//
// Before this rule a dependency was held to one test, no known high or critical advisory, so a change
// could add any package that had none yet: a name it invented that someone else had registered, a
// tarball from any URL, a package that runs a script when it is installed. Nobody reads a factory
// change, so the gate is the only place a person's approval can be required. Decided by the user on
// 2026-11-24.
//
// The dependencies at the head are compared with those at the base, for npm, Python and Go, and four
// things block, each its own allowlist kind (DEP_KINDS):
//
//   - new-dependency: a name the project did not declare at the base, in any manifest of that
//     ecosystem. A lockfile entry that no manifest declares and nothing in the lockfile brings in
//     counts too.
//   - dependency-source: a dependency from somewhere other than the ecosystem's registry (git, a URL,
//     a path outside the project) that the base did not take from there; a registry or index the
//     project's files name and the base's did not; a lockfile entry edited in place, its version the
//     same and what installs different.
//   - install-script: a package new to the lockfile that runs code when it is installed (npm's
//     hasInstallScript; for Python, a lockfile that records only a source distribution, which is
//     built on install), or one whose base versions did not.
//   - unpinned-range: a range that takes anything (`*`, `latest`, a tag, nothing at all, a git
//     branch), added or changed by the change, where no lockfile pins what installs.
//
// What passes: a version move of a dependency the project already had, from the same source, and the
// packages it brings; a removal; a dependency on the project's own code (a path inside it, a
// workspace member).
//
// Nothing here goes to the network, so nothing is looked up in a registry: what a package brings and
// whether it runs a script is what the lockfile says. A manifest or lockfile that cannot be read, at
// the head or the base, is could-not-run and never a pass. Manifests of the ecosystems this does not
// read are named when the change edits one (notRead).
import path from "path";

import { SKIP_DIRS } from "../agent/skip-dirs.mjs";
import { FIXTURE_MARKERS } from "../agent/fixture-markers.mjs";
import { readToml } from "./toml.mjs";

export const DEP_KINDS = {
  "new-dependency": "a dependency the base did not declare, in any manifest of its ecosystem, or a lockfile entry that nothing declares or brings in",
  "dependency-source":
    "a dependency from somewhere other than its ecosystem's registry that the base did not take from there, a registry or index the base's files did not name, or a lockfile entry edited in place",
  "install-script": "a package new to the lockfile, direct or brought in by another, that runs code when it is installed",
  "unpinned-range": "a range that takes any version (`*`, `latest`, a tag, none at all, a git branch), added or changed, where no lockfile pins what installs",
};

export const ECOSYSTEMS = ["npm", "PyPI", "Go"];
const ECO = Object.fromEntries(ECOSYSTEMS.map((e) => [e.toLowerCase(), e]));
export const ecosystemName = (e) => (typeof e === "string" ? ECO[e.toLowerCase()] || null : null);

/** A name as the ecosystem compares it: PyPI folds case and runs of `-_.` (PEP 503); npm and Go compare exactly. */
export function normalName(eco, name) {
  return eco === "PyPI" ? String(name).toLowerCase().replace(/[-_.]+/g, "-") : String(name);
}

// ---------------------------------------------------------------------------------------------
// Which files

// Manifests and lockfiles of ecosystems, or formats, this rule does not read. A change that edits one
// is named above the verdict, since this rule has said nothing about it.
const NOT_READ = [
  [/^Cargo\.(?:toml|lock)$/, "crates.io"],
  [/^(?:Gemfile|Gemfile\.lock|.+\.gemspec)$/, "RubyGems"],
  [/^composer\.(?:json|lock)$/, "Packagist"],
  [/^(?:pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|gradle\.lockfile|libs\.versions\.toml)$/, "Maven"],
  [/^(?:.+\.(?:cs|fs|vb)proj|packages\.config|Directory\.Packages\.props|packages\.lock\.json)$/, "NuGet"],
  [/^(?:Package\.swift|Package\.resolved|Podfile|Podfile\.lock)$/, "Swift"],
  [/^pubspec\.(?:yaml|lock)$/, "Pub"],
  [/^mix\.(?:exs|lock)$/, "Hex"],
  [/^(?:deno\.jsonc?|deno\.lock)$/, "Deno"],
  [/^(?:environment\.ya?ml|conda-lock\.ya?ml)$/, "conda"],
  [/^(?:yarn\.lock|pnpm-lock\.yaml|pnpm-workspace\.yaml|\.pnpmfile\.c?js|bun\.lockb?|\.yarnrc(?:\.yml)?|bunfig\.toml)$/, "npm, a file this rule does not read"],
  [/^(?:setup\.py|setup\.cfg|pdm\.lock|pylock(?:\..+)?\.toml)$/, "PyPI, a file this rule does not read"],
];
const isRequirementsFile = (rel) => {
  const base = path.posix.basename(rel);
  return /\.(?:txt|in)$/.test(base) && (/requirements/i.test(base) || rel.split("/").slice(0, -1).includes("requirements"));
};

/**
 * A tree to read: { files, read(rel) -> text | null, fixtureDirs }. The project on disk, or the base
 * as extracted, or (for a replay) a commit. A file that is listed and reads as null could not be read.
 */
export function treeOf(files, read, fixtureDirs = []) {
  const dirs = fixtureDirs.map((d) => (d === "." ? "" : d));
  const skipped = (rel) => {
    const parts = rel.split("/");
    if (parts.slice(0, -1).some((p) => SKIP_DIRS.has(p))) return true;
    return dirs.some((d) => d === "" || rel === d || rel.startsWith(`${d}/`));
  };
  const kept = files.filter((f) => !skipped(f));
  return { files: kept, all: new Set(files), read };
}

/** The fixture directories a list of files declares (a marker file beside them). */
export const markerDirs = (files) => files.filter((f) => FIXTURE_MARKERS.includes(path.posix.basename(f))).map((f) => path.posix.dirname(f));

// ---------------------------------------------------------------------------------------------
// Sources

const DEFAULT_NPM = ["https://registry.npmjs.org/", "https://registry.yarnpkg.com/"];
const DEFAULT_PYPI = ["https://pypi.org/simple/", "https://files.pythonhosted.org/"];

const slash = (u) => (u.endsWith("/") ? u : `${u}/`);
const normUrl = (u) => {
  try {
    const x = new URL(u);
    x.hash = "";
    x.search = "";
    x.username = "";
    x.password = "";
    return x.toString();
  } catch {
    return u;
  }
};

/** A git location as one comparable string: host and path, no scheme, user, ref or `.git`. */
export function canonicalGit(raw) {
  let s = String(raw).trim().replace(/^git\+/, "");
  const hosts = { github: "github.com", gitlab: "gitlab.com", bitbucket: "bitbucket.org", gist: "gist.github.com" };
  let m = /^(github|gitlab|bitbucket|gist):(.+)$/.exec(s);
  if (m) s = `https://${hosts[m[1]]}/${m[2]}`;
  else if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$/.test(s)) s = `https://github.com/${s}`;
  m = /^[^@/:]+@([^:/]+):(.+)$/.exec(s); // git@host:path
  if (m) s = `https://${m[1]}/${m[2]}`;
  s = s.replace(/#.*$/, "").replace(/\?.*$/, "");
  m = /^[a-z+]+:\/\/(?:[^@/]+@)?([^/:]+)(?::\d+)?(\/.*)?$/i.exec(s);
  if (!m) return s;
  const p = (m[2] || "").replace(/\/+$/, "").replace(/\.git$/, "");
  return `${m[1].toLowerCase()}${p}`;
}

// `id` is what two sources are compared by; `raw` is the text an allowlist entry gives for it.
const source = (type, id, shown, extra = {}) => ({ type, id: `${type}:${id}`, shown, raw: shown, ...extra });
const REGISTRY = (shown) => source("registry", "default", shown, { raw: "" });

// A git ref that pins what installs: a commit, or a version tag. Anything else moves.
const pinsRef = (ref) => Boolean(ref) && (/^[0-9a-f]{7,40}$/i.test(ref) || /^v?\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]*)?$/.test(ref));

function pathSource(spec, manifest, raw) {
  const dir = path.posix.dirname(manifest);
  const target = path.posix.normalize(path.posix.join(dir === "." ? "" : dir, raw));
  const own = !path.posix.isAbsolute(raw) && !raw.startsWith("~") && target !== ".." && !target.startsWith("../");
  return source("path", own ? target : raw, spec, { own });
}

// ---------------------------------------------------------------------------------------------
// npm

const NPM_ANY = /^(?:|\*|[xX*](?:\.[xX*]){0,2}|latest|>=\s*0(?:\.0){0,2}(?:-0)?)$/;

/**
 * What an npm dependency spec says: { real, source, anything }. `real` is the package an alias
 * installs; `anything` that the spec takes any version.
 */
export function npmSpec(spec, manifest, declaredAs) {
  const s = String(spec).trim();
  const alias = /^npm:((?:@[^/@\s]+\/)?[^@\s/]+)(?:@(.*))?$/.exec(s);
  if (alias) {
    const r = npmSpec(alias[2] ?? "", manifest, alias[1]);
    return { ...r, real: alias[1] };
  }
  if (/^(?:git\+[a-z]+:|git:\/\/|[^@/\s:]+@[^:/\s]+:|github:|gitlab:|bitbucket:|gist:)/i.test(s) || /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$/.test(s)) {
    const ref = /#(.*)$/.exec(s)?.[1] || "";
    const semver = /^semver:(.*)$/.exec(ref);
    const anything = semver ? NPM_ANY.test(semver[1].trim()) : !pinsRef(ref);
    return { real: declaredAs, source: source("git", canonicalGit(s), s, { ref }), anything };
  }
  if (/^https?:\/\//i.test(s)) {
    const u = normUrl(s);
    return { real: declaredAs, source: source("url", u.replace(/[^/]*$/, ""), s), anything: false };
  }
  if (/^(?:file:|link:|portal:)/.test(s) || /^(?:\.{1,2}(?:\/|$)|\/|~\/)/.test(s)) {
    return { real: declaredAs, source: pathSource(s, manifest, s.replace(/^(?:file|link|portal):/, "")), anything: false };
  }
  if (/^workspace:/.test(s)) return { real: declaredAs, source: source("path", `workspace:${declaredAs}`, s, { own: true }), anything: false };
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return { real: declaredAs, source: source("other", s, s), anything: false };
  const parts = s.split("||").map((p) => p.trim());
  // A word that is not a version is a dist-tag, which the registry moves: `latest`, `next`, `beta`.
  const tag = /^[A-Za-z][A-Za-z0-9._-]*$/.test(s) && !/^[vV]\d/.test(s);
  return { real: declaredAs, source: REGISTRY("the npm registry"), anything: tag || parts.some((p) => NPM_ANY.test(p)) };
}

const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

function readNpmManifest(rel, text, out) {
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch (e) {
    return `it is not JSON (${e.message})`;
  }
  if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) return "it is not a JSON object";
  const m = { path: rel, name: typeof pkg.name === "string" ? pkg.name : null, workspaces: [] };
  for (const section of NPM_SECTIONS) {
    const deps = pkg[section];
    if (deps === undefined || deps === null) continue;
    if (typeof deps !== "object" || Array.isArray(deps)) return `its ${section} is not an object`;
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== "string") return `${section}.${name} is not a string`;
      const r = npmSpec(spec, rel, name);
      out.decl.push({ eco: "npm", name: r.real, key: r.real, declaredAs: name, spec, manifest: rel, section, source: r.source, anything: r.anything, role: "dependency" });
    }
  }
  // Overrides choose what a dependency of a dependency resolves to. They add no name of their own,
  // but an alias in one installs another package, and a git URL or tarball in one is a source.
  const overrides = (obj, where, parent) => {
    for (const [k, v] of Object.entries(obj || {})) {
      const name = k === "." ? parent : k.replace(/^.*>/, "").replace(/^(@[^/]+\/[^@]+|[^@]+)@.*$/, "$1").replace(/^(?:\*\*\/)+/, "").replace(/^.*\/(?=(?:@[^/]+\/)?[^/]+$)/, "");
      if (typeof v === "string") {
        if (v.startsWith("$")) continue;
        const r = npmSpec(v, rel, name);
        out.decl.push({ eco: "npm", name: r.real, key: r.real, declaredAs: name, spec: v, manifest: rel, section: where, source: r.source, anything: false, role: "override" });
      } else if (v && typeof v === "object") overrides(v, where, name);
      else return `${where}.${k} is neither a string nor an object`;
    }
    return null;
  };
  for (const [field, obj] of [["overrides", pkg.overrides], ["resolutions", pkg.resolutions], ["pnpm.overrides", pkg.pnpm?.overrides]]) {
    if (obj === undefined) continue;
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return `its ${field} is not an object`;
    const err = overrides(obj, field, null);
    if (err) return err;
  }
  const ws = Array.isArray(pkg.workspaces) ? pkg.workspaces : Array.isArray(pkg.workspaces?.packages) ? pkg.workspaces.packages : [];
  m.workspaces = ws.filter((w) => typeof w === "string");
  out.manifests.push(m);
  return null;
}

/** A lockfile entry's source, from `resolved`. */
function npmResolved(e, lockPath) {
  // A link is a directory npm points at: a workspace member, or a path a manifest gave. In the
  // project it is the project's own code.
  if (e.link) return pathSource(e.resolved || "", path.posix.join(path.posix.dirname(lockPath), "package.json"), e.resolved || "");
  const r = e.resolved;
  if (!r) return e.inBundle ? source("bundled", "", "inside the package that bundles it") : REGISTRY("the npm registry");
  if (/^(?:git\+|git:\/\/|github:)/.test(r)) return source("git", canonicalGit(r), r);
  if (/^file:/.test(r)) return pathSource(r, path.posix.join(path.posix.dirname(lockPath), "package.json"), r.slice(5));
  if (/^https?:\/\//.test(r)) return source("url-resolved", normUrl(r), r);
  return source("other", r, r);
}

function readNpmLock(rel, text, out) {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch (e) {
    return `it is not JSON (${e.message})`;
  }
  if (!lock || typeof lock !== "object") return "it is not a JSON object";
  const entries = new Map();
  const add = (key, e, scriptsKnown) => {
    if (!e || typeof e !== "object") throw new Error(`entry ${key} is not an object`);
    const local = key === "" || !key.includes("node_modules/");
    // The name the key gives is where node finds it; `name`, when given, is the package installed
    // there, which differs for an alias.
    const keyName = local ? null : key.slice(key.lastIndexOf("node_modules/") + 13);
    const name = typeof e.name === "string" && !local ? e.name : keyName;
    const deps = { ...(e.dependencies || {}), ...(e.optionalDependencies || {}), ...(e.peerDependencies || {}), ...(e.requires || {}) };
    entries.set(key, {
      key,
      name,
      keyName,
      version: typeof e.version === "string" ? e.version : null,
      resolved: e.resolved || null,
      integrity: e.integrity || null,
      scripts: scriptsKnown ? e.hasInstallScript === true : null,
      link: e.link === true,
      local,
      dev: Boolean(e.dev || e.devOptional),
      deps,
      devDeps: local ? e.devDependencies || {} : {},
      source: local ? null : npmResolved(e, rel),
    });
  };
  try {
    if (lock.packages && typeof lock.packages === "object") {
      for (const [key, e] of Object.entries(lock.packages)) add(key, e, true);
    } else if (lock.dependencies && typeof lock.dependencies === "object") {
      // lockfileVersion 1: nested, with no record of install scripts.
      const walk = (deps, prefix) => {
        for (const [name, e] of Object.entries(deps)) {
          const key = `${prefix}node_modules/${name}`;
          add(key, { ...e, version: /^\d/.test(e.version || "") ? e.version : e.version, resolved: e.resolved || (/^(?:git|github|file|https?):/.test(e.version || "") ? e.version : undefined) }, false);
          if (e.dependencies) walk(e.dependencies, `${key}/`);
        }
      };
      add("", { dependencies: {} }, false);
      walk(lock.dependencies, "");
    } else return "it holds neither `packages` nor `dependencies`";
  } catch (e) {
    return e.message;
  }
  out.locks.push({ eco: "npm", path: rel, format: lock.packages ? `v${lock.lockfileVersion}` : "v1", entries });
  return null;
}

// Settings in an .npmrc that change what npm downloads or whom it trusts to serve it, besides
// registry=: a proxy sees and can replace every package, and so can a server npm is told to trust.
const NPMRC_SOURCE = new Set(["proxy", "https-proxy", "http-proxy", "cafile", "ca", "ca[]", "replace-registry-host"]);

// `registry=` and `@scope:registry=` in an .npmrc, and the settings above.
function readNpmrc(rel, text, out) {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^((?:@[^:\s]+:)?registry)\s*=\s*(.*)$/.exec(line);
    if (m) {
      out.indexes.push({ eco: "npm", file: rel, scope: m[1].includes(":") ? m[1].split(":")[0] : null, url: m[2].trim().replace(/^["']|["']$/g, "") });
      continue;
    }
    const kv = /^([A-Za-z][\w.[\]-]*)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const value = kv[2].trim().replace(/^["']|["']$/g, "");
    if (NPMRC_SOURCE.has(key) || (key === "strict-ssl" && value.toLowerCase() === "false")) out.indexes.push({ eco: "npm", file: rel, scope: null, kind: "setting", url: `${key}=${value}` });
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Python

const PY_NAME = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/s;
const PY_ANY = (spec) => {
  const s = spec.replace(/^\(|\)$/g, "").trim();
  return s === "" || s === "*" || s === "==*" || /^>=\s*0(?:\.0)*$/.test(s);
};
const VCS = /^(?:git|hg|svn|bzr)\+/;

/** A URL or path requirement's source, and the name it installs when the line does not say. */
function pyLocation(loc, manifest) {
  if (VCS.test(loc)) {
    // git+https://host/repo.git@ref#egg=name
    const noFrag = loc.replace(/#.*$/, "");
    const at = /^(.*:\/\/[^/]+\/[^@]*)@([^@/]+)$/.exec(noFrag) || /^([^:]+:[^@]*)@([^@/]+)$/.exec(noFrag.replace(/^[a-z]+\+/, ""));
    const ref = at ? at[2] : "";
    const base = at ? at[1] : noFrag;
    return { source: source("git", canonicalGit(base.replace(/^(?:hg|svn|bzr)\+/, "")), loc, { ref }), anything: !pinsRef(ref), guess: /#.*egg=([^&]+)/.exec(loc)?.[1] || base.replace(/\.git$/, "").split("/").pop() };
  }
  if (/^https?:\/\//i.test(loc)) {
    const file = loc.replace(/[?#].*$/, "").split("/").pop() || "";
    return { source: source("url", normUrl(loc).replace(/[^/]*$/, ""), loc), anything: false, guess: /#.*egg=([^&]+)/.exec(loc)?.[1] || file.split("-")[0] };
  }
  const raw = loc.replace(/^file:(?:\/\/)?/, "");
  const ps = pathSource(loc, manifest, raw);
  return { source: ps, anything: false, guess: raw.replace(/\/+$/, "").split("/").pop() };
}

/** One PEP 508 requirement, or a URL or path with its name, or null when it is neither. */
export function pyRequirement(text, manifest) {
  const s = text.trim();
  if (VCS.test(s) || /^https?:\/\//i.test(s) || /^(?:\.{1,2}(?:\/|$)|\/|file:)/.test(s)) {
    const loc = pyLocation(s.split(/\s*;\s*/)[0], manifest);
    return { name: loc.guess, spec: s, source: loc.source, anything: loc.anything };
  }
  const m = PY_NAME.exec(s);
  if (!m) return null;
  let rest = m[3].trim();
  const marker = rest.search(/;/);
  if (rest.startsWith("@")) {
    const url = rest.slice(1).trim().split(/\s+;|\s+/)[0];
    const loc = pyLocation(url, manifest);
    return { name: m[1], spec: s, source: loc.source, anything: loc.anything };
  }
  if (marker >= 0) rest = rest.slice(0, marker).trim();
  if (rest && !/^[(<>=!~][^;]*$/.test(rest) && rest !== "*") return null;
  return { name: m[1], spec: s, source: REGISTRY("PyPI"), anything: PY_ANY(rest), pinned: /^\(?\s*===?\s*[^,*]+\)?$/.test(rest) };
}

const REQ_OPTIONS_IGNORED = new Set(["--pre", "--prefer-binary", "--require-hashes", "--only-binary", "--no-binary", "--use-feature", "--trusted-host", "--no-deps", "--progress-bar"]);
const REQ_OPTIONS_VALUE = new Set(["--only-binary", "--no-binary", "--use-feature", "--trusted-host", "--progress-bar"]);

/** A requirements file: { deps, indexes, includes, pins } or { error }. */
export function parseRequirements(text, manifest) {
  const deps = [];
  const indexes = [];
  const includes = [];
  const pins = new Set();
  const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n].replace(/(^|\s)#.*$/, "").trim();
    if (!line) continue;
    const at = `line ${n + 1}`;
    if (line.startsWith("-")) {
      const m = /^(-[A-Za-z]|--[a-z-]+)(?:[=\s]\s*(.*))?$/.exec(line);
      if (!m) return { error: `${at}: an option this rule does not read: ${line.slice(0, 80)}` };
      const [opt, value = ""] = [m[1], (m[2] || "").trim()];
      if (opt === "-r" || opt === "--requirement") includes.push({ type: "requirement", path: value });
      else if (opt === "-c" || opt === "--constraint") includes.push({ type: "constraint", path: value });
      else if (opt === "-e" || opt === "--editable") {
        const r = pyRequirement(value, manifest);
        if (!r) return { error: `${at}: an editable requirement this rule does not read: ${value.slice(0, 80)}` };
        deps.push({ ...r, editable: true });
      } else if (opt === "-i" || opt === "--index-url") indexes.push({ kind: "index-url", url: value });
      else if (opt === "--extra-index-url") indexes.push({ kind: "extra-index-url", url: value });
      else if (opt === "-f" || opt === "--find-links") indexes.push({ kind: "find-links", url: value });
      else if (opt === "--no-index") indexes.push({ kind: "no-index", url: "" });
      else if (REQ_OPTIONS_IGNORED.has(opt)) {
        if (REQ_OPTIONS_VALUE.has(opt) && !value) return { error: `${at}: ${opt} with no value` };
      } else return { error: `${at}: an option this rule does not read: ${opt}` };
      continue;
    }
    // Per-requirement options: hashes and build settings, none of which change what is named.
    const req = line.replace(/\s+--(?:hash|config-settings|global-option|install-option)(?:=|\s+)\S+/g, "").trim();
    const r = pyRequirement(req, manifest);
    if (!r) return { error: `${at}: a requirement this rule does not read: ${line.slice(0, 80)}` };
    deps.push(r);
    if (r.pinned) pins.add(normalName("PyPI", r.name));
  }
  return { deps, indexes, includes, pins };
}

const isTable = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** A poetry or Pipfile dependency value: a constraint string, a table, or a list of tables. */
function tomlDep(name, v, manifest, section, out, named = {}) {
  const one = (x) => {
    if (typeof x === "string") return { source: REGISTRY("PyPI"), anything: PY_ANY(x) || x.trim() === "" };
    if (!isTable(x)) return null;
    if (typeof x.git === "string") {
      const ref = x.tag || x.rev || x.ref || "";
      return { source: source("git", canonicalGit(x.git), x.git, { ref: x.branch || ref }), anything: !pinsRef(ref) };
    }
    if (typeof x.path === "string") return { source: pathSource(x.path, manifest, x.path), anything: false };
    if (typeof x.url === "string") return { source: source("url", normUrl(x.url).replace(/[^/]*$/, ""), x.url), anything: false };
    if (typeof x.file === "string") return { source: pathSource(x.file, manifest, x.file.replace(/^file:(?:\/\/)?/, "")), anything: false };
    const idx = x.source || x.index;
    const src = typeof idx === "string" ? source("index", named[idx] || idx, `the index ${idx}${named[idx] ? ` (${named[idx]})` : ""}`, { raw: named[idx] || idx }) : REGISTRY("PyPI");
    return { source: src, anything: typeof x.version !== "string" || PY_ANY(x.version) };
  };
  for (const x of Array.isArray(v) ? v : [v]) {
    const r = one(x);
    if (!r) return `${section}.${name} is not a version or a table`;
    out.decl.push({ eco: "PyPI", name, key: normalName("PyPI", name), declaredAs: name, spec: typeof x === "string" ? x : JSON.stringify(x), manifest, section, source: r.source, anything: r.anything, role: "dependency" });
  }
  return null;
}

// `role`: "dependency" installs, "build" installs for a build, "override" (an override or a
// constraint) adds no name of its own and can say where an existing one comes from.
function pushPep508(list, manifest, section, out, role = section === "build-system.requires" ? "build" : "dependency") {
  if (!Array.isArray(list)) return `${section} is not a list`;
  for (const raw of list) {
    if (isTable(raw) && typeof raw["include-group"] === "string") continue;
    // uv's extra-build-dependencies take { requirement, match-runtime } as well as a string.
    const item = isTable(raw) && typeof raw.requirement === "string" ? raw.requirement : raw;
    if (typeof item !== "string") return `${section} holds something that is not a requirement`;
    // Hatch formats a requirement first: {root:uri} is the project's directory.
    const text = item.replace(/\{root((?::parent)*)(?::real)?:uri\}/g, (_, up) => `file:${up ? up.split(":").filter(Boolean).map(() => "..").join("/") : "."}`);
    const r = pyRequirement(text, manifest);
    if (!r) return `${section} holds a requirement this rule does not read: ${item.slice(0, 80)}`;
    out.decl.push({ eco: "PyPI", name: r.name, key: normalName("PyPI", r.name), declaredAs: r.name, spec: item, manifest, section, source: r.source, anything: r.anything, role });
  }
  return null;
}

// Hatch's environments and build: in pyproject.toml under tool.hatch, or in hatch.toml at the top.
function pushHatch(hatch, prefix, manifest, out, errs) {
  if (!isTable(hatch)) return;
  for (const [env, t] of Object.entries(isTable(hatch.envs) ? hatch.envs : {})) {
    if (!isTable(t)) continue;
    for (const k of ["dependencies", "extra-dependencies"]) if (t[k] !== undefined) errs.push(pushPep508(t[k], manifest, `${prefix}envs.${env}.${k}`, out));
  }
  const build = isTable(hatch.build) ? hatch.build : {};
  const hooks = (h, at) => {
    for (const [name, t] of Object.entries(isTable(h) ? h : {})) if (isTable(t) && t.dependencies !== undefined) errs.push(pushPep508(t.dependencies, manifest, `${at}.hooks.${name}.dependencies`, out, "build"));
  };
  hooks(build.hooks, `${prefix}build`);
  for (const [target, t] of Object.entries(isTable(build.targets) ? build.targets : {})) {
    if (!isTable(t)) continue;
    if (t.dependencies !== undefined) errs.push(pushPep508(t.dependencies, manifest, `${prefix}build.targets.${target}.dependencies`, out, "build"));
    hooks(t.hooks, `${prefix}build.targets.${target}`);
  }
}

function readHatchToml(rel, text, out) {
  const t = readToml(text);
  if (t.error) return `it is not TOML (${t.error})`;
  const errs = [];
  pushHatch(t.value, "", rel, out, errs);
  return errs.find(Boolean) || null;
}

function readPyproject(rel, text, out) {
  const t = readToml(text);
  if (t.error) return `it is not TOML (${t.error})`;
  const doc = t.value;
  const project = doc.project;
  if (project !== undefined && !isTable(project)) return "[project] is not a table";
  if (typeof project?.name === "string") out.pyOwn.set(rel, normalName("PyPI", project.name));
  const tool = isTable(doc.tool) ? doc.tool : {};
  const uv = isTable(tool.uv) ? tool.uv : {};
  const poetry = isTable(tool.poetry) ? tool.poetry : {};
  if (typeof poetry.name === "string" && !out.pyOwn.has(rel)) out.pyOwn.set(rel, normalName("PyPI", poetry.name));
  const named = {};
  for (const [label, list] of [["tool.uv.index", uv.index], ["tool.poetry.source", poetry.source], ["tool.pdm.source", tool.pdm?.source]]) {
    if (list === undefined) continue;
    if (!Array.isArray(list)) return `${label} is not a list`;
    for (const s of list) {
      if (!isTable(s) || typeof s.url !== "string") return `${label} holds an entry with no url`;
      if (typeof s.name === "string") named[s.name] = s.url;
      out.indexes.push({ eco: "PyPI", file: rel, kind: label, url: s.url });
    }
  }
  const uvPip = isTable(uv.pip) ? uv.pip : {};
  for (const k of ["index-url", "extra-index-url", "find-links"]) {
    for (const u of [uv[k]].flat()) if (typeof u === "string") out.indexes.push({ eco: "PyPI", file: rel, kind: `tool.uv.${k}`, url: u });
    for (const u of [uvPip[k]].flat()) if (typeof u === "string") out.indexes.push({ eco: "PyPI", file: rel, kind: `tool.uv.pip.${k}`, url: u });
  }
  // setuptools reads dependencies from files the pyproject names (tool.setuptools.dynamic).
  const dyn = isTable(tool.setuptools?.dynamic) ? tool.setuptools.dynamic : {};
  for (const v of [dyn.dependencies, ...Object.values(isTable(dyn["optional-dependencies"]) ? dyn["optional-dependencies"] : {})]) {
    for (const file of [v?.file].flat()) if (typeof file === "string") out.extraRequirements.push(path.posix.normalize(path.posix.join(path.posix.dirname(rel) === "." ? "" : path.posix.dirname(rel), file)));
  }
  const before = out.decl.length;
  const errs = [];
  if (project?.dependencies !== undefined) errs.push(pushPep508(project.dependencies, rel, "project.dependencies", out));
  for (const [g, list] of Object.entries(isTable(project?.["optional-dependencies"]) ? project["optional-dependencies"] : {})) errs.push(pushPep508(list, rel, `project.optional-dependencies.${g}`, out));
  for (const [g, list] of Object.entries(isTable(doc["dependency-groups"]) ? doc["dependency-groups"] : {})) errs.push(pushPep508(list, rel, `dependency-groups.${g}`, out));
  if (doc["build-system"]?.requires !== undefined) errs.push(pushPep508(doc["build-system"].requires, rel, "build-system.requires", out));
  for (const [g, list] of Object.entries(isTable(tool.pdm?.["dev-dependencies"]) ? tool.pdm["dev-dependencies"] : {})) errs.push(pushPep508(list, rel, `tool.pdm.dev-dependencies.${g}`, out));
  // uv: what installs beside the project, and what overrides or constrains a resolution or a build.
  if (uv["dev-dependencies"] !== undefined) errs.push(pushPep508(uv["dev-dependencies"], rel, "tool.uv.dev-dependencies", out));
  for (const k of ["override-dependencies", "constraint-dependencies", "build-constraint-dependencies"]) if (uv[k] !== undefined) errs.push(pushPep508(uv[k], rel, `tool.uv.${k}`, out, "override"));
  if (uv["extra-build-dependencies"] !== undefined) {
    if (!isTable(uv["extra-build-dependencies"])) return "tool.uv.extra-build-dependencies is not a table";
    for (const [name, list] of Object.entries(uv["extra-build-dependencies"])) errs.push(pushPep508(list, rel, `tool.uv.extra-build-dependencies.${name}`, out, "build"));
  }
  // pdm: an override is a version, or a URL or path to take the package from.
  const pdmOver = tool.pdm?.resolution?.overrides;
  if (pdmOver !== undefined) {
    if (!isTable(pdmOver)) return "tool.pdm.resolution.overrides is not a table";
    for (const [name, v] of Object.entries(pdmOver)) {
      if (typeof v !== "string") return `tool.pdm.resolution.overrides.${name} is not a string`;
      const req = /^[a-z][a-z0-9+.-]*:|^\.{0,2}\//i.test(v) ? `${name} @ ${v}` : /^\d/.test(v) ? `${name}==${v}` : `${name}${v}`;
      errs.push(pushPep508([req], rel, `tool.pdm.resolution.overrides`, out, "override"));
    }
  }
  pushHatch(tool.hatch, "tool.hatch.", rel, out, errs);
  // requires-plugins: poetry installs them into its own environment, and runs them.
  const poetryTables = [["tool.poetry.dependencies", poetry.dependencies], ["tool.poetry.dev-dependencies", poetry["dev-dependencies"]], ["tool.poetry.requires-plugins", poetry["requires-plugins"]]];
  for (const [g, grp] of Object.entries(isTable(poetry.group) ? poetry.group : {})) poetryTables.push([`tool.poetry.group.${g}.dependencies`, grp?.dependencies]);
  for (const [section, tbl] of poetryTables) {
    if (tbl === undefined) continue;
    if (!isTable(tbl)) return `${section} is not a table`;
    for (const [name, v] of Object.entries(tbl)) if (name !== "python") errs.push(tomlDep(name, v, rel, section, out, named));
  }
  const err = errs.find(Boolean);
  if (err) return err;
  // tool.uv.sources says where a dependency declared above comes from.
  if (uv.sources !== undefined) {
    if (!isTable(uv.sources)) return "tool.uv.sources is not a table";
    for (const [name, v] of Object.entries(uv.sources)) {
      const key = normalName("PyPI", name);
      for (const x of Array.isArray(v) ? v : [v]) {
        if (!isTable(x)) return `tool.uv.sources.${name} is not a table`;
        let src;
        if (x.workspace === true) src = source("path", `workspace:${key}`, "a uv workspace member", { own: true });
        else if (typeof x.git === "string") src = source("git", canonicalGit(x.git), x.git, { ref: x.tag || x.rev || x.branch || "" });
        else if (typeof x.path === "string") src = pathSource(x.path, rel, x.path);
        else if (typeof x.url === "string") src = source("url", normUrl(x.url).replace(/[^/]*$/, ""), x.url);
        else if (typeof x.index === "string") src = source("index", named[x.index] || x.index, `the index ${x.index}`, { raw: named[x.index] || x.index });
        else return `tool.uv.sources.${name} names no source this rule reads`;
        const anything = src.type === "git" && !pinsRef(x.tag || x.rev || "");
        for (const d of out.decl.slice(before)) if (d.key === key) Object.assign(d, { source: src, anything: d.anything || anything });
      }
    }
  }
  return null;
}

function readPipfile(rel, text, out) {
  const t = readToml(text);
  if (t.error) return `it is not TOML (${t.error})`;
  const named = {};
  for (const s of [t.value.source].flat().filter(Boolean)) {
    if (!isTable(s) || typeof s.url !== "string") return "a [[source]] has no url";
    if (typeof s.name === "string") named[s.name] = s.url;
    out.indexes.push({ eco: "PyPI", file: rel, kind: "source", url: s.url });
  }
  for (const [section, tbl] of Object.entries(t.value)) {
    if (["source", "requires", "scripts", "pipenv"].includes(section) || !isTable(tbl)) continue;
    for (const [name, v] of Object.entries(tbl)) {
      const err = tomlDep(name, v, rel, section, out, named);
      if (err) return err;
    }
  }
  return null;
}

function readUvToml(rel, text, out) {
  const t = readToml(text);
  if (t.error) return `it is not TOML (${t.error})`;
  for (const k of ["index-url", "extra-index-url", "find-links"]) for (const u of [t.value[k]].flat()) if (typeof u === "string") out.indexes.push({ eco: "PyPI", file: rel, kind: k, url: u });
  for (const s of [t.value.index].flat().filter(Boolean)) if (isTable(s) && typeof s.url === "string") out.indexes.push({ eco: "PyPI", file: rel, kind: "index", url: s.url });
  return null;
}

// `files`: each file's name and hash, so a file whose hash changed while its version did not shows.
// A re-lock may add or drop files of one version (wheels for more or fewer platforms); it does not
// change one. `urls`: where the files download from, when the lockfile says.
function pyLockEntry(rel, name, version, src, scripts, deps, files = [], urls = []) {
  return { key: `${normalName("PyPI", name)}@${version}`, name, version, source: src, scripts, deps, local: src?.own === true, integrity: null, files: new Map(files), urls };
}
const fileName = (u) => String(u).replace(/[?#].*$/, "").split("/").pop();

function readUvLock(rel, text, out) {
  const t = readToml(text);
  if (t.error) return `it is not TOML (${t.error})`;
  if (!Array.isArray(t.value.package)) return "it has no [[package]] list";
  const entries = new Map();
  for (const p of t.value.package) {
    if (!isTable(p) || typeof p.name !== "string") return "a [[package]] has no name";
    const s = isTable(p.source) ? p.source : {};
    let src;
    if (typeof s.registry === "string") src = source("index", slash(s.registry), s.registry);
    else if (typeof s.git === "string") src = source("git", canonicalGit(s.git), s.git);
    else if (typeof s.url === "string") src = source("url", normUrl(s.url).replace(/[^/]*$/, ""), s.url);
    else {
      const local = s.editable ?? s.virtual ?? s.directory ?? s.path;
      if (typeof local !== "string") return `package ${p.name} has a source this rule does not read`;
      src = pathSource(local, rel, local);
    }
    const wheels = Array.isArray(p.wheels) ? p.wheels.length : 0;
    const deps = [p.dependencies, ...Object.values(isTable(p["optional-dependencies"]) ? p["optional-dependencies"] : {}), ...Object.values(isTable(p["dev-dependencies"]) ? p["dev-dependencies"] : {})]
      .flat()
      .filter((d) => isTable(d) && typeof d.name === "string")
      .map((d) => normalName("PyPI", d.name));
    const builds = src.type !== "path" && !wheels && (isTable(p.sdist) || src.type === "git");
    const files = [p.sdist, ...(Array.isArray(p.wheels) ? p.wheels : [])].filter(isTable);
    const e = pyLockEntry(rel, p.name, String(p.version ?? ""), src, builds, deps, files.filter((x) => typeof x.url === "string" && typeof x.hash === "string").map((x) => [fileName(x.url), x.hash]), files.map((x) => x.url).filter((u) => typeof u === "string"));
    entries.set(e.key, e);
  }
  out.locks.push({ eco: "PyPI", path: rel, format: "uv.lock", entries });
  return null;
}

function readPoetryLock(rel, text, out) {
  const t = readToml(text);
  if (t.error) return `it is not TOML (${t.error})`;
  const entries = new Map();
  for (const p of [t.value.package].flat().filter(Boolean)) {
    if (!isTable(p) || typeof p.name !== "string") return "a [[package]] has no name";
    const s = isTable(p.source) ? p.source : null;
    let src = REGISTRY("PyPI");
    if (s?.type === "git") src = source("git", canonicalGit(s.url || ""), s.url || "");
    else if (s?.type === "legacy") src = source("index", slash(s.url || ""), s.url || "");
    else if (s?.type === "url") src = source("url", normUrl(s.url || "").replace(/[^/]*$/, ""), s.url || "");
    else if (s?.type === "file" || s?.type === "directory") src = pathSource(s.url || "", rel, s.url || "");
    else if (s) return `package ${p.name} has a source type this rule does not read (${s.type})`;
    const files = Array.isArray(p.files) ? p.files.map((f) => f?.file).filter((f) => typeof f === "string") : null;
    const builds = src.type === "git" || (Array.isArray(files) && files.length > 0 && !files.some((f) => f.endsWith(".whl")));
    const named = Array.isArray(p.files) ? p.files.filter((x) => typeof x?.file === "string" && typeof x?.hash === "string").map((x) => [x.file, x.hash]) : [];
    const e = pyLockEntry(rel, p.name, String(p.version ?? ""), src, builds, Object.keys(isTable(p.dependencies) ? p.dependencies : {}).map((d) => normalName("PyPI", d)), named);
    entries.set(e.key, e);
  }
  out.locks.push({ eco: "PyPI", path: rel, format: "poetry.lock", entries });
  return null;
}

function readPipfileLock(rel, text, out) {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch (e) {
    return `it is not JSON (${e.message})`;
  }
  const named = Object.fromEntries((lock?._meta?.sources || []).filter((s) => s?.name && s?.url).map((s) => [s.name, s.url]));
  const entries = new Map();
  for (const section of ["default", "develop"]) {
    for (const [name, p] of Object.entries(isTable(lock?.[section]) ? lock[section] : {})) {
      let src = REGISTRY("PyPI");
      if (typeof p?.git === "string") src = source("git", canonicalGit(p.git), p.git);
      else if (typeof p?.path === "string") src = pathSource(p.path, rel, p.path);
      else if (typeof p?.file === "string") src = source("url", normUrl(p.file).replace(/[^/]*$/, ""), p.file);
      else if (typeof p?.index === "string" && named[p.index] && !DEFAULT_PYPI.some((d) => slash(named[p.index]).startsWith(d))) src = source("index", slash(named[p.index]), named[p.index]);
      const version = String(p?.version || "").replace(/^==/, "");
      // Pipfile.lock records hashes, not whether a file is a wheel, and no edges.
      const e = pyLockEntry(rel, name, version, src, null, null);
      entries.set(e.key, e);
    }
  }
  out.locks.push({ eco: "PyPI", path: rel, format: "Pipfile.lock", entries });
  return null;
}

// ---------------------------------------------------------------------------------------------
// Go

const GO_DIRECTIVES = new Set(["module", "go", "toolchain", "godebug", "require", "exclude", "replace", "retract", "tool", "ignore", "use"]);

function goTokens(line) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|`([^`]*)`|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/** go.mod or go.work: { module, requires, replaces, tools, uses } or { error }. */
export function parseGoMod(text, { work = false } = {}) {
  const res = { module: null, requires: [], replaces: [], tools: [], uses: [] };
  let block = null;
  const lines = text.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const raw = lines[n];
    const c = raw.indexOf("//");
    const indirect = c >= 0 && /^\/\/\s*indirect\b/.test(raw.slice(c).trim());
    const line = (c >= 0 ? raw.slice(0, c) : raw).trim();
    if (!line) continue;
    let directive;
    let args;
    if (block) {
      if (line === ")") {
        block = null;
        continue;
      }
      directive = block;
      args = goTokens(line);
    } else {
      const t = goTokens(line);
      directive = t[0];
      if (!GO_DIRECTIVES.has(directive) || (work && ["module", "require", "exclude", "retract", "tool", "ignore"].includes(directive)) || (!work && directive === "use")) {
        return { error: `line ${n + 1}: ${JSON.stringify(directive)} is not a ${work ? "go.work" : "go.mod"} directive` };
      }
      if (t[1] === "(" && t.length === 2) {
        block = directive;
        continue;
      }
      args = t.slice(1);
    }
    const at = `line ${n + 1}`;
    if (directive === "module") res.module = args[0];
    else if (directive === "require") {
      if (args.length !== 2) return { error: `${at}: a require line that is not a module and a version` };
      res.requires.push({ path: args[0], version: args[1], indirect });
    } else if (directive === "replace") {
      const arrow = args.indexOf("=>");
      if (arrow < 1 || arrow > 2 || args.length - arrow - 1 < 1 || args.length - arrow - 1 > 2) return { error: `${at}: a replace line this rule does not read` };
      res.replaces.push({ path: args[0], version: arrow === 2 ? args[1] : null, to: args[arrow + 1], toVersion: args[arrow + 2] || null });
    } else if (directive === "tool") res.tools.push(args[0]);
    else if (directive === "use") res.uses.push(args[0]);
  }
  if (block) return { error: `a ${block} block that does not close` };
  if (!work && !res.module) return { error: "no module line" };
  return res;
}

function readGoMod(rel, text, out, work) {
  const g = parseGoMod(text, { work });
  if (g.error) return g.error;
  if (g.module) out.goModules.set(rel, g.module);
  if (work) out.goWork.push({ file: rel, uses: g.uses });
  for (const t of g.tools) out.goTools.add(t);
  for (const r of g.requires) {
    out.decl.push({ eco: "Go", name: r.path, key: r.path, declaredAs: r.path, spec: r.version, manifest: rel, section: r.indirect ? "require // indirect" : "require", source: REGISTRY("the Go module proxy"), anything: false, role: r.indirect ? "indirect" : "dependency" });
  }
  for (const r of g.replaces) {
    const local = /^(?:\.{1,2}\/|\/)/.test(r.to) || r.to === "." || r.to === "..";
    const src = local ? pathSource(r.to, rel, r.to) : source("module", r.to, `${r.to}${r.toVersion ? ` ${r.toVersion}` : ""}`);
    out.replaces.push({ eco: "Go", file: rel, path: r.path, source: src });
  }
  return null;
}

function readGoSum(rel, text, out) {
  const modules = new Set();
  for (const [n, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line) continue;
    const t = line.split(/\s+/);
    if (t.length !== 3 || !/^h\d:/.test(t[2])) return `line ${n + 1} is not a module, a version and a hash`;
    modules.add(t[0]);
  }
  out.goSums.push({ path: rel, modules });
  return null;
}

// A Go interpreted string literal's text: go reads "github.com/pkg/\x65rrors" as the plain path.
const GO_ESC = { a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"' };
function goUnquote(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\") {
      bytes.push(...Buffer.from(s[i], "utf8"));
      continue;
    }
    const c = s[i + 1];
    let m;
    if (GO_ESC[c] !== undefined) {
      bytes.push(GO_ESC[c].charCodeAt(0));
      i += 1;
    } else if (c === "x" && (m = /^[0-9a-fA-F]{2}/.exec(s.slice(i + 2)))) {
      bytes.push(parseInt(m[0], 16));
      i += 3;
    } else if ((m = /^[0-7]{3}/.exec(s.slice(i + 1)))) {
      bytes.push(parseInt(m[0], 8) & 0xff);
      i += 3;
    } else if ((c === "u" && (m = /^[0-9a-fA-F]{4}/.exec(s.slice(i + 2)))) || (c === "U" && (m = /^[0-9a-fA-F]{8}/.exec(s.slice(i + 2))))) {
      bytes.push(...Buffer.from(String.fromCodePoint(parseInt(m[0], 16)), "utf8"));
      i += 1 + m[0].length;
    } else bytes.push(92);
  }
  return Buffer.from(bytes).toString("utf8");
}

/** The import paths in Go source, read without a parser: `import "x"`, `import y "x"` and blocks. */
export function goImports(text) {
  const out = [];
  const src = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const lit = (q, b) => (q !== undefined ? goUnquote(q) : b);
  for (const m of src.matchAll(/\bimport\s*\(([^)]*)\)/g)) for (const s of m[1].matchAll(/"((?:[^"\\\n]|\\.)+)"|`([^`]+)`/g)) out.push(lit(s[1], s[2]));
  for (const m of src.matchAll(/\bimport\s+(?:[A-Za-z_.][\w.]*\s+)?(?:"((?:[^"\\\n]|\\.)+)"|`([^`]+)`)/g)) out.push(lit(m[1], m[2]));
  return out;
}

// ---------------------------------------------------------------------------------------------
// A tree's dependencies

/**
 * Everything this rule reads in a tree: declarations, lockfile entries, registries and indexes, and
 * the files it could not read ({ errors: [{ path, why }] }).
 */
export function inventory(tree) {
  const out = { decl: [], locks: [], indexes: [], replaces: [], manifests: [], pyOwn: new Map(), goModules: new Map(), goWork: [], goTools: new Set(), goSums: [], lockDirs: { npm: new Set(), PyPI: new Set() }, pins: new Map(), errors: [], files: tree.files, read: tree.read, extraRequirements: [] };
  const readers = [];
  const queue = [];
  for (const rel of tree.files) {
    const base = path.posix.basename(rel);
    const dir = path.posix.dirname(rel);
    const parts = rel.split("/");
    const goSkip = parts.slice(0, -1).some((p) => p === "testdata" || p === "vendor");
    if (base === "package.json") readers.push([rel, readNpmManifest]);
    else if (base === "package-lock.json" || base === "npm-shrinkwrap.json") readers.push([rel, readNpmLock]);
    else if (base === ".npmrc") readers.push([rel, readNpmrc]);
    else if (base === "pyproject.toml") readers.push([rel, readPyproject]);
    else if (base === "Pipfile") readers.push([rel, readPipfile]);
    else if (base === "uv.toml") readers.push([rel, readUvToml]);
    else if (base === "hatch.toml") readers.push([rel, readHatchToml]);
    else if (base === "uv.lock") readers.push([rel, readUvLock]);
    else if (base === "poetry.lock") readers.push([rel, readPoetryLock]);
    else if (base === "Pipfile.lock") readers.push([rel, readPipfileLock]);
    else if (isRequirementsFile(rel)) queue.push(rel);
    else if (base === "go.mod" && !goSkip) readers.push([rel, (r, t, o) => readGoMod(r, t, o, false)]);
    else if (base === "go.work" && !goSkip) readers.push([rel, (r, t, o) => readGoMod(r, t, o, true)]);
    else if (base === "go.sum" && !goSkip) readers.push([rel, readGoSum]);
    if (["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"].includes(base)) out.lockDirs.npm.add(dir);
    if (["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"].includes(base) || /^pylock(?:\..+)?\.toml$/.test(base)) out.lockDirs.PyPI.add(dir);
  }
  for (const [rel, fn] of readers) {
    const text = tree.read(rel);
    if (text === null || text === undefined) {
      out.errors.push({ path: rel, why: "it could not be read" });
      continue;
    }
    const err = fn(rel, text, out);
    if (err) out.errors.push({ path: rel, why: err });
  }
  // Requirements files, every file one includes with -r or -c, and every file setuptools is told
  // to read dependencies from, whatever it is called.
  queue.push(...out.extraRequirements);
  const seen = new Set();
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    const text = tree.all.has(rel) ? tree.read(rel) : null;
    if (text === null || text === undefined) {
      out.errors.push({ path: rel, why: tree.all.has(rel) ? "it could not be read" : "a requirements file includes it, and it is not in the project" });
      continue;
    }
    const r = parseRequirements(text, rel);
    if (r.error) {
      out.errors.push({ path: rel, why: r.error });
      continue;
    }
    for (const d of r.deps) out.decl.push({ eco: "PyPI", name: d.name, key: normalName("PyPI", d.name), declaredAs: d.name, spec: d.spec, manifest: rel, section: "requirements", source: d.source, anything: d.anything, role: "dependency", pinned: d.pinned });
    for (const x of r.indexes) out.indexes.push({ eco: "PyPI", file: rel, kind: x.kind, url: x.url });
    for (const p of r.pins) out.pins.set(`${rel}|${p}`, true);
    for (const inc of r.includes) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(rel), inc.path));
      if (target.startsWith("../") || path.posix.isAbsolute(inc.path)) {
        out.errors.push({ path: rel, why: `it includes ${inc.path}, which is outside the project` });
        continue;
      }
      queue.push(target);
      if (inc.type === "constraint") out.constraintOf = [...(out.constraintOf || []), [rel, target]];
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The judgement

// Whether a dependency is the project's own code: only where the tool resolves it locally. A name
// that matches a workspace member, a nested project or a nested module is still fetched from the
// registry unless something points the tool at the directory.
function ownSource(d, inv) {
  if (d.source?.own === true) return true;
  if (d.eco === "npm") {
    // The lockfile says where npm puts it: a link to a member, or the registry's package.
    const at = npmLockFor(d.manifest, inv.locks);
    const e = at && npmResolve(at.lock, at.key, d.declaredAs);
    return Boolean(e && (e.local || (e.link && e.source?.own)));
  }
  // A project's own extras, `p[extra]` in p's pyproject.toml. Anywhere else pip and uv look the name up.
  if (d.eco === "PyPI") return inv.pyOwn.get(d.manifest) === d.key;
  if (d.eco === "Go") {
    const dir = path.posix.dirname(d.manifest);
    if (inv.replaces.some((r) => r.path === d.key && r.source.own && (r.file === d.manifest || r.file.endsWith("go.work")))) return true;
    for (const w of inv.goWork) {
      const wdir = path.posix.dirname(w.file);
      const inWork = (x) => wdir === "." || x === wdir || x.startsWith(`${wdir}/`);
      if (!inWork(dir)) continue;
      for (const u of w.uses) {
        const mod = path.posix.join(path.posix.normalize(path.posix.join(wdir === "." ? "" : wdir, u)), "go.mod");
        if (inv.goModules.get(mod) === d.key) return true;
      }
    }
    return false;
  }
  return false;
}

const isRegistryUrl = (eco, url, extra) => {
  const u = slash(normUrl(url));
  return [...(eco === "npm" ? DEFAULT_NPM : DEFAULT_PYPI), ...extra].some((d) => u.startsWith(slash(normUrl(d))));
};

/**
 * For a file from the default registry, whether it is this package's: npm serves a package's tarball
 * at <registry>/<name>/-/<last part of the name>-<version>.tgz, and PyPI names a file <name>-<version>...
 * with the name folded. A registry URL to another package's tarball is the registry, and installs
 * that package under this name. Null when the URL is not on a default registry, where the layout is
 * the registry's own.
 */
export function registryFileMatches(eco, url, name, version) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (eco === "npm") {
    if (!DEFAULT_NPM.some((d) => url.startsWith(d))) return null;
    const p = decodeURIComponent(u.pathname);
    return p === `/${name}/-/${name.split("/").pop()}-${version}.tgz`;
  }
  if (!DEFAULT_PYPI.some((d) => url.startsWith(d))) return null;
  const file = decodeURIComponent(u.pathname.split("/").pop() || "");
  const m = /^(.+?)-(\d[^-]*?)(?:-|\.tar\.gz$|\.zip$|\.tar\.bz2$)/.exec(file);
  return Boolean(m) && normalName("PyPI", m[1]) === normalName("PyPI", name) && m[2] === version;
}

/** Whether a source is the ecosystem's registry, or an index the base already named. */
function fromRegistry(src, eco, baseIndexes) {
  if (!src) return true;
  if (src.type === "registry" || src.type === "bundled") return true;
  if (src.type === "url-resolved" || src.type === "index") return isRegistryUrl(eco, src.raw, baseIndexes);
  return false;
}

// The npm lockfile and the key in it of the package a manifest is, or null.
function npmLockFor(manifest, locks) {
  let dir = path.posix.dirname(manifest);
  for (;;) {
    for (const l of locks) {
      if (l.eco !== "npm") continue;
      const ldir = path.posix.dirname(l.path);
      if (ldir !== dir) continue;
      const mdir = path.posix.dirname(manifest);
      const key = mdir === ldir ? "" : path.posix.relative(ldir === "." ? "" : ldir, mdir);
      if (l.entries.has(key)) return { lock: l, key };
    }
    if (dir === "." || dir === "") return null;
    dir = path.posix.dirname(dir);
  }
}

// Where `name` resolves from the package at `from`, as node does it: the nearest node_modules up.
function npmResolve(lock, from, name) {
  let at = from;
  for (;;) {
    const key = `${at ? `${at}/` : ""}node_modules/${name}`;
    const e = lock.entries.get(key);
    if (e) return e.link && e.resolved !== null ? lock.entries.get(e.resolved) || e : e;
    if (!at) return null;
    const cut = at.lastIndexOf("/node_modules/");
    at = cut >= 0 ? at.slice(0, cut) : at.startsWith("node_modules/") ? "" : "";
  }
}

// `declared`, when given, maps a local entry (the project, a workspace member) to what its
// package.json declares, which is what an install starts from: the lockfile's own record of it is
// the lockfile's to edit.
function npmReach(lock, startKeys, declared = null) {
  const seen = new Set();
  const stack = [...startKeys];
  while (stack.length) {
    const k = stack.pop();
    if (seen.has(k)) continue;
    seen.add(k);
    const e = lock.entries.get(k);
    if (!e) continue;
    const names = e.local && declared?.has(k) ? declared.get(k) : Object.keys({ ...e.deps, ...e.devDeps });
    for (const dep of names) {
      const t = npmResolve(lock, k.includes("node_modules/") || e.local ? k : "", dep);
      if (t && !seen.has(t.key)) stack.push(t.key);
    }
  }
  return seen;
}

function pyReach(lock, names) {
  const byName = new Map();
  for (const e of lock.entries.values()) byName.set(normalName("PyPI", e.name), [...(byName.get(normalName("PyPI", e.name)) || []), e]);
  const seen = new Set();
  const stack = [...names];
  const out = [];
  while (stack.length) {
    const n = stack.pop();
    if (seen.has(n)) continue;
    seen.add(n);
    for (const e of byName.get(n) || []) {
      out.push(e);
      for (const d of e.deps || []) stack.push(d);
    }
  }
  return out;
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// The entry that brings an npm lockfile entry in, named for a person, or null.
function npmParent(lock, e) {
  const name = e.keyName || e.name;
  const p = [...lock.entries.values()].find((x) => x.deps && Object.hasOwn(x.deps, name) && npmResolve(lock, x.key, name)?.key === e.key);
  return p ? p.name || (p.key === "" ? "the project itself" : p.key) : null;
}

const JS_SOURCE = /\.(?:[cm]?[jt]sx?|vue|svelte)$/;

/** JavaScript and TypeScript source without its comments; strings and template text are kept. */
function stripJsComments(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === "/" && text[i + 1] === "/") {
      while (i < n && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? n : end + 2;
      out += " ";
    } else if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < n && text[j] !== c && !(c !== "`" && text[j] === "\n")) j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * The packages JavaScript or TypeScript source imports, by the name node looks for in
 * node_modules: require(), import, import(), export ... from. Relative paths, node: builtins, URLs
 * and subpath imports (#x) are not packages.
 */
export function jsImports(text) {
  const src = stripJsComments(text);
  const specs = [];
  for (const re of [
    /\brequire\s*\(\s*(["'`])([^"'`\n]+)\1\s*\)/g,
    /\bimport\s*\(\s*(["'`])([^"'`\n]+)\1/g,
    /\bimport\s+(?:type\s+)?(?:[\w$*{}\s,]+?\s+from\s*)?(["'])([^"'\n]+)\1/g,
    /\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s*from\s*(["'])([^"'\n]+)\1/g,
  ]) {
    for (const m of src.matchAll(re)) specs.push(m[2]);
  }
  const out = new Set();
  for (const s of specs) {
    if (/^[./#]/.test(s) || /^[a-z][a-z0-9+.-]*:/i.test(s)) continue;
    const parts = s.split("/");
    out.add(s.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0]);
  }
  return [...out];
}

/** The allowlist entry, written out, that would approve a finding. */
export function approvingEntry(f) {
  return {
    kind: f.kind,
    ecosystem: f.eco,
    ...(f.package !== null ? { package: f.package } : {}),
    ...(f.kind === "dependency-source" ? { source: f.sourceShown } : {}),
    reason: "<why a person approved it>",
  };
}

/** The allowlist entry that approves a finding, or null. Never a "*" entry. */
export function depApproved(f, entries) {
  return (
    entries.find((e) => {
      if (e.kind !== f.kind || e.ecosystem !== f.eco) return false;
      if ((e.package ?? null) === null ? f.package !== null : f.package === null || normalName(f.eco, e.package) !== normalName(f.eco, f.package)) return false;
      if (e.path && e.path !== "." && !(f.manifests || []).every((m) => m === e.path || m.startsWith(`${e.path}/`))) return false;
      if (f.kind === "dependency-source" && canonicalSource(f.eco, e.source) !== f.sourceKey) return false;
      return true;
    }) || null
  );
}

/** A source as an allowlist entry gives it, in the form findings compare: git without its ref, a URL's directory. */
export function canonicalSource(eco, raw) {
  const s = String(raw ?? "").trim();
  if (eco === "Go") return /^(?:\.{1,2}\/|\/)/.test(s) || s === "." || s === ".." ? `path:${s}` : `module:${s.split(/\s+/)[0]}`;
  if (VCS.test(s) || /^(?:git:\/\/|github:|gitlab:|bitbucket:|gist:|[^@/\s:]+@[^:/\s]+:)/.test(s) || /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$/.test(s)) return `git:${canonicalGit(s.replace(/#.*$/, "").replace(/@[^@/:]+$/, ""))}`;
  if (/^https?:\/\//i.test(s)) {
    const u = normUrl(s);
    // A file's URL is compared by its directory, so a version move from the same place passes; an
    // index or registry, whole.
    return `url:${/\/[^/]*\.[^/]*$/.test(new URL(u).pathname) ? u.replace(/[^/]*$/, "") : slash(u)}`;
  }
  if (/^(?:file:|link:|portal:|\.{1,2}(?:\/|$)|\/|~)/.test(s)) return `path:${s.replace(/^(?:file|link|portal):(?:\/\/)?/, "")}`;
  if (/^sha\d+-/.test(s)) return `integrity:${s}`;
  return `other:${s}`;
}

/**
 * The dependency rule, for one change: head and base are inventory() results. Returns
 * { findings: [...], errors: [...], notRead: [...] }; a finding carries `approvedBy` when the
 * allowlist approves it. `changed` are the files the change wrote, for notRead.
 */
export function judgeDependencies(head, base, { changed = [], allowlist = [] } = {}) {
  const errors = [
    ...base.errors.map((e) => ({ ...e, side: "the base" })),
    ...head.errors.map((e) => ({ ...e, side: "the head" })),
  ];
  const findings = [];
  const add = (f) => {
    const key = `${f.kind}|${f.eco}|${f.package === null ? "" : normalName(f.eco, f.package)}|${f.sourceKey || ""}`;
    const had = findings.find((x) => x.id === key);
    if (had) {
      for (const m of f.manifests || []) if (!had.manifests.includes(m)) had.manifests.push(m);
      return had;
    }
    const done = { ...f, id: key };
    const by = depApproved(done, allowlist);
    if (by) done.approvedBy = by.reason;
    findings.push(done);
    return done;
  };

  const baseKeys = new Map(); // eco|key -> [decl]
  for (const d of base.decl) if (d.role !== "override") baseKeys.set(`${d.eco}|${d.key}`, [...(baseKeys.get(`${d.eco}|${d.key}`) || []), d]);
  const baseSources = new Map(); // eco|key -> Set(source id)
  const note = (eco, key, src) => {
    if (!src) return;
    const k = `${eco}|${normalName(eco, key)}`;
    if (!baseSources.has(k)) baseSources.set(k, new Set());
    baseSources.get(k).add(src.type === "url-resolved" ? `url:${src.id.slice(13).replace(/[^/]*$/, "")}` : src.id);
  };
  for (const d of base.decl) note(d.eco, d.key, d.source);
  for (const l of base.locks) for (const e of l.entries.values()) if (e.name) note(l.eco, e.name, e.source);
  const baseIdx = { npm: base.indexes.filter((x) => x.eco === "npm" && x.kind !== "setting").map((x) => x.url), PyPI: base.indexes.filter((x) => x.eco === "PyPI").map((x) => x.url) };

  // What the base's lockfiles held, by name and by name@version.
  const baseLock = { npm: new Map(), PyPI: new Map() };
  const baseLockNames = { npm: new Map(), PyPI: new Map() };
  for (const l of base.locks) {
    for (const e of l.entries.values()) {
      if (!e.name || e.local) continue;
      if (e.link && e.source?.own) continue;
      const nk = normalName(l.eco, e.name);
      baseLock[l.eco].set(`${nk}@${e.version}`, e);
      const s = baseLockNames[l.eco].get(nk) || { scripts: false, known: false };
      if (e.scripts === true) s.scripts = true;
      if (e.scripts !== null) s.known = true;
      baseLockNames[l.eco].set(nk, s);
    }
  }
  const baseGoSum = new Set(base.goSums.flatMap((s) => [...s.modules]));

  // What a new direct dependency brings into the lockfile, for the finding a person approves from.
  const brings = (d) => {
    if (d.eco === "npm") {
      const at = npmLockFor(d.manifest, head.locks);
      if (!at) return { lock: null, why: head.lockDirs.npm.size ? "no package-lock.json covers this manifest" : "there is no lockfile" };
      const start = npmResolve(at.lock, at.key, d.declaredAs);
      if (!start) return { lock: at.lock.path, why: `${at.lock.path} does not hold it` };
      const keys = npmReach(at.lock, [start.key]);
      const fresh = [...keys].map((k) => at.lock.entries.get(k)).filter((e) => e && e.name && !e.local && !baseLock.npm.has(`${e.name}@${e.version}`));
      return { lock: at.lock.path, count: fresh.length, scripts: fresh.filter((e) => e.scripts === true).map((e) => e.name), scriptsKnown: fresh.every((e) => e.scripts !== null) };
    }
    if (d.eco === "PyPI") {
      const dir = path.posix.dirname(d.manifest);
      const lock = head.locks.find((l) => l.eco === "PyPI" && l.entries.size && (path.posix.dirname(l.path) === dir || dir.startsWith(`${path.posix.dirname(l.path)}/`) || path.posix.dirname(l.path) === "."));
      if (!lock) return { lock: null, why: "there is no lockfile this rule reads" };
      if (lock.format === "Pipfile.lock") return { lock: lock.path, why: "Pipfile.lock does not record which package brings which" };
      const fresh = pyReach(lock, [d.key]).filter((e) => !e.local && !baseLock.PyPI.has(e.key));
      if (!fresh.length) return { lock: lock.path, why: `${lock.path} does not hold it` };
      return { lock: lock.path, count: fresh.length, scripts: fresh.filter((e) => e.scripts === true).map((e) => e.name), scriptsKnown: true, scriptWord: "build from source" };
    }
    const sums = head.goSums.flatMap((s) => [...s.modules]).filter((m) => !baseGoSum.has(m));
    return { lock: "go.sum", count: new Set(sums).size, scripts: [], scriptsKnown: true, goTotal: true };
  };

  // Go: a module marked `// indirect` is direct if the project imports it.
  let goImported = null;
  const importedByProject = (mod) => {
    if (!goImported) {
      goImported = new Set();
      for (const f of head.files) {
        if (!f.endsWith(".go")) continue;
        if (f.split("/").some((p) => p === "testdata" || p === "vendor")) continue;
        // read lazily through the tree the inventory came from
        const text = head.read(f);
        if (text) for (const p of goImports(text)) goImported.add(p);
      }
    }
    // A tool line runs a package of the module, so the module is the project's as much as an import.
    const inMod = (p) => p === mod || p.startsWith(`${mod}/`);
    if ([...goImported].some(inMod)) return "the project's code imports it";
    if ([...head.goTools].some(inMod)) return "a tool line in go.mod runs it";
    return false;
  };

  // npm: the first file of the project's code that imports a package, by the name node finds it by.
  let jsImported = null;
  const importedByCode = (name) => {
    if (!jsImported) {
      jsImported = new Map();
      for (const f of head.files) {
        if (!JS_SOURCE.test(f)) continue;
        const text = head.read(f);
        if (text) for (const n of jsImports(text)) if (!jsImported.has(n)) jsImported.set(n, f);
      }
    }
    return jsImported.get(name) || null;
  };

  // 1, 2 and 4, from what the manifests declare.
  for (const d of head.decl) {
    if (ownSource(d, head)) continue;
    const k = `${d.eco}|${d.key}`;
    const wasDeclared = baseKeys.has(k);
    const viaIndirect = d.role === "indirect";
    const isNew = !wasDeclared && d.role !== "override" && (!viaIndirect || importedByProject(d.key));
    const aliasNew = d.role === "override" && d.key !== d.declaredAs && !wasDeclared && !baseLockNames.npm.has(d.key);
    const sourceKey = d.source.type === "url-resolved" ? `url:${d.source.id.slice(13).replace(/[^/]*$/, "")}` : d.source.id;
    const raw = d.source.type === "git" ? d.source.raw.replace(/#.*$/, "") : d.source.raw;
    const sourceOk = fromRegistry(d.source, d.eco, baseIdx[d.eco] || []) || baseSources.get(`${d.eco}|${normalName(d.eco, d.key)}`)?.has(sourceKey);
    const shared = {
      eco: d.eco,
      package: d.key === d.declaredAs || d.eco === "PyPI" ? d.name : d.key,
      declaredAs: d.declaredAs !== d.name ? d.declaredAs : null,
      spec: d.spec,
      manifests: [d.manifest],
      section: d.section,
      resolves: d.source.type === "registry" ? d.source.shown : d.source.shown,
    };
    if (isNew || aliasNew) add({ ...shared, kind: "new-dependency", brings: brings(d), indirectMarked: viaIndirect ? importedByProject(d.key) : null });
    if (!sourceOk && (d.role !== "indirect" || isNew)) add({ ...shared, kind: "dependency-source", sourceKey: canonicalSource(d.eco, raw), sourceShown: raw, why: wasDeclared ? "its source changed" : "it is new, and not from the registry" });
    if (d.anything && d.role === "dependency") {
      const unchanged = (baseKeys.get(k) || []).some((b) => b.spec === d.spec);
      const dir = path.posix.dirname(d.manifest);
      const lockDirs = head.lockDirs[d.eco] || new Set();
      let covered = false;
      for (let at = dir; ; at = path.posix.dirname(at)) {
        if (lockDirs.has(at)) covered = true;
        if (at === "." || at === "") break;
      }
      if (d.eco === "PyPI" && d.section === "requirements") covered = (head.constraintOf || []).some(([from, c]) => from === d.manifest && head.pins.has(`${c}|${d.key}`));
      if (!unchanged && !covered) add({ ...shared, kind: "unpinned-range" });
    }
  }

  // Go replace lines: each one says where a module comes from.
  const baseReplace = new Map(base.replaces.map((r) => [r.path, r.source.id]));
  for (const r of head.replaces) {
    if (r.source.own || baseReplace.get(r.path) === r.source.id) continue;
    add({ eco: "Go", package: r.path, kind: "dependency-source", manifests: [r.file], spec: `replace ${r.path} => ${r.source.shown}`, resolves: r.source.shown, sourceKey: canonicalSource("Go", r.source.raw.split(" ")[0]), sourceShown: r.source.raw.split(" ")[0], why: baseReplace.has(r.path) ? "its replace line points somewhere else" : "a replace line the base did not have" });
  }

  // Registries and indexes the project's files name.
  const baseIndexSet = new Set(base.indexes.map((x) => `${x.eco}|${x.scope || ""}|${slash(normUrl(x.url))}`));
  for (const x of head.indexes) {
    if (baseIndexSet.has(`${x.eco}|${x.scope || ""}|${slash(normUrl(x.url))}`)) continue;
    if (x.kind === "no-index") continue;
    const setting = x.kind === "setting";
    add({ eco: x.eco, package: x.scope || null, kind: "dependency-source", manifests: [x.file], spec: setting ? x.url : x.kind ? `${x.kind} ${x.url}` : `${x.scope ? `${x.scope}:` : ""}registry=${x.url}`, resolves: setting ? "wherever that setting sends it" : x.url, sourceKey: canonicalSource(x.eco, x.url), sourceShown: x.url, registry: true, why: setting ? "a setting the base did not have that changes where packages come from, or which server npm trusts to serve them" : "a registry or index the base did not name" });
  }

  // npm names the project's manifests ask for, by the name installed and the name it is installed as.
  const npmDeclared = new Set(head.decl.filter((d) => d.eco === "npm").flatMap((d) => [d.key, d.declaredAs]));
  const baseLockAt = new Map(base.locks.map((l) => [l.path, l]));

  // The lockfiles: entries from a new source, edited in place, nothing brings in, or with a new script.
  for (const l of head.locks) {
    // lockfileVersion 1 records no install scripts, and npm then reads each package for them and
    // runs what it finds. Packages the change added or moved in one cannot be judged for scripts.
    if (l.eco === "npm" && l.format === "v1") {
      const fresh = [...l.entries.values()].filter((e) => e.name && !e.local && !e.link && !baseLock.npm.has(`${normalName("npm", e.name)}@${e.version}`));
      const was = baseLockAt.get(l.path)?.format;
      // A lockfile written back to version 1 is reported even with nothing new in it: no npm since
      // version 7 writes one.
      if (fresh.length || (was && was !== "v1")) {
        const list = fresh.slice(0, 8).map((e) => `${e.name} ${e.version}`).join(", ") + (fresh.length > 8 ? `, +${fresh.length - 8} more` : "");
        errors.push({
          path: l.path,
          side: "the head",
          why: "lockfileVersion 1 records no install scripts",
          text:
            `factory: ${l.path} at the head is lockfileVersion 1, which records no install scripts (${was ? `the base's is ${was}${was === "v1" ? "" : ", so this change rewrote it in the older format"}` : "the base has none"}). ` +
            `${fresh.length ? `The change adds or moves ${plural(fresh.length, "package")} in it (${list}), and npm reads each for a script and runs it. ` : ""}` +
            `Whether this change adds a package that runs code when installed is not known. Write the lockfile with npm 7 or later, which records it.`,
        });
      }
    }
    let reached = null;
    if (l.eco === "npm" && l.format !== "v1") {
      const ldir = path.posix.dirname(l.path);
      const declared = new Map();
      for (const e of l.entries.values()) {
        if (!e.local) continue;
        const manifest = path.posix.normalize(path.posix.join(ldir === "." ? "" : ldir, e.key, "package.json"));
        if (head.manifests.some((m) => m.path === manifest)) declared.set(e.key, head.decl.filter((d) => d.eco === "npm" && d.manifest === manifest && d.role !== "override").map((d) => d.declaredAs));
      }
      reached = npmReach(l, [...l.entries.values()].filter((e) => e.local).map((e) => e.key), declared);
    }
    for (const e of l.entries.values()) {
      if (!e.name || e.local) continue;
      if (e.link && e.source?.own) continue;
      const nk = normalName(l.eco, e.name);
      const before = baseLock[l.eco].get(`${nk}@${e.version}`);
      const shared = { eco: l.eco, package: e.name, spec: e.version, manifests: [l.path], section: "lockfile", resolves: e.source?.shown || "the registry" };
      const srcKey = e.source?.type === "url-resolved" ? `url:${e.source.id.slice(13).replace(/[^/]*$/, "")}` : e.source?.id;
      if (!fromRegistry(e.source, l.eco, baseIdx[l.eco] || []) && !e.source?.own && !baseSources.get(`${l.eco}|${nk}`)?.has(srcKey)) {
        add({ ...shared, kind: "dependency-source", sourceKey: canonicalSource(l.eco, e.source.raw), sourceShown: e.source.type === "git" ? e.source.raw.replace(/#.*$/, "") : e.source.raw, why: "the lockfile takes it from somewhere other than the registry" });
      }
      // A Python lockfile names the files it downloads. From the registry, they are on its own hosts.
      const offHost = l.eco === "PyPI" && fromRegistry(e.source, l.eco, baseIdx.PyPI) ? (e.urls || []).find((u) => !isRegistryUrl("PyPI", u, [...baseIdx.PyPI, ...(e.source?.raw ? [new URL(slash(e.source.raw)).origin] : [])])) : null;
      if (offHost) add({ ...shared, kind: "dependency-source", resolves: offHost, sourceKey: canonicalSource(l.eco, offHost), sourceShown: offHost, why: "the lockfile downloads a file of it from outside the registry" });
      const fileUrls = l.eco === "npm" ? (e.resolved && e.source?.type === "url-resolved" ? [e.resolved] : []) : e.urls || [];
      const other = fileUrls.find((u) => registryFileMatches(l.eco, u, e.name, e.version) === false);
      if (other) add({ ...shared, kind: "dependency-source", resolves: other, sourceKey: canonicalSource(l.eco, other), sourceShown: other, why: `the lockfile takes ${e.name} ${e.version} from a file of the registry's that is not that package's` });
      // The same version from the registry is the same bytes, so an entry edited in place is not npm's doing.
      if (before && fromRegistry(e.source, l.eco, baseIdx[l.eco] || []) && fromRegistry(before.source, l.eco, baseIdx[l.eco] || [])) {
        const what = [];
        if (before.integrity && e.integrity && before.integrity !== e.integrity) what.push("its integrity");
        const changedFile = l.eco === "PyPI" ? [...(e.files || new Map())].find(([n, h]) => before.files?.has(n) && before.files.get(n) !== h) : null;
        if (changedFile) what.push(`the hash of ${changedFile[0]}`);
        if (l.eco === "npm" && before.resolved && e.resolved && normUrl(before.resolved) !== normUrl(e.resolved) && !(isRegistryUrl("npm", before.resolved, []) && isRegistryUrl("npm", e.resolved, []) && before.resolved.split("/-/")[1] === e.resolved.split("/-/")[1])) what.push("where it resolves");
        if (before.scripts === true && e.scripts === false) what.push("its install-script flag (removed)");
        if (l.eco === "npm" && before.scripts !== null && e.scripts !== null && JSON.stringify(Object.keys(before.deps).sort()) !== JSON.stringify(Object.keys(e.deps).sort())) what.push("what it depends on");
        if (what.length) {
          add({ ...shared, kind: "dependency-source", sourceKey: canonicalSource(l.eco, e.integrity || changedFile?.[1] || e.resolved || e.version), sourceShown: e.integrity || changedFile?.[1] || e.resolved || e.version, why: `the entry for ${e.name} ${e.version} was edited in place: ${what.join(", ")} changed while the version did not` });
        }
      }
      if (l.eco === "npm" && reached && !reached.has(e.key) && !before) {
        add({ ...shared, kind: "new-dependency", orphan: true, brings: { lock: l.path, count: 1, scripts: e.scripts ? [e.name] : [], scriptsKnown: e.scripts !== null } });
      }
      // Another package under a key: npm installs `name`'s code where node looks for the key's
      // name. That is an alias, which a manifest or the entry that brings it in declares.
      if (l.eco === "npm" && !e.link && e.keyName && e.name !== e.keyName) {
        const asked = head.decl.some((d) => d.eco === "npm" && d.declaredAs === e.keyName && d.key === e.name);
        const brought = [...l.entries.values()].some((p) => !p.local && typeof p.deps[e.keyName] === "string" && p.deps[e.keyName].startsWith(`npm:${e.name}@`) && npmResolve(l, p.key, e.keyName)?.key === e.key);
        const had = baseLockAt.get(l.path)?.entries.get(e.key)?.name === e.name;
        if (!asked && !brought && !had) add({ ...shared, kind: "new-dependency", installedAs: e.keyName, brings: { lock: l.path, count: 1, scripts: e.scripts ? [e.name] : [], scriptsKnown: e.scripts !== null } });
      }
      // A package new to the lockfile that no manifest declares and the project's code imports. A
      // version move brings what the lockfile says it brings, and the lockfile can be written.
      if (l.eco === "npm" && !e.link && !npmDeclared.has(e.name) && !npmDeclared.has(e.keyName) && !baseLockNames.npm.has(nk)) {
        const file = importedByCode(e.keyName);
        if (file) add({ ...shared, kind: "new-dependency", imported: file, broughtBy: npmParent(l, e), brings: { lock: l.path, count: 1, scripts: e.scripts ? [e.name] : [], scriptsKnown: e.scripts !== null } });
      }
      if (e.scripts === true) {
        const had = baseLockNames[l.eco].get(nk);
        if (!had || (had.known && !had.scripts)) {
          add({ ...shared, kind: "install-script", broughtBy: l.eco === "npm" ? npmParent(l, e) : null, was: had ? "versions at the base had none" : null, scriptWord: l.eco === "PyPI" ? "build" : "script" });
        }
      }
    }
  }

  // Files the change wrote that this rule does not read.
  const notRead = [];
  for (const c of changed) {
    const base = path.posix.basename(c.path);
    const hit = NOT_READ.find(([re]) => re.test(base));
    if (hit) notRead.push({ path: c.path, ecosystem: hit[1] });
  }
  return { findings, errors, notRead };
}

// ---------------------------------------------------------------------------------------------
// Words

const quote = (s) => JSON.stringify(s);

/** The blocking line a person approves from. */
export function findingLine(f) {
  const what = `${f.eco} package ${f.package ?? "(every package)"}`;
  const where = f.manifests.join(", ");
  const entry = JSON.stringify(approvingEntry(f));
  const as = f.declaredAs ? `, declared as ${f.declaredAs}` : "";
  if (f.kind === "new-dependency") {
    const b = f.brings || {};
    let brought;
    const fromLock = f.orphan || f.imported || f.installedAs;
    if (f.orphan) brought = `It is in ${where}, and no manifest declares it and nothing in the lockfile brings it in.`;
    else if (f.imported) brought = `It is new to ${where}${f.broughtBy ? `, brought in by ${f.broughtBy}` : ""}; no manifest declares it, and the project's code imports it (${f.imported}).`;
    else if (f.installedAs) brought = `It is in ${where}, installed as ${f.installedAs}, and neither a manifest nor the package that brings it in declares that alias.`;
    else if (b.count === undefined) brought = `${b.why ? `${b.why[0].toUpperCase()}${b.why.slice(1)}` : "No lockfile covers it"}, so which packages it brings, and whether any runs code when it is installed, is not known.`;
    else if (b.goTotal) brought = `go.sum gains ${plural(b.count, "module")} in all with this change; Go modules run nothing when they are fetched.`;
    else if (!b.count) brought = `It adds no package to ${b.lock}, which already held it and what it needs.`;
    else {
      const runs = b.scriptWord ? ["is built from source when installed, which runs its own code", "are built from source when installed, which runs their own code"] : ["runs code when installed", "run code when installed"];
      const names = `(${b.scripts.slice(0, 8).join(", ")}${b.scripts.length > 8 ? `, +${b.scripts.length - 8} more` : ""})`;
      const s = b.scripts.length
        ? `and ${b.scripts.length} of them ${runs[b.scripts.length === 1 ? 0 : 1]} ${names}`
        : b.scriptsKnown
          ? `none of which ${b.scriptWord ? "is built from source when installed" : "runs code when installed"}`
          : `and the lockfile does not say whether any runs code when installed`;
      brought = `It adds ${plural(b.count, "package")} to ${b.lock}, ${s}.`;
    }
    const indirect = f.indirectMarked ? ` It is marked \`// indirect\`, and ${f.indirectMarked}.` : "";
    return (
      `factory: new dependency — ${what} ${fromLock ? f.spec : quote(f.spec)}${as} in ${where}${fromLock ? "" : ` (${f.section})`}, from ${f.resolves}. ${brought}${indirect} ` +
      `The base did not declare it, and in factory mode a dependency needs a person's approval. Remove it, or have the pipeline's allowlist approve it: ${entry}`
    );
  }
  if (f.kind === "dependency-source") {
    return (
      `factory: dependency from a new source — ${f.registry ? `${f.eco} ${f.package ? `${f.package} packages` : "packages"}: ${f.spec} in ${where}` : `${what} ${quote(f.spec)}${as} in ${where}`}, from ${f.resolves}: ${f.why}. ` +
      `Approving a name does not approve where it comes from. Take it from the registry, or have the pipeline's allowlist approve this source: ${entry}`
    );
  }
  if (f.kind === "install-script") {
    const how = f.scriptWord === "build" ? "has only a source distribution in the lockfile, so installing it builds it, which runs its own code" : "runs code when it is installed (hasInstallScript in the lockfile)";
    return (
      `factory: install script — ${what} ${f.spec} in ${where} ${how}${f.broughtBy ? `, brought in by ${f.broughtBy}` : ""}${f.was ? `; its ${f.was}` : ""}. ` +
      `Approving its name does not approve the script. Drop it, or have the pipeline's allowlist approve it: ${entry}`
    );
  }
  return (
    `factory: a range that takes anything — ${what} ${quote(f.spec)}${as} in ${where} (${f.section}), and no lockfile pins what installs, so the next install takes whatever is published then. ` +
    `Pin a version or commit a lockfile, or have the pipeline's allowlist approve it: ${entry}`
  );
}

/** The allowlist entry for one of DEP_KINDS: { entry } or { error }. */
export function parseDepEntry(e) {
  const eco = ecosystemName(e.ecosystem);
  if (!eco) return { error: `names no ecosystem this rule reads (ecosystem is ${JSON.stringify(e.ecosystem)}; it must be one of ${ECOSYSTEMS.join(", ")})` };
  const hasPackage = e.package !== undefined && e.package !== null;
  if (hasPackage && (typeof e.package !== "string" || !e.package.trim())) return { error: "has a package that is not a name" };
  if (hasPackage && /[*?[\]{}]/.test(e.package)) return { error: "names a pattern; an entry names one package exactly" };
  if (!hasPackage && !(e.kind === "dependency-source" && typeof e.source === "string")) return { error: "names no package" };
  if (e.kind === "dependency-source" && (typeof e.source !== "string" || !e.source.trim())) return { error: "is a dependency-source entry with no source" };
  if (e.path !== undefined && typeof e.path !== "string") return { error: "has a path that is not a string" };
  if (!e.reason || !String(e.reason).trim()) return { error: "gives no reason" };
  return {
    entry: {
      kind: e.kind,
      ecosystem: eco,
      package: hasPackage ? e.package.trim() : null,
      ...(e.kind === "dependency-source" ? { source: e.source.trim() } : {}),
      path: typeof e.path === "string" ? e.path.replace(/^\.\/|\/$/g, "") || "." : ".",
      reason: String(e.reason),
    },
  };
}

