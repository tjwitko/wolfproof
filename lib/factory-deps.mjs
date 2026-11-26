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
//     ecosystem. So is a name in a lockfile that is new to the project (the base's lockfiles did
//     not hold it and its manifests did not declare it) and that no manifest declares, unless a
//     dependency new in the manifests brings it in and that one's finding lists it. A version
//     move's are included, and a first lockfile's. Names new to the project do not vouch for each
//     other.
//   - dependency-source: a dependency the project had that the head takes from another place than
//     the base took it from (a git repository, a URL, a path, a registry or an index: the public
//     registry is a place like any other); a new one from somewhere other than the ecosystem's
//     registry; a registry or index a tool reads for a place that the base did not name there, or
//     one the base named there that the head no longer does, or names in a weaker role; a lockfile
//     entry edited in place, its version the same and what installs different.
//   - install-script: a package new to the lockfile that runs code when it is installed (npm's
//     hasInstallScript; for Python, a lockfile that records only a source distribution, which is
//     built on install), or one whose base versions did not.
//   - unpinned-range: a range that takes anything (`*`, `latest`, a tag, nothing at all, a git
//     branch), added or changed by the change, where no lockfile pins what installs.
//
// What passes: a version move of a dependency the project already had, from the same source, and the
// packages it brings that the project already had; a removal; a dependency on the
// project's own code, where the tool resolves it locally (a path inside it, a linked workspace member).
//
// Nothing here goes to the network, so nothing is looked up in a registry: what a package brings and
// whether it runs a script is what the lockfile says. A manifest or lockfile that cannot be read, at
// the head or the base, is could-not-run and never a pass. Manifests of the ecosystems this does not
// read are named when the change edits one (notRead).
import path from "path";
import { createHash } from "crypto";

import { SKIP_DIRS } from "../agent/skip-dirs.mjs";
import { FIXTURE_MARKERS } from "../agent/fixture-markers.mjs";
import { readToml } from "./toml.mjs";

export const DEP_KINDS = {
  "new-dependency": "a dependency the base did not declare, in any manifest of its ecosystem, or a name in a lockfile that is new to the project and that no manifest declares",
  "dependency-source":
    "a dependency the head takes from another place than the base took it from, the public registry included, or a new one from somewhere other than its ecosystem's registry; a registry or index the base's files did not name or the head's no longer do, where the tool reads it; or a lockfile entry edited in place",
  "install-script": "a package new to the lockfile, direct or brought in by another, that runs code when it is installed",
  "unpinned-range": "a range that takes any version (`*`, `latest`, a tag, none at all, a git branch), added or changed, where no lockfile pins what installs",
};

export const ECOSYSTEMS = ["npm", "PyPI", "Go"];
// A Map, so a word every object has (`constructor`) names no ecosystem.
const ECO = new Map(ECOSYSTEMS.map((e) => [e.toLowerCase(), e]));
export const ecosystemName = (e) => (typeof e === "string" ? ECO.get(e.toLowerCase()) ?? null : null);

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
 * A tree to read: { files, read(rel) -> text | null | { unread: why }, fixtureDirs }. The project on
 * disk, or the base as extracted, or (for a replay) a commit. A file that is listed and reads as
 * anything but text could not be read; `unread` says why (a symbolic link is not followed).
 */
export function treeOf(files, read, fixtureDirs = []) {
  const dirs = fixtureDirs.map((d) => (d === "." ? "" : d));
  const skipped = (rel) => {
    const parts = rel.split("/");
    if (parts.slice(0, -1).some((p) => SKIP_DIRS.has(p))) return true;
    return dirs.some((d) => d === "" || rel === d || rel.startsWith(`${d}/`));
  };
  const kept = files.filter((f) => !skipped(f));
  return { files: kept, all: new Set(files), read, skipped: (rel) => whySkipped(rel, dirs) };
}

// Why a file is left out of a tree: a directory the gate's walks skip, or a declared fixture.
function whySkipped(rel, fixtureDirs) {
  const skip = rel.split("/").slice(0, -1).find((p) => SKIP_DIRS.has(p));
  if (skip) return `under ${skip}/, a directory this rule does not read`;
  const fixture = fixtureDirs.find((d) => d === "" || rel === d || rel.startsWith(`${d}/`));
  return fixture === undefined ? null : `under ${fixture || "."}, a declared fixture, which this rule does not read`;
}

// The files this rule reads, by name.
const READ_NAMES = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc", "pyproject.toml", "Pipfile", "uv.toml", "hatch.toml", "uv.lock", "poetry.lock", "Pipfile.lock", "go.mod", "go.work", "go.sum"]);

/** The fixture directories a list of files declares (a marker file beside them). */
export const markerDirs = (files) => files.filter((f) => FIXTURE_MARKERS.includes(path.posix.basename(f))).map((f) => path.posix.dirname(f));

// ---------------------------------------------------------------------------------------------
// Sources

const DEFAULT_NPM = ["https://registry.npmjs.org/", "https://registry.yarnpkg.com/"];
const DEFAULT_PYPI = ["https://pypi.org/simple/", "https://files.pythonhosted.org/"];
const NPMJS = "https://registry.npmjs.org/";
const PYPI = "https://pypi.org/simple/";

const slash = (u) => (u.endsWith("/") ? u : `${u}/`);

/**
 * Text as this rule prints it: a URL in it has no user, password or token before its host, and no
 * query. An ssh URL keeps its user, which is an account and not a secret, and loses any password.
 * What two sources are compared by leaves the same parts out, so an allowlist entry copied from a
 * line this rule printed still matches.
 */
export function withoutCredentials(text) {
  return String(text).replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^\s/?#"'<>]*@)?([^\s?#"'<>]*)(\?[^\s#"'<>]*)?/gi, (all, scheme, user, rest) => {
    const kept = user && /(?:^|\+)ssh:\/\/$/i.test(scheme) ? `${user.slice(0, -1).split(":")[0]}@` : "";
    return `${scheme}${kept}${rest}`;
  });
}
const cleaned = (v) => {
  if (typeof v === "string") return withoutCredentials(v);
  if (Array.isArray(v)) return v.map(cleaned);
  if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, cleaned(x)]));
  return v;
};

// A setting whose name says its value is a secret is printed and compared without the value: a
// short hash of it stands in, so a changed value is still a change.
const SECRET_NAME = /auth|token|passw|secret|credential|otp/i;
const settingText = (key, shown) => (SECRET_NAME.test(key.replace(/^.*[:.](?=[^:.]+$)/, "")) ? `${key}=<a value this rule does not print, sha256 ${createHash("sha256").update(shown).digest("hex").slice(0, 8)}>` : `${key}=${shown}`);

/** Whether a URL can be read as one: it parses, and (with `path`) the escapes in its path decode. */
function urlReads(u, withPath = false) {
  try {
    const x = new URL(u);
    if (withPath) decodeURIComponent(x.pathname);
    return true;
  } catch {
    return false;
  }
}
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

// GitHub's shorthand, `owner/repository`. One that starts with a dot is a path.
const GIT_SHORTHAND = /^[A-Za-z0-9_-][A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]+(?:#.*)?$/;

/** A git location as one comparable string: host and path, no scheme, user, ref or `.git`. */
export function canonicalGit(raw) {
  let s = String(raw).trim().replace(/^git\+/, "");
  const hosts = { github: "github.com", gitlab: "gitlab.com", bitbucket: "bitbucket.org", gist: "gist.github.com" };
  let m = /^(github|gitlab|bitbucket|gist):(.+)$/.exec(s);
  if (m) s = `https://${hosts[m[1]]}/${m[2]}`;
  else if (GIT_SHORTHAND.test(s)) s = `https://github.com/${s}`;
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
  // npm reads a spec that starts with a dot, a slash or `~/` as a path before it tries anything else
  // (npm-package-arg), so `./local` is the directory and not GitHub's `./local`.
  if (/^(?:file:|link:|portal:)/.test(s) || /^(?:\.|\/|~\/)/.test(s)) {
    return { real: declaredAs, source: pathSource(s, manifest, s.replace(/^(?:file|link|portal):/, "")), anything: false };
  }
  if (/^(?:git\+[a-z]+:|git:\/\/|[^@/\s:]+@[^:/\s]+:|github:|gitlab:|bitbucket:|gist:)/i.test(s) || GIT_SHORTHAND.test(s)) {
    const ref = /#(.*)$/.exec(s)?.[1] || "";
    const semver = /^semver:(.*)$/.exec(ref);
    const anything = semver ? NPM_ANY.test(semver[1].trim()) : !pinsRef(ref);
    return { real: declaredAs, source: source("git", canonicalGit(s), s, { ref }), anything };
  }
  if (/^https?:\/\//i.test(s)) {
    const u = normUrl(s);
    return { real: declaredAs, source: source("url", u.replace(/[^/]*$/, ""), s), anything: false };
  }
  if (/^workspace:/.test(s)) return { real: declaredAs, source: source("path", `workspace:${declaredAs}`, s, { own: true }), anything: false };
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return { real: declaredAs, source: source("other", s, s), anything: false };
  const parts = s.split("||").map((p) => p.trim());
  // A word that is not a version is a dist-tag, which the registry moves: `latest`, `next`, `beta`.
  const tag = /^[A-Za-z][A-Za-z0-9._-]*$/.test(s) && !/^[vV]\d/.test(s);
  return { real: declaredAs, source: REGISTRY("the npm registry"), anything: tag || parts.some((p) => NPM_ANY.test(p)) };
}

const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

// Why a file is not JSON, without the parser's quotation of it: the file may not be the project's to print.
const notJson = (e) => {
  const at = /at position \d+(?: \(line \d+ column \d+\))?/.exec(String(e?.message || ""));
  return `it is not JSON${at ? ` (${at[0]})` : ""}`;
};

function readNpmManifest(rel, text, out) {
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch (e) {
    return notJson(e);
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
    return notJson(e);
  }
  if (!lock || typeof lock !== "object") return "it is not a JSON object";
  // npm's own test, in arborist: a lockfile whose lockfileVersion is not 2 or more is from before
  // npm 7, whatever sections it has. npm does not trust the install-script flags in one; it reads
  // each package for a script and runs it.
  // One with no `packages` section records no flags either.
  const old = !(lock.lockfileVersion >= 2) || !(lock.packages && typeof lock.packages === "object");
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
      for (const [key, e] of Object.entries(lock.packages)) add(key, e, !old);
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
  const shown = lock.lockfileVersion === undefined ? "no lockfileVersion" : `lockfileVersion ${JSON.stringify(lock.lockfileVersion)}`;
  out.locks.push({ eco: "npm", path: rel, format: old ? "old" : `v${lock.lockfileVersion}`, old, shown, packagesMissing: lock.lockfileVersion >= 2 && !lock.packages, entries });
  return null;
}

// Settings, in an .npmrc or uv's configuration, are judged against two lists. Those that say where
// packages come from or whom the tool trusts to serve them block when the base did not have them,
// with that reason. Those known to leave what installs, and from where, as it was, pass. Any other
// setting the base did not have blocks too: the tool accepts settings this rule has never heard of,
// and a list of the dangerous ones is only as good as the last one somebody thought of.
const WHY_SOURCE_SETTING = "a setting the base did not have that changes where packages come from, or which server the tool trusts to serve them";
const WHY_UNKNOWN_SETTING = "a setting the base did not have, which this rule does not know to leave what installs, and from where, as it was";

// npm: a proxy sees and can replace every package, and so can a server npm is told to trust.
const NPMRC_SOURCE = new Set(["proxy", "https-proxy", "http-proxy", "ca", "cafile", "replace-registry-host"]);
// npm settings that change output, prompts, publishing, the cache's timing, how the tree is laid
// out, or that only make an install stricter. Some are harmless only with one value.
const NPMRC_HARMLESS = new Set([
  "access", "all", "allow-same-version", "also", "audit", "audit-level", "auth-type", "before", "bin-links", "cache-max", "cache-min", "color", "commit-hooks",
  "cpu", "depth", "description", "dev", "diff", "diff-dst-prefix", "diff-ignore-all-space", "diff-name-only", "diff-no-prefix", "diff-src-prefix", "diff-text",
  "diff-unified", "dry-run", "engine-strict", "expect-result-count", "expect-results", "fetch-retries", "fetch-retry-factor", "fetch-retry-maxtimeout",
  "fetch-retry-mintimeout", "fetch-timeout", "foreground-scripts", "format-package-lock", "fund", "git-tag-version", "global-style", "heading", "if-present",
  "include", "include-attestations", "include-staged", "include-workspace-root", "init-author-email", "init-author-name", "init-author-url", "init-license",
  "init-module", "init-private", "init-type", "init-version", "init.author.email", "init.author.name", "init.author.url", "init.license", "init.module",
  "init.version", "install-links", "install-strategy", "json", "legacy-bundling", "legacy-peer-deps", "libc", "link", "lockfile-version", "loglevel", "logs-max",
  "long", "maxsockets", "message", "min-release-age", "noproxy", "omit", "omit-lockfile-registry-resolved", "only", "optional", "os", "pack-destination",
  "package-lock-only", "parseable", "prefer-dedupe", "prefer-offline", "prefer-online", "preid", "production", "progress", "provenance", "read-only",
  "rebuild-bundle", "save", "save-bundle", "save-dev", "save-exact", "save-optional", "save-peer", "save-prefix", "save-prod", "sbom-format", "sbom-type", "scope",
  "searchexclude", "searchlimit", "searchopts", "searchstaleness", "sign-git-commit", "sign-git-tag", "strict-peer-deps", "tag", "tag-version-prefix", "timing",
  "umask", "unicode", "update-notifier", "usage", "user-agent", "workspaces-update", "yes", "offline",
  // pnpm reads .npmrc too; these only lay the tree out or check peers.
  "auto-install-peers", "shamefully-hoist", "strict-peer-dependencies", "dedupe-peer-dependents", "resolution-mode", "node-linker", "hoist", "hoist-pattern", "public-hoist-pattern",
]);
const NPMRC_HARMLESS_WHEN = {
  "ignore-scripts": (v) => v === true,
  "strict-allow-scripts": (v) => v === true,
  "dangerously-allow-all-scripts": (v) => v === false,
  "package-lock": (v) => v === true,
  shrinkwrap: (v) => v === true,
  "allow-git": (v) => v === "none" || v === "root",
  "allow-remote": (v) => v === "none" || v === "root",
  "allow-file": (v) => v === "none" || v === "root",
  "allow-directory": (v) => v === "none" || v === "root",
  // strict-ssl=false is a source setting below; npm still checks the certificate for any other value.
  "strict-ssl": (v) => v !== false,
};
// Per-registry credentials, `//host/path/:_authToken=...`: who to send them to, not where packages come from.
const NPM_NERF = new Set(["_auth", "_authToken", "_password", "username", "email", "certfile", "keyfile", "always-auth"]);
const NPMRC_TOP_AUTH = new Set(["_auth", "_authToken", "_password", "username", "email", "cert", "key", "otp"]);

/** One value or key as npm's ini reader (ini 6) gives it: trimmed, quotes taken off, an inline comment cut. */
function iniUnsafe(raw) {
  let val = (raw || "").trim();
  const quoted = (val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"));
  if (quoted && val.length > 1) {
    if (val[0] === "'") val = val.slice(1, -1);
    try {
      val = JSON.parse(val);
    } catch {
      /* kept as it is, as ini keeps it */
    }
    return val;
  }
  let esc = false;
  let out = "";
  for (const c of val) {
    if (esc) {
      out += "\\;#".includes(c) ? c : `\\${c}`;
      esc = false;
    } else if (";#".includes(c)) break;
    else if (c === "\\") esc = true;
    else out += c;
  }
  if (esc) out += "\\";
  return out.trim();
}

/** The top-level settings of an .npmrc as npm reads them: [{ key, value, raw }]. A `[section]` ends them. */
export function npmrcSettings(text) {
  const out = [];
  for (const [n, line] of text.split(/\r\n|\r|\n/).entries()) {
    if (!line || /^\s*[;#]/.test(line) || /^\s*$/.test(line)) continue;
    const m = /^\[([^\]]*)\]\s*$|^([^=]+)(=(.*))?$/i.exec(line);
    if (!m) continue;
    if (m[1] !== undefined) break;
    const keyRaw = iniUnsafe(m[2]);
    // A quoted key is read as JSON, so '[1,2,3]' is a list, which npm turns into the key "1,2,3".
    // No setting is named that way, and this rule does not guess which one was meant.
    if (typeof keyRaw !== "string") throw new Error(`line ${n + 1}: its key, ${withoutCredentials(m[2].trim()).slice(0, 60)}, is JSON that is not a string once its quotes are taken off`);
    const isArray = keyRaw.length > 2 && keyRaw.endsWith("[]");
    const key = isArray ? keyRaw.slice(0, -2) : keyRaw;
    const valueRaw = m[3] ? iniUnsafe(m[4]) : true;
    const value = valueRaw === "true" ? true : valueRaw === "false" ? false : valueRaw === "null" ? null : valueRaw;
    out.push({ key, value, raw: settingText(key, typeof valueRaw === "string" ? valueRaw : String(valueRaw)) });
  }
  return out;
}

// `registry=` and `@scope:registry=`, and every other setting, judged by the lists above.
function readNpmrc(rel, text, out) {
  for (const { key, value, raw } of npmrcSettings(text)) {
    const scoped = /^(@[^:]+):registry$/.exec(key);
    if (key === "registry" || scoped) {
      out.indexes.push({ eco: "npm", tool: "npm", file: rel, scope: scoped ? scoped[1] : null, url: String(value) });
      continue;
    }
    // A key with an environment variable in it, which npm fills in, is on neither list and blocks.
    const setting = (why) => out.indexes.push({ eco: "npm", tool: "npm", file: rel, scope: null, kind: "setting", url: raw, why, key, value });
    const nerf = /^\/\/.*:([^:]+)$/.exec(key);
    if (nerf) {
      if (!NPM_NERF.has(nerf[1])) setting(WHY_UNKNOWN_SETTING);
      continue;
    }
    if (NPMRC_SOURCE.has(key) || (key === "strict-ssl" && value === false)) setting(WHY_SOURCE_SETTING);
    else if (NPMRC_HARMLESS.has(key) || NPMRC_TOP_AUTH.has(key)) continue;
    else if (NPMRC_HARMLESS_WHEN[key]) {
      if (!NPMRC_HARMLESS_WHEN[key](value)) setting(WHY_UNKNOWN_SETTING);
    } else setting(WHY_UNKNOWN_SETTING);
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

const REQ_OPTIONS_IGNORED = new Set(["--pre", "--prefer-binary", "--require-hashes", "--only-binary", "--no-binary", "--use-feature", "--no-deps", "--progress-bar"]);
const REQ_OPTIONS_VALUE = new Set(["--only-binary", "--no-binary", "--use-feature", "--progress-bar"]);

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
      if (!m) return { error: `${at}: an option this rule does not read: ${withoutCredentials(line).slice(0, 80)}` };
      const [opt, value = ""] = [m[1], (m[2] || "").trim()];
      if (opt === "-r" || opt === "--requirement") includes.push({ type: "requirement", path: value });
      else if (opt === "-c" || opt === "--constraint") includes.push({ type: "constraint", path: value });
      else if (opt === "-e" || opt === "--editable") {
        const r = pyRequirement(value, manifest);
        if (!r) return { error: `${at}: an editable requirement this rule does not read: ${withoutCredentials(value).slice(0, 80)}` };
        deps.push({ ...r, editable: true });
      } else if (opt === "-i" || opt === "--index-url") indexes.push({ kind: "index-url", url: value });
      else if (opt === "--extra-index-url") indexes.push({ kind: "extra-index-url", url: value });
      else if (opt === "-f" || opt === "--find-links") indexes.push({ kind: "find-links", url: value });
      else if (opt === "--no-index") indexes.push({ kind: "no-index", url: "" });
      // pip takes anything served from a trusted host, over plain http or with any certificate.
      else if (opt === "--trusted-host") {
        if (!value) return { error: `${at}: --trusted-host with no value` };
        indexes.push({ kind: "setting", url: `--trusted-host ${value}`, why: WHY_SOURCE_SETTING });
      }
      else if (REQ_OPTIONS_IGNORED.has(opt)) {
        if (REQ_OPTIONS_VALUE.has(opt) && !value) return { error: `${at}: ${opt} with no value` };
      } else return { error: `${at}: an option this rule does not read: ${opt}` };
      continue;
    }
    // Per-requirement options: hashes and build settings, none of which change what is named.
    const req = line.replace(/\s+--(?:hash|config-settings|global-option|install-option)(?:=|\s+)\S+/g, "").trim();
    const r = pyRequirement(req, manifest);
    if (!r) return { error: `${at}: a requirement this rule does not read: ${withoutCredentials(line).slice(0, 80)}` };
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
    if (!r) return `${section} holds a requirement this rule does not read: ${withoutCredentials(item).slice(0, 80)}`;
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

// uv's settings, in [tool.uv] and uv.toml, by the two lists (see WHY_SOURCE_SETTING). The keys uv
// 0.12.1 accepts, each in one place: read here as declarations or indexes, a source, harmless, or
// neither. `harmless when` takes the value.
const UV_READ = new Set(["index", "index-url", "extra-index-url", "find-links", "sources", "dependency-metadata", "override-dependencies", "constraint-dependencies", "build-constraint-dependencies", "dev-dependencies", "extra-build-dependencies", "pip"]);
const UV_SOURCE = new Set(["allow-insecure-host", "native-tls", "system-certs", "http-proxy", "https-proxy", "python-install-mirror", "pypy-install-mirror", "python-downloads-json-url", "torch-backend", "no-sources", "no-sources-package"]);
const UV_HARMLESS = new Set([
  "required-version", "offline", "no-cache", "preview", "preview-features", "python-preference", "python-downloads", "concurrent-downloads", "concurrent-builds",
  "concurrent-installs", "no-index", "no-proxy", "resolution", "prerelease", "prerelease-package", "fork-strategy", "exclude-newer", "exclude-newer-package", "link-mode",
  "compile-bytecode", "upgrade", "upgrade-package", "reinstall", "reinstall-package", "no-build", "no-build-package", "publish-url", "trusted-publishing", "check-url",
  "add-bounds", "audit", "cache-keys", "exclude-dependencies", "environments", "required-environments", "conflicts", "workspace", "managed", "package",
  "default-groups", "dependency-groups", "build-backend",
]);
const UV_PIP_READ = new Set(["index-url", "extra-index-url", "find-links", "dependency-metadata", "extra-build-dependencies"]);
const UV_PIP_SOURCE = new Set(["torch-backend", "no-sources", "no-sources-package"]);
const UV_PIP_HARMLESS = new Set([
  "system", "break-system-packages", "target", "prefix", "no-index", "no-build", "only-binary", "strict", "extra", "all-extras", "no-extra", "no-deps", "group",
  "allow-empty-requirements", "resolution", "prerelease", "fork-strategy", "output-file", "no-strip-extras", "no-strip-markers", "no-annotate", "no-header",
  "custom-compile-command", "generate-hashes", "python-version", "python-platform", "universal", "exclude-newer", "exclude-newer-package", "no-emit-package",
  "emit-index-url", "emit-find-links", "emit-build-options", "emit-marker-expression", "emit-index-annotation", "annotation-style", "link-mode", "compile-bytecode",
  "require-hashes", "upgrade", "upgrade-package", "reinstall", "reinstall-package",
]);
// index-strategy other than first-index takes a name from whichever index has the best version,
// which is how a public package replaces a private one; a keyring provider runs a program.
const UV_HARMLESS_WHEN = { "index-strategy": (v) => v === "first-index", "keyring-provider": (v) => v === "disabled", "verify-hashes": (v) => v === true };

/** [tool.uv] (prefix "tool.uv.") or uv.toml (prefix ""): declarations, indexes and settings; errors go in errs. */
function readUvSettings(uv, rel, prefix, out, errs, named) {
  const setting = (key, value, why) => out.indexes.push({ eco: "PyPI", tool: "uv", file: rel, scope: null, kind: "setting", url: settingText(key, JSON.stringify(value)), why });
  const judge = (table, at, read, src, harmless) => {
    for (const [k, v] of Object.entries(table)) {
      if (read.has(k)) continue;
      if (src.has(k)) setting(`${at}${k}`, v, WHY_SOURCE_SETTING);
      else if (UV_HARMLESS_WHEN[k]) {
        if (!UV_HARMLESS_WHEN[k](v)) setting(`${at}${k}`, v, k === "verify-hashes" ? WHY_UNKNOWN_SETTING : WHY_SOURCE_SETTING);
      } else if (!harmless.has(k)) setting(`${at}${k}`, v, WHY_UNKNOWN_SETTING);
    }
  };
  if (uv.index !== undefined) {
    if (!Array.isArray(uv.index)) return errs.push(`${prefix}index is not a list`);
    for (const s of uv.index) {
      if (!isTable(s) || typeof s.url !== "string") return errs.push(`${prefix}index holds an entry with no url`);
      if (typeof s.name === "string") named[s.name] = s.url;
      // default = true puts it in PyPI's place; explicit = true keeps it to the names a source pins to it.
      const role = [s.default === true && "default", s.explicit === true && "explicit"].filter(Boolean).join("+") || "index";
      out.indexes.push({ eco: "PyPI", tool: "uv", file: rel, kind: `${prefix}index`, url: s.url, role });
    }
  }
  const pip = uv.pip === undefined ? {} : uv.pip;
  if (!isTable(pip)) return errs.push(`${prefix}pip is not a table`);
  for (const [t, at] of [[uv, prefix], [pip, `${prefix}pip.`]]) {
    // no-index = true keeps every index out, as pip's --no-index does: taken away, they are back.
    if (t["no-index"] === true) out.indexes.push({ eco: "PyPI", tool: "uv", file: rel, kind: "no-index", url: "", shownAs: `${at}no-index = true` });
    for (const k of ["index-url", "extra-index-url", "find-links"]) for (const u of [t[k]].flat()) if (typeof u === "string") out.indexes.push({ eco: "PyPI", tool: "uv", file: rel, kind: `${at}${k}`, url: u });
    // dependency-metadata stands in for what a package declares, so its requires-dist is what uv
    // installs with it: each name in it is a dependency.
    if (t["dependency-metadata"] !== undefined) {
      if (!Array.isArray(t["dependency-metadata"])) return errs.push(`${at}dependency-metadata is not a list`);
      for (const m of t["dependency-metadata"]) {
        if (!isTable(m) || typeof m.name !== "string") return errs.push(`${at}dependency-metadata holds an entry with no name`);
        if (m["requires-dist"] !== undefined) errs.push(pushPep508(m["requires-dist"], rel, `${at}dependency-metadata.${m.name}.requires-dist`, out));
      }
    }
    if (t["extra-build-dependencies"] !== undefined) {
      if (!isTable(t["extra-build-dependencies"])) return errs.push(`${at}extra-build-dependencies is not a table`);
      for (const [name, list] of Object.entries(t["extra-build-dependencies"])) errs.push(pushPep508(list, rel, `${at}extra-build-dependencies.${name}`, out, "build"));
    }
  }
  // What installs beside the project, and what overrides or constrains a resolution or a build.
  if (uv["dev-dependencies"] !== undefined) errs.push(pushPep508(uv["dev-dependencies"], rel, `${prefix}dev-dependencies`, out));
  for (const k of ["override-dependencies", "constraint-dependencies", "build-constraint-dependencies"]) if (uv[k] !== undefined) errs.push(pushPep508(uv[k], rel, `${prefix}${k}`, out, "override"));
  // A pyproject's sources are read with its declarations; sources in uv.toml is a setting like any other.
  judge(uv, prefix, prefix ? UV_READ : new Set([...UV_READ].filter((k) => k !== "sources")), UV_SOURCE, UV_HARMLESS);
  judge(pip, `${prefix}pip.`, UV_PIP_READ, UV_PIP_SOURCE, UV_PIP_HARMLESS);
  return null;
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
  out.pyprojects.push(rel);
  // What uv's search for a workspace reads of each pyproject.toml: whether it is a project, and the members its workspace takes.
  const strings = (l) => (Array.isArray(l) ? l.filter((x) => typeof x === "string") : []);
  out.uvRoots.set(path.posix.dirname(rel), { project: project !== undefined, workspace: isTable(uv.workspace) ? { members: strings(uv.workspace.members), exclude: strings(uv.workspace.exclude) } : null });
  if (isTable(tool.poetry)) out.pyTools.add(`poetry|${rel}`);
  if (isTable(tool.pdm)) out.pyTools.add(`pdm|${rel}`);
  const named = {};
  for (const [label, list] of [["tool.poetry.source", poetry.source], ["tool.pdm.source", tool.pdm?.source]]) {
    if (list === undefined) continue;
    if (!Array.isArray(list)) return `${label} is not a list`;
    for (const s of list) {
      if (!isTable(s)) return `${label} holds an entry that is not a table`;
      // poetry's own way to place PyPI among its sources: the name, in any case, and no url.
      const pypi = label === "tool.poetry.source" && typeof s.name === "string" && s.name.toLowerCase() === "pypi" && s.url === undefined;
      const url = pypi ? PYPI : s.url;
      if (typeof url !== "string") return `${label} holds an entry with no url`;
      if (typeof s.name === "string") named[s.name] = url;
      // poetry: a primary source puts PyPI out of use; supplemental and explicit ones do not.
      const role = label === "tool.poetry.source" ? (typeof s.priority === "string" ? s.priority : s.default === true ? "default" : s.secondary === true ? "secondary" : "primary") : "source";
      out.indexes.push({ eco: "PyPI", tool: label === "tool.poetry.source" ? "poetry" : "pdm", file: rel, kind: label, url, role });
    }
  }
  if (tool.uv !== undefined && !isTable(tool.uv)) return "[tool.uv] is not a table";
  // uv reads its settings from the nearest directory up that has a uv.toml or a [tool.uv] table, however little is in it.
  if (tool.uv !== undefined) out.uvConfig.set(path.posix.dirname(rel), { ...(out.uvConfig.get(path.posix.dirname(rel)) || {}), pyproject: rel });
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
  readUvSettings(uv, rel, "tool.uv.", out, errs, named);
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
      const made = [];
      // A source with a marker, an extra or a group covers part of what installs; the rest comes
      // from the index, as if the name had no source.
      let partial = false;
      for (const x of Array.isArray(v) ? v : [v]) {
        if (!isTable(x)) return `tool.uv.sources.${name} is not a table`;
        let src;
        if (x.workspace === true) src = source("path", `workspace:${key}`, "a uv workspace member", { own: true });
        else if (typeof x.git === "string") src = source("git", canonicalGit(x.git), x.git, { ref: x.tag || x.rev || x.branch || "" });
        else if (typeof x.path === "string") src = pathSource(x.path, rel, x.path);
        else if (typeof x.url === "string") src = source("url", normUrl(x.url).replace(/[^/]*$/, ""), x.url);
        else if (typeof x.index === "string") src = source("index", named[x.index] || x.index, `the index ${x.index}`, { raw: named[x.index] || x.index });
        else return `tool.uv.sources.${name} names no source this rule reads`;
        src.uvSource = true;
        if (typeof x.marker === "string" || typeof x.extra === "string" || typeof x.group === "string") partial = true;
        made.push({ src, anything: src.type === "git" && !pinsRef(x.tag || x.rev || "") });
      }
      // A source for a name this file does not declare: in a uv workspace the root's sources are
      // every member's, so it says where a name comes from without asking for it, as an override does.
      const mine = out.decl.slice(before).filter((x) => x.key === key);
      if (!mine.length) for (const m of made) out.decl.push({ eco: "PyPI", name, key, declaredAs: name, spec: `tool.uv.sources.${name}`, manifest: rel, section: "tool.uv.sources", source: m.src, anything: false, role: "override" });
      // One declaration for each source the name is given, and one more for the index where a source is partial.
      for (const d of mine) {
        const plain = { ...d };
        const last = made[made.length - 1];
        if (!last) continue;
        Object.assign(d, { source: last.src, anything: d.anything || last.anything });
        for (const m of made.slice(0, -1)) out.decl.push({ ...plain, source: m.src, anything: plain.anything || m.anything });
        if (partial) out.decl.push(plain);
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
    out.indexes.push({ eco: "PyPI", tool: "pipenv", file: rel, kind: "source", url: s.url });
  }
  out.pyTools.add(`pipenv|${rel}`);
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
  // uv.toml holds what [tool.uv] holds, and uv applies it the same way, uv pip compile included.
  out.uvConfig.set(path.posix.dirname(rel), { ...(out.uvConfig.get(path.posix.dirname(rel)) || {}), toml: rel });
  const errs = [];
  readUvSettings(t.value, rel, "", out, errs, {});
  return errs.find(Boolean) || null;
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
    return notJson(e);
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
      // The index the entry names, PyPI included; an entry that names none comes from the Pipfile's first source.
      if (src.type === "registry" && typeof p?.index === "string" && named[p.index]) e.indexUrl = named[p.index];
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
  const out = { decl: [], locks: [], indexes: [], replaces: [], manifests: [], pyOwn: new Map(), goModules: new Map(), goWork: [], goTools: new Set(), goSums: [], lockDirs: { npm: new Set(), PyPI: new Set() }, unreadLockDirs: { npm: new Set(), PyPI: new Set() }, pins: new Map(), errors: [], files: tree.files, read: tree.read, skipped: tree.skipped || (() => null), extraRequirements: [], pyprojects: [], pyTools: new Set(), uvConfig: new Map(), uvRoots: new Map(), reqFiles: [], reqIncludes: new Map() };
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
    // Lockfiles this rule does not read: what they hold, and which manifests they cover, is not known.
    if (["yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"].includes(base)) out.unreadLockDirs.npm.add(dir);
    if (base === "pdm.lock" || /^pylock(?:\..+)?\.toml$/.test(base)) out.unreadLockDirs.PyPI.add(dir);
  }
  for (const [rel, fn] of readers) {
    const text = tree.read(rel);
    if (typeof text !== "string") {
      out.errors.push({ path: rel, why: text?.unread || "it could not be read" });
      continue;
    }
    // A reader that throws has not read the file: that is could-not-run for it, by name.
    let err;
    try {
      err = fn(rel, text, out);
    } catch (e) {
      err = `this rule could not read it (${e?.message || e})`;
    }
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
    if (typeof text !== "string") {
      out.errors.push({ path: rel, why: tree.all.has(rel) ? text?.unread || "it could not be read" : "a requirements file includes it, and it is not in the project" });
      continue;
    }
    const r = parseRequirements(text, rel);
    if (r.error) {
      out.errors.push({ path: rel, why: r.error });
      continue;
    }
    for (const d of r.deps) out.decl.push({ eco: "PyPI", name: d.name, key: normalName("PyPI", d.name), declaredAs: d.name, spec: d.spec, manifest: rel, section: "requirements", source: d.source, anything: d.anything, role: "dependency", pinned: d.pinned });
    out.reqFiles.push(rel);
    for (const x of r.indexes) out.indexes.push({ eco: "PyPI", tool: "pip", file: rel, kind: x.kind, url: x.url, ...(x.why ? { why: x.why } : {}) });
    for (const p of r.pins) out.pins.set(`${rel}|${p}`, true);
    for (const inc of r.includes) {
      // pip fetches a file given as a URL: it is not in the project, and its name is not a path.
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(inc.path)) {
        out.errors.push({ path: rel, why: `it includes ${withoutCredentials(inc.path).slice(0, 120)}, which is outside the project` });
        continue;
      }
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(rel), inc.path));
      if (target.startsWith("../") || path.posix.isAbsolute(inc.path)) {
        out.errors.push({ path: rel, why: `it includes ${inc.path}, which is outside the project` });
        continue;
      }
      queue.push(target);
      out.reqIncludes.set(rel, [...(out.reqIncludes.get(rel) || []), target]);
      if (inc.type === "constraint") out.constraintOf = [...(out.constraintOf || []), [rel, target]];
    }
  }
  // A URL that does not parse, or a file's URL whose path does not decode, is one this rule cannot
  // compare with anything: the file that gives it has not been read.
  const unread = new Map();
  const check = (file, u, withPath) => {
    if (typeof u === "string" && /^https?:\/\//i.test(u) && !urlReads(u, withPath) && !unread.has(file)) unread.set(file, u);
  };
  for (const d of out.decl) if (d.source?.type === "url") check(d.manifest, d.source.raw, d.eco === "npm");
  for (const l of out.locks) {
    for (const e of l.entries.values()) {
      check(l.path, e.resolved, true);
      for (const u of e.urls || []) check(l.path, u, true);
      if (e.source && ["index", "url", "url-resolved"].includes(e.source.type)) check(l.path, e.source.raw, false);
    }
  }
  for (const [file, u] of unread) out.errors.push({ path: file, why: `it gives a URL this rule cannot read as one: ${withoutCredentials(u).slice(0, 120)}` });
  return out;
}

// ---------------------------------------------------------------------------------------------
// The judgement

// Whether a dependency is the project's own code: only where the tool resolves it locally. A name
// that matches a workspace member, a nested project or a nested module is still fetched from the
// registry unless something points the tool at the directory.
function ownSource(d, inv) {
  // tool.uv.sources is uv's alone: pip, and anything else that installs the project, reads the name
  // from PyPI. It is the project's own only where uv.lock covers the manifest and says so.
  if (d.source?.uvSource) return d.source.own === true && uvLockSaysLocal(d, inv);
  if (d.source?.own === true) return true;
  if (d.eco === "npm") {
    // The lockfile says where npm puts it: a link to a member, or the registry's package.
    const at = npmLockFor(d.manifest, inv);
    const e = at && npmResolve(at.lock, at.key, d.declaredAs);
    return Boolean(e && (e.local || (e.link && e.source?.own)));
  }
  // A project's own extras, `p[extra]` in p's pyproject.toml. Anywhere else pip and uv look the name up.
  if (d.eco === "PyPI") return inv.pyOwn.get(d.manifest) === d.key;
  if (d.eco === "Go") {
    const dir = path.posix.dirname(d.manifest);
    if (inv.replaces.some((r) => r.path === d.key && r.source.own && r.file === d.manifest)) return true;
    // A go.work applies to the modules it uses, and to no other: go run in another module ignores it
    // or refuses to build, and with GOWORK=off takes the proxy's module.
    for (const w of inv.goWork) {
      const wdir = path.posix.dirname(w.file);
      const used = w.uses.map((u) => path.posix.normalize(path.posix.join(wdir === "." ? "" : wdir, u)).replace(/\/+$/, "") || ".");
      if (!used.includes(dir)) continue;
      if (inv.replaces.some((r) => r.file === w.file && r.path === d.key && r.source.own)) return true;
      if (used.some((u) => inv.goModules.get(u === "." ? "go.mod" : `${u}/go.mod`) === d.key)) return true;
    }
    return false;
  }
  return false;
}

// Whether a uv.lock covers a manifest (it records the manifest's directory as one of its local
// projects) and holds the name from a directory inside the project.
function uvLockSaysLocal(d, inv) {
  const mdir = path.posix.dirname(d.manifest);
  for (const l of inv.locks) {
    if (l.format !== "uv.lock") continue;
    const ldir = path.posix.dirname(l.path);
    if (!(ldir === "." || mdir === ldir || mdir.startsWith(`${ldir}/`))) continue;
    const entries = [...l.entries.values()];
    if (!entries.some((e) => e.local && e.source?.id === `path:${mdir}`)) continue;
    if (entries.some((e) => normalName("PyPI", e.name) === d.key && e.local)) return true;
  }
  return false;
}

const isRegistryUrl = (eco, url, extra) => {
  const u = slash(normUrl(url));
  return [...(eco === "npm" ? DEFAULT_NPM : DEFAULT_PYPI), ...extra].some((d) => u.startsWith(slash(normUrl(d))));
};

/**
 * For a file from a registry, whether it is this package's: npm serves a package's tarball at
 * <registry>/<name>/-/<last part of the name>-<version>.tgz, and PyPI names a file <name>-<version>...
 * with the name folded. A registry URL to another package's tarball is the registry, and installs
 * that package under this name. `registries` are the npm registries the project's files name: under
 * one, the name is read from the path before /-/, scoped names included, and the file is the last
 * part of the path (some registries repeat the scope there). With no version (a URL a manifest
 * gives) the name alone is checked. Under a named registry with no /-/ in the path, the name has to
 * be in the path segment for segment. Null when the URL is under no registry this knows.
 */
export function registryFileMatches(eco, url, name, version, registries = []) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (eco === "npm") {
    const last = name.split("/").pop();
    const fileIs = (f) => (version === null || version === undefined ? f.startsWith(`${last}-`) && f.endsWith(".tgz") : f === `${last}-${version}.tgz`);
    if (DEFAULT_NPM.some((d) => url.startsWith(d))) {
      let p;
      try {
        p = decodeURIComponent(u.pathname);
      } catch {
        return false;
      }
      return p.startsWith(`/${name}/-/`) && fileIs(p.slice(`/${name}/-/`.length));
    }
    const full = normUrl(url);
    const root = registries.find((k) => full.startsWith(k));
    if (!root) return null;
    let rest;
    try {
      rest = decodeURIComponent(full.slice(root.length));
    } catch {
      return false;
    }
    const at = rest.indexOf("/-/");
    if (at < 0) {
      // Another layout (GitHub Packages serves download/<name>/<version>/<hash>): the name has to be
      // in the path, segment for segment, and an unscoped name not as the last part of a scoped one.
      const segs = rest.split("/");
      const want = name.split("/");
      return segs.some((_, i) => want.every((w, j) => segs[i + j] === w) && (want.length > 1 || !(segs[i - 1] || "").startsWith("@")));
    }
    return rest.slice(0, at) === name && fileIs(rest.slice(at + 3).split("/").pop());
  }
  if (!DEFAULT_PYPI.some((d) => url.startsWith(d))) return null;
  let file;
  try {
    file = decodeURIComponent(u.pathname.split("/").pop() || "");
  } catch {
    return false;
  }
  const m = /^(.+?)-(\d[^-]*?)(?:-|\.tar\.gz$|\.zip$|\.tar\.bz2$)/.exec(file);
  return Boolean(m) && normalName("PyPI", m[1]) === normalName("PyPI", name) && m[2] === version;
}

/**
 * Whether a wheel's or sdist's file name is this package's: <name>-<version>..., the name folded as
 * PyPI folds it. A name may hold a hyphen, so every hyphen is tried as the end of it, and what
 * follows has to start as a version does.
 */
export function pyFileNamed(file, name) {
  let f = String(file).replace(/[?#].*$/, "").split("/").pop() || "";
  try {
    f = decodeURIComponent(f);
  } catch {
    /* kept as it is written */
  }
  // An escaped slash makes the name a path, which a server may read as another file.
  if (/[/\\]/.test(f)) return false;
  const want = normalName("PyPI", name);
  for (let i = f.indexOf("-"); i > 0; i = f.indexOf("-", i + 1)) {
    if (normalName("PyPI", f.slice(0, i)) === want && /^\d/.test(f.slice(i + 1))) return true;
  }
  return false;
}

// A registry or index, and the role it has. npm: which names it serves (every name, or a scope's).
// pip: --index-url replaces PyPI, --extra-index-url and --find-links are searched beside it, and
// --no-index keeps PyPI out. uv: `default = true` replaces PyPI, `explicit = true` serves only the
// names a source pins to it. poetry: a primary source keeps PyPI out. A role ranked higher keeps the
// public default out at least as well as a lower one; roles with no rank compare only as equal.
const ROLE_RANK = { "index-url": 2, default: 2, primary: 2, "extra-index-url": 1, "find-links": 1, index: 1, supplemental: 1, secondary: 1, source: 1 };
const indexKey = (x) => `${x.eco}|${x.kind === "no-index" ? "no-index" : slash(normUrl(x.url))}`;
function indexRole(x) {
  if (x.eco === "npm") return x.scope ? `${x.scope}:registry` : "registry";
  if (x.role) return x.role;
  if (x.kind === "no-index") return "no-index";
  return /extra-index-url$/.test(x.kind) ? "extra-index-url" : /index-url$/.test(x.kind) ? "index-url" : /find-links$/.test(x.kind) ? "find-links" : x.kind;
}
const roleWord = (eco, r) =>
  eco === "npm" ? `${r}=` : { "index-url": "--index-url", "extra-index-url": "--extra-index-url", "find-links": "--find-links", "no-index": "--no-index", default: "default = true", explicit: "explicit = true", "default+explicit": "default = true and explicit = true", index: "an index with neither default nor explicit", source: "a source" }[r] || `priority = "${r}"`;
function indexShown(x) {
  if (x.eco === "npm") return `${x.scope ? `${x.scope}:` : ""}registry=${x.url}`;
  if (x.kind === "no-index") return x.shownAs || "--no-index";
  if (/^(?:index-url|extra-index-url|find-links)$/.test(x.kind)) return `--${x.kind} ${x.url}`;
  return `${x.kind} ${x.url}${x.role && x.role !== "source" ? ` (${roleWord(x.eco, x.role)})` : ""}`;
}

/** Whether a source is the ecosystem's registry, or an index the base already named. */
function fromRegistry(src, eco, baseIndexes) {
  if (!src) return true;
  if (src.type === "registry" || src.type === "bundled") return true;
  if (src.type === "url-resolved" || src.type === "index") return isRegistryUrl(eco, src.raw, baseIndexes);
  return false;
}

// Brace expansion as minimatch does it: `{a,b}`, nested, and `{1..3}` or `{a..c}` sequences. A
// brace with neither stays as it is written.
function expandBraces(p) {
  for (let i = 0; i < p.length; i++) {
    if (p[i] !== "{") continue;
    let depth = 0;
    let start = i + 1;
    const parts = [];
    for (let j = i; j < p.length; j++) {
      if (p[j] === "{") depth++;
      else if (p[j] === "," && depth === 1) {
        parts.push(p.slice(start, j));
        start = j + 1;
      } else if (p[j] === "}" && --depth === 0) {
        parts.push(p.slice(start, j));
        const [pre, post] = [p.slice(0, i), p.slice(j + 1)];
        if (parts.length > 1) return parts.flatMap((a) => expandBraces(pre + a + post));
        const num = /^(-?\d+)\.\.(-?\d+)$/.exec(parts[0]);
        const chr = /^([A-Za-z])\.\.([A-Za-z])$/.exec(parts[0]);
        if (num || chr) {
          const [a, b] = num ? [Number(num[1]), Number(num[2])] : [chr[1].charCodeAt(0), chr[2].charCodeAt(0)];
          const out = [];
          for (let k = a; a <= b ? k <= b : k >= b; k += a <= b ? 1 : -1) out.push(num ? String(k) : String.fromCharCode(k));
          return out.flatMap((a2) => expandBraces(pre + a2 + post));
        }
        break;
      }
    }
  }
  return [p];
}

// minimatch 10's POSIX classes, as it writes them; graph is the one it negates.
const POSIX_CLASS = { alnum: "\\p{L}\\p{Nl}\\p{Nd}", alpha: "\\p{L}\\p{Nl}", ascii: "\\x00-\\x7f", blank: "\\p{Zs}\\t", cntrl: "\\p{Cc}", digit: "\\p{Nd}", graph: "\\p{Z}\\p{C}", lower: "\\p{Ll}", print: "\\p{C}", punct: "\\p{P}", space: "\\p{Z}\\t\\r\\n\\v\\f", upper: "\\p{Lu}", word: "\\p{L}\\p{Nl}\\p{Nd}\\p{Pc}", xdigit: "A-Fa-f0-9" };

// A character class at seg[pos] as minimatch reads one: { re, end }, { literal, end } for a class of
// one character, { never } for one that can match nothing (which makes the whole pattern match
// nothing), or null when it does not close and the "[" is a plain character.
function charClass(seg, pos) {
  const esc = (s) => s.replace(/[[\]\\-]/g, "\\$&");
  const ranges = [];
  const negs = [];
  let i = pos + 1;
  let sawStart = false;
  let negate = false;
  let end = -1;
  let rangeStart = "";
  outer: while (i < seg.length) {
    const c = seg[i];
    if ((c === "!" || c === "^") && i === pos + 1) {
      negate = true;
      i++;
      continue;
    }
    if (c === "]" && sawStart) {
      end = i;
      break;
    }
    sawStart = true;
    if (c === "[") {
      for (const [name, cls] of Object.entries(POSIX_CLASS)) {
        if (!seg.startsWith(`[:${name}:]`, i)) continue;
        if (rangeStart) return { never: true };
        i += name.length + 4;
        (name === "graph" ? negs : ranges).push(cls);
        continue outer;
      }
    }
    if (rangeStart) {
      // A range written backwards is dropped, and the rest of the class still counts.
      if (c > rangeStart) ranges.push(`${esc(rangeStart)}-${esc(c)}`);
      else if (c === rangeStart) ranges.push(esc(c));
      rangeStart = "";
      i++;
    } else if (seg.startsWith("-]", i + 1)) {
      ranges.push(esc(`${c}-`));
      i += 2;
    } else if (seg.startsWith("-", i + 1)) {
      rangeStart = c;
      i += 2;
    } else {
      ranges.push(esc(c));
      i++;
    }
  }
  if (end < 0) return null;
  if (!ranges.length && !negs.length) return { never: true };
  if (!negs.length && ranges.length === 1 && /^\\?.$/u.test(ranges[0]) && !negate) return { literal: ranges[0].slice(-1), end };
  const s = `[${negate ? "^" : ""}${ranges.join("")}]`;
  const n = `[${negate ? "" : "^"}${negs.join("")}]`;
  return { re: `(?!/)${ranges.length && negs.length ? `(?:${s}|${n})` : ranges.length ? s : n}`, end };
}

/**
 * Whether a workspace pattern in a package.json names a directory (relative to it), as npm's
 * minimatch reads it: braces, `*`, `?`, `**`, character classes, and a name that starts with a dot
 * matched only by a pattern that spells the dot. Null for an extglob (`+(a|b)`, `!(x)`), which this
 * rule does not read: the caller decides which way that falls.
 */
export function workspaceMatches(pattern, dir) {
  // npm turns a backslash into a slash before it globs, so there is no escape.
  const p = String(pattern).trim().replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/^(?:\.\/)+/, "").replace(/\/+$/, "");
  let unread = false;
  const hit = expandBraces(p).some((alt) => {
    const segs = alt.split("/");
    let re = "";
    for (const [i, seg] of segs.entries()) {
      const last = i === segs.length - 1;
      if (seg === "**") {
        re += last ? "(?:(?!\\.)[^/]+)(?:/(?!\\.)[^/]+)*" : "(?:(?!\\.)[^/]+/)*";
        continue;
      }
      if (/[!?+*@]\(/.test(seg)) {
        unread = true;
        return false;
      }
      // A name that starts with a dot is matched only where the pattern starts it with one, written
      // as a character (`.x`, or `[.]x`, which minimatch reads as the character).
      let s = "";
      let first = null;
      let tokens = 0;
      for (let k = 0; k < seg.length; k++) {
        const c = seg[k];
        let lit = null;
        if (c === "*") s += "[^/]*";
        else if (c === "?") s += "[^/]";
        else if (c === "[") {
          const cls = charClass(seg, k);
          if (cls?.never) return false;
          if (cls?.literal !== undefined) lit = cls.literal;
          else if (cls) s += cls.re;
          else lit = "[";
          if (cls) k = cls.end;
        } else lit = c;
        if (lit !== null) s += /[.+*?^$(){}|[\]\\/]/.test(lit) ? `\\${lit}` : lit;
        if (tokens++ === 0) first = lit;
      }
      re += (first === "." ? "" : "(?!\\.)") + s + (last ? "" : "/");
    }
    return new RegExp(`^${re}$`, "u").test(dir);
  });
  return hit ? true : unread ? null : false;
}

// The npm lockfile and the key in it of the package a manifest is, or null. A lockfile covers a
// manifest only where it is that lockfile's root, or a member its root package.json's `workspaces`
// names: npm run anywhere else uses that directory's own lockfile, or none. In one directory npm
// follows npm-shrinkwrap.json and not package-lock.json.
function npmLockFor(manifest, inv) {
  const mdir = path.posix.dirname(manifest);
  for (let dir = mdir; ; dir = path.posix.dirname(dir)) {
    const here = inv.locks.filter((l) => l.eco === "npm" && path.posix.dirname(l.path) === dir);
    const l = here.find((x) => path.posix.basename(x.path) === "npm-shrinkwrap.json") || here.find((x) => path.posix.basename(x.path) === "package-lock.json");
    if (l) {
      if (mdir === dir) return { lock: l, key: "" };
      const key = path.posix.relative(dir === "." ? "" : dir, mdir);
      const root = inv.manifests.find((m) => m.path === (dir === "." ? "package.json" : `${dir}/package.json`));
      const members = root?.workspaces || [];
      // A pattern this rule does not read (an extglob) makes no member and excludes any.
      if (l.entries.has(key) && members.some((w) => !w.startsWith("!") && workspaceMatches(w, key) === true) && !members.some((w) => w.startsWith("!") && workspaceMatches(w.slice(1), key) !== false)) return { lock: l, key };
    }
    if (dir === "." || dir === "") return null;
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
// `through`, when given, says which entries the walk goes on through: one it turns down is reached,
// and what only it depends on is not.
function npmReach(lock, startKeys, declared = null, through = null) {
  const seen = new Set();
  const stack = [...startKeys];
  while (stack.length) {
    const k = stack.pop();
    if (seen.has(k)) continue;
    seen.add(k);
    const e = lock.entries.get(k);
    if (!e) continue;
    if (through && !startKeys.includes(k) && !through(e)) continue;
    const names = e.local && declared?.has(k) ? declared.get(k) : Object.keys({ ...e.deps, ...e.devDeps });
    for (const dep of names) {
      const t = npmResolve(lock, k.includes("node_modules/") || e.local ? k : "", dep);
      if (t && !seen.has(t.key)) stack.push(t.key);
    }
  }
  return seen;
}

function pyReach(lock, names, through = null) {
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
      if (through && !names.includes(n) && !through(e)) continue;
      for (const d of e.deps || []) stack.push(d);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Where a name comes from
//
// One comparison decides it. Every place the tree records a name (a declaration, a lockfile entry,
// an override or a replace line) is given the place the tool takes the name from: a git
// repository, a URL, a path, a named registry or index, or, where the record names none, what the
// tool's settings give it there. The head's place for a name the project had must be the base's.
// The public registry is a place like any other, so a name moved onto it is a change of source.

const dirOf = (f) => path.posix.dirname(f);
const npmRegUrl = (u) => {
  const s = slash(normUrl(String(u)));
  return DEFAULT_NPM.some((d) => s.startsWith(d)) ? NPMJS : s;
};
const pyIndexUrl = (u) => {
  const s = slash(normUrl(String(u)));
  return s.startsWith(PYPI) ? PYPI : s;
};
const idxOnly = (scope) => (scope ? scope.entries.filter((x) => x.kind !== "setting") : []);

// Whether one of uv's globs (*, ?, [...], and ** for any depth) names a path, both relative to the
// workspace root. uv 0.12.1 takes a directory out of a workspace where an `exclude` pattern's *
// runs across a /, which `across` reads the same way; a member is a directory the pattern names.
function uvGlobMatches(pattern, rel, across = false) {
  const pat = pattern.replace(/^\.\//, "").replace(/\/+$/, "");
  let re = "";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (c === "*" && pat[i + 1] === "*") {
      re += pat[i + 2] === "/" ? "(?:.*/)?" : ".*";
      i += pat[i + 2] === "/" ? 2 : 1;
    } else if (c === "*") re += across ? ".*" : "[^/]*";
    else if (c === "?") re += across ? "." : "[^/]";
    else if (c === "[" && pat.indexOf("]", i + 2) > i) {
      const end = pat.indexOf("]", i + 2);
      const body = pat.slice(i + 1, end);
      re += `[${/^[!^]/.test(body) ? "^" : ""}${body.replace(/^[!^]/, "").replace(/[\\\]^]/g, "\\$&")}]`;
      i = end;
    } else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`).test(rel);
}

// The uv workspace root that takes a project's directory as a member, as uv looks for it: the
// nearest pyproject.toml above that is a project or has a [tool.uv.workspace], and only where that
// table's members name the directory and its exclude does not. uv 0.12.1, run against two local
// indexes, reads a member's indexes and settings from that root, whatever [tool.uv] table or
// uv.toml the member has of its own; a directory the root excludes, or does not name, reads its own.
function uvWorkspaceRoot(dir, inv) {
  if (!inv.uvRoots.has(dir)) return null;
  for (let at = dir; at !== "." && at !== ""; ) {
    at = dirOf(at);
    const above = inv.uvRoots.get(at);
    if (!above) continue;
    if (!above.workspace) {
      if (above.project) return null;
      continue;
    }
    const rel = path.posix.relative(at === "." ? "" : at, dir);
    return above.workspace.members.some((m) => uvGlobMatches(m, rel)) && !above.workspace.exclude.some((m) => uvGlobMatches(m, rel, true)) ? at : null;
  }
  return null;
}

/**
 * The registries, indexes and settings each tool reads, by the place it reads them for (a scope):
 * npm, the .npmrc of a project's directory; pip, a requirements file and the files it includes; uv,
 * the nearest directory up that has a uv.toml or a [tool.uv] table, the uv.toml hiding the table
 * beside it, and for a uv workspace's member what the workspace's root reads; poetry, pdm and
 * pipenv, the file that declares the sources. A setting in a file no tool reads for a place does
 * not count there.
 */
function scopeConfigs(inv) {
  const scopes = new Map();
  const put = (key, tool, entries, file) => scopes.set(key, { key, tool, entries, file });
  const of = (tool, pred) => inv.indexes.filter((x) => x.tool === tool && pred(x));
  const npmDirs = new Set([...inv.manifests.map((m) => dirOf(m.path)), ...inv.locks.filter((l) => l.eco === "npm").map((l) => dirOf(l.path)), ...of("npm", () => true).map((x) => dirOf(x.file))]);
  for (const d of npmDirs) {
    // npm reads the last line that sets a key, so an earlier one names no registry.
    const all = of("npm", (x) => dirOf(x.file) === d);
    const read = all.filter((x, i) => x.kind === "setting" || !all.slice(i + 1).some((y) => y.kind !== "setting" && (y.scope || "") === (x.scope || "")));
    put(`npm|${d}`, "npm", read, d === "." ? ".npmrc" : `${d}/.npmrc`);
  }
  for (const f of inv.reqFiles) {
    const closure = new Set([f]);
    for (const x of closure) for (const t of inv.reqIncludes.get(x) || []) closure.add(t);
    put(`pip|${f}`, "pip", of("pip", (x) => closure.has(x.file)), f);
  }
  for (const d of new Set([...inv.pyprojects.map(dirOf), ...inv.uvConfig.keys()])) {
    let conf = null;
    for (let at = d; ; at = dirOf(at)) {
      conf = inv.uvConfig.get(uvWorkspaceRoot(at, inv) ?? at) || null;
      if (conf || at === "." || at === "") break;
    }
    const file = conf ? conf.toml || conf.pyproject : null;
    put(`uv|${d}`, "uv", file ? of("uv", (x) => x.file === file) : [], file);
    // A member's own table or uv.toml, which uv does not read while the directory is a member. It
    // is still judged for what it names and no longer names, as a place of its own: the directory
    // read alone, outside its workspace, takes its names from there.
    const own = uvWorkspaceRoot(d, inv) === null ? null : inv.uvConfig.get(d);
    if (own) put(`uv-own|${d}`, "uv", of("uv", (x) => x.file === (own.toml || own.pyproject)), own.toml || own.pyproject);
  }
  for (const k of inv.pyTools) {
    const [tool, file] = [k.slice(0, k.indexOf("|")), k.slice(k.indexOf("|") + 1)];
    put(k, tool, of(tool, (x) => x.file === file), file);
  }
  return scopes;
}

/** npm's registries for a directory: every name's, each scope's, and the host it rewrites in a lockfile. */
function npmSettings(scope) {
  const idx = idxOnly(scope);
  const host = scope?.entries.filter((x) => x.kind === "setting" && x.key === "replace-registry-host").at(-1)?.value;
  return {
    registry: npmRegUrl(idx.filter((x) => !x.scope).at(-1)?.url || NPMJS),
    scopes: new Map(idx.filter((x) => x.scope).map((x) => [x.scope, npmRegUrl(x.url)])),
    replaceHost: host === undefined || host === "npmjs" ? "registry.npmjs.org" : String(host),
  };
}

/** Whether the public registry or index serves names in a scope, or the scope's settings keep it out. */
function publicServes(scope) {
  const idx = idxOnly(scope);
  const other = (pred) => idx.some((x) => pred(x) && !isRegistryUrl(x.eco, x.url, []));
  if (scope.tool === "npm") return !other((x) => !x.scope);
  if (scope.tool === "pip") return !idx.some((x) => x.kind === "no-index") && !other((x) => indexRole(x) === "index-url");
  if (scope.tool === "uv") return !idx.some((x) => x.kind === "no-index") && !other((x) => ["default", "default+explicit", "index-url"].includes(indexRole(x)));
  // poetry 2 puts PyPI out of use when a primary source is named, unless PyPI is named as a source too.
  if (scope.tool === "poetry") return !other((x) => ["primary", "default"].includes(indexRole(x))) || idx.some((x) => isRegistryUrl(x.eco, x.url, []));
  if (scope.tool === "pipenv") return !idx.length || idx.some((x) => isRegistryUrl(x.eco, x.url, []));
  return true;
}

/** The indexes a name with no source of its own can come from in a scope: { list, ordered }. */
function pyCandidates(scope) {
  const idx = idxOnly(scope);
  const urls = (pred) => idx.filter(pred).map((x) => (/find-links$/.test(x.kind) ? `links:${x.url}` : pyIndexUrl(x.url)));
  const uniq = (l) => [...new Set(l)];
  if (scope.tool === "pip") {
    // pip takes the best version from any of them, so they are one set.
    if (idx.some((x) => x.kind === "no-index")) return { list: uniq(urls((x) => indexRole(x) === "find-links")).sort(), ordered: false };
    const main = urls((x) => indexRole(x) === "index-url");
    return { list: uniq([...(main.length ? main : [PYPI]), ...urls((x) => ["extra-index-url", "find-links"].includes(indexRole(x)))]).sort(), ordered: false };
  }
  if (scope.tool === "uv") {
    // uv takes a name from the first index that has it: those listed, in order, then the default one.
    if (idx.some((x) => x.kind === "no-index")) return { list: uniq(urls((x) => indexRole(x) === "find-links")), ordered: false };
    const def = idx.find((x) => ["default", "index-url"].includes(indexRole(x)));
    const none = idx.some((x) => indexRole(x) === "default+explicit");
    return { list: uniq([...urls((x) => ["index", "extra-index-url", "find-links"].includes(indexRole(x))), ...(def ? [pyIndexUrl(def.url)] : none ? [] : [PYPI])]), ordered: true };
  }
  if (scope.tool === "poetry") {
    // poetry 1 keeps PyPI beside a primary source and poetry 2 does not, and either may be reading.
    return { list: uniq([...urls((x) => indexRole(x) !== "explicit"), ...(idx.some((x) => indexRole(x) === "default") ? [] : [PYPI])]).sort(), ordered: false };
  }
  if (scope.tool === "pipenv") return { list: idx.length ? uniq(urls(() => true)) : [PYPI], ordered: false };
  if (scope.tool === "pdm") return { list: uniq([PYPI, ...urls(() => true)]).sort(), ordered: false };
  return { list: [PYPI], ordered: false };
}

/**
 * The place a record that names no source of its own takes a name from, under a side's settings:
 * { id, first, shown, source }. `id` compares two such records; `first` is the one place it comes
 * to, where that can be told (one candidate, or the first of an ordered list), which is what a
 * lockfile entry's place is compared with.
 */
function defaultPlace(def, cfgs, name) {
  if (def.tool === "npm") {
    const c = npmSettings(cfgs.get(def.scopes[0]));
    const scope = def.variant === "name" ? /^(@[^/]+)\//.exec(name)?.[1] : null;
    const url = (scope && c.scopes.get(scope)) || c.registry;
    return { id: `reg:${url}`, first: `reg:${url}`, shown: url === NPMJS ? "the npm registry" : `the registry ${url}`, source: url };
  }
  const lists = def.scopes.map((k) => pyCandidates(cfgs.get(k) || { tool: k.slice(0, k.indexOf("|")), entries: [] }));
  if (!lists.length) lists.push({ list: [PYPI], ordered: false });
  const same = lists.every((l) => JSON.stringify(l.list) === JSON.stringify(lists[0].list));
  const one = same && lists[0].list.length === 1 ? lists[0].list[0] : null;
  const heads = lists.map((l) => (l.list.length === 1 || (l.ordered && l.list.length && !l.list.some((u) => u.startsWith("links:"))) ? l.list[0] : null));
  const first = heads.every((h) => h && h === heads[0]) ? `index:${heads[0]}` : null;
  const all = [...new Set(lists.flatMap((l) => l.list))];
  return {
    id: one ? `index:${one}` : `multi:${JSON.stringify(same ? lists[0].list : lists.map((l) => l.list))}`,
    first,
    shown: one === PYPI ? "PyPI" : one ? `the index ${one}` : `the indexes its file reads (${all.join(", ") || "none"})`,
    source: one || `the indexes ${all.join(", ") || "none"}`,
  };
}

// The directory npm takes its .npmrc from for a manifest: the workspace root that names it as a
// member, or its own.
function npmRootDir(manifest, inv) {
  const mdir = dirOf(manifest);
  for (let dir = mdir; dir !== "." && dir !== ""; ) {
    dir = dirOf(dir);
    const root = inv.manifests.find((m) => m.path === (dir === "." ? "package.json" : `${dir}/package.json`));
    const key = path.posix.relative(dir === "." ? "" : dir, mdir);
    const members = root?.workspaces || [];
    if (members.some((w) => !w.startsWith("!") && workspaceMatches(w, key) === true) && !members.some((w) => w.startsWith("!") && workspaceMatches(w.slice(1), key) !== false)) return dir;
  }
  return mdir;
}

/**
 * Every record in a tree of where a name comes from: { recs, ofDecl, ofEntry, bySlot, byFile, byName,
 * pins }. A record has a `place` (an id, how it is shown, and the text an allowlist entry gives for
 * it) or, where it names none, a `def`: the tool and the scopes whose settings decide. `slot` is the
 * record's own position (a manifest's name, a lockfile's key), which is what it is compared at.
 * A pin (an override, a replace line) says where a name comes from without asking for it.
 */
function placeRecords(inv, cfgs, knownNpm) {
  const out = { recs: [], ofDecl: new Map(), ofEntry: new Map(), bySlot: new Map(), byFile: new Map(), byName: new Map(), pins: [] };
  const index = (map, k, r) => map.set(k, [...(map.get(k) || []), r]);
  const record = (r) => {
    out.recs.push(r);
    index(out.bySlot, r.slot, r);
    index(out.byFile, `${r.file}|${r.eco}|${r.name}`, r);
    index(out.byName, `${r.eco}|${r.name}`, r);
    if (r.pin) out.pins.push(r);
    return r;
  };
  const concrete = (src) => ({ id: src.id, shown: src.own ? `the project's own ${src.id.slice(5) || "directory"}` : src.shown, source: src.type === "git" ? src.raw.replace(/#.*$/, "") : src.raw, own: src.own === true });
  // A URL under a registry the project's files name is that registry; any other, its directory, so a
  // version move from the same place compares equal.
  const npmUrl = (url) => {
    const u = normUrl(url);
    const root = knownNpm.find((k) => slash(u).startsWith(k));
    return root ? `reg:${npmRegUrl(root)}` : `url:${u.replace(/[^/]*$/, "")}`;
  };
  const npmConcrete = (src) => (src.type === "url" || src.type === "url-resolved" ? { id: npmUrl(src.raw), shown: src.raw, source: src.raw, own: false } : concrete(src));
  const npmDef = (dir, variant) => ({ tool: "npm", key: `npm|${dir}`, scopes: [`npm|${dir}`], variant });
  const npmPlace = (l, e) => {
    const ldir = dirOf(l.path);
    if (e.local) return { place: { id: `path:${path.posix.normalize(path.posix.join(ldir === "." ? "" : ldir, e.key || "."))}`, shown: `the project's own ${e.key || "package"}`, source: e.key || ".", own: true } };
    const s = e.source;
    // No `resolved`: npm asks the registry it has for the name, a scope's or every name's.
    if (!s || s.type === "registry") return { def: npmDef(ldir, "name") };
    if (s.type === "url-resolved") {
      // npm reads a `resolved` on registry.npmjs.org as "the registry every name has", not the
      // scope's, and fetches from that one (replace-registry-host says which host it reads so).
      // A plain-http `resolved` is not read so: npm before 7 fetches it as written, over http. At
      // the base it is also the registry, so that moving off http is not a change of place.
      let host = "";
      let plain = false;
      try {
        const u = new URL(e.resolved);
        host = u.hostname;
        plain = u.protocol !== "https:";
      } catch {
        /* not a URL: compared as it is written */
      }
      const c = npmSettings(cfgs.get(`npm|${ldir}`));
      if (host && (c.replaceHost === "always" || host === c.replaceHost)) return plain ? { place: npmConcrete(s), also: npmDef(ldir, "default") } : { def: npmDef(ldir, "default") };
    }
    return { place: npmConcrete(s) };
  };
  const pyConcrete = (src) => {
    if (src.type !== "index") return concrete(src);
    const url = /^https?:/i.test(src.raw) ? pyIndexUrl(src.raw) : null;
    return { id: `index:${url || `named ${src.raw}`}`, shown: url === PYPI ? "PyPI" : /^the index /.test(src.shown) ? src.shown : `the index ${src.raw}`, source: src.raw, own: false };
  };
  // The requirements files that read each one: itself, and every file that includes it.
  const readBy = new Map();
  for (const f of inv.reqFiles) {
    const closure = new Set([f]);
    for (const x of closure) for (const t of inv.reqIncludes.get(x) || []) closure.add(t);
    for (const x of closure) readBy.set(x, [...(readBy.get(x) || []), f]);
  }
  const pyDefs = (d) => {
    const base = path.posix.basename(d.manifest);
    if (d.section === "requirements") return (readBy.get(d.manifest) || [d.manifest]).map((f) => ({ tool: "pip", key: `pip|${f}`, scopes: [`pip|${f}`] }));
    if (base === "Pipfile") return [{ tool: "pipenv", key: `pipenv|${d.manifest}`, scopes: [`pipenv|${d.manifest}`] }];
    if (base === "pyproject.toml") return [{ tool: "pyproject", key: `pyproject|${d.manifest}`, scopes: [`uv|${dirOf(d.manifest)}`, ...["poetry", "pdm"].map((t) => `${t}|${d.manifest}`).filter((k) => inv.pyTools.has(k))] }];
    if (base === "uv.toml") return [{ tool: "pyproject", key: `uv|${d.manifest}`, scopes: [`uv|${dirOf(d.manifest)}`] }];
    return [{ tool: "plain", key: "plain", scopes: [] }];
  };
  const goReplace = (manifest, mod) =>
    inv.replaces.find((r) => r.path === mod && (r.file === manifest || inv.goWork.some((w) => w.file === r.file && w.uses.map((u) => path.posix.normalize(path.posix.join(dirOf(w.file) === "." ? "" : dirOf(w.file), u)).replace(/\/+$/, "") || ".").includes(dirOf(manifest)))));

  for (const d of inv.decl) {
    const name = normalName(d.eco, d.key);
    const base = { eco: d.eco, name, file: d.manifest, slot: `${d.manifest}|${d.eco}|${name}`, spec: d.spec };
    const made = [];
    // The project's own code where only the tool's files say so: a module a go.work uses, a project's own extras.
    if (d.eco !== "npm" && d.source?.own !== true && !d.source?.uvSource && ownSource(d, inv)) made.push({ place: { id: `own:${name}`, shown: "the project's own code", source: ".", own: true } });
    else if (d.eco === "npm") {
      if (d.role === "override") {
        if (d.source.type !== "registry") made.push({ place: npmConcrete(d.source), pin: "an override" });
      } else if (d.source.type === "registry") {
        // A range is whatever the lockfile that covers the manifest resolves it to: the registry's
        // package, or a workspace member npm links.
        const at = npmLockFor(d.manifest, inv);
        const e = at && npmResolve(at.lock, at.key, d.declaredAs);
        made.push(e ? npmPlace(at.lock, e) : { def: npmDef(at ? dirOf(at.lock.path) : npmRootDir(d.manifest, inv), "name") });
      } else made.push({ place: npmConcrete(d.source) });
    } else if (d.eco === "PyPI") {
      // A uv source is where uv takes the name from, lockfile or not: taken away, the name comes from the index.
      const src = d.source;
      if (d.role === "override") {
        if (src.type !== "registry") made.push({ place: pyConcrete(src), pin: d.section === "tool.uv.sources" ? "a uv source" : "an override" });
      } else if (src.type === "registry") for (const def of pyDefs(d)) made.push({ def });
      else made.push({ place: pyConcrete(src) });
    } else if (d.eco === "Go") {
      const rep = goReplace(d.manifest, d.key);
      made.push(rep ? { place: concrete(rep.source), replaced: true } : { place: { id: `module:${d.key}`, shown: "its own path, through the Go module proxy", source: d.key, own: false } });
    }
    const recs = made.map((m) => record({ ...base, ...m, ...(m.pin ? { slot: `${base.slot}|pin` } : {}) }));
    out.ofDecl.set(d, recs);
  }
  // A replace line for a module no require line of its file names: a pin.
  for (const r of inv.replaces) {
    if (inv.decl.some((d) => d.eco === "Go" && d.key === r.path && d.manifest === r.file)) continue;
    record({ eco: "Go", name: r.path, file: r.file, slot: `${r.file}|Go|${r.path}|pin`, spec: `replace ${r.path} => ${r.source.shown}`, place: concrete(r.source), pin: "a replace line" });
  }
  for (const l of inv.locks) {
    for (const e of l.entries.values()) {
      if (!e.name) continue;
      let m;
      if (l.eco === "npm") {
        if (e.local) continue;
        m = npmPlace(l, e);
      } else if (e.indexUrl) m = { place: { id: `index:${pyIndexUrl(e.indexUrl)}`, shown: `the index ${e.indexUrl}`, source: e.indexUrl, own: false } };
      else if (!e.source || e.source.type === "registry") {
        // poetry.lock gives a source to every package not from PyPI; a Pipfile.lock entry that names no index comes from the Pipfile's.
        const pipfile = path.posix.join(dirOf(l.path), "Pipfile");
        m = l.format === "Pipfile.lock" ? { def: { tool: "pipenv", key: `pipenv|${pipfile}`, scopes: [`pipenv|${pipfile}`] } } : { place: { id: `index:${PYPI}`, shown: "PyPI", source: PYPI, own: false } };
      } else m = { place: pyConcrete(e.source) };
      const name = normalName(l.eco, e.name);
      out.ofEntry.set(e, record({ eco: l.eco, name, file: l.path, slot: `${l.path}|${l.eco === "npm" ? e.key : name}`, spec: e.version, lock: true, ...m }));
    }
  }
  return out;
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// The entries that bring a lockfile entry in: for npm, those that depend on its name and resolve it
// to this entry; for uv.lock and poetry.lock, those that depend on its name.
function lockParents(lock, e) {
  if (!lock.parents) {
    lock.parents = new Map();
    for (const p of lock.entries.values()) {
      for (const n of lock.eco === "npm" ? Object.keys(p.deps || {}) : p.deps || []) {
        const k = lock.eco === "npm" ? n : normalName("PyPI", n);
        if (!lock.parents.has(k)) lock.parents.set(k, []);
        lock.parents.get(k).push(p);
      }
    }
  }
  if (lock.eco === "npm") return (lock.parents.get(e.keyName || e.name) || []).filter((p) => npmResolve(lock, p.key, e.keyName || e.name)?.key === e.key);
  return lock.parents.get(normalName("PyPI", e.name)) || [];
}

// The entry that brings an npm lockfile entry in, named for a person, or null.
function npmParent(lock, e) {
  const name = e.keyName || e.name;
  const p = [...lock.entries.values()].find((x) => x.deps && Object.hasOwn(x.deps, name) && npmResolve(lock, x.key, name)?.key === e.key);
  return p ? p.name || (p.key === "" ? "the project itself" : p.key) : null;
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

/**
 * The allowlist entry that approves a finding, or null. Never a "*" entry. An entry approves the
 * manifests under its path and no other, so a finding in several manifests is approved only when
 * each of them is under some entry's path: then what comes back carries each entry's reason.
 */
export function depApproved(f, entries) {
  const forIt = entries.filter((e) => {
    if (e.kind !== f.kind || e.ecosystem !== f.eco) return false;
    if ((e.package ?? null) === null ? f.package !== null : f.package === null || normalName(f.eco, e.package) !== normalName(f.eco, f.package)) return false;
    if (f.kind === "dependency-source" && canonicalSource(f.eco, e.source) !== f.sourceKey) return false;
    return true;
  });
  const covers = (e, m) => !e.path || e.path === "." || m === e.path || m.startsWith(`${e.path}/`);
  const manifests = f.manifests || [];
  const one = forIt.find((e) => manifests.every((m) => covers(e, m)));
  if (one) return one;
  const each = manifests.map((m) => forIt.find((e) => covers(e, m)));
  if (!each.length || each.some((e) => !e)) return null;
  return { ...each[0], reason: [...new Set(each.map((e) => e.reason))].join("; ") };
}

/** A source as an allowlist entry gives it, in the form findings compare: git without its ref, a URL's directory. */
export function canonicalSource(eco, raw) {
  const s = withoutCredentials(String(raw ?? "").trim());
  // A registry or index taken away: its own kind of source, so approving a registry is not approving its removal.
  if (/^no longer\s/.test(s)) return `gone:${s.slice(9).trim().replace(/\s+/g, " ")}`;
  if (eco === "Go") return /^(?:\.{1,2}\/|\/)/.test(s) || s === "." || s === ".." ? `path:${s}` : `module:${s.split(/\s+/)[0]}`;
  if (VCS.test(s) || /^(?:git:\/\/|github:|gitlab:|bitbucket:|gist:|[^@/\s:]+@[^:/\s]+:)/.test(s) || GIT_SHORTHAND.test(s)) return `git:${canonicalGit(s.replace(/#.*$/, "").replace(/@[^@/:]+$/, ""))}`;
  if (/^https?:\/\//i.test(s)) {
    const u = normUrl(s);
    // A file's URL is compared by its directory, so a version move from the same place passes; an
    // index or registry, whole.
    let file = false;
    try {
      file = /\/[^/]*\.[^/]*$/.test(new URL(u).pathname);
    } catch {
      /* not a URL: compared as it is written */
    }
    return `url:${file ? u.replace(/[^/]*$/, "") : slash(u)}`;
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
  // An allowlist entry whose source says it is a URL and is not one approves nothing this rule can
  // name, and the run says so: the entry may have been meant for a finding of this change.
  for (const e of allowlist) {
    if (e.kind === "dependency-source" && /^https?:\/\//i.test(e.source || "") && !urlReads(e.source)) {
      errors.push({ path: "the allowlist", why: "an entry's source is not a URL", text: `factory: the allowlist's entry ${withoutCredentials(JSON.stringify({ kind: e.kind, ecosystem: e.ecosystem, ...(e.package !== null ? { package: e.package } : {}), source: e.source }))} names a source that starts as a URL and cannot be read as one. Whether it was meant to approve a finding of this change is not known. Write the source as the blocking line gives it.` });
    }
  }
  const findings = [];
  const add = (f) => {
    const key = `${f.kind}|${f.eco}|${f.package === null ? "" : normalName(f.eco, f.package)}|${f.sourceKey || ""}`;
    const had = findings.find((x) => x.id === key);
    // Approval is asked again each time a manifest joins a finding: an entry narrowed to a path
    // approves what is under it, whichever file was read first.
    const approve = (x) => {
      const by = depApproved(x, allowlist);
      if (by) x.approvedBy = by.reason;
      else delete x.approvedBy;
      return x;
    };
    if (had) {
      for (const m of f.manifests || []) if (!had.manifests.includes(m)) had.manifests.push(m);
      return approve(had);
    }
    const done = approve({ ...f, id: key });
    findings.push(done);
    return done;
  };

  const baseKeys = new Map(); // eco|key -> [decl]
  for (const d of base.decl) if (d.role !== "override") baseKeys.set(`${d.eco}|${d.key}`, [...(baseKeys.get(`${d.eco}|${d.key}`) || []), d]);
  const baseIdx = { npm: base.indexes.filter((x) => x.eco === "npm" && x.kind !== "setting").map((x) => x.url), PyPI: base.indexes.filter((x) => x.eco === "PyPI" && x.kind !== "setting").map((x) => x.url) };

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

  // Where each name comes from, at the base and at the head, and the settings that decide it where
  // a record names no source.
  const baseCfg = scopeConfigs(base);
  const headCfg = scopeConfigs(head);
  const knownNpm = [...new Set([...DEFAULT_NPM, ...[...base.indexes, ...head.indexes].filter((x) => x.tool === "npm" && x.kind !== "setting").map((x) => slash(normUrl(x.url)))])].sort((a, b) => b.length - a.length);
  const baseRecs = placeRecords(base, baseCfg, knownNpm);
  const headRecs = placeRecords(head, headCfg, knownNpm);
  const scopeChanged = new Set();
  const placeWords = (r, cfgs) => (r.place ? r.place : defaultPlace(r.def, cfgs, r.name));
  const samePlace = (h, b) => {
    if (b.also && samePlace(h, { ...b, place: null, def: b.also, also: null })) return true;
    if (h.place && b.place) return h.place.id === b.place.id;
    const inBase = (def) => def.scopes.every((k) => baseCfg.has(k));
    if (!h.place && !b.place) {
      // In one scope, a change of its settings is that scope's finding and not each name's.
      const same = h.def.key === b.def.key && inBase(h.def);
      return defaultPlace(h.def, same ? baseCfg : headCfg, h.name).id === defaultPlace(b.def, baseCfg, h.name).id;
    }
    if (h.place) return h.place.id === defaultPlace(b.def, baseCfg, h.name).first;
    if (defaultPlace(h.def, headCfg, h.name).first === b.place.id) return true;
    // Under the base's settings the head's record is the base's place, and the change of settings has its own finding.
    return inBase(h.def) && h.def.scopes.some((k) => scopeChanged.has(k)) && defaultPlace(h.def, baseCfg, h.name).first === b.place.id;
  };
  const scopeFindings = [];
  // Registries, indexes and settings, compared for each place a tool reads them (a scope). One a
  // scope's files name that the base's did not name there is a finding; in a scope the base did not
  // have, one the base named nowhere. The public default, named where it already served, is no change.
  const idx3 = (x) => `${x.eco}|${x.scope || ""}|${slash(normUrl(x.url))}`;
  const baseAll = new Set(base.indexes.map(idx3));
  const headIn = new Map();
  for (const sc of headCfg.values()) for (const x of sc.entries) headIn.set(x, [...(headIn.get(x) || []), sc]);
  // One the base named for a scope that the head no longer reads there, or reads in a weaker role:
  // what the base took from it can then come from the public default, where anyone can publish
  // under a private name. A file that hides another's settings takes away what it hides.
  const removals = new Map();
  for (const b of baseCfg.values()) {
    const h = headCfg.get(b.key);
    if (!h) continue;
    const roles = new Map();
    for (const x of idxOnly(h)) roles.set(indexKey(x), [...(roles.get(indexKey(x)) || []), indexRole(x)]);
    const gone = [];
    for (const x of idxOnly(b)) {
      // The public default named and then not is no change, unless it was named for an npm scope
      // and every other name's registry at the head is another: the scope's names then move to that one.
      const elsewhere = x.eco === "npm" && x.scope && npmSettings(h).registry !== NPMJS ? npmSettings(h).registry : null;
      if (x.url && isRegistryUrl(x.eco, x.url, []) && !elsewhere) continue;
      const role = indexRole(x);
      const now = roles.get(indexKey(x)) || [];
      if (now.some((r) => r === role || (ROLE_RANK[r] && ROLE_RANK[role] && ROLE_RANK[r] > ROLE_RANK[role]))) continue;
      gone.push({ x, role, now, elsewhere: x.url && isRegistryUrl(x.eco, x.url, []) ? elsewhere : null, hidden: head.indexes.some((y) => y.file === x.file && y.tool === x.tool && indexKey(y) === indexKey(x) && indexRole(y) === role) ? h.file : null });
    }
    if (gone.length) removals.set(b.key, gone);
  }
  for (const x of head.indexes) {
    if (x.kind === "no-index") continue;
    const setting = x.kind === "setting";
    const isDefault = !setting && isRegistryUrl(x.eco, x.url, []);
    const fresh = (headIn.get(x) || []).filter((sc) => {
      const b = baseCfg.get(sc.key);
      if (!b) return !isDefault && !baseAll.has(idx3(x));
      if (b.entries.some((y) => idx3(y) === idx3(x))) return false;
      // The public default named again where the base's settings kept it out; a finding for what kept it out says so already.
      return !isDefault || (!publicServes(b) && !removals.has(sc.key));
    });
    if (!fresh.length) continue;
    for (const sc of fresh) scopeChanged.add(sc.key);
    scopeFindings.push({ eco: x.eco, package: x.scope || null, kind: "dependency-source", manifests: [x.file], spec: setting ? x.url : x.kind ? `${x.kind} ${x.url}` : `${x.scope ? `${x.scope}:` : ""}registry=${x.url}`, resolves: setting ? (x.why === WHY_UNKNOWN_SETTING ? "wherever that setting may send it" : "wherever that setting sends it") : x.url, sourceKey: canonicalSource(x.eco, x.url), sourceShown: x.url, registry: true, ...(isDefault ? { back: true } : {}), why: setting ? x.why || WHY_SOURCE_SETTING : isDefault ? "the base's settings kept the public default out of the names this file serves, and this names it again" : "a registry or index the base did not name" });
  }
  for (const [key, gone] of removals) {
    scopeChanged.add(key);
    for (const { x, role, now, hidden, elsewhere } of gone) {
      const shown = indexShown(x);
      scopeFindings.push({
        eco: x.eco,
        package: x.scope || null,
        kind: "dependency-source",
        manifests: [x.file],
        spec: shown,
        resolves: elsewhere ? `the registry ${elsewhere}` : x.eco === "npm" ? "the npm registry" : "PyPI",
        sourceKey: canonicalSource(x.eco, `no longer ${shown}`),
        sourceShown: `no longer ${shown}`,
        registry: true,
        removed: now.length ? `the head names it only as ${[...new Set(now)].map((r) => roleWord(x.eco, r)).join(", ")}` : hidden ? `the head reads ${hidden} in its place, which does not name it` : "the head no longer names it",
        // explicit = true taken away, or given, changes which names come from the index and which
        // from PyPI, in either direction.
        why: elsewhere
          ? `what the base took from the public npm registry under this scope comes from ${elsewhere} instead`
          : now.length && !ROLE_RANK[role]
            ? `which names come from it and which from PyPI is no longer what the base said`
            : `what the base took ${x.kind === "no-index" ? "from its own files and indexes" : "from it"} can come from ${x.eco === "npm" ? "the public npm registry" : "PyPI"} instead, where anyone can publish under a name that was private`,
      });
    }
  }
  // uv takes a name from the first index that has it, and pipenv a name with no index of its own
  // from the first source, so the order is part of where a name comes from.
  for (const b of baseCfg.values()) {
    const h = headCfg.get(b.key);
    if (!h || !["uv", "pipenv"].includes(b.tool) || scopeChanged.has(b.key)) continue;
    const [was, now] = [pyCandidates(b).list, pyCandidates(h).list];
    if (JSON.stringify(was) === JSON.stringify(now) || JSON.stringify([...was].sort()) !== JSON.stringify([...now].sort())) continue;
    scopeChanged.add(b.key);
    const shown = `the order ${was.join(", ")}`;
    scopeFindings.push({ eco: "PyPI", package: null, kind: "dependency-source", manifests: [h.file || b.file], spec: `the indexes ${b.tool} reads, in ${shown}`, resolves: "PyPI", sourceKey: canonicalSource("PyPI", `no longer ${shown}`), sourceShown: `no longer ${shown}`, registry: true, removed: `the head lists them in the order ${now.join(", ")}`, why: `${b.tool === "uv" ? "uv takes a name from the first index that has it" : "pipenv takes a name with no index of its own from the first source"}, so which index serves a name is no longer what the base said` });
  }

  // The one comparison: the head's place for a name the project had is the base's place for it, at
  // the same position, in the same file, or anywhere, in that order. True when the name was judged
  // (it passes, or has its finding), false when the project did not have the name at the base.
  const judgePlace = (h, shared) => {
    if (h.place?.own) return true;
    const was = baseRecs.bySlot.get(h.slot) || baseRecs.byFile.get(`${h.file}|${h.eco}|${h.name}`) || baseRecs.byName.get(`${h.eco}|${h.name}`);
    if (!was) return false;
    if (was.some((b) => samePlace(h, b))) return true;
    const now = placeWords(h, headCfg);
    const from = [...new Set(was.map((b) => placeWords(b, baseCfg).shown))];
    add({ ...shared, kind: "dependency-source", resolves: now.shown, sourceKey: canonicalSource(h.eco, now.source), sourceShown: now.source, moved: from, why: `its source changed (the base took it from ${from.slice(0, 3).join(", or from ")}${from.length > 3 ? `, or ${from.length - 3} more` : ""})` });
    return true;
  };

  // Names the project had at the base: in its lockfiles, or declared by its manifests. A name is new
  // to the project only when it is neither, so a first lockfile's names are judged as well.
  const baseDeclared = { npm: new Set(), PyPI: new Set() };
  for (const d of base.decl) if (baseDeclared[d.eco] && d.role !== "override") for (const n of [d.key, d.declaredAs]) baseDeclared[d.eco].add(normalName(d.eco, n));
  const baseHad = (eco, nk) => baseLockNames[eco].has(nk) || baseDeclared[eco].has(nk);
  // Names the head's manifests ask for: npm's by the name installed and the name it is installed
  // as. An override chooses a version and adds no name.
  const declaredNames = { npm: new Set(), PyPI: new Set() };
  for (const d of head.decl) if (declaredNames[d.eco] && d.role !== "override") for (const n of [d.key, d.declaredAs]) declaredNames[d.eco].add(normalName(d.eco, n));
  // A name new to the project that no manifest declares: it needs a finding of its own, unless it
  // comes with a dependency new in the manifests and is counted in that one's.
  const undeclaredNew = (l, e) => {
    if (!e.name || e.local || e.link) return false;
    const nk = normalName(l.eco, e.name);
    const names = e.keyName && e.keyName !== e.name ? [nk, e.keyName] : [nk];
    return !names.some((n) => declaredNames[l.eco].has(n)) && !baseHad(l.eco, nk);
  };
  // The lockfile entries that come with a new dependency, by lockfile: those it brings in itself, or
  // through names that are new to the project too. Its finding lists them, and they need none of
  // their own. A name it reaches only through a package the project had is that package's to
  // answer for, and gets its finding below.
  const newToProject = (l) => (e) => Boolean(e.name) && !e.local && !baseHad(l.eco, normalName(l.eco, e.name));
  const counted = new Map();
  const count = (lock, entries) => {
    if (!counted.has(lock.path)) counted.set(lock.path, new Set());
    for (const e of entries) counted.get(lock.path).add(e.key);
  };
  const listed = (entries) => entries.map((e) => ({ name: e.name, version: e.version }));

  // What a new direct dependency brings into the lockfile, for the finding a person approves from.
  const brings = (d) => {
    if (d.eco === "npm") {
      const at = npmLockFor(d.manifest, head);
      if (!at) return { lock: null, why: head.lockDirs.npm.size ? "no package-lock.json covers this manifest" : "there is no lockfile" };
      const start = npmResolve(at.lock, at.key, d.declaredAs);
      if (!start) return { lock: at.lock.path, why: `${at.lock.path} does not hold it` };
      const keys = npmReach(at.lock, [start.key]);
      const fresh = [...keys].map((k) => at.lock.entries.get(k)).filter((e) => e && e.name && !e.local && !baseLock.npm.has(`${e.name}@${e.version}`));
      count(at.lock, [...npmReach(at.lock, [start.key], null, newToProject(at.lock))].map((k) => at.lock.entries.get(k)).filter(Boolean));
      return { lock: at.lock.path, count: fresh.length, packages: listed(fresh), scripts: fresh.filter((e) => e.scripts === true).map((e) => e.name), scriptsKnown: fresh.every((e) => e.scripts !== null) };
    }
    if (d.eco === "PyPI") {
      const dir = path.posix.dirname(d.manifest);
      const lock = head.locks.find((l) => l.eco === "PyPI" && l.entries.size && (path.posix.dirname(l.path) === dir || dir.startsWith(`${path.posix.dirname(l.path)}/`) || path.posix.dirname(l.path) === "."));
      if (!lock) return { lock: null, why: "there is no lockfile this rule reads" };
      if (lock.format === "Pipfile.lock") {
        // No edges: whatever is new to it beside this dependency may be what it brings, and is
        // listed in this finding for the person who approves it.
        const beside = [...lock.entries.values()].filter((e) => undeclaredNew(lock, e));
        count(lock, beside);
        return { lock: lock.path, why: "Pipfile.lock does not record which package brings which", packages: listed(beside), pipfile: true };
      }
      const fresh = pyReach(lock, [d.key]).filter((e) => !e.local && !baseLock.PyPI.has(e.key));
      if (!fresh.length) return { lock: lock.path, why: `${lock.path} does not hold it` };
      count(lock, pyReach(lock, [d.key], newToProject(lock)));
      return { lock: lock.path, count: fresh.length, packages: listed(fresh), scripts: fresh.filter((e) => e.scripts === true).map((e) => e.name), scriptsKnown: true, scriptWord: "build from source" };
    }
    const sums = head.goSums.flatMap((s) => [...s.modules]).filter((m) => !baseGoSum.has(m));
    return { lock: "go.sum", count: new Set(sums).size, scripts: [], scriptsKnown: true, goTotal: true };
  };

  // Go: a module marked `// indirect` is the project's own dependency when its code imports it or a
  // tool line runs it. The marker is a comment the change writes, so it is not taken on its word.
  const goImportedAt = { head: null, base: null };
  const goImportsOf = (inv, side) => {
    if (!goImportedAt[side]) {
      const set = new Set();
      for (const f of inv.files) {
        if (!f.endsWith(".go")) continue;
        if (f.split("/").some((p) => p === "testdata" || p === "vendor")) continue;
        // read lazily through the tree the inventory came from
        const text = inv.read(f);
        if (typeof text !== "string") {
          errors.push({ path: f, why: `${text?.unread || "it could not be read"}, so the modules it imports are not known`, side: side === "head" ? "the head" : "the base" });
          continue;
        }
        for (const p of goImports(text)) set.add(p);
      }
      goImportedAt[side] = set;
    }
    return goImportedAt[side];
  };
  const importedByProject = (mod) => {
    // A tool line runs a package of the module, so the module is the project's as much as an import.
    const inMod = (p) => p === mod || p.startsWith(`${mod}/`);
    if ([...goImportsOf(head, "head")].some(inMod)) return "the project's code imports it";
    if ([...head.goTools].some(inMod)) return "a tool line in go.mod runs it";
    return false;
  };
  // Whether the base had a Go module as a dependency of its own: listed without `// indirect`, or
  // imported by its code, or run by a tool line. One held only as indirect, which nothing of the
  // base's used, was another module's dependency and not the project's. An import belongs to the
  // longest module path the base's go.mod files require that it sits under.
  let baseGoMods = null;
  const baseHadGo = (mod) => {
    if ((baseKeys.get(`Go|${mod}`) || []).some((b) => b.role !== "indirect")) return true;
    baseGoMods ||= [...new Set(base.decl.filter((b) => b.eco === "Go").map((b) => b.key))].sort((a, b) => b.length - a.length);
    const owner = (p) => baseGoMods.find((m) => p === m || p.startsWith(`${m}/`));
    return [...goImportsOf(base, "base"), ...base.goTools].some((p) => owner(p) === mod);
  };

  // 1, 2 and 4, from what the manifests declare.
  for (let d of head.decl) {
    const records = headRecs.ofDecl.get(d) || [];
    if (ownSource(d, head)) continue;
    // A uv source that is not the project's own by uv.lock: pip, and uv with no lockfile to follow
    // for it, takes the name from PyPI.
    if (d.source?.uvSource && d.source.own) d = { ...d, source: REGISTRY(`PyPI (tool.uv.sources names ${d.source.shown}, which only uv reads, and no uv.lock covering ${d.manifest} holds it from there)`) };
    const k = `${d.eco}|${d.key}`;
    const viaIndirect = d.role === "indirect";
    // A Go module the head uses, which the base held only as `// indirect` and did not use, is new
    // to the project as a dependency of its own, as an npm package is that goes from a lockfile
    // entry another package brought to a line in package.json.
    const goUsed = d.eco === "Go" && d.role !== "override" && (!viaIndirect || Boolean(importedByProject(d.key)));
    const wasIndirect = goUsed && baseKeys.has(k) && !baseHadGo(d.key);
    const wasDeclared = baseKeys.has(k) && !wasIndirect;
    const isNew = !wasDeclared && d.role !== "override" && (!viaIndirect || importedByProject(d.key));
    const aliasNew = d.role === "override" && d.key !== d.declaredAs && !wasDeclared && !baseLockNames.npm.has(d.key);
    const raw = d.source.type === "git" ? d.source.raw.replace(/#.*$/, "") : d.source.raw;
    const shared = {
      eco: d.eco,
      package: d.key === d.declaredAs || d.eco === "PyPI" ? d.name : d.key,
      declaredAs: d.declaredAs !== d.name ? d.declaredAs : null,
      spec: d.spec,
      manifests: [d.manifest],
      section: d.section,
      resolves: d.source.type === "registry" ? d.source.shown : d.source.shown,
    };
    if (isNew || aliasNew) add({ ...shared, kind: "new-dependency", brings: brings(d), indirectMarked: viaIndirect ? importedByProject(d.key) : null, ...(wasIndirect ? { wasIndirect: true } : {}) });
    // A name the project had comes from where it came from; a Go module a replace line moves has its finding below.
    const had = records.filter((h) => !h.replaced).map((h) => judgePlace(h, shared)).some(Boolean);
    // A name new to the project is from the registry, or an index the base named, or its source is a finding beside its name's.
    if (!had && !fromRegistry(d.source, d.eco, baseIdx[d.eco] || []) && (d.role !== "indirect" || isNew)) add({ ...shared, kind: "dependency-source", sourceKey: canonicalSource(d.eco, raw), sourceShown: raw, why: "it is new, and not from the registry" });
    // A URL to a registry's file is that registry, so the file has to be the package's own, as a lockfile entry's is.
    if (d.eco === "npm" && d.source.type === "url" && registryFileMatches("npm", d.source.raw, d.key, null, knownNpm) === false && !base.decl.some((b) => b.eco === "npm" && b.key === d.key && b.source.type === "url" && b.source.raw === d.source.raw)) {
      add({ ...shared, kind: "dependency-source", sourceKey: canonicalSource("npm", d.source.raw), sourceShown: d.source.raw, why: `${d.manifest} takes ${d.key} from a file of the registry's that is not that package's` });
    }
    if (d.anything && d.role === "dependency") {
      const unchanged = (baseKeys.get(k) || []).some((b) => b.spec === d.spec);
      // A lockfile pins a range where it covers the manifest and holds the name. One this rule reads
      // is asked both: a package-lock.json above a manifest that is not its workspace's member does
      // not cover it, and a lockfile that does not hold the name pins nothing for it. One this rule
      // does not read is taken to cover every manifest under its directory.
      const dir = path.posix.dirname(d.manifest);
      const under = (at) => at === "." || dir === at || dir.startsWith(`${at}/`);
      let covered = [...(head.unreadLockDirs[d.eco] || [])].some(under);
      if (!covered && d.eco === "npm") {
        const at = npmLockFor(d.manifest, head);
        covered = Boolean(at && npmResolve(at.lock, at.key, d.declaredAs));
      }
      if (!covered && d.eco === "PyPI") covered = head.locks.some((l) => l.eco === "PyPI" && under(path.posix.dirname(l.path)) && [...l.entries.values()].some((e) => normalName("PyPI", e.name) === d.key));
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

  // Registries, indexes and settings: the findings worked out above, in their place among the others.
  for (const f of scopeFindings) add(f);

  // An override or a replace line the base had that the head does not: the name it pinned comes
  // from the registry again, unless the head still takes it from the same place or no longer has it.
  for (const b of baseRecs.pins) {
    if (!head.files.includes(b.file)) continue;
    const now = headRecs.byName.get(`${b.eco}|${b.name}`) || [];
    if (now.some((h) => h.place?.id === b.place.id)) continue;
    if (!now.length) {
      // Nothing at the head records the name. With a lockfile that covers the file, it is gone.
      const dir = dirOf(b.file);
      if (b.eco === "npm" && npmLockFor(b.file, head)) continue;
      if (b.eco === "PyPI" && head.locks.some((l) => l.eco === "PyPI" && (dirOf(l.path) === "." || dir === dirOf(l.path) || dir.startsWith(`${dirOf(l.path)}/`)))) continue;
      if (b.eco === "Go" && head.goSums.length && !head.goSums.some((g) => g.modules.has(b.name))) continue;
    }
    const to = now.length ? placeWords(now[0], headCfg) : b.eco === "npm" ? defaultPlace({ tool: "npm", scopes: [`npm|${npmRootDir(b.file, head)}`], variant: "name" }, headCfg, b.name) : b.eco === "Go" ? { shown: "its own path, through the Go module proxy", source: b.name } : { shown: "PyPI", source: PYPI };
    add({ eco: b.eco, package: b.name, kind: "dependency-source", manifests: [b.file], spec: b.spec, section: "override", unpinned: true, resolves: to.shown, sourceKey: canonicalSource(b.eco, to.source), sourceShown: to.source, moved: [b.place.shown], why: `${b.pin} in ${b.file} at the base took it from ${b.place.shown}, and the head has none${now.length ? "" : "; no lockfile at the head shows whether it is still installed"}` });
  }

  const baseLockAt = new Map(base.locks.map((l) => [l.path, l]));

  // The lockfiles: entries from a new source, edited in place, nothing brings in, or with a new script.
  for (const l of head.locks) {
    // npm reads a lockfile whose lockfileVersion is not 2 or more as one from before npm 7: it does
    // not trust its install-script flags, and reads each package for a script and runs it. Packages
    // the change added or moved in one cannot be judged for scripts.
    if (l.eco === "npm" && l.old) {
      const fresh = [...l.entries.values()].filter((e) => e.name && !e.local && !e.link && !baseLock.npm.has(`${normalName("npm", e.name)}@${e.version}`));
      const was = baseLockAt.get(l.path);
      // A lockfile rewritten in the old format is reported even with nothing new in it: no npm since
      // version 7 writes one.
      if (fresh.length || (was && !was.old)) {
        const list = fresh.slice(0, 8).map((e) => `${e.name} ${e.version}`).join(", ") + (fresh.length > 8 ? `, +${fresh.length - 8} more` : "");
        errors.push({
          path: l.path,
          side: "the head",
          why: `npm reads it as a lockfile from before npm 7 (${l.shown}${l.packagesMissing ? ", no packages section" : ""}), which records no install scripts`,
          text:
            `factory: ${l.path} at the head has ${l.shown}${l.packagesMissing ? " and no packages section" : ""}, so npm reads it as a lockfile from before npm 7, which records no install scripts (${was ? `the base's has ${was.shown}${was.old ? "" : ", so this change rewrote it in the older format"}` : "the base has none"}). ` +
            `${fresh.length ? `The change adds or moves ${plural(fresh.length, "package")} in it (${list}), and npm reads each for a script and runs it. ` : ""}` +
            `Whether this change adds a package that runs code when installed is not known. Write the lockfile with npm 7 or later, which records it.`,
        });
      }
    }
    let reached = null;
    if (l.eco === "npm" && !l.old) {
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
      // A name the project had comes from where it came from; one new to it, from the registry or an index the base named.
      const rec = headRecs.ofEntry.get(e);
      if (!(rec && judgePlace(rec, shared)) && !fromRegistry(e.source, l.eco, baseIdx[l.eco] || []) && !e.source?.own) {
        add({ ...shared, kind: "dependency-source", sourceKey: canonicalSource(l.eco, e.source.raw), sourceShown: e.source.type === "git" ? e.source.raw.replace(/#.*$/, "") : e.source.raw, why: "the lockfile takes it from somewhere other than the registry" });
      }
      // A Python lockfile names the files it downloads. From the registry, they are on its own hosts.
      const offHost = l.eco === "PyPI" && fromRegistry(e.source, l.eco, baseIdx.PyPI) ? (e.urls || []).find((u) => !isRegistryUrl("PyPI", u, [...baseIdx.PyPI, ...(e.source?.raw && urlReads(slash(e.source.raw)) ? [new URL(slash(e.source.raw)).origin] : [])])) : null;
      if (offHost) add({ ...shared, kind: "dependency-source", resolves: offHost, sourceKey: canonicalSource(l.eco, offHost), sourceShown: offHost, why: "the lockfile downloads a file of it from outside the registry" });
      const fileUrls = l.eco === "npm" ? (e.resolved && e.source?.type === "url-resolved" ? [e.resolved] : []) : e.urls || [];
      let other = fileUrls.find((u) => registryFileMatches(l.eco, u, e.name, e.version, knownNpm) === false);
      // An entry from an index lists its files, by URL or by name. On whatever host, each is named
      // for the package: another package's file is installed under its own name, with no finding of its own.
      if (!other && l.eco === "PyPI" && ["registry", "index"].includes(e.source?.type)) {
        other = [...fileUrls.filter((u) => registryFileMatches("PyPI", u, e.name, e.version) === null), ...(e.files?.keys() || [])].find((f) => !pyFileNamed(f, e.name));
      }
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
        add({ ...shared, kind: "new-dependency", orphan: true, brings: { lock: l.path, count: 1, packages: listed([e]), scripts: e.scripts ? [e.name] : [], scriptsKnown: e.scripts !== null } });
      }
      // Another package under a key: npm installs `name`'s code where node looks for the key's
      // name. That is an alias, which a manifest or the entry that brings it in declares.
      if (l.eco === "npm" && !e.link && e.keyName && e.name !== e.keyName) {
        const asked = head.decl.some((d) => d.eco === "npm" && d.declaredAs === e.keyName && d.key === e.name);
        const brought = [...l.entries.values()].some((p) => !p.local && typeof p.deps[e.keyName] === "string" && p.deps[e.keyName].startsWith(`npm:${e.name}@`) && npmResolve(l, p.key, e.keyName)?.key === e.key);
        const had = baseLockAt.get(l.path)?.entries.get(e.key)?.name === e.name;
        if (!asked && !brought && !had) add({ ...shared, kind: "new-dependency", installedAs: e.keyName, brings: { lock: l.path, count: 1, packages: listed([e]), scripts: e.scripts ? [e.name] : [], scriptsKnown: e.scripts !== null } });
      }
      if (e.scripts === true) {
        const had = baseLockNames[l.eco].get(nk);
        if (!had || (had.known && !had.scripts)) {
          add({ ...shared, kind: "install-script", broughtBy: l.eco === "npm" ? npmParent(l, e) : null, was: had ? "versions at the base had none" : null, scriptWord: l.eco === "PyPI" ? "build" : "script" });
        }
      }
    }

    // A name new to the project that no manifest declares, and that no new dependency's finding
    // counts, is a new dependency of its own where something the project had, or the lockfile's own
    // record of the project, brings it in; what comes only through it is counted in that finding.
    // A lockfile is the change's to write, so an edge in it is not evidence that anyone asked for a
    // name, and names new to the project vouch for nothing: not for each other, and not for
    // themselves. A version move that brings a name the project never had is approved like any
    // other new name, and so is what a first lockfile brings with a name the base declared.
    // An old npm lockfile is exit 3 above, and one from npm 3 records no edges. An npm entry that
    // nothing brings in at all has its finding above.
    if (!(l.eco === "npm" && l.old)) {
      const already = counted.get(l.path) || new Set();
      const open = [...l.entries.values()].filter((e) => undeclaredNew(l, e) && !already.has(e.key) && !(reached && !reached.has(e.key)));
      const fresh = (es) => es.filter((x) => x && x.name && !x.local && !baseLock[l.eco].has(`${normalName(l.eco, x.name)}@${x.version}`));
      const of = (e) => ({ eco: l.eco, package: e.name, spec: e.version, manifests: [l.path], section: "lockfile", resolves: e.source?.shown || "the registry" });
      if (l.format === "Pipfile.lock") {
        // No edges, and no new dependency's finding lists these: nothing this change declares brings them.
        for (const e of open) add({ ...of(e), kind: "new-dependency", unbrought: { pipfile: true }, brings: { lock: l.path, count: 1, packages: listed([e]), scripts: [], scriptsKnown: false } });
      } else {
        const openKeys = new Set(open.map((e) => e.key));
        const covered = new Set();
        const finding = (e, parents, had = false) => {
          const reach = fresh(l.eco === "npm" ? [...npmReach(l, [e.key])].map((k) => l.entries.get(k)) : pyReach(l, [normalName(l.eco, e.name)]));
          for (const x of [e, ...reach]) covered.add(x.key);
          add({ ...of(e), kind: "new-dependency", unbrought: { parents, had }, brings: { lock: l.path, count: reach.length, packages: listed(reach), scripts: reach.filter((x) => x.scripts === true).map((x) => x.name), scriptsKnown: reach.every((x) => x.scripts !== null), ...(l.eco === "PyPI" ? { scriptWord: "build from source" } : {}) } });
        };
        for (const e of open) {
          const outside = lockParents(l, e).filter((p) => !openKeys.has(p.key));
          if (outside.length) finding(e, [...new Set(outside.map((p) => (p.local ? `the lockfile's own record of ${l.eco === "npm" ? p.key || "the project" : p.name}` : `${p.name} ${p.version}`)))], outside.every((p) => p.local || !newToProject(l)(p)));
        }
        // Names that only other new names bring in, in a cycle with nothing the project had above it.
        for (const e of open) if (!covered.has(e.key)) finding(e, []);
      }
    }
  }

  // Files the change wrote that this rule does not read.
  const notRead = [];
  for (const c of changed) {
    const base = path.posix.basename(c.path);
    const hit = NOT_READ.find(([re]) => re.test(base));
    // A manifest or lockfile where this rule does not look: another check blocks a write there, and
    // when a person has approved the place, the file is still named as one nobody read for dependencies.
    const where = hit || READ_NAMES.has(base) || isRequirementsFile(c.path) ? head.skipped(c.path) : null;
    if (where) notRead.push({ path: c.path, ecosystem: where });
    else if (hit) notRead.push({ path: c.path, ecosystem: hit[1] });
  }
  // Nothing printed from here carries a URL's user, password, token or query. An allowlist entry's
  // reason is the pipeline's own text and stays as written.
  return { findings: findings.map(({ approvedBy, ...f }) => ({ ...cleaned(f), ...(approvedBy === undefined ? {} : { approvedBy }) })), errors: errors.map(cleaned), notRead };
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
    const fromLock = f.orphan || f.unbrought || f.installedAs;
    // The packages that come with it, by name: approving it approves them.
    const others = (b.packages || []).filter((p) => normalName(f.eco, p.name) !== normalName(f.eco, f.package ?? ""));
    const few = (list) => `${list.slice(0, 6).map((p) => `${p.name} ${p.version}`).join(", ")}${list.length > 6 ? `, +${list.length - 6} more` : ""}`;
    const counted = () => (b.count > 1 ? ` With it ${b.count === 2 ? "comes" : "come"} ${plural(b.count - 1, "more package")} new to the lockfile${others.length ? ` (${few(others)})` : ""}${b.scripts?.length ? `, and ${b.scripts.join(", ")} ${b.scriptWord ? "is built from source when installed" : "runs code when installed"}` : ""}.` : b.scripts?.length ? ` It ${b.scriptWord ? "is built from source when installed" : "runs code when installed"}.` : "");
    if (f.orphan) brought = `It is in ${where}, and no manifest declares it and nothing in the lockfile brings it in.`;
    else if (f.unbrought?.pipfile) brought = `It is new to ${where}, and no manifest declares it. Pipfile.lock does not record which package brings which, and this change declares no new dependency beside it, so nothing it adds brings this one in.`;
    else if (f.unbrought) {
      const by = f.unbrought.parents.length ? `brought in by ${f.unbrought.parents.slice(0, 4).join(", ")}${f.unbrought.parents.length > 4 ? `, +${f.unbrought.parents.length - 4} more` : ""}${f.unbrought.had ? ", which the project had at the base" : ""}` : "and nothing the project had brings it in, only names new to it";
      brought = `It is new to ${where}, ${by}; no manifest declares it. A package the project has never had is approved like any new dependency, also when a version move brings it.${counted()}`;
    }
    else if (f.installedAs) brought = `It is in ${where}, installed as ${f.installedAs}, and neither a manifest nor the package that brings it in declares that alias.`;
    else if (b.count === undefined) {
      brought = `${b.why ? `${b.why[0].toUpperCase()}${b.why.slice(1)}` : "No lockfile covers it"}, so which packages it brings, and whether any runs code when it is installed, is not known.`;
      if (b.pipfile && others.length) brought += ` New to ${b.lock} with this change, and declared by no manifest: ${few(others)}. Approving this dependency approves them as what it brings.`;
    }
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
      brought = `It adds ${plural(b.count, "package")} to ${b.lock}${others.length ? ` (with it: ${few(others)})` : ""}, ${s}.`;
    }
    const indirect = f.indirectMarked ? ` It is marked \`// indirect\`, and ${f.indirectMarked}.` : "";
    const base = f.wasIndirect ? "The base's go.mod held it only as `// indirect`, for another module, and nothing of the base's imported it; now the project uses it itself" : "The base did not declare it";
    return (
      `factory: new dependency — ${what} ${fromLock ? f.spec : quote(f.spec)}${as} in ${where}${fromLock ? "" : ` (${f.section})`}, from ${f.resolves}. ${brought}${indirect} ` +
      `${base}, and in factory mode a dependency needs a person's approval. Remove it, or have the pipeline's allowlist approve it: ${entry}`
    );
  }
  if (f.kind === "dependency-source" && f.removed) {
    return (
      `factory: dependency from a new source — ${f.eco} ${f.package ? `${f.package} packages` : "packages"}: ${f.spec} in ${where} at the base, and ${f.removed}: ${f.why}. ` +
      `Name it again as the base did, or have the pipeline's allowlist approve this: ${entry}`
    );
  }
  if (f.kind === "dependency-source") {
    return (
      `factory: dependency from a new source — ${f.registry ? `${f.eco} ${f.package ? `${f.package} packages` : "packages"}: ${f.spec} in ${where}` : `${what}${f.unpinned ? "" : ` ${quote(f.spec)}`}${as} in ${where}`}, from ${f.resolves}: ${f.why}. ` +
      `Approving a name does not approve where it comes from. ${f.moved ? "Take it from where the base took it" : f.back ? "Leave it out, as the base did" : "Take it from the registry"}, or have the pipeline's allowlist approve this source: ${entry}`
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

