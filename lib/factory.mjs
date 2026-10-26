// Factory mode: nothing the change under test grants itself loosens the gate.
//
// In the default mode every escape hatch is printed for a reader -- a marker's reason, an opt-out's
// reason, the control a project config pointed at. That is right where a person reviews the change,
// and it is no protection at all where nobody does: in a "dark factory", agents write the code and
// the gate's verdict is the review. Measured on v1.3.1 against test/fixtures/factory-scenario.mjs, a
// project with an open purge endpoint, SQL injection and two hardcoded AWS credentials reached exit 0
// through three things an agent can write: routes renamed under a probe path, a one-line
// .tfguard-fixture, and a .wolfproof.json pointing secret-guard at an empty directory. Every one was
// in the report. Nobody read it.
//
// So factory mode compares the tree under test with a base ref -- what existed before the change --
// and refuses what the change added:
//
//   - Controls come from the pipeline (an environment variable) or the gate's own node_modules, never
//     from the project. A project config that overrides one is a blocking finding.
//   - A self-granted loosening -- every kind the gate or a control honours, listed in GRANT_KINDS --
//     is honoured only if it existed at the base, or the pipeline's allowlist (a file outside the
//     project) approves it. One the change added is a blocking finding.
//   - Code the change put where a check does not look -- under an exemption that predates it, in a
//     directory the checks skip, or moved there from somewhere they do look -- is a blocking finding.
//   - The requirements are read as they were at the base. A change that edits them is blocking.
//   - A server written into a test name or test directory, which the authentication check skips, is
//     blocking when code outside the tests runs or imports it.
//   - The pipeline is not the change's to edit: a file under .github/workflows or .github/actions that
//     the change added, edited or deleted is blocking, unless the allowlist approves it.
//   - Advisories are classified (lib/advisory-classes.mjs) and none may leave the verdict clean by
//     meaning "nothing was checked".
//
// Blocking rather than exit 3 throughout, except where the base itself cannot be established: the
// change made each of these and can undo it, while exit 3 says "fix the environment", which would
// send it to the wrong owner. A base that cannot be resolved is exit 3, because then nothing can be
// told apart from anything.
//
// What it does not do: measure behaviour. Whether the software does what its user needs is scenario
// validation -- holdout end-to-end checks the agents cannot read -- and wolfproof sits beside it.
import { spawnSync } from "child_process";
import { REVIEW_FILE, loadProjectReviews } from "./reviewed.mjs";
import { existsSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { declaredFixtures, FIXTURE_MARKERS } from "../agent/fixture-markers.mjs";
import { SKIP_DIRS } from "../agent/skip-dirs.mjs";
import { checkAuthentication, TEST_FILE, skippedTestDir } from "../agent/authentication.mjs";
import { CONFIG_FILE, LEGACY_CONFIG_FILE } from "./resolve-controls.mjs";
import { actionFor, FINDING } from "./advisory-classes.mjs";

const MAX_BYTES = 1024 * 1024;

function git(cwd, args, opts = {}) {
  const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...opts });
  return { ok: r.status === 0, out: r.stdout || "", err: (r.stderr || "").trim(), raw: r };
}

function real(p) {
  try {
    return realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/** Whether `p` is inside `dir` (not equal to it), comparing real paths. */
export function isInside(dir, p) {
  const rel = path.relative(real(dir), real(p));
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

// ---------------------------------------------------------------------------------------------
// The base

/**
 * The commit `ref` names, as seen from the project. { sha } or { error }.
 *
 * A shallow checkout -- actions/checkout fetches depth 1 by default -- has no parent and usually no
 * PR base, and that is the common way this fails. The message says what to fetch.
 */
export function resolveBase(projectDir, ref) {
  if (!ref) return { error: "no base ref was given" };
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]);
  if (!top.ok) return { error: `${projectDir} is not inside a git repository, so there is no history to compare against` };
  const r = git(projectDir, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  if (!r.ok) {
    const shallow = git(projectDir, ["rev-parse", "--is-shallow-repository"]).out.trim() === "true";
    // A relative ref (HEAD~1) cannot be fetched by name; the history it walks has to be deepened.
    // Measured against a depth-1 clone of this repository: `--deepen=1` made HEAD~1 resolve, and
    // `--depth=1 origin <sha>` made a three-commits-older base resolve, with nothing in between.
    const fetch = /[~^]/.test(ref) ? "git fetch --no-tags --deepen=1 origin" : `git fetch --no-tags --depth=1 origin ${ref}`;
    return {
      error:
        `the base ref ${ref} is not in this checkout` +
        (shallow ? ` -- the clone is shallow, so only the commits it was cloned with are present. Fetch the base first: \`${fetch}\`` : ""),
    };
  }
  return { sha: r.out.trim() };
}

/**
 * The project as it was at `sha`, extracted into a temporary directory -- only the project's own
 * subtree when it is a subdirectory of the repository. `empty` when the project did not exist then,
 * in which case everything in it is the change. Call `cleanup()` when done.
 */
export function materializeBase(projectDir, sha) {
  const dir = mkdtempSync(path.join(tmpdir(), "wolfproof-base-"));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  const prefix = git(projectDir, ["rev-parse", "--show-prefix"]).out.trim().replace(/\/$/, "");
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]).out.trim();
  const treeish = prefix ? `${sha}:${prefix}` : sha;
  if (!git(projectDir, ["cat-file", "-e", treeish]).ok) return { dir, empty: true, cleanup };
  // From the repository's top, not the project's directory: run in a subdirectory, git archive takes
  // that directory as a pathspec inside the tree it was given, and archived nothing.
  const archive = spawnSync("git", ["-C", top, "archive", "--format=tar", treeish], { maxBuffer: 1024 * 1024 * 1024 });
  if (archive.status !== 0) {
    cleanup();
    return { error: `git archive of ${treeish} failed: ${String(archive.stderr || "").trim().split("\n")[0]}` };
  }
  const untar = spawnSync("tar", ["-x", "-C", dir], { input: archive.stdout, maxBuffer: 64 * 1024 * 1024 });
  if (untar.status !== 0) {
    cleanup();
    return { error: `extracting the base failed: ${String(untar.stderr || "").trim().split("\n")[0]}` };
  }
  return { dir, empty: false, cleanup };
}

/**
 * What the change did, relative to the project: [{ status: "A"|"M"|"D"|"R", path, from? }]. The
 * working tree against the base, so an uncommitted edit counts, plus untracked files as added.
 */
function nameStatus(out) {
  const changes = [];
  const parts = out.split("\0").filter(Boolean);
  for (let i = 0; i < parts.length; ) {
    const status = parts[i++];
    if (status.startsWith("R") || status.startsWith("C")) {
      const from = parts[i++];
      const to = parts[i++];
      changes.push({ status: status[0], path: to, from });
    } else {
      changes.push({ status: status[0], path: parts[i++] });
    }
  }
  return changes;
}

export function changesSinceBase(projectDir, sha) {
  const diff = git(projectDir, ["diff", "--name-status", "-M", "--relative", "-z", sha]);
  const out = diff.ok ? nameStatus(diff.out) : [];
  for (const f of git(projectDir, ["ls-files", "--others", "--exclude-standard", "-z"]).out.split("\0").filter(Boolean)) {
    out.push({ status: "A", path: f });
  }
  return out;
}

// The workflows, and the local actions they call: a step that says `uses: ./.github/actions/gate` runs
// whatever that directory holds, so editing the action edits the workflow without touching it.
export const PIPELINE_DIRS = [".github/workflows", ".github/actions"];

/**
 * The files under .github/workflows or .github/actions the change added, edited, renamed or deleted,
 * with paths from the repository root. Read at the root rather than the project, because that is the
 * only place GitHub runs workflows from: a project in a subdirectory is built by workflows outside it.
 */
export function workflowChanges(projectDir, sha) {
  const spec = PIPELINE_DIRS.map((d) => `:(top)${d}`);
  const diff = git(projectDir, ["diff", "--name-status", "-M", "-z", sha, "--", ...spec]);
  const out = diff.ok ? nameStatus(diff.out) : [];
  const untracked = git(projectDir, ["ls-files", "--others", "--exclude-standard", "--full-name", "-z", "--", ...spec]);
  for (const f of untracked.out.split("\0").filter(Boolean)) out.push({ status: "A", path: f });
  return out;
}

// ---------------------------------------------------------------------------------------------
// The files a tree holds

function walk(root) {
  const out = [];
  const go = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === ".git") continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) go(full);
      else if (e.isFile()) out.push(path.relative(root, full).split(path.sep).join("/"));
    }
  };
  go(root);
  return out;
}

/**
 * The project's files, as relative paths. In a repository, what git sees -- tracked, plus untracked
 * files that are not ignored -- so an installed node_modules is not read as the project. Otherwise
 * (an extracted base), every file.
 */
export function projectFiles(root) {
  const ls = git(root, ["ls-files", "-co", "--exclude-standard", "-z"]);
  if (ls.ok && git(root, ["rev-parse", "--show-toplevel"]).ok) return ls.out.split("\0").filter(Boolean);
  return walk(root);
}

function readText(root, rel) {
  const full = path.join(root, rel);
  try {
    const st = statSync(full);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const buf = readFileSync(full);
    if (buf.includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// Self-granted loosenings

/**
 * Every way a project can narrow what a check looks at, and what each one narrows. Found by reading
 * every check and control, and each one that is a real escape was confirmed against the gate:
 * gitleaks:allow and a .gitleaksignore carrying the findings' fingerprints each removed both
 * credential findings; an osv-scanner.toml PackageOverrides entry took four blocking CVEs to exit 0;
 * `# noqa` and a ruff.toml extend-exclude each cleared an undefined name.
 *
 * Not here, because nothing honours them: a project .gitleaks.toml (secret-guard passes its own -c),
 * `nosemgrep` and .semgrepignore (sast passes --disable-nosem and its own file list), a pyproject
 * `ignore` for F rules (the gate's --select F wins), .gitignore (sast passes --no-git-ignore).
 */
export const GRANT_KINDS = {
  "fixture-marker": "a .tfguard-fixture or .identity-exception, which takes a whole directory out of every source check and out of terraform-guard's and identity-guard's scans",
  "identity-guard:allow": "an inline opt-out from one identity-guard rule",
  "gitleaks:allow": "an inline comment gitleaks skips a line for",
  ".gitleaksignore": "fingerprints of credential findings secret-guard then ignores (read at the project root)",
  "osv-scanner.toml": "vulnerabilities or whole packages osv-scanner ignores, beside the lockfile it scans",
  "noqa": "a `# noqa` that hides a Python static-check finding",
  "ruff config": "a ruff.toml, .ruff.toml or pyproject [tool.ruff] section the Python static check reads -- extend-exclude in it hides whole directories",
  "checkov:skip": "an inline checkov skip, hiding findings the pipeline's policy blocks",
  "checkov config": "a .checkov.yaml or .checkov.yml checkov reads, hiding findings the pipeline's policy blocks",
  "changed-under-exemption": "code the change wrote inside a directory an exemption that predates it covers",
  "skipped-location": "code the change wrote where the checks do not look: a directory every source check skips, or one secret-guard's gitleaks allowlist does",
  "moved-to-unchecked": "code the change moved from where a check looks to where it does not",
  "server-in-test": "an HTTP server written into a test-named file or a test directory, which the authentication check skips, that code outside the tests runs or imports",
  "workflow-change": "an edit to the pipeline itself: a file under .github/workflows, or under .github/actions where its local actions live, added, changed, renamed or deleted",
  "reviewed-finding": "an entry in .wolfproof-reviewed.json, which takes one named finding out of the verdict",
};

const COMMENT_GRANTS = [
  { kind: "gitleaks:allow", re: /gitleaks:allow/, applies: () => true },
  { kind: "identity-guard:allow", re: /identity-guard:allow\b/, applies: () => true },
  { kind: "noqa", re: /#\s*(?:ruff:\s*)?noqa\b/i, applies: (rel) => rel.endsWith(".py") },
  { kind: "checkov:skip", re: /checkov:skip=/i, applies: () => true },
];

const isComment = (line) => !line || /^\s*(#|;|\/\/)/.test(line);

function configLines(kind, rel, text) {
  const out = [];
  const lines = text.split("\n");
  if (kind === "ruff config" && path.posix.basename(rel) === "pyproject.toml") {
    let inRuff = false;
    lines.forEach((l, i) => {
      const t = l.trim();
      if (/^\[/.test(t)) inRuff = /^\[+\s*tool\.ruff\b/.test(t);
      if (inRuff && t && !isComment(t)) out.push({ line: i + 1, text: t });
    });
    return out;
  }
  lines.forEach((l, i) => {
    const t = l.trim();
    if (t && !isComment(t)) out.push({ line: i + 1, text: t });
  });
  return out;
}

function configKind(rel) {
  const base = path.posix.basename(rel);
  if (rel === ".gitleaksignore") return ".gitleaksignore";
  if (base === "osv-scanner.toml") return "osv-scanner.toml";
  if (base === "ruff.toml" || base === ".ruff.toml" || base === "pyproject.toml") return "ruff config";
  if (base === ".checkov.yaml" || base === ".checkov.yml") return "checkov config";
  return null;
}

/**
 * Every self-granted loosening in a tree: [{ kind, key, path, line?, text? }]. `key` is what is
 * compared with the base, so it holds the line's text: the same `gitleaks:allow` on a line whose
 * credential changed is a new grant, because it now covers something else.
 */
export function inventoryGrants(root, files = projectFiles(root)) {
  const grants = [];
  for (const f of declaredFixtures(root)) {
    grants.push({ kind: "fixture-marker", key: `fixture-marker|${f.path}`, path: f.path, text: `${f.marker}: ${f.reason}`, marker: f.marker });
  }
  // One grant per reviewed finding. The key holds the ID and the expiry: a later date on the same
  // finding extends what the change grants itself, so it is a new grant like any other.
  for (const e of loadProjectReviews(root).entries) {
    grants.push({ kind: "reviewed-finding", key: `reviewed-finding|${e.id}|${e.expires || ""}`, path: REVIEW_FILE, text: `${e.id}: ${e.reason}` });
  }
  for (const rel of files) {
    const kind = configKind(rel);
    if (kind) {
      const text = readText(root, rel);
      if (text !== null) {
        for (const l of configLines(kind, rel, text)) {
          grants.push({ kind, key: `${kind}|${rel}|${l.text}`, path: rel, line: l.line, text: l.text });
        }
      }
    }
    const applicable = COMMENT_GRANTS.filter((c) => c.applies(rel));
    if (!applicable.length) continue;
    const text = readText(root, rel);
    if (text === null) continue;
    if (!applicable.some((c) => c.re.test(text))) continue;
    text.split("\n").forEach((l, i) => {
      for (const c of applicable) {
        if (c.re.test(l)) grants.push({ kind: c.kind, key: `${c.kind}|${rel}|${l.trim()}`, path: rel, line: i + 1, text: l.trim().slice(0, 200) });
      }
    });
  }
  return grants;
}

/**
 * Directories secret-guard's gitleaks config never scans, read from the control that will actually
 * run rather than copied here, so the two cannot drift. Falls back to the list as of secret-guard
 * v1.0.2 when the file cannot be read.
 */
export function secretGuardAllowlist(secretGuardEntry) {
  const fallback = ["vendor", ".venv", "node_modules", ".terraform", ".external_modules", "__pycache__"].map(
    (d) => new RegExp(`(^|/)${d.replace(/\./g, "\\.")}/`)
  );
  if (!secretGuardEntry) return fallback;
  try {
    const toml = readFileSync(path.join(path.dirname(secretGuardEntry), "gitleaks", "extra-rules.toml"), "utf8");
    const allow = /\[allowlist\][\s\S]*?paths\s*=\s*\[([\s\S]*?)\]/.exec(toml);
    if (!allow) return fallback;
    const res = [...allow[1].matchAll(/'''([^']+)'''/g)].map((m) => new RegExp(m[1]));
    return res.length ? res : fallback;
  } catch {
    return fallback;
  }
}

/** Where a path sits that some check does not look, or null. */
export function uncheckedLocation(rel, { gitleaksAllow = [] } = {}) {
  const parts = rel.split("/");
  const dirs = parts.slice(0, -1);
  const skipped = dirs.find((d) => SKIP_DIRS.has(d));
  if (skipped) return { where: dirs.slice(0, dirs.indexOf(skipped) + 1).join("/"), why: `every source check skips ${skipped}/` };
  const gl = gitleaksAllow.find((re) => re.test(rel));
  if (gl) return { where: dirs.join("/") || ".", why: `secret-guard's gitleaks allowlist does not scan it (${gl.source})` };
  return null;
}

// Files that name a test file without running it as the service: documentation, and the configuration
// of test runners, linters and compilers. package.json is read without its test scripts.
const NOT_A_RUNNER = /\.(?:md|markdown|rst|txt|adoc)$|(?:^|\/)(?:tsconfig|jsconfig)[^/]*\.json$|(?:^|\/)(?:jest|vitest|karma|mocha|playwright|cypress|eslint)\.config\.[^/]+$|(?:^|\/)\.(?:mocharc|eslintrc)[^/]*$|(?:^|\/)(?:pytest\.ini|conftest\.py|tox\.ini|setup\.cfg)$/;

/**
 * The files outside the tests that refer to `rel` -- a start script, a Dockerfile CMD, a Procfile, an
 * import from application code. A server in a test file is ordinary when only tests use it (a stub
 * upstream, an app built inline for supertest); referred to from here, it is the service.
 */
function referencedOutsideTests(root, rel, files) {
  const parts = rel.split("/");
  const noExt = (p) => p.replace(/\.[^./]+$/, "");
  const needles = new Set([noExt(parts[parts.length - 1])]);
  const skipped = skippedTestDir(rel);
  if (skipped) {
    const testDir = skipped.split("/").length - 2;
    needles.add(noExt(parts.slice(testDir).join("/")));
  }
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const res = [...needles].map((n) => new RegExp(`(?<![A-Za-z0-9_])${esc(n)}(?![A-Za-z0-9_-])`));
  const by = [];
  for (const f of files) {
    if (f === rel || authUnchecked(f) || NOT_A_RUNNER.test(f)) continue;
    const fp = f.split("/");
    if (fp[0] === ".github" || fp.some((p) => SKIP_DIRS.has(p))) continue;
    let text = readText(root, f);
    if (!text) continue;
    if (fp[fp.length - 1] === "package.json") {
      try {
        const pkg = JSON.parse(text);
        for (const k of Object.keys(pkg.scripts || {})) if (/^(?:pre|post)?test(?:$|[:-])/.test(k)) delete pkg.scripts[k];
        text = JSON.stringify(pkg);
      } catch {
        /* read as text */
      }
    }
    if (res.some((re) => re.test(text))) by.push(f);
  }
  return by;
}

function authUnchecked(rel) {
  const parts = rel.split("/");
  const testDir = skippedTestDir(rel);
  if (testDir) return `the authentication check skips ${testDir}`;
  if (TEST_FILE.test(parts[parts.length - 1])) return "the authentication check skips files named as tests";
  return null;
}

// ---------------------------------------------------------------------------------------------
// The project's own claims about what gates it

/** Every control a project config file overrides: [{ file, control, value }]. Both names are read. */
export function declaredOverrides(projectDir) {
  const out = [];
  for (const file of [CONFIG_FILE, LEGACY_CONFIG_FILE]) {
    const full = path.join(projectDir, file);
    if (!existsSync(full)) continue;
    let cfg;
    try {
      cfg = JSON.parse(readFileSync(full, "utf8"));
    } catch {
      continue;
    }
    for (const [control, value] of Object.entries((cfg && cfg.controls) || {})) out.push({ file, control, value });
  }
  return out;
}

// Evidence a project starts an HTTP server. Test files and test directories are not evidence: a
// library's tests that stand up an Express app to exercise a client are not a service.
const SERVES_HTTP = [
  /require\(\s*["'](?:express|koa|fastify|@hapi\/hapi|hapi|restify|hono)["']\s*\)|from\s+["'](?:express|koa|fastify|@hapi\/hapi|hapi|restify|hono|@nestjs\/core)["']|\bhttps?\.createServer\s*\(/,
  /\bfrom\s+(?:flask|fastapi|starlette|aiohttp)\b|\bimport\s+(?:flask|fastapi)\b|\bFastAPI\s*\(|\bFlask\s*\(\s*__name__|\bdjango\.urls\b|\bhttp\.server\b|\buvicorn\.run\b/,
  /"net\/http"|\bhttp\.ListenAndServe|\bgin\.(?:Default|New)\(|\becho\.New\(|\bfiber\.New\(|\bchi\.NewRouter\(/,
  /@RestController|@SpringBootApplication|\bextends\s+HttpServlet\b|(?:javax|jakarta)\.ws\.rs/,
  /\bSinatra\b|\bRails\.application\b|require\s+["']sinatra["']/,
  /\bWebApplication\.CreateBuilder\b|\[ApiController\]|\.Map(?:Get|Post|Put|Delete)\s*\(/,
  /\baxum::|\bactix_web\b|\bwarp::|\brocket::/,
  /\bhttplib::Server\b|\bcrow::SimpleApp\b|\bdrogon::app\b/,
];
const CODE_EXT = /\.(?:[mc]?[jt]sx?|py|go|java|rb|cs|rs|c|cc|cpp|cxx|h|hpp)$/;

export function servesHttp(root, files = projectFiles(root)) {
  // Code under a declared fixture is out of scope for every check, so it is not evidence either: a
  // service whose server sits in an honoured exemption is one the authentication check was told to
  // leave alone, and reading it here would block on the exemption the base already granted.
  const exempt = declaredFixtures(root).map((f) => f.path);
  for (const rel of files) {
    if (!CODE_EXT.test(rel)) continue;
    if (exempt.some((d) => under(rel, d))) continue;
    const parts = rel.split("/");
    if (parts.some((p) => SKIP_DIRS.has(p) || p === "test" || p === "tests" || p === "spec") || skippedTestDir(rel)) continue;
    if (TEST_FILE.test(parts[parts.length - 1])) continue;
    const text = readText(root, rel);
    if (text && SERVES_HTTP.some((re) => re.test(text))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// The pipeline's own inputs: an allowlist and a policy, both outside the project

/**
 * A JSON input factory mode reads -- the allowlist or the policy. It must exist, parse, and live
 * outside the project: one the change can edit approves whatever the change likes. Returns
 * { value } or { error } (a usage error: the pipeline's configuration, not the change, is wrong).
 */
export function readPipelineInput(file, label, projectDir) {
  if (!existsSync(file)) return { error: `the ${label} file ${file} does not exist` };
  if (!statSync(file).isFile()) return { error: `the ${label} file ${file} is not a file` };
  if (isInside(projectDir, file)) {
    return { error: `the ${label} file ${file} is inside the project, so the change under test could edit it. In factory mode it must live outside the project` };
  }
  try {
    return { value: JSON.parse(readFileSync(file, "utf8")) };
  } catch (err) {
    return { error: `the ${label} file ${file} could not be parsed as JSON: ${err.message}` };
  }
}

/**
 * The allowlist's usable entries and the ones it ignored. An entry approves grants of its `kind` at
 * its `path` or anywhere under it, and needs a `reason` -- the same rule a fixture marker follows:
 * an approval that does not say what it is for does not exist.
 */
export function parseAllowlist(value) {
  const entries = [];
  const ignored = [];
  for (const e of (value && value.exemptions) || []) {
    if (!e || typeof e.kind !== "string" || typeof e.path !== "string") {
      ignored.push({ entry: e, why: "needs a kind and a path" });
    } else if (!(e.kind in GRANT_KINDS) && e.kind !== "*") {
      ignored.push({ entry: e, why: `unknown kind "${e.kind}"` });
    } else if (!e.reason || !String(e.reason).trim()) {
      ignored.push({ entry: e, why: "gives no reason" });
    } else {
      entries.push({ kind: e.kind, path: e.path.replace(/^\.\/|\/$/g, "") || ".", reason: String(e.reason) });
    }
  }
  return { entries, ignored };
}

function under(p, dir) {
  return dir === "." || p === dir || p.startsWith(`${dir}/`);
}

export function allowlisted(grant, entries) {
  return entries.find((e) => (e.kind === "*" || e.kind === grant.kind) && under(grant.path, e.path)) || null;
}

// ---------------------------------------------------------------------------------------------
// Requirements as they were

/**
 * The text of a requirement file (the task file, or a baseline inside the project) as it was at the
 * base, and whether the change touched it. { outside } for a file outside the repository, which the
 * change cannot edit and which is read as it is.
 */
export function requirementAtBase(projectDir, sha, file) {
  const top = git(projectDir, ["rev-parse", "--show-toplevel"]);
  if (!top.ok) return { outside: true };
  const root = real(top.out.trim());
  const abs = real(file);
  if (!isInside(root, abs)) return { outside: true };
  const rel = path.relative(root, abs).split(path.sep).join("/");
  const before = git(root, ["show", `${sha}:${rel}`]);
  const now = existsSync(abs) ? readFileSync(abs, "utf8") : null;
  if (!before.ok) return { rel, added: true, text: "" };
  return { rel, text: before.out, changed: now !== before.out };
}

// ---------------------------------------------------------------------------------------------
// The judgement

const short = (sha) => sha.slice(0, 12);

/**
 * Compares the project with its base and returns what factory mode refuses: { failures, notes,
 * grants, changed, newProbeRoutes }. `failures` are blocking findings; `notes` are reported and do
 * not block.
 */
// A checkov skip hides checkov findings, which are advisories: they never block in default mode, and
// in factory mode only when the pipeline's policy says so. Blocking the skip whatever the policy
// says would treat hiding a finding as worse than the finding itself, so an added skip blocks only
// when the findings it hides would: the policy's action for the advisory id of what the file is.
// .checkov.yaml hides the same findings, project-wide, and is judged the same way.
const CHECKOV_GRANTS = new Set(["checkov:skip", "checkov config"]);
const CONFIG_GRANT_FILES = new Set([".checkov.yaml", ".checkov.yml"]);
function checkovAdvisoryId(rel) {
  const base = path.posix.basename(rel);
  if (/^Dockerfile|\.Dockerfile$|\.dockerfile$/i.test(base)) return "dockerfile-checkov";
  if (/\.(tf|tfvars)$/i.test(base) || CONFIG_GRANT_FILES.has(base)) return "checkov";
  return "iac-checkov";
}

/** Whether an added checkov grant blocks under the pipeline's policy, with the advisory id it follows. */
export function checkovGrantBlocks(grant, policy = {}) {
  const id = checkovAdvisoryId(grant.path);
  const action = actionFor({ id, class: FINDING }, policy);
  return { id, blocks: action === "block" || action === "incomplete" };
}

export function judgeChange(projectDir, { sha, baseDir, allowlist = [], secretGuardEntry = null, policy = {} }) {
  const failures = [];
  const notes = [];
  const gitleaksAllow = secretGuardAllowlist(secretGuardEntry);

  // Self-granted loosenings: pre-existing ones are honoured, allowlisted ones are honoured, the rest
  // were granted by the change.
  const now = inventoryGrants(projectDir);
  const before = new Set(inventoryGrants(baseDir).map((g) => g.key));
  const grants = now.map((g) => {
    const approved = allowlisted(g, allowlist);
    const status = before.has(g.key) ? "pre-existing" : approved ? "allowlisted" : "added";
    return { ...g, status, ...(approved ? { approvedBy: approved.reason } : {}) };
  });
  const added = grants.filter((g) => {
    if (g.status !== "added" || !CHECKOV_GRANTS.has(g.kind)) return g.status === "added";
    const { id, blocks } = checkovGrantBlocks(g, policy);
    if (!blocks) {
      notes.push(
        `a ${g.kind} this change added, not blocking: ${g.line ? `${g.path}:${g.line}` : g.path}. It hides ${id} findings, which the ` +
          `pipeline's policy does not block, so hiding them is not blocking either.`
      );
    }
    return blocks;
  });
  const byKind = new Map();
  for (const g of added) byKind.set(g.kind, [...(byKind.get(g.kind) || []), g]);
  for (const [kind, list] of byKind) {
    const where = list.map((g) =>
      g.line ? `${g.path}:${g.line}` : g.kind === "fixture-marker" ? `${g.path}/${g.marker}` : g.kind === "reviewed-finding" ? `${g.path} (${g.text.split(": ")[0]})` : g.path
    );
    failures.push(
      `factory: ${list.length} ${kind} grant(s) this change added — ${where.slice(0, 8).join(", ")}${where.length > 8 ? `, +${where.length - 8} more` : ""}. ` +
        `Each is ${GRANT_KINDS[kind]}, and none of them existed at the base (${short(sha)}). In factory mode the change does not get ` +
        `to narrow what checks it: remove ${list.length === 1 ? "it" : "them"} and fix what ${list.length === 1 ? "it was" : "they were"} hiding, ` +
        `or have the pipeline's allowlist approve ${list.length === 1 ? "it" : "them"}.`
    );
  }

  // Code the change wrote where a check does not look.
  const changed = changesSinceBase(projectDir, sha).filter((c) => c.status !== "D");
  const exemptDirs = grants.filter((g) => g.kind === "fixture-marker" && g.status === "pre-existing").map((g) => g.path);
  const isMarker = (rel) => FIXTURE_MARKERS.includes(path.posix.basename(rel));
  const flagged = (kind, rel) => !allowlisted({ kind, path: rel }, allowlist);

  // An allowlisted exemption is approved whole, code written under it included: approving a marker
  // is approving the directory it covers.
  const underExemption = new Map();
  for (const c of changed) {
    if (isMarker(c.path)) continue;
    const dir = exemptDirs.find((d) => under(c.path, d));
    if (!dir || allowlisted({ kind: "fixture-marker", path: dir }, allowlist)) continue;
    if (flagged("changed-under-exemption", c.path)) underExemption.set(dir, [...(underExemption.get(dir) || []), c.path]);
  }
  for (const [dir, files] of underExemption) {
    failures.push(
      `factory: ${files.length} file(s) changed under ${dir}, which an exemption that predates this change takes out of the checks — ` +
        `${files.slice(0, 8).join(", ")}${files.length > 8 ? `, +${files.length - 8} more` : ""}. The exemption existed at the base; this code ` +
        `did not, and nothing has checked it. Move it out of ${dir}, or have the pipeline's allowlist approve ${dir}.`
    );
  }

  const skipped = new Map();
  for (const c of changed) {
    const loc = uncheckedLocation(c.path, { gitleaksAllow });
    if (loc && flagged("skipped-location", c.path)) {
      const k = `${loc.where}|${loc.why}`;
      skipped.set(k, { ...loc, files: [...((skipped.get(k) || {}).files || []), c.path] });
    }
  }
  for (const s of skipped.values()) {
    failures.push(
      `factory: ${s.files.length} file(s) this change wrote under ${s.where}, where ${s.why} — ` +
        `${s.files.slice(0, 8).join(", ")}${s.files.length > 8 ? `, +${s.files.length - 8} more` : ""}. Nothing checked this code. ` +
        `Put it where the checks look, or have the pipeline's allowlist approve ${s.where}.`
    );
  }

  for (const c of changed.filter((x) => x.status === "R" && x.from)) {
    const fromLoc = uncheckedLocation(c.from, { gitleaksAllow }) || authUnchecked(c.from);
    const toLoc = uncheckedLocation(c.path, { gitleaksAllow });
    const toAuth = authUnchecked(c.path);
    if (fromLoc || (!toLoc && !toAuth)) continue;
    if (!flagged("moved-to-unchecked", c.path)) continue;
    // An unchecked location is already reported above; a move into a test name or test directory
    // narrows only the authentication check, and is reported here.
    if (toLoc) continue;
    failures.push(
      `factory: this change moved ${c.from} to ${c.path}, where ${toAuth}. Moving code out of a check's view is not a fix; ` +
        `move it back, or have the pipeline's allowlist approve ${c.path}.`
    );
  }

  // A server written straight into a test name or test directory. A move there is refused above; one
  // written there from the start was skipped by the authentication check and not flagged at all. Only
  // when something outside the tests runs it: a test that builds a server is ordinary.
  let files = null;
  for (const c of changed.filter((x) => x.status === "A" || x.status === "M")) {
    const why = authUnchecked(c.path);
    if (!why || !CODE_EXT.test(c.path) || uncheckedLocation(c.path, { gitleaksAllow })) continue;
    if (exemptDirs.some((d) => under(c.path, d))) continue;
    const text = readText(projectDir, c.path);
    if (!text || !SERVES_HTTP.some((re) => re.test(text))) continue;
    files ||= projectFiles(projectDir);
    const by = referencedOutsideTests(projectDir, c.path, files);
    if (!by.length || !flagged("server-in-test", c.path)) continue;
    failures.push(
      `factory: ${c.path} builds an HTTP server, and ${by.slice(0, 4).join(", ")}${by.length > 4 ? `, +${by.length - 4} more` : ""} ` +
        `${by.length === 1 ? "refers" : "refer"} to it from outside the tests — but ${why}, so the routes it serves were never judged. ` +
        `Move the server out of the test name, or have the pipeline's allowlist approve ${c.path}.`
    );
  }

  // The pipeline's own definition. A workflow decides which checks run, with what, and what a passing
  // run then does -- deploy, publish, merge -- so a change that edits one, or a local action one
  // calls, has edited its own review.
  const STATUS = { A: "added", M: "changed", D: "deleted", R: "renamed", C: "copied", T: "changed" };
  const workflows = workflowChanges(projectDir, sha).filter(
    (c) => !allowlisted({ kind: "workflow-change", path: c.path }, allowlist) && !(c.from && allowlisted({ kind: "workflow-change", path: c.from }, allowlist))
  );
  if (workflows.length) {
    const what = workflows.map((c) => (c.from ? `${c.from} → ${c.path} (renamed)` : `${c.path} (${STATUS[c.status] || c.status})`));
    failures.push(
      `factory: this change edits the pipeline — ${what.slice(0, 8).join(", ")}${what.length > 8 ? `, +${what.length - 8} more` : ""}. ` +
        `A workflow, and a local action it calls, decides what checks the change and what a passing run then does, so in factory ` +
        `mode the change does not get to edit one. Make the edit in a change a person reviews, or have the pipeline's allowlist approve it (kind "workflow-change", ` +
        `path from the repository root).`
    );
  }

  // Routes exempt by name are conventional, not self-granted, and stay exempt. One the change
  // introduced is named, because a purge endpoint renamed to /health is exempt too.
  let newProbeRoutes = [];
  try {
    const was = new Set((checkAuthentication(baseDir).exempt || []).map((r) => `${r.method} ${r.route}`));
    newProbeRoutes = (checkAuthentication(projectDir).exempt || []).filter((r) => !was.has(`${r.method} ${r.route}`));
  } catch {
    /* the authentication check reports its own crash in the run itself */
  }
  for (const r of newProbeRoutes) {
    notes.push(`a route exempt by name that the base did not have: ${r.method} ${r.route} (${r.file}:${r.line})`);
  }

  return { failures, notes, grants, changed, newProbeRoutes, workflows };
}
