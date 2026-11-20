// Factory mode: credentials in the change's own commits.
//
// secret-guard scans the working tree. In a factory a change can add a credential in one commit and
// delete it in a later commit of the same branch: the tree is clean, the gate passes, and the value
// is in the branch on the remote, and in the target branch's history after a merge commit or a
// rebase merge. Measured on 0907366: a base, a commit adding an AWS access key ID to config.js and a
// commit removing the line, `--factory --base=<base>`, exit 0 with BLOCKING none.
//
// So factory mode also scans what each commit between the base and the head added. The files a
// commit added to are written, as that commit had them, under a temporary directory, and the
// pipeline's own secret-guard scans it with the call it makes for the tree (scan_path), so the rules
// are the same ones. A finding counts when it is on a line the commit added. Nothing here reads a
// credential: secret-guard's findings never carry the value.
//
// An exemption is judged as factory mode judges it in the tree (lib/factory.mjs, inventoryGrants):
// honoured when it existed at the base or the pipeline's allowlist approves it, and not otherwise. A
// `gitleaks:allow` that is not honoured is taken out of the copy that is scanned, so the line is
// scanned; a .gitleaksignore is never in the scanned directory, and its honoured entries are applied
// here.
import { spawnSync } from "child_process";
import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { allowlisted, plainPath } from "./factory.mjs";

const MAX_BUFFER = 256 * 1024 * 1024;
// One scan covers at most this much, because secret-guard gives gitleaks 120 seconds a scan.
const BATCH_BYTES = 32 * 1024 * 1024;
const BATCH_FILES = 4000;

function git(cwd, args, opts = {}) {
  const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", maxBuffer: MAX_BUFFER, ...opts });
  return { ok: r.status === 0, out: r.stdout || "", err: String(r.stderr || "").trim(), raw: r };
}

const short = (sha) => sha.slice(0, 12);
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * The commits the change is made of: every commit reachable from the head and not from the base,
 * oldest first, each with its parents. { commits: [{ sha, parents }] } or { error }.
 *
 * A shallow clone can hold the base and the head and none of the commits between them --
 * actions/checkout fetches depth 1, and the Action used to fetch only the base beside it. Git then
 * walks what it has and stops at a commit whose parents are missing, with no error: asked for
 * base..HEAD in such a clone it answers with the head alone. So the walk is trusted only when no
 * commit on either side of it is one the clone was cut at. Either side, because the base's own
 * history is what tells git where the change starts: with the base cut and the branch complete, the
 * walk runs past the fork point and reports the target branch's old commits as the change's.
 */
export function commitRange(projectDir, sha) {
  if (!git(projectDir, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]).ok) return { error: "HEAD names no commit, so there is no head to read the change's commits from" };
  if (git(projectDir, ["rev-parse", "--is-shallow-repository"]).out.trim() === "true") {
    let cut;
    try {
      const file = path.resolve(projectDir, git(projectDir, ["rev-parse", "--git-path", "shallow"]).out.trim());
      cut = new Set(readFileSync(file, "utf8").split("\n").filter(Boolean));
    } catch (e) {
      return { error: `the clone is shallow and the list of commits it was cut at could not be read (${e?.code || e?.message}), so whether the change's commits are all here is not known` };
    }
    const sides = git(projectDir, ["rev-list", `${sha}...HEAD`]);
    if (!sides.ok) return { error: `git rev-list of ${short(sha)}...HEAD failed: ${sides.err.split("\n")[0]}` };
    const missing = sides.out.split("\n").filter((c) => cut.has(c));
    if (missing.length) {
      return {
        incomplete: true,
        error:
          `the clone is shallow, and it was cut at ${plural(missing.length, "commit")} between the base (${short(sha)}) and the head ` +
          `(${missing.slice(0, 3).map(short).join(", ")}${missing.length > 3 ? ", …" : ""}), whose parents are not here, so the commits of this change are not all in the checkout. ` +
          `Fetch the history between the two: \`fetch-depth: 0\` on actions/checkout, or \`git fetch --unshallow origin\``,
      };
    }
  }
  const list = git(projectDir, ["rev-list", "--reverse", "--topo-order", "--parents", `${sha}..HEAD`]);
  if (!list.ok) return { error: `git rev-list of ${short(sha)}..HEAD failed: ${list.err.split("\n")[0]}` };
  const commits = list.out
    .split("\n")
    .filter(Boolean)
    .map((l) => l.split(" "))
    .map(([c, ...parents]) => ({ sha: c, parents }));
  return { commits };
}

/** `git diff --raw -z` between two trees, under the project: [{ status, mode, oldOid, newOid, path }]. */
function rawDiff(projectDir, from, to) {
  // --relative, so a project in a subdirectory is read as the tree scan reads it: its own files,
  // by their paths from the project. --no-abbrev for whole object names.
  const d = git(projectDir, ["diff", "--raw", "-z", "--no-abbrev", "-M", "--relative", "--no-ext-diff", from, to]);
  if (!d.ok) return { error: `git diff of ${short(from)} and ${short(to)} failed: ${d.err.split("\n")[0]}` };
  const out = [];
  const parts = d.out.split("\0");
  for (let i = 0; i < parts.length; ) {
    const head = parts[i++];
    if (!head) continue;
    const m = /^:(\d+) (\d+) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])\d*$/.exec(head);
    if (!m) return { error: `git diff of ${short(from)} and ${short(to)} printed a line this does not read: ${JSON.stringify(head.slice(0, 80))}` };
    const two = m[5] === "R" || m[5] === "C";
    if (two) i++; // the path it was renamed or copied from
    out.push({ status: m[5], mode: m[2], oldOid: m[3], newOid: m[4], path: parts[i++] });
  }
  return { entries: out };
}

/**
 * The lines of the new blob that the old one did not have: a Set of line numbers, or "all".
 *
 * Between blobs, so no rename guess decides which file is compared with which. --text, because a
 * .gitattributes the change carries reaches a diff between blobs too: measured with git 2.50.1 and
 * `* -diff` in the working tree, the diff of two blobs was "Binary files differ" and named no line;
 * with --text it named them. A diff that names no line, for blobs that differ, counts every line.
 */
function addedLines(projectDir, oldOid, newOid) {
  if (/^0+$/.test(oldOid)) return "all";
  if (oldOid === newOid) return new Set();
  const d = git(projectDir, ["diff", "--text", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", oldOid, newOid], { encoding: "latin1" });
  if (!d.ok) return "all";
  const lines = new Set();
  let hunks = 0;
  for (const m of d.out.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    hunks++;
    const start = Number(m[1]);
    const count = m[2] === undefined ? 1 : Number(m[2]);
    for (let l = start; l < start + count; l++) lines.add(l);
  }
  return hunks ? lines : "all";
}

const both = (a, b) => (a === "all" ? b : b === "all" ? a : new Set([...a].filter((l) => b.has(l))));

/**
 * What one commit added: [{ path, oid, lines }], regular files only. For a merge, what it has that
 * none of its parents has: lines the merge itself wrote, such as a conflict's resolution. A commit
 * with no parent added everything in it.
 */
function addedByCommit(projectDir, commit, emptyTree) {
  const parents = commit.parents.length ? commit.parents : [emptyTree];
  const raws = [];
  for (const p of parents) {
    const r = rawDiff(projectDir, p, commit.sha);
    if (r.error) return { error: r.error };
    // A symbolic link holds a path and a gitlink a commit; the tree scan reads neither as a file.
    raws.push(new Map(r.entries.filter((e) => e.status !== "D" && e.mode.startsWith("100")).map((e) => [e.path, e])));
  }
  const files = [];
  for (const [rel, first] of raws[0]) {
    if (!raws.every((m) => m.has(rel))) continue;
    let lines = "all";
    for (const m of raws) {
      // Against the blob this path itself had in that parent when there was one, and against the
      // blob git says it was renamed from otherwise.
      lines = both(lines, addedLines(projectDir, m.get(rel).oldOid, first.newOid));
      if (lines !== "all" && !lines.size) break;
    }
    if (lines === "all" || lines.size) files.push({ path: rel, oid: first.newOid, lines });
  }
  return { files };
}

const ALLOW = "gitleaks:allow";
const UNALLOW = "gitleaks_allow";

/**
 * A blob as it is scanned: every `gitleaks:allow` that is not honoured replaced, byte for byte in
 * length, so that gitleaks reads the line. latin1 keeps every byte as it was.
 */
function withoutUnhonouredAllows(buf, rel, honoured) {
  if (!buf.includes(ALLOW)) return buf;
  const lines = buf.toString("latin1").split("\n");
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes(ALLOW)) continue;
    const text = Buffer.from(lines[i], "latin1").toString("utf8").trim();
    if (honoured(rel, text)) continue;
    lines[i] = lines[i].split(ALLOW).join(UNALLOW);
    changed = true;
  }
  return changed ? Buffer.from(lines.join("\n"), "latin1") : buf;
}

/** The slots of one commit's directory: two paths that differ only by case, or by a file where the other has a directory, never share one. */
function slotFor(slots, rel) {
  const key = rel.normalize("NFC").toLowerCase();
  const parts = key.split("/");
  const ancestors = parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join("/"));
  let n = slots.findIndex((s) => !s.files.has(key) && !s.dirs.has(key) && !ancestors.some((a) => s.files.has(a)));
  if (n < 0) n = slots.push({ files: new Set(), dirs: new Set() }) - 1;
  slots[n].files.add(key);
  for (const a of ancestors) slots[n].dirs.add(a);
  return n;
}

/**
 * Scans what each commit between the base and the head added, and returns what factory mode refuses.
 *
 * @param {string} projectDir
 * @param {object} o
 * @param {string} o.sha            the base
 * @param {() => Set<string>} o.baseKeys  the keys of the grants the base held (inventoryGrants), read only when an exemption has to be judged
 * @param {object[]} o.allowlist    the pipeline's allowlist entries
 * @param {RegExp[]} o.gitleaksAllow the paths secret-guard's gitleaks allowlist never scans
 * @param {Set<string>} o.reported  paths the tree's own judgement already reported as written where no check looks
 * @param {(dir: string) => Promise<{ text?: string, error?: string }>} o.scan  secret-guard's scan_path over a directory
 * @returns {Promise<{ commits: number, files: number, findings: object[], skipped: object[], failures: string[], error?: string }>}
 */
export async function commitSecrets(projectDir, { sha, baseKeys: readBaseKeys = () => new Set(), allowlist = [], gitleaksAllow = [], reported = new Set(), scan }) {
  // Most changes carry no exemption, and the base's inventory is a read of every file in it.
  let held = null;
  const baseKeys = { has: (k) => (held ||= readBaseKeys()).has(k) };
  const result = { commits: 0, files: 0, findings: [], skipped: [], failures: [] };
  const fail = (error) => ({ ...result, error: `the commits between the base (${short(sha)}) and the head were not all scanned for credentials — ${error}` });
  const range = commitRange(projectDir, sha);
  if (range.error) return fail(range.error);
  result.commits = range.commits.length;
  if (!range.commits.length) return result;

  const empty = git(projectDir, ["hash-object", "-t", "tree", "--stdin"], { input: "" }).out.trim();
  if (!empty) return fail("git could not name the empty tree");
  const honouredAllow = (rel, text) => baseKeys.has(`${ALLOW}|${rel}|${text}`) || Boolean(allowlisted({ kind: ALLOW, path: rel }, allowlist));

  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "wolfproof-commits-")));
  const cleanup = () => rmSync(root, { recursive: true, force: true });
  try {
    // A scan of a directory secret-guard's own allowlist covers would read nothing and say so of nothing.
    const hidden = gitleaksAllow.find((re) => re.test(`${root.split(path.sep).join("/")}/`));
    if (hidden) return fail(`the temporary directory ${root} is under a path secret-guard's gitleaks allowlist does not scan (${hidden.source}); set TMPDIR to one that is not`);

    // Batches: [{ dir, bytes, files: Map("<n>.<slot>/<path>" -> { commit, path, lines }) }]
    const batches = [];
    const open = () => {
      const dir = path.join(root, String(batches.length));
      mkdirSync(dir);
      batches.push({ dir, bytes: 0, files: new Map() });
    };
    for (const [n, commit] of range.commits.entries()) {
      const added = addedByCommit(projectDir, commit, empty);
      if (added.error) return fail(added.error);
      const slots = [];
      for (const f of added.files) {
        if (!plainPath(f.path) || f.path.split("/").some((p) => p.toLowerCase() === ".git")) {
          return fail(`commit ${short(commit.sha)} holds a file at ${JSON.stringify(f.path)}, a path git does not check out`);
        }
        const unscanned = gitleaksAllow.find((re) => re.test(f.path));
        if (unscanned) {
          if (!reported.has(f.path) && !allowlisted({ kind: "skipped-location", path: f.path }, allowlist)) result.skipped.push({ commit: commit.sha, path: f.path, why: unscanned.source });
          continue;
        }
        const blob = spawnSync("git", ["-C", projectDir, "cat-file", "blob", f.oid], { maxBuffer: MAX_BUFFER });
        if (blob.status !== 0) return fail(`reading ${f.path} at ${short(commit.sha)} failed: ${String(blob.stderr || blob.error?.message || "").trim().split("\n")[0]}`);
        const data = withoutUnhonouredAllows(blob.stdout, f.path, honouredAllow);
        if (!batches.length || batches.at(-1).bytes + data.length > BATCH_BYTES || batches.at(-1).files.size >= BATCH_FILES) open();
        const batch = batches.at(-1);
        const key = `${String(n).padStart(6, "0")}.${slotFor(slots, f.path)}/${f.path}`;
        try {
          mkdirSync(path.dirname(path.join(batch.dir, key)), { recursive: true });
          const fd = openSync(path.join(batch.dir, key), "wx");
          try {
            writeFileSync(fd, data);
          } finally {
            closeSync(fd);
          }
        } catch (e) {
          return fail(`${f.path} at ${short(commit.sha)} could not be written to a temporary directory to be scanned (${e?.code || e?.message})`);
        }
        batch.bytes += data.length;
        batch.files.set(key, { commit: commit.sha, path: f.path, lines: f.lines });
        result.files++;
      }
    }

    // The .gitleaksignore a commit held at the project's root, as the entries factory mode honours.
    const ignoreAt = new Map();
    const honouredIgnores = (commit) => {
      if (!ignoreAt.has(commit)) {
        const shown = git(projectDir, ["show", `${commit}:./.gitleaksignore`]);
        const entries = shown.ok ? shown.out.split("\n").map((l) => l.trim()).filter((l) => l && !/^(#|;|\/\/)/.test(l)) : [];
        const approved = Boolean(allowlisted({ kind: ".gitleaksignore", path: ".gitleaksignore" }, allowlist));
        ignoreAt.set(commit, new Set(entries.filter((e) => approved || baseKeys.has(`.gitleaksignore|.gitleaksignore|${e}`))));
      }
      return ignoreAt.get(commit);
    };
    // secret-guard's fingerprint for a finding in the tree: the file's whole path, the rule and the line.
    const roots = [...new Set([path.resolve(projectDir), realpathSync(projectDir)])];

    for (const batch of batches) {
      const scanned = await scan(batch.dir);
      if (scanned.error) return fail(`secret-guard did not scan them: ${scanned.error}`);
      let parsed;
      try {
        parsed = JSON.parse(scanned.text);
      } catch {
        const m = /^(?:TOOL REPORTED A PROBLEM:\n|ERROR: )([\s\S]*)$/.exec(scanned.text || "");
        const said = m ? m[1].split(/\s*stderr:/)[0].replace(/\s+/g, " ").trim().slice(0, 300) : "";
        return fail(said ? `secret-guard could not scan them: ${said}` : "secret-guard's scan of them produced no parseable result");
      }
      let target = null;
      try {
        target = parsed.target && realpathSync(parsed.target);
      } catch {
        /* a target that is not there is not this directory */
      }
      if (target !== batch.dir || !Array.isArray(parsed.findings)) return fail("secret-guard's result does not say it scanned the directory it was given, so it is not evidence about them");
      for (const f of parsed.findings) {
        const key = path.relative(batch.dir, path.resolve(batch.dir, String(f.file))).split(path.sep).join("/");
        const file = batch.files.get(key);
        if (!file) return fail(`secret-guard reported a finding in ${JSON.stringify(String(f.file).slice(0, 200))}, which is not a file it was given`);
        const start = Number(f.startLine) || 1;
        const end = Math.max(start, Number(f.endLine) || start);
        let on = file.lines === "all";
        for (let l = start; l <= end && !on; l++) on = file.lines.has(l);
        if (!on) continue;
        const ignored = honouredIgnores(file.commit);
        if (roots.some((r) => ignored.has(`${r}/${file.path}:${f.rule}:${start}`))) continue;
        const approved = allowlisted({ kind: "secret-in-commit", path: file.path }, allowlist);
        result.findings.push({
          commit: file.commit,
          path: file.path,
          line: start,
          rule: String(f.rule),
          ...(f.heuristic ? { heuristic: true } : {}),
          status: approved ? "allowlisted" : "added",
          ...(approved ? { approvedBy: approved.reason } : {}),
        });
      }
    }
  } finally {
    cleanup();
  }

  const list = (items, show) => `${items.slice(0, 8).map(show).join(", ")}${items.length > 8 ? `, +${items.length - 8} more` : ""}`;
  const added = result.findings.filter((f) => f.status === "added");
  if (added.length) {
    const one = added.length === 1;
    result.failures.push(
      `factory: ${plural(added.length, "credential")} in the commits of this change — ${list(added, (f) => `commit ${short(f.commit)} ${f.path}:${f.line} (${f.rule})`)}. ` +
        `${one ? "It is" : "Each is"} on a line a commit between the base (${short(sha)}) and the head added. The scan of the working tree does not see a line a later commit ` +
        `removed, and the value is still in that commit: in the branch wherever it was pushed, and in the target branch's history after a merge. Treat ${one ? "it" : "each"} as ` +
        `compromised and rotate it at the provider. Then rewrite the branch so that no commit carries it, or have the pipeline's allowlist approve the file ` +
        `(kind "secret-in-commit", path from the project).`
    );
  }
  if (result.skipped.length) {
    const s = result.skipped;
    result.failures.push(
      `factory: ${plural(s.length, "file")} a commit of this change wrote where secret-guard's gitleaks allowlist does not scan — ${list(s, (f) => `commit ${short(f.commit)} ${f.path}`)}. ` +
        `Nothing scanned what ${s.length === 1 ? "that commit" : "those commits"} added there for credentials, and the working tree no longer shows it as this change wrote it. ` +
        `Rewrite the branch so that no commit writes there, or have the pipeline's allowlist approve the location (kind "skipped-location").`
    );
  }
  return result;
}
