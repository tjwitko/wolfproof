// Factory mode: credentials in the change's own commits.
//
// secret-guard scans the working tree. In a factory a change can add a credential in one commit and
// delete it in a later commit of the same branch: the tree is clean, the gate passes, and the value
// is in the branch on the remote, and in the target branch's history after a merge commit or a
// rebase merge. Measured on 0907366: a base, a commit adding an AWS access key ID to config.js and a
// commit removing the line, `--factory --base=<base>`, exit 0 with BLOCKING none.
//
// So factory mode also scans what each commit between the base and the head added, and each
// commit's message. The files a commit added to are written, as that commit had them, under a
// temporary directory, and the pipeline's own secret-guard scans it with the call it makes for the
// tree (scan_path), so the rules are the same ones. A finding is the commit's unless a parent already
// held it: unless the lines it spans stand together, in the same order, in a parent's scanned copy of
// the file. Nothing here reads a credential: secret-guard's findings never carry the value.
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
 * oldest first, each with its parents and its message. { commits: [{ sha, parents, message }] } or { error }.
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
  // One record a commit: "commit <sha> <parent>..." on a line, then its message, then a NUL.
  const list = git(projectDir, ["rev-list", "--reverse", "--topo-order", "--parents", "--format=%B%x00", `${sha}..HEAD`]);
  if (!list.ok) return { error: `git rev-list of ${short(sha)}..HEAD failed: ${list.err.split("\n")[0]}` };
  const commits = [];
  for (const record of list.out.split("\0")) {
    const text = record.replace(/^\n/, "");
    if (!text.trim()) continue;
    const nl = text.indexOf("\n");
    const head = /^commit ([0-9a-f]+)((?: [0-9a-f]+)*)$/.exec(nl < 0 ? text : text.slice(0, nl));
    if (!head) return { error: `git rev-list of ${short(sha)}..HEAD printed a record this does not read: ${JSON.stringify(text.slice(0, 80))}` };
    commits.push({ sha: head[1], parents: head[2].trim() ? head[2].trim().split(" ") : [], message: nl < 0 ? "" : text.slice(nl + 1) });
  }
  return { commits };
}

// One read of blobs covers at most this much.
const READ_BYTES = 64 * 1024 * 1024;
const READ_FILES = 2000;

/**
 * What every commit changed under the project, from one git process: Map(sha -> one list a parent,
 * in the parents' order, of { status, oldMode, mode, oldOid, newOid, path, from? }). A commit with
 * no parent has one list, against the empty tree.
 *
 * One process, because one a commit and one a file was where the time went: measured on dfd8f60 with
 * a scanner that returns at once, a commit that added 6,001 files took 112 s and 400 commits took
 * 22 s. --relative, so a project in a subdirectory is read as the tree scan reads it: its own files,
 * by their paths from the project. --always, so a merge prints a list for each parent even when one
 * is empty, and which list is which parent's is its position.
 */
/**
 * `--raw -z` output as lists of entries. With `headed`, each list follows the name of its commit and
 * the result is { by: Map(sha -> lists) }; without, the whole output is one list, { lists: [list] }.
 */
function parseRaw(parts, headed) {
  const by = new Map();
  let list = headed ? null : [];
  const lists = headed ? null : [list];
  for (let i = 0; i < parts.length; i++) {
    const t = parts[i].replace(/^\n/, "");
    if (!t) continue;
    if (t[0] === ":") {
      const m = /^:(\d+) (\d+) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])\d*$/.exec(t);
      if (!m || !list) return { error: `git printed a line of changes this does not read: ${JSON.stringify(t.slice(0, 80))}` };
      const from = m[5] === "R" || m[5] === "C" ? parts[++i] : undefined;
      list.push({ status: m[5], oldMode: m[1], mode: m[2], oldOid: m[3], newOid: m[4], path: parts[++i], ...(from === undefined ? {} : { from }) });
    } else if (headed && /^[0-9a-f]{40,64}$/.test(t)) {
      list = [];
      by.set(t, [...(by.get(t) || []), list]);
    } else {
      return { error: `git printed a line of changes this does not read: ${JSON.stringify(t.slice(0, 80))}` };
    }
  }
  return headed ? { by } : { lists };
}

function rawDiffs(projectDir, commits) {
  const input = commits.map((c) => [c.sha, ...c.parents].join(" ")).join("\n") + "\n";
  const d = git(projectDir, ["diff-tree", "--stdin", "--always", "-r", "--raw", "-z", "--no-abbrev", "-M", "-m", "--root", "--relative", "--no-ext-diff"], { input });
  if (!d.ok) return { error: `git diff-tree of the change's commits failed: ${d.err.split("\n")[0]}` };
  const parsed = parseRaw(d.out.split("\0"), true);
  if (parsed.error) return parsed;
  const by = parsed.by;
  for (const c of commits) {
    const lists = by.get(c.sha) || [];
    if (lists.length === Math.max(1, c.parents.length)) continue;
    // A merge that is the same as one of its parents prints no list for that parent, and nothing
    // says which one is missing. Measured with git 2.50.1: a merge of a branch into its own fork
    // point printed one list for two parents. So such a merge is read one parent at a time.
    if (c.parents.length < 2) return { error: `git diff-tree gave ${lists.length} list(s) of changes for ${short(c.sha)}, which has ${c.parents.length} parent(s)` };
    const each = [];
    for (const parent of c.parents) {
      const one = git(projectDir, ["diff", "--raw", "-z", "--no-abbrev", "-M", "--relative", "--no-ext-diff", parent, c.sha]);
      if (!one.ok) return { error: `git diff of ${short(parent)} and ${short(c.sha)} failed: ${one.err.split("\n")[0]}` };
      const read = parseRaw(one.out.split("\0"), false);
      if (read.error) return read;
      each.push(read.lists[0] || []);
    }
    by.set(c.sha, each);
  }
  return { by };
}

/**
 * The files one commit may have added lines to: [{ path, oid, olds }], regular files only. `olds`
 * holds, for each parent, the blob to compare with, or null where every line counts as added.
 *
 * Every line counts where the file was not a scanned regular file in that parent: it did not exist,
 * it was a symbolic link or a gitlink, or it sat where secret-guard does not scan. Measured on
 * 8105daf, both exit 0: a link whose target text was a credential, made a regular file with the same
 * blob by the next commit (old and new object equal, so "nothing changed"); and vendor/x.js added
 * with a credential, renamed unchanged to y.js, with vendor approved as a skipped location.
 *
 * For a merge, a file counts only when it differs from every parent: what the merge itself wrote.
 */
function candidates(lists, gitleaksAllow) {
  // A symbolic link holds a path and a gitlink a commit; the tree scan reads neither as a file.
  const maps = lists.map((l) => new Map(l.filter((e) => e.status !== "D" && e.mode.startsWith("100")).map((e) => [e.path, e])));
  const files = [];
  for (const [rel, first] of maps[0]) {
    if (!maps.every((m) => m.has(rel))) continue;
    const olds = maps.map((m) => {
      const e = m.get(rel);
      const was = e.from ?? rel;
      const scanned = e.status !== "A" && e.oldMode.startsWith("100") && !/^0+$/.test(e.oldOid) && !gitleaksAllow.some((re) => re.test(was));
      return scanned ? e.oldOid : null;
    });
    // The same blob as a parent's scanned file: a rename, or a change of mode. Nothing was added.
    if (olds.some((o) => o === first.newOid)) continue;
    files.push({ path: rel, oid: first.newOid, olds });
  }
  return files;
}

/** The sizes of blobs, from one `git cat-file --batch-check`: Map(oid -> bytes), or { error }. */
function blobSizes(projectDir, oids) {
  const sizes = new Map();
  if (!oids.length) return { sizes };
  const r = spawnSync("git", ["-C", projectDir, "cat-file", "--batch-check"], { input: oids.join("\n") + "\n", encoding: "utf8", maxBuffer: MAX_BUFFER });
  if (r.status !== 0) return { error: `git cat-file failed: ${String(r.stderr || r.error?.message || "").trim().split("\n")[0]}` };
  for (const line of r.stdout.split("\n").filter(Boolean)) {
    const [oid, type, size] = line.split(" ");
    if (type !== "blob") return { error: `${short(oid)} is not a blob git can read (${type || "no answer"})` };
    sizes.set(oid, Number(size));
  }
  return { sizes };
}

/** Blobs, from one `git cat-file --batch`: Map(oid -> Buffer), or { error }. */
function readBlobs(projectDir, oids, bytes) {
  const blobs = new Map();
  if (!oids.length) return { blobs };
  const r = spawnSync("git", ["-C", projectDir, "cat-file", "--batch"], { input: oids.join("\n") + "\n", maxBuffer: bytes + oids.length * 256 + 1024 * 1024 });
  if (r.status !== 0) return { error: `git cat-file failed: ${String(r.stderr || r.error?.message || "").trim().split("\n")[0]}` };
  let at = 0;
  for (const oid of oids) {
    const nl = r.stdout.indexOf(10, at);
    const head = nl < 0 ? "" : r.stdout.subarray(at, nl).toString("latin1");
    const m = /^([0-9a-f]+) blob (\d+)$/.exec(head);
    if (!m || m[1] !== oid) return { error: `git cat-file answered ${JSON.stringify(head.slice(0, 80))} for ${short(oid)}` };
    const size = Number(m[2]);
    blobs.set(oid, r.stdout.subarray(nl + 1, nl + 1 + size));
    at = nl + 1 + size + 1;
  }
  return { blobs };
}

/**
 * Whether a finding was already in a parent: whether the lines it spans, first to last, stand
 * together and in the same order in one parent's scanned copy of the file.
 *
 * By the text and not by a diff, so a credential the base held, moved within the file, is not the
 * commit's, and no .gitattributes or diff setting has a say. By the whole span and not line by line:
 * measured on df8c55b, where each line was judged alone, a private key committed with its lines in
 * reverse order and put in order by the next commit exited 0, because every line's text was in the
 * parent's copy though the credential first existed in the second commit. gitleaks reports every
 * line its rule matched (measured: a rule matching a label on one line and a value on the next gave
 * startLine 2, endLine 3), so the span is what the rule needed to see.
 *
 * `olds` holds a parent's copy, or null for a parent whose scan did not read the file. A merge wrote
 * a finding itself only when no parent held it.
 */
function heldByAParent(now, olds, start, end) {
  const lines = now.toString("latin1").split("\n").slice(start - 1, end);
  if (!lines.length) return false;
  return olds.some((old) => {
    if (old === null) return false;
    const then = old.toString("latin1").split("\n");
    for (let i = then.indexOf(lines[0]); i !== -1; i = then.indexOf(lines[0], i + 1)) {
      if (lines.every((l, k) => then[i + k] === l)) return true;
    }
    return false;
  });
}

/** Blobs for a list of object names, read in groups of at most READ_FILES names or READ_BYTES: calls `each(blobs, from, to)` a group. */
function inGroups(projectDir, items, oidsOf, each) {
  const sized = blobSizes(projectDir, [...new Set(items.flatMap(oidsOf))]);
  if (sized.error) return sized.error;
  for (let i = 0; i < items.length; ) {
    const group = [];
    const oids = new Set();
    let bytes = 0;
    while (i < items.length && group.length < READ_FILES && (!group.length || bytes < READ_BYTES)) {
      const item = items[i++];
      group.push(item);
      for (const oid of oidsOf(item)) {
        if (!oids.has(oid)) bytes += sized.sizes.get(oid) || 0;
        oids.add(oid);
      }
    }
    const read = readBlobs(projectDir, [...oids], bytes);
    if (read.error) return read.error;
    const failed = each(read.blobs, group);
    if (failed) return failed;
  }
  return null;
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
    const write = (key, data, record, what) => {
      if (!batches.length || batches.at(-1).bytes + data.length > BATCH_BYTES || batches.at(-1).files.size >= BATCH_FILES) open();
      const batch = batches.at(-1);
      try {
        mkdirSync(path.dirname(path.join(batch.dir, key)), { recursive: true });
        const fd = openSync(path.join(batch.dir, key), "wx");
        try {
          writeFileSync(fd, data);
        } finally {
          closeSync(fd);
        }
      } catch (e) {
        return `${what} could not be written to a temporary directory to be scanned (${e?.code || e?.message})`;
      }
      batch.bytes += data.length;
      batch.files.set(key, record);
      return null;
    };

    const diffs = rawDiffs(projectDir, range.commits);
    if (diffs.error) return fail(diffs.error);
    // The files to read, in the commits' order: [{ n, commit, path, oid, olds, slot }]
    const pending = [];
    for (const [n, commit] of range.commits.entries()) {
      const prefix = String(n).padStart(6, "0");
      // The message is part of the commit, and a credential pasted into one is pushed with it.
      // Measured on 8105daf: a commit whose message held an AWS access key ID exited 0.
      if (commit.message.trim()) {
        const text = withoutUnhonouredAllows(Buffer.from(commit.message, "utf8"), ".", (rel) => Boolean(allowlisted({ kind: ALLOW, path: rel }, allowlist)));
        const failed = write(`${prefix}.message/commit-message.txt`, text, { commit: commit.sha, message: true }, `the message of ${short(commit.sha)}`);
        if (failed) return fail(failed);
      }
      const slots = [];
      for (const f of candidates(diffs.by.get(commit.sha), gitleaksAllow)) {
        if (!plainPath(f.path) || f.path.split("/").some((p) => p.toLowerCase() === ".git")) {
          return fail(`commit ${short(commit.sha)} holds a file at ${JSON.stringify(f.path)}, a path git does not check out`);
        }
        const unscanned = gitleaksAllow.find((re) => re.test(f.path));
        if (unscanned) {
          if (!reported.has(f.path) && !allowlisted({ kind: "skipped-location", path: f.path }, allowlist)) result.skipped.push({ commit: commit.sha, path: f.path, why: unscanned.source });
          continue;
        }
        pending.push({ ...f, commit: commit.sha, key: `${prefix}.${slotFor(slots, f.path)}/${f.path}` });
      }
    }

    // Every file a commit changed is scanned whole, and what was already in a parent is told apart
    // afterwards, finding by finding (heldByAParent). Read in groups, each through one git process.
    const wrote = inGroups(projectDir, pending, (f) => [f.oid], (blobs, group) => {
      for (const f of group) {
        const failed = write(f.key, withoutUnhonouredAllows(blobs.get(f.oid), f.path, honouredAllow), { commit: f.commit, path: f.path, oid: f.oid, olds: f.olds }, `${f.path} at ${short(f.commit)}`);
        if (failed) return failed;
        result.files++;
      }
      return null;
    });
    if (wrote) return fail(wrote);

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

    const raised = [];
    const keep = (file, start, rule, heuristic) => {
      // A message has no path: no ignore entry names it, and only an approval of the whole project covers it.
      if (!file.message && roots.some((r) => honouredIgnores(file.commit).has(`${r}/${file.path}:${rule}:${start}`))) return;
      const approved = allowlisted({ kind: "secret-in-commit", path: file.message ? "." : file.path }, allowlist);
      result.findings.push({
        commit: file.commit,
        ...(file.message ? { message: true } : { path: file.path }),
        line: start,
        rule,
        ...(heuristic ? { heuristic: true } : {}),
        status: approved ? "allowlisted" : "added",
        ...(approved ? { approvedBy: approved.reason } : {}),
      });
    };
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
      // Findings can come with what the scan did not read (`skipped`, secret-guard v1.0.4 on). With
      // none found that is already an error, above. With some found it is not, and the findings may
      // all be lines a parent held: a scan cut short at its time limit would then count the files it
      // never reached as scanned. The files are ones written here a moment ago, so nothing unread is
      // expected and none of it is set aside.
      if (parsed.skipped !== undefined && !(Array.isArray(parsed.skipped) && !parsed.skipped.length)) {
        const why = [...new Set((Array.isArray(parsed.skipped) ? parsed.skipped : []).map((s) => String(s?.reason || "not read").replace(/\s+/g, " ").trim().slice(0, 120)))];
        return fail(`secret-guard did not read all of them${why.length ? `: ${why.slice(0, 3).join("; ")}` : ""}`);
      }
      for (const f of parsed.findings) {
        const key = path.relative(batch.dir, path.resolve(batch.dir, String(f.file))).split(path.sep).join("/");
        const file = batch.files.get(key);
        if (!file) return fail(`secret-guard reported a finding in ${JSON.stringify(String(f.file).slice(0, 200))}, which is not a file it was given`);
        const start = Number(f.startLine) || 1;
        const end = Math.max(start, Number(f.endLine) || start);
        if (!file.message && file.olds.some((o) => o !== null)) {
          raised.push({ file, start, end, rule: String(f.rule), heuristic: Boolean(f.heuristic) });
          continue;
        }
        keep(file, start, String(f.rule), Boolean(f.heuristic));
      }
    }
    // The findings in files a parent's scan had read: the commit's unless a parent held the same lines.
    const judged = inGroups(projectDir, raised, (r) => [r.file.oid, ...r.file.olds.filter(Boolean)], (blobs, group) => {
      for (const r of group) {
        if (!heldByAParent(blobs.get(r.file.oid), r.file.olds.map((o) => (o === null ? null : blobs.get(o))), r.start, r.end)) keep(r.file, r.start, r.rule, r.heuristic);
      }
      return null;
    });
    if (judged) return fail(judged);
  } finally {
    cleanup();
  }

  const list = (items, show) => `${items.slice(0, 8).map(show).join(", ")}${items.length > 8 ? `, +${items.length - 8} more` : ""}`;
  const added = result.findings.filter((f) => f.status === "added");
  if (added.length) {
    const one = added.length === 1;
    result.failures.push(
      `factory: ${plural(added.length, "credential")} in the commits of this change — ${list(added, (f) => `commit ${short(f.commit)} ${f.message ? `message, line ${f.line}` : `${f.path}:${f.line}`} (${f.rule})`)}. ` +
        `${one ? "It is" : "Each is"} on a line a commit between the base (${short(sha)}) and the head added, or in a commit's message. The scan of the working tree does not see a line a later commit ` +
        `removed, and the value is still in that commit: in the branch wherever it was pushed, and in the target branch's history after a merge. Treat ${one ? "it" : "each"} as ` +
        `compromised and rotate it at the provider. Then rewrite the branch so that no commit carries it, or have the pipeline's allowlist approve the file ` +
        `(kind "secret-in-commit", path from the project; a message is covered only by an approval of the whole project, path ".").`
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
