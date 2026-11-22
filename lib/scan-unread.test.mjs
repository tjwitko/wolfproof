import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { incompleteScan, skipsNotAccountedFor, validateProject } from "./gate-core.mjs";

// What the gate does with a secret scan that left something unread (lib/gate-core.mjs).
//
// secret-guard from v1.0.4 says what gitleaks walked past. With nothing found that is an error, whose
// second block lists the paths; with something found it is a `skipped` list beside the findings. The
// gate sets aside one kind of path and no other: one at or under a directory it could not list
// itself and git ignores, which it already reports in a line above the verdict.
//
// The scanner here is a stand-in that answers as secret-guard does, so these test what is done with
// the answer. The real scanner, through the real CLI, is in bin/scan-unread.test.mjs.

const asRoot = process.getuid?.() === 0 && "root reads every directory";

/**
 * A committed project with `data/postgres`, which git ignores, and `locked`, which it does not.
 * `dir` is as the temp directory spells it and `real` as the scanner would: on macOS they differ.
 */
function project() {
  const dir = mkdtempSync(path.join(tmpdir(), "scan-unread-"));
  mkdirSync(path.join(dir, "data", "postgres"), { recursive: true });
  mkdirSync(path.join(dir, "data", "postgres2"));
  mkdirSync(path.join(dir, "locked"));
  writeFileSync(path.join(dir, "README.md"), "a project\n");
  writeFileSync(path.join(dir, ".gitignore"), "data/\n");
  writeFileSync(path.join(dir, "data", "postgres", "PG_VERSION"), "17\n");
  symlinkSync(path.join("data", "postgres"), path.join(dir, "link"));
  for (const args of [["init", "-q"], ["add", "-A"], ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-qm", "a"]]) {
    spawnSync("git", args, { cwd: dir });
  }
  return { dir, real: realpathSync(dir), done: () => rmSync(dir, { recursive: true, force: true }) };
}

const UNREAD = [
  { dir: path.join("data", "postgres"), why: "not readable (EACCES)", ignored: true },
  { dir: "locked", why: "not readable (EACCES)", ignored: false },
];

test("a skipped path is accounted for only at or under a directory the gate could not list and git ignores", () => {
  const p = project();
  try {
    const left = (s) => skipsNotAccountedFor([s], p.dir, UNREAD).length === 1;
    const at = (...parts) => ({ path: path.join(p.real, ...parts), reason: "permission denied" });
    assert.equal(left(at("data", "postgres")), false, "the directory itself");
    assert.equal(left(at("data", "postgres", "base", "1")), false, "a path under it, which is not there to resolve");
    // The same directory by the other spelling of the temp directory: both sides are real paths.
    assert.equal(left({ path: path.join(p.dir, "data", "postgres"), reason: "permission denied" }), false, "a path that is not a real one");
    assert.equal(left(at("data", "postgres2")), true, "a directory whose name only begins the same way");
    assert.equal(left(at("data")), true, "its parent");
    assert.equal(left(at("locked")), true, "a directory the gate could not list and git does not ignore");
    assert.equal(left(at(".env")), true, "a file");
    assert.equal(left(at("link")), true, "a link to the directory is where the link is, not where it points");
    assert.equal(left({ path: null, reason: "the scan stopped before it finished" }), true, "an entry with no path");
    assert.equal(left({ path: path.join("data", "postgres"), reason: "permission denied" }), true, "a path that is not absolute");
    assert.equal(left({ reason: "permission denied" }), true);
    assert.equal(left(null), true);
    assert.equal(left("data/postgres"), true);
    // A list that is not one is one entry not accounted for, never none.
    assert.deepEqual(skipsNotAccountedFor("some", p.dir, UNREAD), ["some"]);
    // And nothing is accounted for when the gate found no such directory.
    assert.equal(skipsNotAccountedFor([at("data", "postgres")], p.dir, []).length, 1);
    assert.equal(skipsNotAccountedFor([at("data", "postgres")], p.dir, [{ dir: ".", why: "x", ignored: true }]).length, 1);
    assert.equal(skipsNotAccountedFor([at("data", "postgres")], p.dir, [{ ...UNREAD[0], ignored: false }]).length, 1);
  } finally {
    p.done();
  }
});

test("the list of what a scan left unread is read from the second block of the error, and from nowhere else", () => {
  const doc = { target: "/p", incomplete: true, skipped: [{ path: "/p/x", reason: "permission denied" }] };
  assert.deepEqual(incompleteScan([JSON.stringify(doc)]), doc);
  assert.equal(incompleteScan([]), null);
  assert.equal(incompleteScan(undefined), null);
  assert.equal(incompleteScan(["not JSON"]), null);
  assert.equal(incompleteScan([JSON.stringify({ ...doc, incomplete: false })]), null);
  assert.equal(incompleteScan([JSON.stringify({ target: "/p", skipped: doc.skipped })]), null);
  assert.equal(incompleteScan([JSON.stringify({ ...doc, skipped: [] })]), null);
  assert.equal(incompleteScan([JSON.stringify({ ...doc, skipped: "all of it" })]), null);
  assert.equal(incompleteScan(["null"]), null);
});

/** The gate's could-not-run and blocking lines about the secret scan, for one answer from the scanner. */
async function gateOn(p, server) {
  const r = await validateProject(p.dir, new Map([["scan_path", { kind: "mcp", server }]]), "");
  return {
    couldNotRun: r.couldNotRun.filter((c) => c.startsWith("scan_path")),
    failures: r.failures.filter((f) => f.startsWith("scan_path")),
    ran: r.ran.includes("scan_path"),
  };
}

const ERROR = "TOOL REPORTED A PROBLEM:\nnot a clean scan: gitleaks did not read";
const DENIED = "permission denied";
const OLD_LINE = /^scan_path: secret-guard could not scan — not a clean scan: gitleaks did not read .* No file was checked for credentials\.$/;
const PART_LINE = /^scan_path: secret-guard could not scan all of the project — /;

test("an error that lists only a directory the gate has already reported is a scan that ran, and anything else on the list is could-not-run", { skip: asRoot }, async () => {
  const p = project();
  chmodSync(path.join(p.dir, "data", "postgres"), 0o000);
  const pg = { path: path.join(p.real, "data", "postgres"), reason: DENIED };
  const env = { path: path.join(p.real, ".env"), reason: DENIED };
  const error = (skipped, target = p.real) => ({
    callBlocks: async () => ({
      text: `${ERROR} ${skipped.map((s) => `${s.path} (${s.reason})`).join(", ")}`,
      more: [JSON.stringify({ ...(target ? { target } : {}), incomplete: true, skipped })],
    }),
  });
  try {
    // Every path on the list is the directory in the line above the verdict: run, and clean.
    assert.deepEqual(await gateOn(p, error([pg])), { couldNotRun: [], failures: [], ran: true });

    // A file beside it: could-not-run, naming the file from the project's top and not the directory.
    let r = await gateOn(p, error([pg, env]));
    assert.equal(r.couldNotRun.length, 1, JSON.stringify(r.couldNotRun));
    assert.equal(r.couldNotRun[0], "scan_path: secret-guard could not scan all of the project — it did not read .env (permission denied). What it did not read was not checked for credentials.");
    assert.deepEqual(r.failures, []);

    // An entry with no path: the scan stopped, and no directory accounts for that.
    r = await gateOn(p, error([pg, { path: null, reason: "the scan stopped before it finished: context deadline exceeded" }]));
    assert.equal(r.couldNotRun.length, 1, JSON.stringify(r.couldNotRun));
    assert.match(r.couldNotRun[0], /^scan_path: secret-guard could not scan all of the project — the scan stopped before it finished: context deadline exceeded\. /);

    // The same error with no second block, as a caller that reads one block sees it, and as every
    // other error is: could-not-run, in the scanner's words.
    r = await gateOn(p, { call: async () => `${ERROR} ${pg.path} (${DENIED})` });
    assert.equal(r.couldNotRun.length, 1, JSON.stringify(r.couldNotRun));
    assert.match(r.couldNotRun[0], OLD_LINE);
    r = await gateOn(p, { callBlocks: async () => ({ text: `${ERROR} ${pg.path} (${DENIED})`, more: ["not JSON"] }) });
    assert.match(r.couldNotRun[0] || "", OLD_LINE);
    // A reply that is not a control's error is not made one by a list beside it.
    r = await gateOn(p, { callBlocks: async () => ({ text: "(no output)", more: [JSON.stringify({ target: p.real, incomplete: true, skipped: [pg] })] }) });
    assert.deepEqual(r.couldNotRun, ["scan_path: the scan produced no parseable result, so no file was checked for credentials"]);

    // A list about somewhere else, or about nowhere it names, is not about this project.
    for (const target of [path.dirname(p.real), path.join(p.real, "data"), null]) {
      r = await gateOn(p, error([pg], target));
      assert.equal(r.couldNotRun.length, 1, `target ${target}: ${JSON.stringify(r.couldNotRun)}`);
      assert.match(r.couldNotRun[0], OLD_LINE);
    }
  } finally {
    chmodSync(path.join(p.dir, "data", "postgres"), 0o755);
    p.done();
  }
});

test("findings stand beside what the scan left unread, and a path the gate has not accounted for is could-not-run as well", { skip: asRoot }, async () => {
  const p = project();
  chmodSync(path.join(p.dir, "data", "postgres"), 0o000);
  const pg = { path: path.join(p.real, "data", "postgres"), reason: DENIED };
  const found = (skipped) => ({
    call: async () =>
      JSON.stringify({
        target: p.real,
        clean: false,
        summary: { total: 1 },
        findings: [{ rule: "stand-in", file: "conf.yaml", startLine: 1 }],
        ...(skipped === undefined ? {} : { skipped }),
      }),
  });
  try {
    let r = await gateOn(p, found(undefined));
    assert.equal(r.failures.length, 1);
    assert.deepEqual(r.couldNotRun, []);

    r = await gateOn(p, found([pg]));
    assert.match(r.failures[0] || "", /^scan_path: 1 hardcoded credential\(s\)/);
    assert.deepEqual(r.couldNotRun, [], "the directory in the line above the verdict");

    r = await gateOn(p, found([pg, { path: path.join(p.real, "app", "settings.env"), reason: DENIED }]));
    assert.match(r.failures[0] || "", /^scan_path: 1 hardcoded credential\(s\)/);
    assert.deepEqual(r.couldNotRun, ["scan_path: secret-guard could not scan all of the project — it did not read app/settings.env (permission denied). What it did not read was not checked for credentials."]);

    r = await gateOn(p, found("some"));
    assert.equal(r.failures.length, 1);
    assert.match(r.couldNotRun[0] || "", PART_LINE);

    // A report that says it is clean and lists something unread is not a clean scan of the project.
    const clean = (skipped) => ({ call: async () => JSON.stringify({ target: p.real, clean: true, summary: { total: 0 }, findings: [], skipped }) });
    assert.deepEqual(await gateOn(p, clean([pg])), { couldNotRun: [], failures: [], ran: true });
    r = await gateOn(p, clean([{ path: path.join(p.real, ".env"), reason: DENIED }]));
    assert.deepEqual(r.failures, []);
    assert.match(r.couldNotRun[0] || "", /— it did not read \.env \(permission denied\)\./);
  } finally {
    chmodSync(path.join(p.dir, "data", "postgres"), 0o755);
    p.done();
  }
});
