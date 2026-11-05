// Known findings through the whole check run (lib/gate-core.mjs validateProject): what a snapshot
// sets aside, what it never can, and every entry that did nothing. docs/candidate-rules.md #36.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, realpathSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { validateProject } from "./gate-core.mjs";
import { KNOWN_FILE } from "./known.mjs";
import { REVIEW_FILE } from "./reviewed.mjs";

async function project(files, fn) {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "known-gate-")));
  for (const [rel, contents] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), contents);
  }
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// The temporary project is not a repository, so the uncommitted-work check reports that; it is not
// what these tests are about.
const findings = (r) => r.failures.filter((f) => !f.startsWith("uncommitted work:"));

// The two controls whose findings have IDs, returning what they return, about this directory.
function controls(dir, { vulns = [], identity = [], secrets = 0, depResult = null } = {}) {
  const tool = (out) => ({ server: { call: async () => JSON.stringify(out(dir)) } });
  // `depResult` replaces the dependency scan's result.
  const deps = tool(depResult || ((d) => ({ directory: d, findings: vulns })));
  return new Map([
    ["check_dependencies", deps],
    ["check_auth_posture", tool((d) => ({ root: d, findings: identity }))],
    [
      "scan_path",
      tool((d) => ({
        target: d,
        clean: secrets === 0,
        summary: { total: secrets },
        findings: Array.from({ length: secrets }, (_, i) => ({ rule: "generic-api-key", file: `${d}/conf.py`, startLine: i + 1 })),
      })),
    ],
  ]);
}

const APP = [
  "import os",
  "from flask import Flask, request",
  "app = Flask(__name__)",
  "",
  '@app.route("/items", methods=["POST"])',
  "def add_item():",
  '    token = request.headers.get("X-Token")',
  '    if token == os.environ["API_TOKEN"]:',
  '        return "ok"',
  '    return "no", 403',
  "",
].join("\n");

const VULN = { package: "lodash", version: "4.17.4", ecosystem: "npm", id: "GHSA-jf85-cpcp-j695", summary: "Prototype pollution", cvssScore: 9.1, fixedVersion: "4.17.12" };
const DB = { ruleId: "auth.db-password", category: "database", severity: "high", file: "db.py", line: 2, heuristic: false, message: "a database connection is authenticating with a password" };

const FILES = {
  "app.py": APP,
  // Assembled at runtime: this file's own source is scanned by the gate's commit hook, and the
  // finding is the fake control's (DB above), not identity-guard reading this line.
  "db.py": "import psycopg2\nconn = psycopg2.connect(" + "pass" + "word=os.environ['PW'])\n",
  "empty.js": "",
  Dockerfile: 'FROM node:14\nCMD ["node", "x.js"]\n',
  "package.json": '{"dependencies": {"lodash": "4.17.4"}}\n',
  "package-lock.json": '{"lockfileVersion": 3, "packages": {}}\n',
};

test("a snapshot of every finding sets aside each family it can hold; a secret still blocks", async () => {
  await project(FILES, async (dir) => {
    const r = await validateProject(dir, controls(dir, { vulns: [VULN], identity: [DB], secrets: 1 }), "", { known: { every: true } });
    // Only the secret is left: it is never snapshotted.
    assert.deepEqual(findings(r).map((f) => f.split(/[:\n]/)[0]), ["scan_path"], findings(r).join("\n"));
    const ids = r.known.map((k) => k.id).sort();
    assert.deepEqual(ids.map((id) => id.replace(/:[0-9a-f]{8}$/, ":<hash>")), [
      "authentication:ROUTE /items:app.py",
      "authentication:timing:app.py:<hash>",
      "dependencies:npm/lodash:GHSA-jf85-cpcp-j695",
      "dockerfile:Dockerfile:-:node:node",
      "identity:auth.db-password:db.py:<hash>",
      "presence:empty:empty.js",
    ]);
    // Every one is in the records, marked known, with where it is.
    const rec = new Map(r.records.map((x) => [x.id, x]));
    for (const id of ids) assert.equal(rec.get(id)?.known, true, id);
    assert.deepEqual([rec.get(ids.find((i) => i.startsWith("identity:"))).file, rec.get(ids.find((i) => i.startsWith("identity:"))).line], ["db.py", 2]);
    assert.deepEqual([rec.get("authentication:ROUTE /items:app.py").file, rec.get("authentication:ROUTE /items:app.py").line], ["app.py", 5]);
  });
});

test("with the snapshot written, nothing it holds blocks; a new finding does, and is the one record not known", async () => {
  await project(FILES, async (dir) => {
    const first = await validateProject(dir, controls(dir, { vulns: [VULN], identity: [DB] }), "", { known: { every: true } });
    writeFileSync(path.join(dir, KNOWN_FILE), JSON.stringify({ known: first.known.map(({ id, where }) => ({ id, where })) }));
    const clean = await validateProject(dir, controls(dir, { vulns: [VULN], identity: [DB] }), "");
    assert.deepEqual(findings(clean), []);
    assert.equal(clean.known.length, first.known.length);
    assert.ok(clean.known.every((k) => k.source === KNOWN_FILE));
    assert.deepEqual(clean.advisories.filter((a) => /^known: /.test(a)), []);

    // One new route, one new vulnerability in a package already flagged, one new identity finding.
    writeFileSync(path.join(dir, "app.py"), `${APP}\n@app.route("/admin/delete", methods=["POST"])\ndef delete_all():\n    return "deleted"\n`);
    const VULN2 = { ...VULN, id: "GHSA-4xc9-xhrj-v574" };
    const DB2 = { ...DB, file: "app.py", line: 13 };
    const r = await validateProject(dir, controls(dir, { vulns: [VULN, VULN2], identity: [DB, DB2] }), "");
    const fresh = r.records.filter((x) => !x.known);
    assert.deepEqual(fresh.map((x) => x.id.replace(/:[0-9a-f]{8}$/, ":<hash>")).sort(), [
      "authentication:ROUTE /admin/delete:app.py",
      "dependencies:npm/lodash:GHSA-4xc9-xhrj-v574",
      "identity:auth.db-password:app.py:<hash>",
    ]);
    assert.deepEqual(fresh.find((x) => x.id.startsWith("authentication:")).line, 12);
    assert.equal(findings(r).length, 3, findings(r).join("\n"));
    assert.match(r.failures.join("\n"), /ROUTE \/admin\/delete \(app\.py:12\)\. 1 more is open and known from the snapshot\./);
    assert.match(r.failures.join("\n"), /^check_dependencies: 1 finding\(s\) at or above high severity \(1 more set aside, listed separately\):\n[\s\S]*GHSA-4xc9-xhrj-v574/m);
    assert.doesNotMatch(r.failures.find((f) => f.startsWith("check_dependencies")), /GHSA-jf85-cpcp-j695/);
  });
});

test("an upgrade that leaves the advisory open is the same finding; an edit above a flagged line keeps its ID", async () => {
  await project(FILES, async (dir) => {
    const first = await validateProject(dir, controls(dir, { vulns: [VULN], identity: [DB] }), "", { known: { every: true } });
    writeFileSync(path.join(dir, KNOWN_FILE), JSON.stringify({ known: first.known.map(({ id }) => ({ id })) }));
    writeFileSync(path.join(dir, "app.py"), `# a comment added at the top\n\n${APP}`);
    writeFileSync(path.join(dir, "db.py"), `# moved down a line\n${FILES["db.py"]}`);
    writeFileSync(path.join(dir, "Dockerfile"), `# syntax=docker/dockerfile:1\nFROM node:14.21\nCMD ["node", "x.js"]\n`);
    const r = await validateProject(dir, controls(dir, { vulns: [{ ...VULN, version: "4.17.5" }], identity: [{ ...DB, line: 3 }] }), "");
    assert.deepEqual(findings(r), []);
    assert.deepEqual(r.records.filter((x) => !x.known), []);
  });
});

test("an entry matching nothing is reported only for a check that ran; an entry naming no family is ignored", async () => {
  const known = {
    known: [
      { id: "presence:empty:gone.js" },
      { id: "dependencies:npm/left-pad:GHSA-0000-0000-0000" },
      { id: "secret:conf.py:abcd1234" },
      { id: "authentication:ROUTE /items:app.py" },
    ],
  };
  await project({ "app.py": APP, [KNOWN_FILE]: JSON.stringify(known) }, async (dir) => {
    // No dependency control: its entry cannot be judged, so it is not stale.
    const r = await validateProject(dir, new Map(), "");
    const notes = r.advisories.filter((a) => /^known: /.test(a));
    assert.equal(notes.length, 2, notes.join("\n"));
    assert.match(notes[0], /^known: 1 snapshot entry matches no finding — presence:empty:gone\.js\./);
    assert.match(notes[1], /^known: an entry in \.wolfproof-known\.json needs an "id" naming a finding of .* so it was ignored: \{"id":"secret:conf\.py:abcd1234"\}/);
    assert.deepEqual(r.staleKnown.map((e) => e.id), ["presence:empty:gone.js"]);
  });
});

test("a review wins over the snapshot's entry for the same finding", async () => {
  await project(
    {
      "app.py": APP,
      [KNOWN_FILE]: JSON.stringify({ known: [{ id: "authentication:ROUTE /items:app.py" }] }),
      [REVIEW_FILE]: JSON.stringify({ reviewed: [{ id: "authentication:ROUTE /items:app.py", reason: "public by design" }] }),
    },
    async (dir) => {
      const r = await validateProject(dir, new Map(), "");
      assert.deepEqual(r.reviewed.map((x) => x.id), ["authentication:ROUTE /items:app.py"]);
      assert.deepEqual(r.known.map((x) => x.id), []);
      assert.equal(r.records.find((x) => x.id === "authentication:ROUTE /items:app.py").reviewed, true);
    }
  );
});

test("a manifest only a lockfile makes readable is never snapshotted: Gradle, or npm", async () => {
  for (const [file, text] of [
    ["build.gradle", "dependencies {\n  implementation 'org.example:lib:1.0'\n}\n"],
    ["package.json", '{"dependencies": {"lodash": "4.17.4"}}\n'],
  ]) {
    await project({ [file]: text }, async (dir) => {
      const r = await validateProject(dir, controls(dir), "", { known: { every: true } });
      assert.match(r.failures.join("\n"), /^check_dependencies: 1 manifest\(s\) declare dependencies that no scanner read/m);
      assert.deepEqual(r.known, []);
    });
  }
});

// The review of #36: an entry the dependency scan could still hold must not look stale when it did
// not run, or \`wolfproof known\` would remove it for good.
test("a dependency entry is stale only when the scan ran and every manifest of its ecosystem was read", async () => {
  const LODASH = "dependencies:npm/lodash:GHSA-jf85-cpcp-j695";
  const lodash = { ecosystem: "npm", package: "lodash", version: "4.17.4", id: "GHSA-jf85-cpcp-j695", severity: "critical" };
  const files = (extra = {}) => ({
    "api/package.json": JSON.stringify({ dependencies: { lodash: "4.17.4" } }),
    "api/package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.4" } } }),
    [KNOWN_FILE]: JSON.stringify({ known: [{ id: LODASH }] }),
    ...extra,
  });
  const stale = (r) => r.staleKnown.map((e) => e.id);
  await project(files(), async (dir) => {
    assert.deepEqual(stale(await validateProject(dir, controls(dir, { vulns: [lodash] }), "")), []);
    // The scan names no directory, so it is not a scan of this project.
    const a = await validateProject(dir, controls(dir, { depResult: () => ({ findings: [] }) }), "");
    assert.match(a.couldNotRun.join("\n"), /No dependency was checked/);
    assert.deepEqual(stale(a), []);
    assert.deepEqual(stale(await validateProject(dir, controls(dir), "")), [LODASH], "fixed in the lockfile");
  });
  // A package.json no scanner read may still hold it.
  await project(files({ "web/package.json": JSON.stringify({ dependencies: { express: "^4.18.0" } }) }), async (dir) => {
    assert.deepEqual(stale(await validateProject(dir, controls(dir), "")), []);
  });
  // A manifest no scanner read keeps its ecosystem's entries, and only its ecosystem's.
  await project(
    files({ "svc/build.gradle": "dependencies {\n  implementation 'org.example:lib:1.0'\n}\n", [KNOWN_FILE]: JSON.stringify({ known: [{ id: LODASH }, { id: "dependencies:Maven/org.example:lib:CVE-2020-0001" }] }) }),
    async (dir) => {
      assert.deepEqual(stale(await validateProject(dir, controls(dir), "")), [LODASH]);
    }
  );
});

test("each credential compared unsafely has its own ID, so a snapshot of the first does not hide the next", async () => {
  const two = `${APP}\ndef admin():\n    password = request.form["password"]\n    if password == os.environ["ADMIN_PASSWORD"]:\n        return "ok"\n`;
  await project({ "app.py": APP }, async (dir) => {
    const first = await validateProject(dir, new Map(), "", { known: { every: true } });
    writeFileSync(path.join(dir, KNOWN_FILE), JSON.stringify({ known: first.known.map(({ id }) => ({ id })) }));
    writeFileSync(path.join(dir, "app.py"), two);
    const r = await validateProject(dir, new Map(), "");
    const timing = r.failures.filter((f) => /compared with an ordinary equality operator/.test(f));
    assert.equal(timing.length, 1, r.failures.join("\n"));
    assert.match(timing[0], /^authentication: the credential `password` is compared with an ordinary equality operator rather than a constant-time one \(app\.py:14\)/);
  });
});
