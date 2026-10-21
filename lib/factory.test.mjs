// Factory mode's parts, without running the gate: base resolution, the inventory of self-granted
// loosenings, the judgement against a base, the pipeline's inputs, and the advisory classes. The
// end-to-end measurement -- the real gate over test/fixtures/factory-scenario.mjs -- is
// test/factory-scenario.e2e.mjs, run by `npm run test:factory`, because it needs the scanners and
// takes minutes, and this file runs inside the gate's own 120-second test budget.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  resolveBase,
  materializeBase,
  changesSinceBase,
  inventoryGrants,
  judgeChange,
  declaredOverrides,
  servesHttp,
  readPipelineInput,
  parseAllowlist,
  requirementAtBase,
  uncheckedLocation,
  secretGuardAllowlist,
  checkovGrantBlocks,
  GRANT_KINDS,
} from "./factory.mjs";
import { resolveControls } from "./resolve-controls.mjs";
import {
  ADVISORY_CLASSES,
  classifyAdvisory,
  actionFor,
  NOT_CHECKED,
  COULD_NOT_RUN,
  FINDING,
  INFO,
} from "./advisory-classes.mjs";

function repo() {
  const dir = mkdtempSync(path.join(tmpdir(), "factory-unit-"));
  const git = (...a) => {
    const r = spawnSync("git", ["-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", ...a], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q");
  const write = (rel, text) => {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  };
  const commit = (msg = "c") => {
    git("add", "-A");
    git("commit", "-qm", msg, "--allow-empty");
    return git("rev-parse", "HEAD");
  };
  return { dir, git, write, commit, done: () => rmSync(dir, { recursive: true, force: true }) };
}

function judged(r, sha, opts = {}) {
  const base = materializeBase(r.dir, sha);
  try {
    return judgeChange(r.dir, { sha, baseDir: base.dir, ...opts });
  } finally {
    base.cleanup();
  }
}

// ---------------------------------------------------------------------------------------------
// base

test("a base that is not in the checkout is an error that says what to fetch", () => {
  const r = repo();
  try {
    r.write("a.txt", "a");
    r.commit();
    assert.match(resolveBase(r.dir, "deadbeef").error, /the base ref deadbeef is not in this checkout/);
    assert.match(resolveBase(r.dir, "HEAD~1").error, /not in this checkout/);
    assert.match(resolveBase(r.dir, "").error, /no base ref was given/);
    assert.match(resolveBase(r.dir, "HEAD").sha, /^[0-9a-f]{40}$/);
  } finally {
    r.done();
  }
});

test("a directory outside any repository has no base", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "factory-norepo-"));
  try {
    assert.match(resolveBase(dir, "HEAD").error, /not inside a git repository/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a shallow clone's error names the fetch that fixes it, deepening for a relative ref", () => {
  const r = repo();
  const clone = mkdtempSync(path.join(tmpdir(), "factory-shallow-"));
  try {
    r.write("a.txt", "1");
    r.commit();
    r.write("a.txt", "2");
    r.commit();
    spawnSync("git", ["clone", "-q", "--depth", "1", `file://${r.dir}`, clone]);
    assert.match(resolveBase(clone, "HEAD~1").error, /shallow.*git fetch --no-tags --deepen=1 origin/);
    assert.match(resolveBase(clone, "abc123").error, /shallow.*git fetch --no-tags --depth=1 origin abc123/);
  } finally {
    r.done();
    rmSync(clone, { recursive: true, force: true });
  }
});

test("the base is the project's own subtree, and empty when the project did not exist yet", () => {
  const r = repo();
  try {
    r.write("other/x.txt", "x");
    const first = r.commit();
    r.write("svc/app.js", "1");
    const second = r.commit();
    const sub = path.join(r.dir, "svc");
    const before = materializeBase(sub, first);
    assert.equal(before.empty, true);
    before.cleanup();
    const after = materializeBase(sub, second);
    assert.equal(after.empty, false);
    assert.deepEqual(spawnSync("ls", [after.dir], { encoding: "utf8" }).stdout.trim(), "app.js");
    after.cleanup();
  } finally {
    r.done();
  }
});

test("changes since the base count edits, additions, renames and untracked files", () => {
  const r = repo();
  try {
    r.write("src/a.js", "const a = 1;\n".repeat(20));
    r.write("src/b.js", "b");
    const sha = r.commit();
    r.write("src/b.js", "b2");
    renameSync(path.join(r.dir, "src/a.js"), path.join(r.dir, "src/a.test.js"));
    r.git("add", "-A");
    r.write("new.js", "untracked");
    const c = changesSinceBase(r.dir, sha);
    assert.ok(c.some((x) => x.status === "M" && x.path === "src/b.js"), JSON.stringify(c));
    assert.ok(c.some((x) => x.status === "R" && x.from === "src/a.js" && x.path === "src/a.test.js"), JSON.stringify(c));
    assert.ok(c.some((x) => x.status === "A" && x.path === "new.js"), JSON.stringify(c));
  } finally {
    r.done();
  }
});

// ---------------------------------------------------------------------------------------------
// inventory

test("every kind of self-granted loosening is found, keyed by its line", () => {
  const r = repo();
  try {
    r.write("fixtures/.tfguard-fixture", "deliberately insecure samples\n");
    r.write("fixtures/x.tf", "");
    r.write("src/a.js", "const k = readKey(); // gitleaks:allow\n");
    r.write("k8s/d.yaml", "# identity-guard:allow IG001 uses node role on purpose\nkind: Deployment\n");
    r.write("app/m.py", "x = undefined_name  # noqa\n");
    r.write("infra/main.tf", "resource \"x\" \"y\" { #checkov:skip=CKV_AWS_1: fine\n}\n");
    r.write(".gitleaksignore", "# comment\nsrc/a.js:generic-api-key:1\n");
    r.write("sub/.gitleaksignore", "not read: only the root one is\n");
    r.write("osv-scanner.toml", "[[IgnoredVulns]]\nid = \"GHSA-xxxx\"\n");
    r.write("ruff.toml", "extend-exclude = [\"app\"]\n");
    r.write("pyproject.toml", "[project]\nname = \"p\"\n[tool.ruff]\nextend-exclude = [\"x\"]\n[tool.other]\nk = 1\n");
    r.write(".checkov.yaml", "skip-check: CKV_AWS_1\n");
    r.commit();
    const g = inventoryGrants(r.dir);
    const kinds = new Set(g.map((x) => x.kind));
    for (const k of ["fixture-marker", "gitleaks:allow", "identity-guard:allow", "noqa", "checkov:skip", ".gitleaksignore", "osv-scanner.toml", "ruff config", "checkov config"]) {
      assert.ok(kinds.has(k), `${k} not found in ${JSON.stringify([...kinds])}`);
    }
    assert.ok(!g.some((x) => x.path === "sub/.gitleaksignore"), "a nested .gitleaksignore is not read by secret-guard");
    const pyproject = g.filter((x) => x.path === "pyproject.toml").map((x) => x.text);
    assert.deepEqual(pyproject, ["[tool.ruff]", 'extend-exclude = ["x"]'], "only the [tool.ruff] section of pyproject.toml");
    assert.ok(g.find((x) => x.kind === "gitleaks:allow").key.includes("readKey()"), "the key carries the line, so a changed line is a new grant");
    for (const k of kinds) assert.ok(k in GRANT_KINDS, `${k} is described in GRANT_KINDS`);
  } finally {
    r.done();
  }
});

// A checkov skip hides checkov findings, which are advisories. An added one blocks only when the
// pipeline's policy blocks the findings it hides -- decided 2026-10-20: blocking the hiding of a
// finding that cannot block would make the suppression worse than the finding.
test("an added checkov skip blocks only when the policy blocks what it hides", () => {
  const r = repo();
  try {
    r.write("infra/main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n');
    const sha = r.commit();
    r.write("infra/main.tf", 'resource "aws_s3_bucket" "b" {\n  #checkov:skip=CKV_AWS_18: no logging needed\n  bucket = "b"\n}\n');
    r.write(".checkov.yaml", "skip-check: CKV_AWS_21\n");
    r.commit();
    const blocked = (j) => j.failures.filter((f) => /checkov/.test(f));

    let j = judged(r, sha);
    assert.deepEqual(blocked(j), [], "default policy drops checkov findings, so hiding them does not block");
    assert.ok(j.notes.some((n) => /checkov:skip this change added, not blocking: infra\/main\.tf:2/.test(n)), j.notes.join("\n"));
    assert.ok(j.notes.some((n) => /checkov config this change added, not blocking: \.checkov\.yaml/.test(n)), j.notes.join("\n"));
    assert.ok(j.grants.filter((g) => /checkov/.test(g.kind)).every((g) => g.status === "added"), "still recorded as added");

    for (const policy of [{ advisories: { checkov: "block" } }, { advisories: { finding: "block" } }, { advisories: { checkov: "incomplete" } }]) {
      j = judged(r, sha, { policy });
      assert.equal(blocked(j).length, 2, `${JSON.stringify(policy)}: ${j.failures.join("\n")}`);
    }
  } finally {
    r.done();
  }
});

test("a checkov skip follows the policy for the findings of the file it is in", () => {
  const p = { advisories: { "dockerfile-checkov": "block" } };
  assert.deepEqual(checkovGrantBlocks({ path: "Dockerfile" }, p), { id: "dockerfile-checkov", blocks: true });
  assert.deepEqual(checkovGrantBlocks({ path: "svc/api.Dockerfile" }, p), { id: "dockerfile-checkov", blocks: true });
  assert.deepEqual(checkovGrantBlocks({ path: "infra/main.tf" }, p), { id: "checkov", blocks: false });
  assert.deepEqual(checkovGrantBlocks({ path: "cfn/stack.yaml" }, p), { id: "iac-checkov", blocks: false });
  assert.deepEqual(checkovGrantBlocks({ path: ".checkov.yaml" }, { advisories: { checkov: "block" } }), { id: "checkov", blocks: true });
});

test("a marker with no reason is not a grant, because it exempts nothing", () => {
  const r = repo();
  try {
    r.write("x/.tfguard-fixture", "# only a comment\n");
    r.commit();
    assert.equal(inventoryGrants(r.dir).filter((g) => g.kind === "fixture-marker").length, 0);
  } finally {
    r.done();
  }
});

// ---------------------------------------------------------------------------------------------
// judgement

test("a grant the change added blocks; one the base had does not; one the allowlist approves does not", () => {
  const r = repo();
  try {
    r.write("src/a.js", "const a = 1; // gitleaks:allow\n");
    const sha = r.commit();
    r.write("src/b.js", "const b = 2; // gitleaks:allow\n");
    r.write("samples/.tfguard-fixture", "deliberately broken samples\n");
    r.write("samples/s.js", "x");
    r.commit();
    const plain = judged(r, sha);
    const status = Object.fromEntries(plain.grants.map((g) => [g.path, g.status]));
    assert.equal(status["src/a.js"], "pre-existing");
    assert.equal(status["src/b.js"], "added");
    assert.equal(status.samples, "added");
    assert.ok(plain.failures.some((f) => /^factory: 1 gitleaks:allow grant\(s\) this change added — src\/b\.js:1/.test(f)), plain.failures.join("\n"));
    assert.ok(plain.failures.some((f) => /^factory: 1 fixture-marker grant\(s\) this change added — samples\/\.tfguard-fixture/.test(f)), plain.failures.join("\n"));

    const approved = judged(r, sha, {
      allowlist: parseAllowlist({ exemptions: [{ kind: "fixture-marker", path: "samples", reason: "approved by the platform team" }] }).entries,
    });
    assert.equal(approved.grants.find((g) => g.path === "samples").status, "allowlisted");
    assert.ok(!approved.failures.some((f) => /fixture-marker/.test(f)), approved.failures.join("\n"));
    assert.ok(approved.failures.some((f) => /gitleaks:allow/.test(f)), "the allowlist approves only what it names");
  } finally {
    r.done();
  }
});

test("code the change wrote under an exemption that predates it blocks, unless the allowlist approves the exemption", () => {
  const r = repo();
  try {
    r.write("fixtures/.tfguard-fixture", "deliberately insecure samples\n");
    r.write("fixtures/old.tf", "");
    const sha = r.commit();
    r.write("fixtures/server.js", "require('http').createServer().listen(80)");
    r.commit();
    const j = judged(r, sha);
    assert.ok(j.failures.some((f) => /^factory: 1 file\(s\) changed under fixtures, which an exemption that predates this change/.test(f)), j.failures.join("\n"));
    assert.ok(!j.failures.some((f) => /fixture-marker grant/.test(f)), "the marker itself predates the change");
    const ok = judged(r, sha, { allowlist: parseAllowlist({ exemptions: [{ kind: "fixture-marker", path: "fixtures", reason: "ok" }] }).entries });
    assert.equal(ok.failures.length, 0, ok.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("code written where the checks do not look blocks: a skipped directory, or one the gitleaks allowlist skips", () => {
  const r = repo();
  try {
    r.write("README.md", "x");
    const sha = r.commit();
    r.write("dist/server.js", "x");
    r.write("vendor/config.js", "x");
    r.commit();
    const j = judged(r, sha);
    assert.ok(j.failures.some((f) => /under dist, where every source check skips dist\//.test(f)), j.failures.join("\n"));
    assert.ok(j.failures.some((f) => /under vendor, where secret-guard's gitleaks allowlist does not scan it/.test(f)), j.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("moving code to a test name or test directory, which the authentication check skips, blocks", () => {
  const r = repo();
  try {
    r.write("src/server.js", "app.post('/admin/purge', h);\n".repeat(10));
    const sha = r.commit();
    renameSync(path.join(r.dir, "src/server.js"), path.join(r.dir, "src/server.test.js"));
    r.commit();
    const j = judged(r, sha);
    assert.ok(j.failures.some((f) => /moved src\/server\.js to src\/server\.test\.js, where the authentication check skips files named as tests/.test(f)), j.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("a change to the pipeline blocks: a workflow added, edited, renamed, deleted or left untracked", () => {
  const r = repo();
  try {
    // Distinct contents, so git's rename detection pairs old.yml with renamed.yml and not deploy.yml.
    r.write(".github/workflows/ci.yml", "name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n");
    r.write(".github/workflows/deploy.yml", "name: deploy\non: workflow_dispatch\n");
    r.write(".github/workflows/old.yml", "name: nightly\non:\n  schedule:\n    - cron: '0 3 * * *'\njobs:\n  scan:\n    runs-on: ubuntu-latest\n");
    r.write("src/a.js", "a");
    const sha = r.commit();
    r.write(".github/workflows/ci.yml", "name: ci\non: push\njobs: {}\n");
    rmSync(path.join(r.dir, ".github/workflows/deploy.yml"));
    renameSync(path.join(r.dir, ".github/workflows/old.yml"), path.join(r.dir, ".github/workflows/renamed.yml"));
    r.write(".github/workflows/release.yml", "on: tag\n");
    r.commit();
    r.write(".github/workflows/untracked.yml", "on: push\n");
    const j = judged(r, sha);
    const f = j.failures.filter((x) => /^factory: this change edits the pipeline/.test(x));
    assert.equal(f.length, 1, j.failures.join("\n"));
    for (const want of [
      ".github/workflows/ci.yml (changed)",
      ".github/workflows/deploy.yml (deleted)",
      ".github/workflows/old.yml → .github/workflows/renamed.yml (renamed)",
      ".github/workflows/release.yml (added)",
      ".github/workflows/untracked.yml (added)",
    ]) {
      assert.ok(f[0].includes(want), `${want} in ${f[0]}`);
    }
    assert.equal(j.workflows.length, 5);
  } finally {
    r.done();
  }
});

test("the allowlist approves a workflow change by file or by directory, and only what it names", () => {
  const r = repo();
  try {
    r.write(".github/workflows/ci.yml", "on: push\n");
    const sha = r.commit();
    r.write(".github/workflows/ci.yml", "on: [push, pull_request]\n");
    r.write(".github/workflows/deploy.yml", "on: push\n");
    r.commit();
    const entry = (p) => parseAllowlist({ exemptions: [{ kind: "workflow-change", path: p, reason: "reviewed by the platform team" }] }).entries;
    assert.equal(entry("x").length, 1, "workflow-change is a kind the allowlist accepts");

    const one = judged(r, sha, { allowlist: entry(".github/workflows/ci.yml") });
    const f = one.failures.filter((x) => /edits the pipeline/.test(x));
    assert.equal(f.length, 1);
    assert.ok(f[0].includes("deploy.yml (added)") && !f[0].includes("ci.yml"), f[0]);

    const all = judged(r, sha, { allowlist: entry(".github/workflows") });
    assert.ok(!all.failures.some((x) => /edits the pipeline/.test(x)), all.failures.join("\n"));

    const otherKind = judged(r, sha, {
      allowlist: parseAllowlist({ exemptions: [{ kind: "skipped-location", path: ".github", reason: "r" }] }).entries,
    });
    assert.ok(otherKind.failures.some((x) => /edits the pipeline/.test(x)), "another kind does not approve a workflow change");
  } finally {
    r.done();
  }
});

test("a local action is the pipeline too: one the change edits or adds under .github/actions blocks", () => {
  const r = repo();
  try {
    r.write(".github/workflows/ci.yml", "on: push\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/gate\n");
    r.write(".github/actions/gate/action.yml", "runs:\n  using: composite\n  steps:\n    - run: npx wolfproof . --factory\n      shell: bash\n");
    const sha = r.commit();
    r.write(".github/actions/gate/action.yml", "runs:\n  using: composite\n  steps:\n    - run: exit 0\n      shell: bash\n");
    r.write(".github/actions/setup/action.yml", "runs:\n  using: composite\n  steps: []\n");
    r.commit();
    const j = judged(r, sha);
    const f = j.failures.filter((x) => /edits the pipeline/.test(x));
    assert.equal(f.length, 1, j.failures.join("\n"));
    assert.ok(f[0].includes(".github/actions/gate/action.yml (changed)") && f[0].includes(".github/actions/setup/action.yml (added)"), f[0]);
    assert.ok(!f[0].includes("ci.yml"), "the workflow itself was not touched");

    const approved = judged(r, sha, {
      allowlist: parseAllowlist({ exemptions: [{ kind: "workflow-change", path: ".github/actions", reason: "actions owned by the platform team" }] }).entries,
    });
    assert.ok(!approved.failures.some((x) => /edits the pipeline/.test(x)), approved.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("only .github/workflows and .github/actions are the pipeline: other .github files and unchanged ones do not block", () => {
  const r = repo();
  try {
    r.write(".github/workflows/ci.yml", "on: push\n");
    r.write(".github/dependabot.yml", "version: 2\n");
    const sha = r.commit();
    r.write(".github/dependabot.yml", "version: 2\nupdates: []\n");
    r.write(".github/CODEOWNERS", "* @someone\n");
    r.write(".github/workflows-notes.md", "not a workflow\n");
    r.write(".github/actions-notes.md", "not an action\n");
    r.write("src/a.js", "a");
    r.commit();
    const j = judged(r, sha);
    assert.deepEqual(j.workflows, []);
    assert.ok(!j.failures.some((x) => /edits the pipeline/.test(x)), j.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("a project in a subdirectory is still built by the root's workflows, and a change to them blocks", () => {
  const r = repo();
  try {
    r.write("services/api/src/a.js", "a");
    r.write(".github/workflows/ci.yml", "on: push\n");
    r.write("services/api/.github/workflows/ignored.yml", "on: push\n");
    const sha = r.commit();
    r.write(".github/workflows/ci.yml", "on: push\njobs: {}\n");
    r.write("services/api/.github/workflows/ignored.yml", "on: push\njobs: {}\n");
    r.commit();
    const project = path.join(r.dir, "services", "api");
    const base = materializeBase(project, sha);
    try {
      const j = judgeChange(project, { sha, baseDir: base.dir });
      assert.deepEqual(
        j.workflows.map((c) => c.path),
        [".github/workflows/ci.yml"],
        "paths from the repository root, and GitHub never runs a workflow outside it"
      );
      assert.ok(j.failures.some((x) => /edits the pipeline — \.github\/workflows\/ci\.yml \(changed\)/.test(x)), j.failures.join("\n"));
    } finally {
      base.cleanup();
    }
  } finally {
    r.done();
  }
});

const EXPRESS = 'const app = require("express")();\napp.post("/admin/purge", (req, res) => res.send("ok"));\napp.listen(3000);\n';
const serverInTest = (j) => j.failures.filter((f) => /builds an HTTP server, and .* from outside the tests/.test(f));

test("a server written straight into a test name blocks when something outside the tests runs it", () => {
  const cases = [
    ["a start script", { "server.test.js": EXPRESS, "package.json": '{"scripts":{"start":"node server.test.js"}}' }, "server.test.js", "package.json"],
    ["a Dockerfile", { "fixtures/app.js": EXPRESS, Dockerfile: 'FROM node:22\nCMD ["node", "fixtures/app.js"]\n' }, "fixtures/app.js", "Dockerfile"],
    ["an import from application code", { "src/api.test.js": EXPRESS, "src/index.js": 'require("./api.test");\n' }, "src/api.test.js", "src/index.js"],
    ["a Procfile", { "test_app.py": "from flask import Flask\napp = Flask(__name__)\n", Procfile: "web: gunicorn test_app:app\n" }, "test_app.py", "Procfile"],
  ];
  for (const [label, files, server, by] of cases) {
    const r = repo();
    try {
      r.write("README.md", "a service\n");
      const sha = r.commit();
      for (const [rel, text] of Object.entries(files)) r.write(rel, text);
      r.commit();
      const f = serverInTest(judged(r, sha));
      assert.equal(f.length, 1, `${label}: ${JSON.stringify(judged(r, sha).failures)}`);
      assert.ok(f[0].startsWith(`factory: ${server} builds an HTTP server, and ${by} refers to it`), `${label}: ${f[0]}`);
    } finally {
      r.done();
    }
  }
});

test("a server only the tests use is an ordinary test, not a finding", () => {
  const r = repo();
  try {
    r.write("src/app.js", "module.exports = 1;\n");
    const sha = r.commit();
    // An app built inline for supertest, a stub upstream in a fixtures directory, and every way the
    // tests themselves name them: the test script, a test runner config, a README, a workflow.
    r.write("app.test.js", EXPRESS);
    r.write("fixtures/upstream.js", 'const http = require("http");\nmodule.exports = () => http.createServer(() => {}).listen(0);\n');
    r.write("src/client.test.js", 'require("../fixtures/upstream")();\n');
    r.write("package.json", '{"scripts":{"test":"node --test app.test.js","test:unit":"node --test src/client.test.js"}}');
    r.write("jest.config.js", 'module.exports = { testMatch: ["app.test.js"] };\n');
    r.write("README.md", "Run `node app.test.js` to see the stub, and fixtures/upstream for the fake upstream.\n");
    r.write(".github/workflows/ci.yml", "jobs: { t: { steps: [ { run: node --test app.test.js } ] } }\n");
    r.commit();
    const j = judged(r, sha);
    assert.deepEqual(serverInTest(j), [], j.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("a server in a test name is judged only when the change wrote it, and the allowlist approves it", () => {
  const r = repo();
  try {
    r.write("server.test.js", EXPRESS);
    r.write("package.json", '{"scripts":{"start":"node server.test.js"}}');
    const sha = r.commit();
    r.write("src/other.js", "module.exports = 2;\n");
    r.commit();
    assert.deepEqual(serverInTest(judged(r, sha)), [], "it predates the change");

    r.write("server.test.js", EXPRESS + "// edited\n");
    r.commit();
    assert.equal(serverInTest(judged(r, sha)).length, 1, "an edit is code the change wrote");
    const approved = judged(r, sha, {
      allowlist: parseAllowlist({ exemptions: [{ kind: "server-in-test", path: "server.test.js", reason: "legacy entry point, owned by a person" }] }).entries,
    });
    assert.deepEqual(serverInTest(approved), []);
  } finally {
    r.done();
  }
});

test("a route exempt by name that the base did not have is named, not blocked", () => {
  const r = repo();
  try {
    r.write("src/server.js", "const app = require('express')();\napp.get('/status', async (req, res) => res.send('x'));\n");
    const sha = r.commit();
    r.write("src/server.js", "const app = require('express')();\napp.get('/health', async (req, res) => res.send('x'));\n");
    r.commit();
    const j = judged(r, sha);
    assert.deepEqual(j.newProbeRoutes.map((x) => `${x.method} ${x.route}`), ["GET /health"]);
    assert.ok(j.notes.some((n) => /GET \/health \(src\/server\.js:2\)/.test(n)), j.notes.join("\n"));
    assert.equal(j.failures.length, 0, j.failures.join("\n"));
  } finally {
    r.done();
  }
});

test("a write method moved onto a probe path is not an exemption at all", () => {
  // A probe reads: POST /health is checked like any route (agent/authentication.mjs probeExempt),
  // so it is a finding of the authentication check, not a probe for factory mode to name.
  const r = repo();
  try {
    r.write("src/server.js", "const app = require('express')();\napp.post('/admin/purge', async (req, res) => res.send('x'));\n");
    const sha = r.commit();
    r.write("src/server.js", "const app = require('express')();\napp.post('/health', async (req, res) => res.send('x'));\n");
    r.commit();
    assert.deepEqual(judged(r, sha).newProbeRoutes, []);
  } finally {
    r.done();
  }
});

test("locations the checks skip", () => {
  const allow = secretGuardAllowlist(null);
  assert.equal(uncheckedLocation("src/a.js", { gitleaksAllow: allow }), null);
  assert.match(uncheckedLocation("build/a.js", { gitleaksAllow: allow }).why, /every source check skips build\//);
  assert.match(uncheckedLocation("lib/vendor/a.js", { gitleaksAllow: allow }).why, /gitleaks allowlist/);
});

test("the gitleaks allowlist is read from the secret-guard that will run", () => {
  const entry = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "node_modules", "@tjwitko", "secret-guard-mcp", "index.mjs");
  const res = secretGuardAllowlist(entry).map((re) => re.source);
  assert.ok(res.some((s) => s.includes("vendor")), JSON.stringify(res));
});

// ---------------------------------------------------------------------------------------------
// the project's claims, and the pipeline's inputs

test("control overrides are found in both config names, and factory resolution ignores them", () => {
  const r = repo();
  try {
    r.write(".wolfproof.json", JSON.stringify({ controls: { "secret-guard": "./tools/sg.mjs" } }));
    r.write(".agent-gate.json", JSON.stringify({ controls: { "dep-audit": "./tools/da.mjs" } }));
    r.write("tools/sg.mjs", "");
    const o = declaredOverrides(r.dir);
    assert.deepEqual(o.map((x) => `${x.file} ${x.control}`).sort(), [".agent-gate.json dep-audit", ".wolfproof.json secret-guard"]);
    const config = { controls: { "secret-guard": "./tools/sg.mjs" } };
    const plain = resolveControls(r.dir, { config, env: {} }).find((c) => c.name === "secret-guard");
    assert.match(plain.source, /\.wolfproof\.json/);
    for (const c of resolveControls(r.dir, { config, env: {}, factory: true })) {
      assert.ok(!c.source || /^(env |node_modules )/.test(c.source), `${c.name} resolved from ${c.source} in factory mode`);
    }
  } finally {
    r.done();
  }
});

test("serving HTTP is read from code, not from tests or exempt directories", () => {
  const r = repo();
  try {
    r.write("lib/duration.js", "export const ms = (s) => s * 1000;\n");
    r.write("test/client.test.js", "const app = require('express')();\n");
    r.commit();
    assert.equal(servesHttp(r.dir), false);
    r.write("samples/.tfguard-fixture", "samples\n");
    r.write("samples/server.js", "const app = require('express')();\n");
    assert.equal(servesHttp(r.dir), false);
    r.write("src/server.js", "const app = require('express')();\n");
    assert.equal(servesHttp(r.dir), true);
  } finally {
    r.done();
  }
});

test("the allowlist and policy must exist, parse, and live outside the project", () => {
  const r = repo();
  const outside = mkdtempSync(path.join(tmpdir(), "factory-input-"));
  try {
    r.write("allow.json", "{}");
    assert.match(readPipelineInput(path.join(r.dir, "allow.json"), "allowlist", r.dir).error, /inside the project/);
    assert.match(readPipelineInput(path.join(outside, "nope.json"), "allowlist", r.dir).error, /does not exist/);
    writeFileSync(path.join(outside, "bad.json"), "{");
    assert.match(readPipelineInput(path.join(outside, "bad.json"), "policy", r.dir).error, /could not be parsed/);
    writeFileSync(path.join(outside, "ok.json"), '{"exemptions":[]}');
    assert.deepEqual(readPipelineInput(path.join(outside, "ok.json"), "allowlist", r.dir).value, { exemptions: [] });
  } finally {
    r.done();
    rmSync(outside, { recursive: true, force: true });
  }
});

test("an allowlist entry needs a known kind, a path and a reason", () => {
  const a = parseAllowlist({
    exemptions: [
      { kind: "fixture-marker", path: "./fixtures/", reason: "ok" },
      { kind: "fixture-marker", path: "x" },
      { kind: "made-up", path: "x", reason: "r" },
      { path: "x", reason: "r" },
    ],
  });
  assert.deepEqual(a.entries, [{ kind: "fixture-marker", path: "fixtures", reason: "ok" }]);
  assert.deepEqual(a.ignored.map((i) => i.why), ["gives no reason", 'unknown kind "made-up"', "needs a kind and a path"]);
});

test("requirements are read as they were at the base", () => {
  const r = repo();
  const outside = mkdtempSync(path.join(tmpdir(), "factory-req-"));
  try {
    r.write("task.txt", "Tokens must be rotatable.\n");
    const sha = r.commit();
    r.write("task.txt", "Build it.\n");
    const at = requirementAtBase(r.dir, sha, path.join(r.dir, "task.txt"));
    assert.equal(at.changed, true);
    assert.equal(at.text, "Tokens must be rotatable.\n");
    r.write("new-task.txt", "x");
    assert.equal(requirementAtBase(r.dir, sha, path.join(r.dir, "new-task.txt")).added, true);
    writeFileSync(path.join(outside, "t.txt"), "x");
    assert.equal(requirementAtBase(r.dir, sha, path.join(outside, "t.txt")).outside, true);
  } finally {
    r.done();
    rmSync(outside, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------------
// advisory classes

// One real message per class, so a class without an example -- or an example that drifts to a
// different class -- fails here. The messages are the gate's own wording.
const EXAMPLES = {
  "check-crashed": "sast: the check itself crashed and did not run — boom. This is a defect in the checking tool",
  "terraform-plan-unauthenticated": "terraform_plan(infra): the plan could not authenticate to the cloud provider, so NO plan-based security rule ran",
  "checkov-unavailable": "checkov (infra): did NOT run to completion (killed by SIGTERM). Nothing here was scanned by checkov",
  "iac-checkov-unavailable": "iac templates: checkov is not installed, so 2 CloudFormation template(s) were not scanned. Unknown, not clean.",
  "dockerfile-checkov-unavailable": "dockerfile: checkov is not installed, so 1 Dockerfile(s) were checked for end-of-life base images only",
  "workload-identity-unparseable": "workload identity: check_auth_posture returned output that could not be parsed, so nothing was established",
  "tests-not-executed": "tests: NOT EXECUTED — package.json declares no test runner and no runnable JavaScript tests were found. Test files existing",
  "auth-no-routes": "authentication: no HTTP routes were identified, so nothing was checked. If this service exposes endpoints",
  "auth-only-probes": "authentication: the only routes identified are exempt by name, so nothing was checked — GET /healthz",
  "retention-not-checked": "retention: NOT CHECKED — no Terraform configuration, so where these records live is not described. The task requires",
  "retention-undetermined": "retention: S3 lifecycle on \"logs\" — expiration set from var.days, so whether it satisfies the 7 year(s) the task requires could not be established here.",
  "rotation-unverifiable": "secret rotation: the task says a secret rotates, but nothing here reads a secret from a managed store — a secret",
  "dockerfile-unresolved-base": "dockerfile: 1 base image(s) named through a variable with no default could not be judged for end of life — Dockerfile:1",
  "manifest-contract-opaque": "manifest contract: envFrom pulls configmap/app, whose keys are not in the manifests, so the contract cannot be checked here",
  "sast-unparsed": "sast: 2 file(s) could not be fully parsed, so parts of them were not checked — a.js, b.js.",
  "deps-unlocked": "check_dependencies: 3 finding(s) at or above high severity — NOT BLOCKING: no lockfile",
  sast: "sast: SQL built from a value of unknown origin (sql-string-built, not blocking): db.go:10.",
  checkov: "checkov (infra): 4 finding(s) in your own configuration — advisory, not blocking.",
  "checkov-summary": "checkov (terraform): 0 finding(s) in your own configuration — advisory, not blocking. 94 check(s) ran against 40 resource(s), covering 9 of 13 .tf file(s) here; a file declaring no resources checkov has a policy for is not a gap. No files failed to parse.",
  "iac-checkov-summary": "iac templates (CloudFormation): checkov reports 0 finding(s), not blocking.",
  "iac-checkov": "iac templates (CloudFormation): checkov reports 2 finding(s), not blocking",
  "dockerfile-checkov": "dockerfile: checkov reports 2 finding(s) — not blocking. ",
  "workload-identity-heuristic": "workload identity: 1 heuristic finding(s) — k8s/d.yaml: looks like a static credential",
  "iam-unverifiable-policy": "iam: 1 attached AWS managed policy ARN(s) are not in this check's list",
  "iam-irsa-unmatched": "iam: 1 IRSA annotation(s) name a role this project does not define — k8s/sa.yaml",
  "resource-census": "resource census (infra): these resources were declared earlier in this run and are now gone: aws_s3_bucket.a.",
  "retention-backup-only": "retention: aws_backup_plan.x is set, and it is not record retention. ",
  "retention-shorter": "retention: CloudWatch log group \"app\" — 30 days, which is shorter than the 1 year(s) the task requires. ",
  "retention-governance-lock": "retention: Object Lock on \"audit\" is in GOVERNANCE mode",
  "retention-kms-deletable": "retention: KMS key(s) \"k\" have no deletion protection",
  "code-quality-detached-tests": "code quality: 1 of 3 test file(s) import nothing from this project — t.test.js.",
  "rotation-cache": "secret rotation: a secret is fetched once and cached with nothing that can ever re-read it — a.js:3.",
  "auth-probes-listed": "authentication: 1 route(s) exempt by name, not checked — GET /healthz (src/server.js:6, probe).",
  "auth-no-source": "authentication: not checked — no source files in a language this check recognises (Python, JavaScript)",
  "immutability-not-required": "immutability: no append-only store could be identified, so nothing was checked.",
  "k8s-none": "kubernetes manifests: not checked — no Kubernetes manifests found, in YAML or in Terraform",
  "manifest-contract-no-workload": "manifest contract: the code requires 2 environment variable(s) and no Kubernetes workload was found to supply them",
  "retention-not-required": "retention: not checked — the task states no retention period",
  "retention-satisfied": "retention: nothing here deletes the records — no TTL, no lifecycle expiration, no log retention — so",
  "rotation-not-checked": "secret rotation: not checked — no source files to read",
  "code-quality-info": "code quality: 3 test file(s) found and read — a.test.js. This is what is in the files",
  "artifact-presence-not-checked": "artifact presence: not checked — no files in the project",
  "tests-ran": "tests: ran under node --test — 19 of 19 passed.",
  "workload-identity-allowances": "workload identity: 1 finding(s) were opted out of in the manifests, not fixed — k8s/d.yaml: IG001 (\"x\")",
  "workload-identity-refused-allowance": "workload identity: an opt-out in k8s/d.yaml names IG001 and gives no reason, so it had no effect.",
  "task-file-unstaged": "task file: task.txt has changes that are not part of this commit. The gate checked against the version being committed.",
  "baseline-inside-project": "baseline: req.txt is inside the project, so whoever writes the code can edit it.",
  "config-note": "config: .agent-gate.json is ignored: .wolfproof.json is read instead. Delete the old one.",
  settings: "settings: AGENT_GATE_TODAY is set and no longer read since v1.3.0; set WOLFPROOF_TODAY instead.",
};

// checkov's coverage summary is emitted when it found nothing. Classed as a finding, a policy that
// blocks checkov findings blocked every Terraform project where checkov found none -- measured on
// the corpus fixture webhook-claude with {checkov: "block"}.
test("checkov finding nothing is information, whatever the policy says about its findings", () => {
  const policy = { advisories: { checkov: "block", "iac-checkov": "block", finding: "block" } };
  for (const id of ["checkov-summary", "iac-checkov-summary"]) {
    const c = classifyAdvisory(EXAMPLES[id], { servesHttp: true, couldNotRun: [] });
    assert.equal(c.class, INFO, id);
    assert.equal(actionFor(c, policy), "drop", id);
  }
  assert.equal(actionFor(classifyAdvisory(EXAMPLES.checkov, { servesHttp: true, couldNotRun: [] }), policy), "block", "a real finding still follows the policy");
});

test("every advisory class has an example, and each example lands in its own class", () => {
  for (const c of ADVISORY_CLASSES) {
    assert.ok(c.id in EXAMPLES, `no example for ${c.id}`);
    const got = classifyAdvisory(EXAMPLES[c.id], { servesHttp: true, couldNotRun: [] });
    assert.equal(got.id.split(":")[0], c.id, `${JSON.stringify(EXAMPLES[c.id])} classified as ${got.id}, not ${c.id}`);
  }
});

test("the classes that decide most: nothing-checked blocks, could-not-run is incomplete, findings drop, info drops", () => {
  const ctx = { servesHttp: true, couldNotRun: [] };
  const act = (id) => actionFor(classifyAdvisory(EXAMPLES[id], ctx));
  assert.equal(act("auth-no-routes"), "block");
  assert.equal(act("retention-not-checked"), "block");
  assert.equal(act("terraform-plan-unauthenticated"), "incomplete");
  assert.equal(act("sast"), "drop");
  assert.equal(act("tests-ran"), "drop");
});

test("no routes in a project that serves nothing is a fact, not a gap", () => {
  assert.equal(classifyAdvisory(EXAMPLES["auth-no-routes"], { servesHttp: false }).class, INFO);
  assert.equal(classifyAdvisory(EXAMPLES["auth-no-routes"], { servesHttp: true }).class, NOT_CHECKED);
});

test("a suite that could not start is the machine's when the tests check said so, and the project's otherwise", () => {
  const why = "node is not installed";
  const text = `tests: NOT EXECUTED — ${why}. Test files existing is not evidence`;
  assert.equal(classifyAdvisory(text, { couldNotRun: [`tests: ${why}`] }).class, COULD_NOT_RUN);
  assert.equal(classifyAdvisory(text, { couldNotRun: [] }).class, NOT_CHECKED);
});

test("an advisory nobody classified blocks, whatever the policy says about classes", () => {
  const c = classifyAdvisory("frobnicate: something new happened");
  assert.equal(c.unclassified, true);
  assert.equal(actionFor(c, { advisories: { "not-checked": "drop" } }), "block");
});

test("the policy is read most specific first: id, then family, then class", () => {
  const sql = classifyAdvisory(EXAMPLES.sast);
  assert.equal(sql.id, "sast:sql-string-built");
  assert.equal(sql.class, FINDING);
  assert.equal(actionFor(sql, {}), "drop");
  assert.equal(actionFor(sql, { advisories: { finding: "block" } }), "block");
  assert.equal(actionFor(sql, { advisories: { finding: "block", sast: "drop" } }), "drop");
  assert.equal(actionFor(sql, { advisories: { sast: "drop", "sast:sql-string-built": "block" } }), "block");
});
