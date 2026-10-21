import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { validateProject } from "./agent-loop.mjs";
import { scanRootProblem } from "../lib/gate-core.mjs";

// A scan pointed at the wrong tree is the failure this covers. It happened for real: the runner set
// SECRETGUARD_WORKING_ROOT, secret-guard reads SCAN_ROOT, an unrecognised variable is not an error,
// and the server fell back to the caller's cwd and scanned an entire monorepo. Sixteen credentials
// belonging to sibling repos were reported as blocking findings in a project that had none. The
// same misconfiguration pointed at a directory that happens to be clean would have reported a pass.
function registryReturning(payload) {
  return new Map([
    ["scan_path", { kind: "mcp", server: { call: async () => JSON.stringify(payload) } }],
  ]);
}

// Awaited. It returned fn's promise from inside try/finally, so the directory was deleted before any
// test body ran and every test here judged a project that no longer existed -- which went unnoticed
// until a test needed the project to be there.
// No source file: what these tests judge is where a control looked, and a JavaScript file here ran
// semgrep on every validateProject call -- 36 runs and 101s of CPU, the most of any file in the suite.
async function inEmptyProject(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "scanroot-"));
  writeFileSync(path.join(dir, "README.md"), "a project\n");
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const scanFailures = (r) => r.failures.filter((f) => f.includes("scan_path"));

test("a scan of a different directory is reported as unperformed, not as findings", async () => {
  await inEmptyProject(async (dir) => {
    const r = await validateProject(
      dir,
      registryReturning({ clean: false, target: path.dirname(dir), summary: { total: 16 } }),
      ""
    );
    const hit = scanFailures(r);
    assert.equal(hit.length, 1);
    assert.match(hit[0], /did NOT run against this project/);
    assert.doesNotMatch(hit[0], /16 hardcoded/); // the count is not this project's to answer for
  });
});

test("a CLEAN scan of a different directory is not accepted as a pass", async () => {
  await inEmptyProject(async (dir) => {
    const r = await validateProject(
      dir,
      registryReturning({ clean: true, target: path.dirname(dir), summary: { total: 0 } }),
      ""
    );
    assert.equal(scanFailures(r).length, 1);
  });
});

// This was accepted until v1.4.0, and that is how test/fixtures/factory-scenario.mjs reached exit 0: a
// .wolfproof.json pointed secret-guard at an empty subdirectory, and its clean scan passed as the
// project's. The gate asks for the root; part of the tree says nothing about the rest of it.
test("a CLEAN scan of a subdirectory of the project is not accepted as a scan of the project", async () => {
  await inEmptyProject(async (dir) => {
    const r = await validateProject(
      dir,
      registryReturning({ clean: true, target: path.join(dir, "tools", ".scan-root-x"), summary: { total: 0 } }),
      ""
    );
    const hit = scanFailures(r);
    assert.equal(hit.length, 1);
    assert.match(hit[0], /which is only tools\/\.scan-root-x, part of this project/);
    assert.match(hit[0], /did NOT run against this project/);
  });
});

// Compared as strings, a project in macOS's temp directory is /var/... to the gate and /private/var/...
// to anything that resolved it: the same scan was foreign on macOS and accepted on Linux. Here the
// project is reached through a symlink and the control reports the real path, which is the root.
test("the root reached through a symlink is the root", async () => {
  await inEmptyProject(async (dir) => {
    const link = path.join(mkdtempSync(path.join(tmpdir(), "scanroot-link-")), "project");
    symlinkSync(dir, link);
    try {
      const r = await validateProject(link, registryReturning({ clean: true, target: realpathSync(dir), summary: { total: 0 } }), "");
      assert.equal(scanFailures(r).length, 0, JSON.stringify(scanFailures(r)));
      // The other spellings through the same helper the gate calls, without another full run each.
      assert.equal(scanRootProblem(link, realpathSync(dir)), null);
      assert.match(scanRootProblem(path.join(realpathSync(dir), "src"), link).what, /^only src, part of this project/);
    } finally {
      rmSync(path.dirname(link), { recursive: true, force: true });
    }
  });
});

test("check_auth_posture is held to the same rule: the root, and nothing narrower", async () => {
  await inEmptyProject(async (dir) => {
    const posture = (root) =>
      new Map([["check_auth_posture", { kind: "mcp", server: { call: async () => JSON.stringify({ root, findings: [] }) } }]]);
    const hits = (r) => r.failures.filter((f) => f.startsWith("check_auth_posture"));
    const sub = hits(await validateProject(dir, posture(path.join(dir, "k8s")), ""));
    assert.equal(sub.length, 1);
    assert.match(sub[0], /which is only k8s, part of this project .* did NOT run against this project/);
  });
});

test("scanRootProblem: the root itself, and nothing else", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "scanroot-unit-"));
  try {
    assert.equal(scanRootProblem(dir, dir), null);
    assert.equal(scanRootProblem(null, dir), null, "a control that reports no root is judged by its caller: could-not-run");
    assert.match(scanRootProblem(path.join(dir, "a", "b"), dir).what, /^only a\/b, part of this project/);
    assert.match(scanRootProblem(path.dirname(dir), dir).what, /^not this project/);
    assert.match(scanRootProblem(`${dir}-sibling`, dir).what, /^not this project/, "a sibling sharing the prefix is not inside");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("real findings in the project itself still block", async () => {
  await inEmptyProject(async (dir) => {
    const r = await validateProject(
      dir,
      registryReturning({ clean: false, target: dir, summary: { total: 2 } }),
      ""
    );
    const hit = scanFailures(r);
    assert.equal(hit.length, 1);
    assert.match(hit[0], /2 hardcoded credential/);
  });
});

// The dependency scan, held to the same rule. dep-audit has reported its root as `directory` since its
// first release; the gate did not read it, so a scan of an empty directory passed as the project's.
function depAuditReturning(payload) {
  return new Map([
    ["check_dependencies", { kind: "mcp", server: { call: async () => JSON.stringify(payload) } }],
  ]);
}

async function inNodeProject(fn) {
  return inEmptyProject(async (dir) => {
    writeFileSync(path.join(dir, "package.json"), '{"name":"p","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}\n');
    writeFileSync(path.join(dir, "package-lock.json"), '{"name":"p","lockfileVersion":3,"packages":{}}\n');
    return fn(dir);
  });
}

const depFailures = (r) => r.failures.filter((f) => f.startsWith("check_dependencies"));
const FINDING = { package: "lodash", version: "4.17.4", severity: "CRITICAL", id: "GHSA-x" };

test("a dependency scan of a different directory or a subdirectory is unperformed, findings or not", async () => {
  await inNodeProject(async (dir) => {
    for (const [scanned, what] of [
      [path.dirname(dir), /which is not this project/],
      [path.join(dir, ".scan-root-x"), /which is only \.scan-root-x, part of this project/],
    ]) {
      for (const findings of [[], [FINDING]]) {
        const r = await validateProject(dir, depAuditReturning({ directory: scanned, scanned: true, findings }), "");
        const hit = depFailures(r);
        assert.equal(hit.length, 1, JSON.stringify(r.failures));
        assert.match(hit[0], what);
        assert.match(hit[0], /The dependency scan did NOT run against this project/);
        assert.doesNotMatch(hit[0], /finding\(s\) at or above/, "its findings are not this project's to answer for");
      }
    }
  });
});

test("a dependency scan that does not say where it looked could not be judged", async () => {
  await inNodeProject(async (dir) => {
    const r = await validateProject(dir, depAuditReturning({ scanned: true, findings: [] }), "");
    assert.deepEqual(depFailures(r), []);
    assert.ok(
      r.couldNotRun.some((c) => /^check_dependencies: dep-audit's result does not say which directory it scanned/.test(c)),
      JSON.stringify(r.couldNotRun)
    );
  });
});

test("a dependency scan of the root is judged as before: clean passes, findings block", async () => {
  await inNodeProject(async (dir) => {
    const clean = await validateProject(dir, depAuditReturning({ directory: realpathSync(dir), scanned: true, findings: [] }), "");
    assert.deepEqual(depFailures(clean), []);
    assert.ok(!clean.couldNotRun.some((c) => c.startsWith("check_dependencies")), JSON.stringify(clean.couldNotRun));
    const found = await validateProject(dir, depAuditReturning({ directory: dir, scanned: true, findings: [FINDING] }), "");
    assert.equal(depFailures(found).length, 1);
    assert.match(depFailures(found)[0], /^check_dependencies: 1 finding\(s\) at or above high severity/);
  });
});

// Every release of secret-guard and identity-guard reports where it looked. A result that does not is
// not one of theirs, or not one about this project: the redirect that hid four CVEs from the dependency
// scan works as well with a wrapper that drops the field as with one that reports a subdirectory.
test("a secret scan or workload-identity scan that does not say where it looked could not be judged", async () => {
  await inEmptyProject(async (dir) => {
    for (const findings of [0, 3]) {
      const r = await validateProject(dir, registryReturning({ clean: findings === 0, summary: { total: findings } }), "");
      assert.deepEqual(scanFailures(r), [], "neither a pass nor this project's findings");
      assert.ok(r.couldNotRun.some((c) => /^scan_path: secret-guard's result does not say what it scanned/.test(c)), JSON.stringify(r.couldNotRun));
    }
    const posture = new Map([["check_auth_posture", { kind: "mcp", server: { call: async () => JSON.stringify({ clean: true, findings: [] }) } }]]);
    const r = await validateProject(dir, posture, "");
    assert.deepEqual(r.failures.filter((f) => f.startsWith("check_auth_posture") || f.startsWith("workload identity")), []);
    assert.ok(r.couldNotRun.some((c) => /^check_auth_posture: identity-guard's result does not say which directory it scanned/.test(c)), JSON.stringify(r.couldNotRun));
  });
});

test("a workload-identity scan of the root is judged as before", async () => {
  await inEmptyProject(async (dir) => {
    const posture = (payload) => new Map([["check_auth_posture", { kind: "mcp", server: { call: async () => JSON.stringify(payload) } }]]);
    const clean = await validateProject(dir, posture({ root: dir, clean: true, findings: [] }), "");
    assert.ok(!clean.couldNotRun.some((c) => c.startsWith("check_auth_posture")), JSON.stringify(clean.couldNotRun));
    const found = await validateProject(dir, posture({ root: dir, clean: false, findings: [{ file: "k8s/app.yaml", message: "a static key", severity: "high" }] }), "");
    assert.ok(found.failures.some((f) => f === "workload identity: k8s/app.yaml: a static key"), JSON.stringify(found.failures));
  });
});
