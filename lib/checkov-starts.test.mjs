// The three checks that run checkov (Dockerfiles, CloudFormation/ARM/Bicep templates, Terraform) each
// start it once, for the scan. Until this file they asked `checkov --version` first and read any
// failure of that as "not installed" (candidate-rules §18, the 2026-11-11 addendum, item 3).
//
// checkov here is a stand-in: a shell script on a PATH that holds node and nothing else. It appends
// its arguments to a file and then does what the test says, so every case runs the same on a machine
// with checkov and on one without.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { classifyAdvisory, COULD_NOT_RUN } from "./advisory-classes.mjs";

const here = (rel) => JSON.stringify(new URL(rel, import.meta.url).href);
const CHECKS = {
  dockerfile: {
    files: { Dockerfile: "FROM node:24-alpine\nCOPY . .\n" },
    call: (dir) => `(await import(${here("../agent/dockerfile.mjs")})).dockerfileFailures(${JSON.stringify(dir)}).advisories`,
    scan: /^--framework dockerfile --compact -o json -f \S+Dockerfile$/,
    report: '{"check_type":"dockerfile","results":{"failed_checks":[]},"summary":{}}',
  },
  "iac templates": {
    files: { "stack.yaml": 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n' },
    call: (dir) => `(await import(${here("../agent/iac-templates.mjs")})).iacTemplateAdvisories(${JSON.stringify(dir)}).advisories`,
    scan: /^--framework cloudformation --compact -o json -f \S+stack\.yaml$/,
    report: '{"check_type":"cloudformation","results":{"failed_checks":[]},"summary":{"parsing_errors":0}}',
  },
  terraform: {
    files: { "main.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n' },
    call: (dir) => `[(await import(${here("./gate-core.mjs")})).checkovAdvisory(${JSON.stringify(dir)}, ${JSON.stringify(dir)})]`,
    scan: /^-d \S+ --framework terraform --download-external-modules true --compact -o json$/,
    report: '{"check_type":"terraform","results":{"passed_checks":[{"file_path":"/main.tf"}],"failed_checks":[]},"summary":{"resource_count":1,"parsing_errors":0}}',
  },
};

/** What one check reports, and how checkov was started, with `script` as checkov (null: no checkov). */
function run(name, script) {
  const check = CHECKS[name];
  const bin = mkdtempSync(path.join(tmpdir(), "checkov-bin-"));
  const dir = mkdtempSync(path.join(tmpdir(), "checkov-project-"));
  try {
    symlinkSync(process.execPath, path.join(bin, "node"));
    const calls = path.join(bin, "calls");
    if (script !== null) writeFileSync(path.join(bin, "checkov"), `#!/bin/sh\necho "$*" >> '${calls}'\n${script}\n`, { mode: 0o755 });
    for (const [rel, body] of Object.entries(check.files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), body);
    }
    const r = spawnSync(path.join(bin, "node"), ["--input-type=module", "-e", `console.log(JSON.stringify(${check.call(dir)}));`], {
      encoding: "utf8",
      env: { PATH: bin, WOLFPROOF_TODAY: "2026-10-13" },
    });
    assert.equal(r.status, 0, r.stderr);
    return {
      advisories: JSON.parse(r.stdout).filter((a) => a !== null),
      starts: existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n") : [],
    };
  } finally {
    rmSync(bin, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  }
}

// The Terraform check's lines are labelled with the root, "." here, and factory mode reads that label
// against the roots the gate scanned (lib/advisory-classes.mjs).
const couldNotRun = (advisory) => classifyAdvisory(advisory, { servesHttp: false, couldNotRun: [], terraformRoots: ["."] }).class === COULD_NOT_RUN;

test("checkov is started once by each check, for the scan, and never to ask its version", () => {
  for (const [name, check] of Object.entries(CHECKS)) {
    const r = run(name, `printf '%s' '${check.report}'`);
    assert.equal(r.starts.length, 1, `${name}: ${r.starts.join(" | ")}`);
    assert.match(r.starts[0], check.scan, name);
    assert.ok(r.advisories.every((a) => !/not installed|did NOT run|no output|could not be parsed/.test(a)), `${name}: ${r.advisories.join("\n")}`);
  }
  // The scan was read, not just started: Terraform's summary comes from the stand-in's report.
  assert.match(run("terraform", `printf '%s' '${CHECKS.terraform.report}'`).advisories[0], /^checkov \(\.\): 0 finding\(s\) in your own configuration .* 1 check\(s\) ran against 1 resource\(s\), covering 1 of 1 \.tf file/);
});

test("with no checkov, a Dockerfile and a template are reported as not scanned, and could-not-run", () => {
  const docker = run("dockerfile", null);
  assert.match(docker.advisories.join("\n"), /^dockerfile: checkov is not installed, so 1 Dockerfile\(s\) were checked for end-of-life base images only/m);
  const iac = run("iac templates", null);
  assert.deepEqual(iac.advisories, ["iac templates: checkov is not installed, so 1 CloudFormation template(s) were not scanned. Unknown, not clean."]);
  for (const a of [docker.advisories.find((x) => /checkov/.test(x)), iac.advisories[0]]) assert.ok(couldNotRun(a), a);
});

// Recorded so that changing it is a decision. For Terraform checkov is optional (the README's table),
// and its absence has never been reported by this check, with the probe or without it. The toolchain
// report is where a run says checkov was not there.
test("with no checkov, the Terraform check reports nothing, as it did with the probe", () => {
  assert.deepEqual(run("terraform", null), { advisories: [], starts: [] });
});

// The probe read every failure of `checkov --version` as absence: an install whose Python had lost
// the module said "not installed" for a Dockerfile, and nothing at all for Terraform.
test("a checkov that is there and cannot run is did-not-run with its exit, not 'not installed'", () => {
  const broken = "echo 'ModuleNotFoundError: No module named checkov' >&2\nexit 1";
  const expected = {
    dockerfile: /^dockerfile: checkov did NOT run to completion over the Dockerfiles \(exit 1, no output\)\. Its rules are unknown here, not clean\.$/,
    "iac templates": /^iac templates: checkov did NOT run to completion over 1 CloudFormation template\(s\) \(exit 1, no output\)\. Unknown, not clean\.$/,
    terraform: /^checkov \(\.\): produced no output \(exit 1\)\. ModuleNotFoundError: No module named checkov Nothing here was scanned by checkov/,
  };
  for (const name of Object.keys(CHECKS)) {
    const r = run(name, broken);
    const said = r.advisories.filter((a) => /checkov/.test(a));
    assert.equal(said.length, 1, `${name}: ${r.advisories.join("\n")}`);
    assert.match(said[0], expected[name]);
    assert.ok(couldNotRun(said[0]), said[0]);
    assert.equal(r.starts.length, 1, name);
  }
});

test("output that is not a report is could-not-run for all three, the Dockerfile's included", () => {
  for (const name of Object.keys(CHECKS)) {
    const said = run(name, "echo 'Usage: checkov [options]'").advisories.filter((a) => /checkov/.test(a));
    assert.equal(said.length, 1, name);
    assert.match(said[0], /could not be parsed/);
    assert.ok(couldNotRun(said[0]), said[0]);
  }
});
