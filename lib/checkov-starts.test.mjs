// The three checks that run checkov (Dockerfiles, CloudFormation/ARM/Bicep templates, Terraform) each
// start it once, for the scan. Until this file they asked `checkov --version` first and read any
// failure of that as "not installed" (candidate-rules §18, the 2026-11-11 addendum, item 3).
//
// checkov here is a stand-in: a shell script on a PATH that holds node and nothing else. It appends
// its arguments to a file and then does what the test says, so every case runs the same on a machine
// with checkov and on one without. For an install the system cannot start, the stand-in is a file
// whose #! line names an interpreter that is not there, or a link to nothing.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import path from "path";

import { actionFor, classifyAdvisory, COULD_NOT_RUN, INFO } from "./advisory-classes.mjs";

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

const GONE = "/opt/gone/venv/bin/python3";

/**
 * What one check reports, and how checkov was started. `script` is checkov: a shell script's body,
 * null for no checkov, { file } for a file with exactly that content, { link } for a link to that
 * target. `ahead` is the same, for a second checkov in a directory earlier on PATH.
 */
function run(name, script, ahead = null) {
  const check = CHECKS[name];
  const bin = mkdtempSync(path.join(tmpdir(), "checkov-bin-"));
  const first = mkdtempSync(path.join(tmpdir(), "checkov-ahead-"));
  const dir = mkdtempSync(path.join(tmpdir(), "checkov-project-"));
  try {
    symlinkSync(process.execPath, path.join(bin, "node"));
    const calls = path.join(bin, "calls");
    const place = (where, what) => {
      const file = path.join(where, "checkov");
      if (what === null) return;
      if (typeof what === "string") writeFileSync(file, `#!/bin/sh\necho "$*" >> '${calls}'\n${what}\n`, { mode: 0o755 });
      else if (what.link) symlinkSync(what.link, file);
      else writeFileSync(file, what.file, { mode: 0o755 });
    };
    place(bin, script);
    place(first, ahead);
    for (const [rel, body] of Object.entries(check.files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), body);
    }
    const r = spawnSync(path.join(bin, "node"), ["--input-type=module", "-e", `console.log(JSON.stringify(${check.call(dir)}));`], {
      encoding: "utf8",
      env: { PATH: [first, bin].join(path.delimiter), WOLFPROOF_TODAY: "2026-10-13" },
    });
    assert.equal(r.status, 0, r.stderr);
    return {
      advisories: JSON.parse(r.stdout).filter((a) => a !== null),
      starts: existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n") : [],
    };
  } finally {
    rmSync(bin, { recursive: true, force: true });
    rmSync(first, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  }
}

const couldNotRun = (advisory) => classifyAdvisory(advisory, { servesHttp: false, couldNotRun: [] }).class === COULD_NOT_RUN;

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

// For Terraform checkov is optional (the README's table), and until this test its absence was not
// reported by this check at all, with the probe or without it. The toolchain report does not say it
// where a reader looks: it is in --json and --version only, and its null covers a checkov that ran
// and exited non-zero too. So the check says it, in a line that is information: no verdict moves on
// it in either mode, and a policy that blocks checkov's findings does not reach it.
test("with no checkov, the Terraform check says so in one line that is information, not could-not-run", () => {
  const r = run("terraform", null);
  assert.deepEqual(r, {
    advisories: ["checkov: not installed, so its rules did not run over the Terraform here (.). checkov is optional for Terraform, and what it finds there is advisory."],
    starts: [],
  });
  const c = classifyAdvisory(r.advisories[0], { servesHttp: false, couldNotRun: [] });
  assert.equal(c.id, "checkov-absent");
  assert.equal(c.class, INFO);
  assert.equal(actionFor(c), "drop");
  assert.equal(actionFor(c, { advisories: { checkov: "block", finding: "block", "could-not-run": "block" } }), "drop");
  // Its own id, so a pipeline that requires checkov on Terraform can say so.
  assert.equal(actionFor(c, { advisories: { "checkov-absent": "incomplete" } }), "incomplete");
});

// The gate says it once for all its Terraform roots: the reason is the same for each of them.
test("the no-checkov line names every Terraform root in one line, and is the same class", async () => {
  const { checkovAbsentLine } = await import("./gate-core.mjs");
  // A directory's name is the project's own, brackets and all. It must not stop the line being read:
  // an advisory factory mode cannot classify blocks, and this one moves no verdict.
  const line = checkovAbsentLine(["infra", "modules/net (prod)", "a): 3 finding(s) in your own configuration", "."]);
  assert.equal(line, "checkov: not installed, so its rules did not run over the Terraform here (infra, modules/net (prod), a): 3 finding(s) in your own configuration, .). checkov is optional for Terraform, and what it finds there is advisory.");
  const c = classifyAdvisory(line, { servesHttp: false, couldNotRun: [] });
  assert.deepEqual([c.id, c.class, c.unclassified], ["checkov-absent", INFO, undefined]);
});

// A start fails with ENOENT when nothing on PATH is named checkov, and also when something is and the
// system cannot start it: a script whose #! line names a Python that is gone (a pipx or venv install
// after a Python upgrade), or a link whose target is gone. All three checks read the second as the
// first: "not installed" for a Dockerfile and a template, nothing for Terraform and exit 0 in
// factory mode. They are told apart by looking on PATH, and nothing is started to do it.
test("a checkov on PATH that the system cannot start is did-not-run, naming the file and why, not 'not installed'", () => {
  const over = {
    dockerfile: /^dockerfile: checkov did NOT run to completion over the Dockerfiles \(/,
    "iac templates": /^iac templates: checkov did NOT run to completion over 1 CloudFormation template\(s\) \(/,
    terraform: /^checkov \(\.\): did NOT run to completion \(/,
  };
  const cases = [
    [{ file: `#!${GONE}\nimport checkov\n` }, /\(\S+\/checkov is on PATH and could not be started: its #! line names \/opt\/gone\/venv\/bin\/python3, which does not exist\)/],
    [{ link: "/opt/gone/venv/bin/checkov" }, /\(\S+\/checkov is on PATH and could not be started: it is a link to \/opt\/gone\/venv\/bin\/checkov, which does not exist\)/],
  ];
  for (const [checkov, why] of cases) {
    for (const name of Object.keys(CHECKS)) {
      const r = run(name, checkov);
      const said = r.advisories.filter((a) => /checkov/.test(a));
      assert.equal(said.length, 1, `${name}: ${r.advisories.join("\n")}`);
      assert.match(said[0], over[name]);
      assert.match(said[0], why);
      assert.doesNotMatch(said[0], /not installed/);
      assert.ok(couldNotRun(said[0]), said[0]);
      assert.deepEqual(r.starts, [], name);
    }
  }
});

// What the PATH lookup rests on: the system tries every checkov on PATH before it gives ENOENT, so
// ENOENT with a checkov there means none of them could be started, and a working one further along
// is the one that runs.
test("a checkov that cannot start, ahead of one that can: the second runs and nothing is reported about the first", () => {
  for (const [name, check] of Object.entries(CHECKS)) {
    const r = run(name, `printf '%s' '${check.report}'`, { file: `#!${GONE}\n` });
    assert.equal(r.starts.length, 1, name);
    assert.ok(r.advisories.every((a) => !/not installed|did NOT run|could not be started/.test(a)), `${name}: ${r.advisories.join("\n")}`);
  }
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
