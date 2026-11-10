import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import { checkK8sManifests, k8sManifestFailures } from "./k8s-manifest.mjs";

function run(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "k8s-"));
  for (const [rel, contents] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents);
  }
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const APP_WITH_HEALTH = '@app.get("/health")\ndef health():\n    return {"status": "ok"}\n';

function deployment({ resourcesAtPodLevel = false, probe = false, annotation = null } = {}) {
  const container =
    '      - name: receiver\n' +
    '        image: repo/img:latest\n' +
    '        ports:\n        - containerPort: 8000\n' +
    (probe
      ? '        readinessProbe:\n          httpGet:\n            path: /health\n            port: 8000\n'
      : "") +
    (resourcesAtPodLevel ? "" : '        resources:\n          requests:\n            cpu: "100m"\n');
  return (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: webhook-receiver\nspec:\n" +
    "  template:\n" +
    (annotation ? `    metadata:\n      annotations:\n        role-arn: ${annotation}\n` : "") +
    "    spec:\n      containers:\n" +
    container +
    (resourcesAtPodLevel ? '      resources:\n        requests:\n          cpu: "100m"\n' : "")
  );
}

test("a container field on the pod spec fails — the object would be rejected outright", () => {
  const { failures } = run(
    { "k8s/deployment.yaml": deployment({ resourcesAtPodLevel: true, probe: true }), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /"resources" on the pod spec/);
  assert.match(failures[0], /does\s+not deploy at all/);
});

test("the same field inside the container is clean", () => {
  const { failures } = run(
    { "k8s/deployment.yaml": deployment({ probe: true }), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.deepEqual(failures, []);
});

test("${...} interpolation fails — Kubernetes never expands it", () => {
  const { failures } = run(
    {
      "k8s/deployment.yaml": deployment({ probe: true, annotation: "arn:aws:iam::${var.account_id}:role/app" }),
      "app/main.py": APP_WITH_HEALTH,
    },
    k8sManifestFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /never expands/);
});

// Kubernetes DOES substitute $(VAR) in container env and command. Flagging it would be a false
// positive on the one interpolation form that actually works.
test("$(VAR) is left alone", () => {
  const yaml =
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  template:\n    spec:\n" +
    "      containers:\n      - name: c\n        image: i\n        env:\n" +
    "        - name: URL\n          value: http://$(HOST):8080\n" +
    "        readinessProbe:\n          httpGet:\n            path: /health\n            port: 8000\n";
  const { failures } = run({ "k8s/d.yaml": yaml, "app/main.py": APP_WITH_HEALTH }, k8sManifestFailures);
  assert.deepEqual(failures, []);
});

test("a health endpoint with no probe wired to it fails", () => {
  const { failures } = run(
    { "k8s/deployment.yaml": deployment({ probe: false }), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no liveness, readiness or startup probe/);
});

test("a readinessProbe satisfies it", () => {
  const { failures } = run(
    { "k8s/deployment.yaml": deployment({ probe: true }), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.deepEqual(failures, []);
});

// The probe finding needs a target. An app with no health endpoint is not required to grow one.
test("no health endpoint means no probe finding", () => {
  const { failures } = run(
    { "k8s/deployment.yaml": deployment({ probe: false }), "app/main.py": '@app.get("/logs")\ndef logs():\n    pass\n' },
    k8sManifestFailures
  );
  assert.deepEqual(failures, []);
});

// A batch task that exits is supposed to have no readiness probe.
test("a Job is exempt from the probe check", () => {
  const yaml =
    "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: j\nspec:\n  template:\n    spec:\n" +
    "      containers:\n      - name: c\n        image: i\n";
  const { failures } = run({ "k8s/j.yaml": yaml, "app/main.py": APP_WITH_HEALTH }, k8sManifestFailures);
  assert.deepEqual(failures, []);
});

// Silence must never read as success.
test("no manifests is reported as not-checked, never as a pass", () => {
  const { failures, advisories } = run({ "app/main.py": APP_WITH_HEALTH }, k8sManifestFailures);
  assert.deepEqual(failures, []);
  assert.equal(advisories.length, 1);
  assert.match(advisories[0], /not checked/);
});

test("a CronJob's nested pod spec is still read for misplaced fields", () => {
  const yaml =
    "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: c\nspec:\n  schedule: '* * * * *'\n" +
    "  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n" +
    "          - name: c\n            image: i\n          image: wrong\n";
  const { misplaced } = run({ "k8s/c.yaml": yaml }, checkK8sManifests);
  assert.equal(misplaced.length, 1);
  assert.equal(misplaced[0].field, "image");
});

// A probe is a container field, and CONTAINER_ONLY_FIELDS in this same module flags container
// fields found on the pod spec. A remediation that said "add a readinessProbe" without saying where
// could induce the very defect its sibling check catches.
test("the probe remediation shows the probe inside the container", () => {
  const { failures } = run(
    { "k8s/deployment.yaml": deployment({ probe: false }), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.match(failures[0], /CONTAINER field, not a pod-spec one/);
  assert.match(failures[0], /containers:[\s\S]*readinessProbe:[\s\S]*httpGet:/);
});

// --- Kubernetes managed through Terraform ---------------------------------------------------------
// A project declaring kubernetes_deployment instead of a YAML manifest was invisible to this check.

const TF_DEPLOYMENT = (probe) =>
  'resource "kubernetes_deployment" "app" {\n  metadata {\n    name = "webhook-receiver"\n  }\n' +
  "  spec {\n    template {\n      spec {\n" +
  '        container {\n          name  = "receiver"\n          image = "app:latest"\n' +
  (probe ? "          readiness_probe {\n            http_get {\n              path = \"/health\"\n            }\n          }\n" : "") +
  "        }\n      }\n    }\n  }\n}\n";

test("a Terraform-managed workload with no probe is flagged", () => {
  const { failures } = run(
    { "terraform/k8s.tf": TF_DEPLOYMENT(false), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.equal(failures.length, 1);
  assert.match(failures[0], /no liveness, readiness or startup probe/);
  assert.match(failures[0], /receiver/);
});

test("a Terraform-managed workload with a probe is clean", () => {
  const { failures } = run(
    { "terraform/k8s.tf": TF_DEPLOYMENT(true), "app/main.py": APP_WITH_HEALTH },
    k8sManifestFailures
  );
  assert.deepEqual(failures, []);
});

// ${...} is Terraform interpolation, which Terraform expands. Flagging it here would convert a
// correct configuration into a blocking failure — the finding is for YAML only.
test("${...} in Terraform is not the unexpanded-interpolation finding", () => {
  const tf =
    'resource "kubernetes_deployment" "app" {\n  metadata {\n    name = "${var.project}-receiver"\n  }\n' +
    '  spec {\n    template {\n      spec {\n        container {\n          name = "c"\n' +
    "          readiness_probe {\n            http_get {\n              path = \"/health\"\n            }\n          }\n" +
    "        }\n      }\n    }\n  }\n}\n";
  const { failures } = run({ "terraform/k8s.tf": tf, "app/main.py": APP_WITH_HEALTH }, k8sManifestFailures);
  assert.deepEqual(failures, []);
});

test("neither YAML nor Terraform workloads means not-checked, not a pass", () => {
  const { advisories } = run({ "app/main.py": APP_WITH_HEALTH }, k8sManifestFailures);
  assert.match(advisories[0], /in YAML or in Terraform/);
});

// `parseAllDocuments` never throws: a file that did not parse came back as whatever the parser
// salvaged and was read as a complete manifest, and a Helm template's `{{ .Values.image }}` parsed as
// nested mappings rather than tripping the `${...}` rule. Neither is read now, and both are named.
const HELM =
  "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\nspec:\n  template:\n    spec:\n" +
  "      containers:\n      - name: app\n        image: {{ .Values.image }}\n        resources: {{ toYaml .Values.resources | nindent 10 }}\n";
const BROKEN = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n bad: b\nspec:\n  resources: {}\n";

test("a Helm template and a YAML file that does not parse are not read as manifests, and are named", () => {
  const r = run({ "chart/templates/deployment.yaml": HELM, "k8s/broken.yaml": BROKEN }, checkK8sManifests);
  assert.equal(r.ran, false);
  assert.match(r.unknown, /^no Kubernetes manifests read; 2 YAML file\(s\) were not read — chart\/templates\/deployment\.yaml \(a Helm or Go template, which is not a manifest until it is rendered\); k8s\/broken\.yaml \(did not parse as YAML \(All mapping items must start at the same column at line 5, column 1\)\)$/);
  assert.deepEqual(r.unread.map((u) => u.file), ["chart/templates/deployment.yaml", "k8s/broken.yaml"]);

  // Beside a manifest it can read, the check runs over that one and says what it did not read.
  const { failures, advisories } = run({ "chart/templates/deployment.yaml": HELM, "k8s/deployment.yaml": deployment({ probe: true }), "app/main.py": APP_WITH_HEALTH }, k8sManifestFailures);
  assert.deepEqual(failures, []);
  assert.equal(advisories.length, 1, advisories.join("\n"));
  assert.match(advisories[0], /^kubernetes manifests: 1 YAML file\(s\) were not read — chart\/templates\/deployment\.yaml \(a Helm or Go template, which is not a manifest until it is rendered\)\. Nothing in them was checked.*helm template/);
});

// Review of the first version, repro A. A Deployment whose image is `example.com/web:${TAG}` blocks.
// With `# rendered from chart {{ .Chart.Name }}` on line 1 the text held two braces, the file became
// "a Helm template", and the check said "not checked — no Kubernetes manifests read": one comment
// switched the interpolation rule off for the file. The comment is a comment; the file is read.
const UNEXPANDED_UNDER_A_COMMENT =
  "# rendered from chart {{ .Chart.Name }}\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n" +
  "  selector:\n    matchLabels:\n      app: web\n  template:\n    metadata:\n      labels:\n        app: web\n" +
  "    spec:\n      containers:\n        - name: web\n          image: example.com/web:${TAG}\n";

test("a comment holding {{ does not make a manifest a template: its ${...} image still blocks", () => {
  const { failures, advisories } = run({ "k8s/deploy.yaml": UNEXPANDED_UNDER_A_COMMENT }, k8sManifestFailures);
  assert.equal(failures.length, 1, failures.join("\n"));
  assert.match(failures[0], /^kubernetes manifests: 1 value\(s\) contain \$\{\.\.\.\} interpolation that Kubernetes never expands — k8s\/deploy\.yaml: spec\.template\.spec\.containers\[0\]\.image = example\.com\/web:\$\{TAG\}/);
  assert.equal(advisories.some((a) => /not read|not checked/.test(a)), false, advisories.join("\n"));
  // The same file without the comment, for the same answer.
  const plain = run({ "k8s/deploy.yaml": UNEXPANDED_UNDER_A_COMMENT.split("\n").slice(1).join("\n") }, k8sManifestFailures);
  assert.deepEqual(plain.failures, failures);
});

// Repro B's other half: the workflow beside the manifest was named as a Helm template.
test("a workflow's ${{ }} expression is not a Helm template, and the workflow is not named as unread", () => {
  const workflow = 'name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.sha }}"\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.sha }}\n';
  const r = run({ ".github/workflows/ci.yml": workflow, "k8s/deployment.yaml": deployment({ probe: true }), "app/main.py": APP_WITH_HEALTH }, checkK8sManifests);
  assert.equal(r.ran, true);
  assert.deepEqual(r.unread, []);
  // Alone, it is a project with no manifests, as it was before the reader existed.
  const alone = run({ ".github/workflows/ci.yml": workflow }, checkK8sManifests);
  assert.equal(alone.unknown, "no Kubernetes manifests found, in YAML or in Terraform");
});
