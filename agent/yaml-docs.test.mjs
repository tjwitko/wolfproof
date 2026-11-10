import test from "node:test";
import assert from "node:assert/strict";

import { yamlDocs } from "./yaml-docs.mjs";

const TEMPLATE = "a Helm or Go template, which is not a manifest until it is rendered";

// The first version of the reader asked the text for `{{`. One comment made a Deployment "a Helm
// template" and three checks stopped reading it; a workflow's `${{ github.sha }}` did the same to
// the workflow, and the manifest contract then called a missing variable unknown. Each of these is
// text that happens to hold two braces, parses as what it says, and is read.
test("{{ in a comment, a quoted or plain scalar, or a block scalar is text, and the file is read", () => {
  const read = {
    comment: "# rendered from chart {{ .Chart.Name }}\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
    "trailing comment": "kind: Deployment # {{ .Values.kind }}\n",
    "double-quoted": 'kind: Deployment\nmetadata:\n  name: "{{ .Release.Name }}-web"\n',
    "single-quoted": "kind: Deployment\nmetadata:\n  name: '{{ .Release.Name }}'\n",
    "workflow expression in a plain scalar": "steps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.sha }}\n",
    "workflow expression in a quoted command": 'steps:\n  - run: echo "${{ github.sha }}"\n',
    "plain scalar, braces not first": "args:\n  - --name=$(POD)-{{ .Values.suffix }}\n",
    "Prometheus rule in a block scalar":
      "kind: ConfigMap\ndata:\n  rules.yml: |\n    - alert: Down\n      annotations:\n        summary: '{{ $labels.instance }} down'\n        description: {{ $value }}\n",
    "folded scalar": "kind: ConfigMap\ndata:\n  note: >\n    {{ .Values.note }}\n",
    "Argo parameter": 'kind: Workflow\nspec:\n  templates:\n    - container:\n        args: ["{{inputs.parameters.message}}"]\n',
    // Legal YAML, and not a template: the two braces are not adjacent.
    "a flow mapping keyed by a flow mapping": "a: { {b: 1}: 2 }\n",
  };
  for (const [name, text] of Object.entries(read)) {
    const r = yamlDocs(text);
    assert.equal(r.unread, null, `${name}: ${r.unread}`);
    assert.equal(r.docs.length, 1, name);
  }
  // And what was read is what the file says, comment or not.
  assert.equal(yamlDocs(read.comment).docs[0].kind, "Deployment");
  assert.equal(yamlDocs(read["double-quoted"]).docs[0].metadata.name, "{{ .Release.Name }}-web");
});

// What `helm create` writes, cut to the lines that matter: control lines, an include piped to
// nindent, a value where a scalar belongs, a templated key, toYaml under a `with`.
const HELM_CREATE_DEPLOYMENT = [
  "apiVersion: apps/v1",
  "kind: Deployment",
  "metadata:",
  '  name: {{ include "web.fullname" . }}',
  "  labels:",
  '    {{- include "web.labels" . | nindent 4 }}',
  "spec:",
  "  {{- if not .Values.autoscaling.enabled }}",
  "  replicas: {{ .Values.replicaCount }}",
  "  {{- end }}",
  "  template:",
  "    spec:",
  "      {{- with .Values.imagePullSecrets }}",
  "      imagePullSecrets:",
  "        {{- toYaml . | nindent 8 }}",
  "      {{- end }}",
  "      containers:",
  "        - name: {{ .Chart.Name }}",
  '          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"',
  "          resources:",
  "            {{- toYaml .Values.resources | nindent 12 }}",
  "",
].join("\n");

test("a real Helm template is still not read, whichever of its expressions is the unquoted one", () => {
  assert.deepEqual(yamlDocs(HELM_CREATE_DEPLOYMENT), { docs: [], unread: TEMPLATE });
  const structural = {
    "a value": "kind: Deployment\nspec:\n  replicas: {{ .Values.replicaCount }}\n",
    "a value, trimmed": "kind: Deployment\nspec:\n  replicas: {{- .Values.replicaCount -}}\n",
    "a control line": "{{- if .Values.enabled }}\nkind: Deployment\n{{- end }}\n",
    "an include on its own line": 'kind: Deployment\nmetadata:\n  labels:\n    {{- include "web.labels" . | nindent 4 }}\n',
    "a templated key": "kind: ConfigMap\ndata:\n  {{ .Values.key }}: value\n",
    "a sequence item": "kind: Pod\nspec:\n  containers:\n    - {{ .Values.container }}\n",
    "the second document": "kind: Service\n---\nkind: Deployment\nspec:\n  replicas: {{ .Values.replicaCount }}\n",
  };
  for (const [name, text] of Object.entries(structural)) assert.deepEqual(yamlDocs(text), { docs: [], unread: TEMPLATE }, name);
});

test("a document with errors is not read, and the reason is the parser's first line", () => {
  const r = yamlDocs("apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n bad: b\n");
  assert.deepEqual(r.docs, []);
  assert.equal(r.unread, "did not parse as YAML (All mapping items must start at the same column at line 5, column 1)");
  // One broken document among several: none of the file is read, as a half-read file is the defect.
  assert.deepEqual(yamlDocs("kind: Service\n---\nkind: Pod\n bad: b\n").docs, []);
  // The alias limit is the one thing toJS throws for.
  const bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n";
  assert.match(yamlDocs(bomb, { maxAliasCount: 100 }).unread, /^did not parse as YAML \(/);
  assert.equal(yamlDocs(bomb).unread, null);
});
