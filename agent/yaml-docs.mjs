// Reading a YAML file as Kubernetes documents, shared by the three checks that do.
//
// `parseAllDocuments` never throws, and a document's `toJS()` does not either (short of the alias
// limit): a document that failed to parse comes back with `errors` set and whatever the parser
// salvaged. The three readers caught exceptions that never came and consulted `errors` never, so a
// broken manifest was read as a complete one with some of its fields gone. A Helm or Go template is
// the same case from the other side: `{{ .Values.image }}` parses as nested flow mappings, not as a
// string, so a template's `securityContext` came through as a shape that matched nothing, and the
// `${...}` rule, which exists for exactly this -- a value the cluster will receive unexpanded -- did
// not see it. Neither is read any more; the caller is told which files it did not read, and says so.
//
// What makes a file a template is braces that are YAML structure, and the parsed document decides
// it, not the text. The first version of this file tested the text for `{{`, and one comment --
// `# rendered from chart {{ .Chart.Name }}` -- switched all three checks off for a Deployment whose
// `${TAG}` image blocks, while a workflow's `echo "${{ github.sha }}"` turned a missing variable
// into an unknown. `{{` in a comment, in a quoted or plain scalar, or in a block scalar (a
// Prometheus rule, an Argo parameter, a container argument, `${{ }}` in a workflow) is text, the
// file parses as what it says, and it is read. A template whose every expression is quoted parses
// as a manifest holding those strings and is read as one too, as it was before this file existed.
//
// A truncated document that still parses is not caught here: there is nothing in the text that says
// it is incomplete. That is a limit, named in docs/checks.md.
import { parseAllDocuments, visit, isMap } from "yaml";

const TEMPLATE_WHY = "a Helm or Go template, which is not a manifest until it is rendered";

// `{{ x }}` where YAML expects a node is a flow mapping whose key is a flow mapping, the two opening
// braces adjacent. `{ {a: 1}: 2 }` is legal YAML and not a template, hence the adjacency; `{{a: 1}: 2}`
// is legal and unheard of, and a Helm template is in half the repositories with a chart. Asked of
// the document the parser built, salvaged or not: a control line (`{{- if .Values.x }}`) leaves
// errors behind and its two mappings with them.
function isTemplate(doc) {
  let found = false;
  visit(doc, {
    Map(_, node) {
      if (!node.flow || !node.range) return undefined;
      const braces = node.items.some((p) => isMap(p.key) && p.key.flow && p.key.range && p.key.range[0] === node.range[0] + 1);
      if (!braces) return undefined;
      found = true;
      return visit.BREAK;
    },
  });
  return found;
}

/**
 * The documents in a YAML file, as plain objects, with the reason the file was not read instead
 * when it was not: { docs, unread }. `docs` is every document that parsed, `unread` is null or one
 * sentence.
 */
export function yamlDocs(text, { maxAliasCount = -1 } = {}) {
  const parsed = parseAllDocuments(text);
  // Before the errors: a template's control lines do not parse, and "a template" is the reason that
  // tells its author what to do about it.
  if (parsed.some(isTemplate)) return { docs: [], unread: TEMPLATE_WHY };
  const docs = [];
  for (const d of parsed) {
    if (d.errors?.length) {
      const first = String(d.errors[0].message || d.errors[0]).split("\n")[0].replace(/:$/, "");
      return { docs: [], unread: `did not parse as YAML (${first})` };
    }
    let obj;
    try {
      obj = d.toJS?.({ maxAliasCount });
    } catch (e) {
      return { docs: [], unread: `did not parse as YAML (${e?.message || e})` };
    }
    docs.push(obj);
  }
  return { docs, unread: null };
}

/** One advisory sentence naming the files a check did not read, for the three checks to share. */
export function unreadYamlLine(check, unread, consequence) {
  const list = unread
    .slice(0, 5)
    .map((u) => `${u.file} (${u.why})`)
    .join("; ");
  return (
    `${check}: ${unread.length} YAML file(s) were not read — ${list}${unread.length > 5 ? `; +${unread.length - 5} more` : ""}. ` +
    `${consequence} A template is checked by rendering it (\`helm template\`) and running the gate over the output.`
  );
}
