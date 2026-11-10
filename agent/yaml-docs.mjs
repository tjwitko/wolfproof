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
// A truncated document that still parses is not caught here: there is nothing in the text that says
// it is incomplete. That is a limit, named in docs/checks.md.
import { parseAllDocuments } from "yaml";

// Go template delimiters. A YAML flow mapping directly inside another with no space between the
// braces is legal and unheard of; a Helm template is in half the repositories with a chart.
const TEMPLATE = /\{\{/;

/**
 * The documents in a YAML file, as plain objects, with the reason the file was not read instead
 * when it was not: { docs, unread }. `docs` is every document that parsed, `unread` is null or one
 * sentence.
 */
export function yamlDocs(text, { maxAliasCount = -1 } = {}) {
  if (TEMPLATE.test(text)) return { docs: [], unread: "a Helm or Go template, which is not a manifest until it is rendered" };
  const docs = [];
  for (const d of parseAllDocuments(text)) {
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
