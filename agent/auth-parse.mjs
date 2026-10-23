// Shared reading for the authentication adapters that need more than a regex: PHP and Kotlin.
//
// The rule they share with the C# reader: nothing structural can be read until string and comment
// contents are blanked, because route templates are strings full of braces ("{id}") and comments
// quote code. Masking keeps every character's position and every newline, so an index or a line
// number in the masked text is the same in the original, which is where literals are read from.

export function blank(out, from, to) {
  for (let k = from; k < to; k++) if (out[k] !== "\n") out[k] = " ";
}

export function lineAt(text, i) {
  let n = 1;
  for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) n++;
  return n;
}

export function matchClose(masked, open, openCh, closeCh) {
  let depth = 0;
  for (let k = open; k < masked.length; k++) {
    if (masked[k] === openCh) depth++;
    else if (masked[k] === closeCh && --depth === 0) return k;
  }
  return -1;
}

// Split [from, to) at commas that are not inside brackets.
export function splitTopLevel(s, from, to) {
  const parts = [];
  let depth = 0;
  let start = from;
  for (let k = from; k < to; k++) {
    const ch = s[k];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) {
      parts.push([start, k]);
      start = k + 1;
    }
  }
  if (s.slice(start, to).trim()) parts.push([start, to]);
  return parts;
}

// The `;` that ends the statement starting at `from`, skipping nested brackets.
export function statementEnd(masked, from) {
  let depth = 0;
  for (let k = from; k < masked.length; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    else if (ch === ")" || ch === "}" || ch === "]") {
      if (--depth < 0) return k;
    } else if (ch === ";" && depth === 0) return k;
  }
  return masked.length;
}

// The value of the string literal whose opening quote is at `q`, or null when what is there is not
// a literal (a constant, an expression). Escapes are left as written: a route template has none.
export function literalAt(text, masked, q) {
  const quote = masked[q];
  if (quote !== '"' && quote !== "'") return null;
  let end = q + 1;
  while (end < masked.length && masked[end] !== quote) end++;
  if (text.startsWith('"""', q)) return text.slice(q + 3, end - 2);
  return text.slice(q + 1, end);
}

// Every string literal in [from, to), in order.
export function literalsIn(text, masked, from, to) {
  const out = [];
  for (let k = from; k < to; k++) {
    if (masked[k] === '"' || masked[k] === "'") {
      const quote = masked[k];
      let end = k + 1;
      while (end < to && masked[end] !== quote) end++;
      out.push(text.slice(k + 1, end));
      k = end;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// PHP. Code is only what sits between <?php and ?>; outside is HTML and is blanked whole, since an
// apostrophe in prose would otherwise open a string. `#[` is an attribute, any other `#` a comment.
// ---------------------------------------------------------------------------------------------

export function maskPhp(text) {
  const out = text.split("");
  const n = text.length;
  let i = 0;
  let php = false;
  while (i < n) {
    if (!php) {
      const open = text.indexOf("<?", i);
      const stop = open < 0 ? n : open;
      blank(out, i, stop);
      if (open < 0) break;
      php = true;
      // The tag itself is blanked too, so a declaration right after it starts at whitespace.
      const after = open + (text.startsWith("<?php", open) ? 5 : text.startsWith("<?=", open) ? 3 : 2);
      blank(out, open, after);
      i = after;
      continue;
    }
    const c = text[i];
    if (c === "?" && text[i + 1] === ">") {
      php = false;
      i += 2;
      continue;
    }
    if ((c === "/" && text[i + 1] === "/") || (c === "#" && text[i + 1] !== "[")) {
      let k = i;
      while (k < n && text[k] !== "\n" && !(text[k] === "?" && text[k + 1] === ">")) k++;
      blank(out, i, k);
      i = k;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      const stop = end < 0 ? n : end + 2;
      blank(out, i, stop);
      i = stop;
      continue;
    }
    if (c === "<" && text.startsWith("<<<", i)) {
      const h = /^<<<[ \t]*(["']?)(\w+)\1\r?\n/.exec(text.slice(i, i + 80));
      if (h) {
        const close = new RegExp(`\\n[ \\t]*${h[2]}\\b`).exec(text.slice(i + h[0].length - 1));
        const stop = close ? i + h[0].length - 1 + close.index + 1 : n;
        blank(out, i + 3, stop);
        i = close ? stop + close[0].length - 1 : n;
        continue;
      }
    }
    if (c === "'" || c === '"') {
      let k = i + 1;
      while (k < n && text[k] !== c) {
        // "{$row["id"]}": a complex interpolation is code, and may quote its own keys.
        if (c === '"' && text[k] === "{" && text[k + 1] === "$") {
          let depth = 0;
          for (; k < n; k++) {
            if (text[k] === "'" || (text[k] === '"' && depth > 0)) {
              const q = text[k];
              k++;
              while (k < n && text[k] !== q) k += text[k] === "\\" ? 2 : 1;
            } else if (text[k] === "{") depth++;
            else if (text[k] === "}" && --depth === 0) break;
          }
          k++;
          continue;
        }
        k += text[k] === "\\" ? 2 : 1;
      }
      blank(out, i + 1, Math.min(k, n));
      i = k + 1;
      continue;
    }
    i++;
  }
  return out.join("");
}

// ---------------------------------------------------------------------------------------------
// Kotlin. Block comments nest; strings carry templates, and a `${...}` template is code that can
// hold its own strings, so it is skipped whole rather than ending the string at its first quote.
// ---------------------------------------------------------------------------------------------

function skipKotlinString(text, i) {
  // Returns the index of the closing quote of the string opening at i.
  const n = text.length;
  const raw = text.startsWith('"""', i);
  let k = i + (raw ? 3 : 1);
  while (k < n) {
    if (raw) {
      if (text.startsWith('"""', k)) {
        while (text[k + 3] === '"') k++; // """a"""" ends at the last three
        return k + 2;
      }
    } else {
      if (text[k] === "\\") { k += 2; continue; }
      if (text[k] === '"' || text[k] === "\n") return k;
    }
    if (text[k] === "$" && text[k + 1] === "{") {
      let depth = 0;
      let j = k + 1;
      for (; j < n; j++) {
        if (text[j] === '"') j = skipKotlinString(text, j);
        else if (text[j] === "{") depth++;
        else if (text[j] === "}" && --depth === 0) break;
      }
      k = j + 1;
      continue;
    }
    k++;
  }
  return n;
}

export function maskKotlin(text) {
  const out = text.split("");
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === "/" && text[i + 1] === "/") {
      const end = text.indexOf("\n", i);
      const stop = end < 0 ? n : end;
      blank(out, i, stop);
      i = stop;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      let depth = 0;
      let k = i;
      for (; k < n; k++) {
        if (text[k] === "/" && text[k + 1] === "*") { depth++; k++; }
        else if (text[k] === "*" && text[k + 1] === "/") { k++; if (--depth === 0) break; }
      }
      blank(out, i, Math.min(k + 1, n));
      i = k + 1;
      continue;
    }
    if (c === '"') {
      // Everything between the outermost quotes is blanked, a raw string's inner quotes included.
      const end = skipKotlinString(text, i);
      blank(out, i + 1, Math.min(end, n));
      i = end + 1;
      continue;
    }
    if (c === "'") {
      let k = i + 1;
      k += text[k] === "\\" ? 2 : 1;
      while (k < n && k < i + 10 && text[k] !== "'" && text[k] !== "\n") k++;
      if (text[k] === "'") {
        blank(out, i + 1, k);
        i = k + 1;
        continue;
      }
    }
    i++;
  }
  return out.join("");
}
