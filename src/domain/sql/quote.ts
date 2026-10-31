/** Quoting for SQL the tool generates. Every identifier and literal that reaches generated SQL goes through here. */

/** Characters that must not appear raw in generated SQL: they can drive a terminal or hide text (controls, bidi, zero-width, separators). */
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/;

/** `\XXXX` escapes for a Unicode-escape literal (U&"..." or U&'...'): unsafe characters and the backslash itself. */
function unicodeEscaped(text: string): string {
  let out = "";
  for (const ch of text) {
    out += ch === "\\" ? "\\\\" : UNSAFE.test(ch) ? `\\${(ch.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}` : ch;
  }
  return out;
}

/**
 * A quoted identifier. Names with characters that are unsafe to print (an ESC byte, a bidi override, a newline) are
 * written as a Unicode-escape identifier, U&"...", so the generated SQL stays safe to show in a terminal.
 */
export function quoteIdent(name: string): string {
  if (name.includes("\u0000")) throw new Error("identifier contains a NUL byte");
  if (UNSAFE.test(name)) return `U&"${unicodeEscaped(name).replaceAll('"', '""')}"`;
  return `"${name.replaceAll('"', '""')}"`;
}

export function quoteQualified(schema: string, name: string): string {
  return `${quoteIdent(schema)}.${quoteIdent(name)}`;
}

/** A standard_conforming_strings literal: single quotes doubled, nothing else interpreted. */
export function quoteLiteral(text: string): string {
  if (text.includes("\u0000")) throw new Error("literal contains a NUL byte");
  if (UNSAFE.test(text)) return `U&'${unicodeEscaped(text).replaceAll("'", "''")}'`;
  return `'${text.replaceAll("'", "''")}'`;
}

/** Dollar-quote `text` with a tag that does not occur in it, so any statement can be carried as one string. */
export function dollarQuote(text: string): string {
  if (text.includes("\u0000")) throw new Error("text contains a NUL byte");
  let tag = "pa";
  let n = 0;
  while (text.includes(`$${tag}$`) || text.endsWith(`$${tag}`)) {
    n += 1;
    tag = `pa${n}`;
  }
  return `$${tag}$${text}$${tag}$`;
}
