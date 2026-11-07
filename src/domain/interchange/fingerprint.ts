/**
 * Fingerprints of the records in `findings.json`. A fingerprint is built only from stable names (the kind of
 * problem, the schema-qualified table, the policy name, a rule id, a repository-relative file), never from a
 * line number, a time or a count, so editing a migration without touching those names keeps it. The format
 * only allows `[A-Za-z0-9._:/@+-]` after a first letter or digit, so every name goes through `encodeSegment`.
 */

const KEEP = /[A-Za-z0-9._-]/;
const HEX = "0123456789abcdef";
const UTF8 = new TextEncoder();

/**
 * A name as one segment: letters, digits, `.`, `_` and `-` stay; every other UTF-8 byte becomes `+` and two
 * lowercase hex digits (space is `+20`, `+` itself `+2b`, `:` `+3a`, `/` `+2f`). Injective, and the result
 * never contains `:` or `/`, so segments can be joined with them.
 */
export function encodeSegment(name: string): string {
  let out = "";
  for (const ch of name) {
    if (KEEP.test(ch)) {
      out += ch;
      continue;
    }
    for (const byte of UTF8.encode(ch)) out += `+${HEX.charAt(byte >> 4)}${HEX.charAt(byte & 15)}`;
  }
  return out;
}

/** A repository-relative path: the parts between `/` are encoded one by one, the separators stay. */
export function encodePath(path: string): string {
  return path.split("/").map(encodeSegment).join("/");
}

export type RootCauseKind =
  | "rls-disabled"
  | "policy-always-true"
  | "policy-owner-unchecked"
  | "owner-not-compared"
  | "view-bypasses-rls"
  | "unattributed"
  | "untested";

/** A schema or table name inside `schema.table`: like a segment, but a dot in the name is escaped too, so the one dot between the two stays unambiguous. */
const encodeName = (name: string): string => encodeSegment(name).replaceAll(".", "+2e");

/**
 * `proof-audit/rls/<schema>.<name>/<kind>[/<policy>]`: one table (or view) and one root cause. The same
 * fingerprint is used whether the record is confirmed or still needs validation, so a candidate that a later
 * run proves keeps its identity.
 */
export function rlsFingerprint(schema: string, name: string, kind: RootCauseKind, policy: string | null): string {
  const base = `proof-audit/rls/${encodeName(schema)}.${encodeName(name)}/${kind}`;
  return policy === null ? base : `${base}/${encodeSegment(policy)}`;
}

/**
 * The names a static finding is identified by: the non-empty entries of the `subject` array of its report
 * (`[table]` or `[table, policy name]`), else its whole title. This is the choice `saas-audit` makes.
 */
export function staticNames(subject: readonly string[] | null, title: string): readonly string[] {
  const names = (subject ?? []).filter((s) => s !== "");
  return names.length > 0 ? names : [title];
}

/**
 * The fingerprint of a finding of the author's static auditor (`saas-audit`), built as that auditor builds it for
 * its own record: `saas-audit/<rule>:<path>:<name>[:<name>...]`, with the names from `staticNames`. A static
 * finding that this tool's database refused then keeps the identity of the static record, for every report that
 * `saas-audit` writes (with or without `subject`).
 */
export function staticFingerprint(rule: string, file: string, names: readonly string[]): string {
  return `saas-audit/${encodeSegment(rule)}:${encodePath(file)}:${names.map(encodeSegment).join(":")}`;
}
