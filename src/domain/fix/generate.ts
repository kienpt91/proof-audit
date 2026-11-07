import { policyCovers, policyReachesClients, policySoundFor } from "../analysis/causes.js";
import type { FixPlan, Finding } from "../analysis/types.js";
import { detectOwnerColumns, primaryOwnerColumn, type OwnerColumn } from "../schema/owner.js";
import type { Command, Policy, SchemaModel, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import { quoteIdent, quoteQualified } from "../sql/quote.js";
import { visibleEscapes } from "../text/sanitize.js";

const COMMANDS: readonly Command[] = ["select", "insert", "update", "delete"];
const UID = "(select auth.uid())";

interface SubjectFix {
  readonly subject: string;
  readonly statements: readonly string[];
  readonly notes: readonly string[];
}

function typeBase(type: string): string {
  return type.replace(/\(.*?\)/g, "").trim();
}

/** The caller's id in the type of the owner column, or null when no honest comparison exists. */
function callerId(table: Table, owner: OwnerColumn): string | null {
  const type = typeBase(table.columns.find((c) => c.name === owner.column)?.type ?? "");
  if (type === "uuid") return UID;
  if (type === "text" || type === "character varying" || type === "citext" || type === "character") return `${UID}::text`;
  return null;
}

/** A table that links users to tenants: it has a user-like column and a column named like the tenant column. */
function membershipTable(model: SchemaModel, table: Table, tenantColumn: string): { readonly table: Table; readonly userColumn: OwnerColumn } | null {
  const candidates = model.tables
    .filter((t) => t !== table && t.columns.some((c) => c.name === tenantColumn))
    .flatMap((t) => {
      const user = detectOwnerColumns(t).find((o) => o.kind === "user" && o.confidence !== "low");
      return user ? [{ table: t, userColumn: user }] : [];
    });
  const score = (t: Table): number => (/member|membership|team|role|org/i.test(t.name.name) ? 0 : 1);
  return candidates.sort((a, b) => score(a.table) - score(b.table) || (qualifiedKey(a.table.name) < qualifiedKey(b.table.name) ? -1 : 1))[0] ?? null;
}

function ownerRule(model: SchemaModel, table: Table, owner: OwnerColumn): { readonly expr: string } | { readonly reason: string } {
  const column = quoteIdent(owner.column);
  if (owner.kind === "user") {
    const id = callerId(table, owner);
    return id ? { expr: `${column} = ${id}` } : { reason: `the owner column ${owner.column} has a type that cannot be compared with auth.uid()` };
  }
  const link = membershipTable(model, table, owner.column);
  if (!link) {
    return { reason: `${owner.column} identifies a tenant, and no membership table (user id next to ${owner.column}) exists to say who belongs to which tenant` };
  }
  const id = callerId(link.table, link.userColumn);
  if (!id) return { reason: `the membership table ${qualifiedKey(link.table.name)} keeps users in a column type that cannot be compared with auth.uid()` };
  const m = quoteQualified(link.table.name.schema, link.table.name.name);
  return { expr: `${column} IN (SELECT m.${column} FROM ${m} m WHERE m.${quoteIdent(link.userColumn.column)} = ${id})` };
}

function policyName(table: Table, command: Command): string {
  return `${table.name.name}_${command}_own`.slice(0, 60);
}

function createPolicy(table: Table, command: Command, expr: string): string {
  const on = quoteQualified(table.name.schema, table.name.name);
  const head = `CREATE POLICY ${quoteIdent(policyName(table, command))} ON ${on} FOR ${command.toUpperCase()} TO authenticated`;
  if (command === "insert") return `${head} WITH CHECK (${expr})`;
  if (command === "update") return `${head} USING (${expr}) WITH CHECK (${expr})`;
  return `${head} USING (${expr})`;
}

function fixTable(model: SchemaModel, table: Table): SubjectFix | { readonly decision: string } {
  const owner = primaryOwnerColumn(table);
  if (!owner) {
    return { decision: "the table has no owner column, so there is no rule that is safe to write for you; decide who may read and write it" };
  }
  const rule = ownerRule(model, table, owner);
  if ("reason" in rule) return { decision: rule.reason };
  const ownerColumns = owner ? [owner.column] : [];
  const target = quoteQualified(table.name.schema, table.name.name);
  const statements: string[] = [];
  const notes: string[] = [];

  if (!table.rlsEnabled) {
    statements.push(`ALTER TABLE ${target} ENABLE ROW LEVEL SECURITY`);
    notes.push("Turn row level security on.");
  }
  const reachable = table.policies.filter((p) => p.permissive && policyReachesClients(p));
  const replaced = reachable.filter((p) => COMMANDS.some((c) => policyCovers(p, c) && !policySoundFor(p, c, ownerColumns)));
  for (const p of replaced) {
    statements.push(`DROP POLICY IF EXISTS ${quoteIdent(p.name)} ON ${target}`);
    notes.push(`Drop policy "${p.name}": it does not tie every command to the row's owner.`);
  }
  const kept: Policy[] = reachable.filter((p) => !replaced.includes(p));
  const created: string[] = [];
  for (const command of COMMANDS) {
    if (kept.some((p) => policySoundFor(p, command, ownerColumns))) continue;
    statements.push(createPolicy(table, command, rule.expr));
    created.push(command);
  }
  if (created.length > 0) notes.push(`Allow signed-in users to ${created.join(", ")} only rows whose ${owner.column} is theirs.`);
  statements.push(`REVOKE ALL ON TABLE ${target} FROM anon`);
  notes.push("Take every privilege away from the anon role (the public key).");
  return { subject: qualifiedKey(table.name), statements, notes };
}

function fixView(view: View): SubjectFix {
  const target = quoteQualified(view.name.schema, view.name.name);
  return {
    subject: qualifiedKey(view.name),
    statements: [`ALTER VIEW ${target} SET (security_invoker = true)`, `REVOKE ALL ON TABLE ${target} FROM anon`],
    notes: ["Make the view run with the caller's rights so row level security applies to it.", "Take every privilege away from the anon role."],
  };
}

function commentLine(text: string): string {
  return `-- ${visibleEscapes(text)}`;
}

/**
 * A starting-point fix for every PROVEN table and view: row level security on, owner-scoped policies written
 * with `(select auth.uid())`, anon privileges revoked, views switched to security_invoker. Where the model
 * does not say who owns a row the tool does not invent a rule and lists the subject under `needsDecision`.
 */
export function generateFix(model: SchemaModel, findings: readonly Finding[]): FixPlan {
  const fixes: SubjectFix[] = [];
  const needsDecision: { subject: string; reason: string }[] = [];
  for (const finding of findings) {
    if (finding.tier !== "PROVEN") continue;
    if (finding.subjectKind === "view") {
      const view = model.views.find((v) => qualifiedKey(v.name) === finding.subject);
      if (view) fixes.push(fixView(view));
      continue;
    }
    const table = model.tables.find((t) => qualifiedKey(t.name) === finding.subject);
    if (!table) continue;
    const result = fixTable(model, table);
    if ("decision" in result) needsDecision.push({ subject: finding.subject, reason: result.decision });
    else fixes.push(result);
  }
  fixes.sort((a, b) => (a.subject < b.subject ? -1 : 1));
  needsDecision.sort((a, b) => (a.subject < b.subject ? -1 : 1));
  const lines: string[] = [
    "-- proof-audit proposed fix: a STARTING POINT, not a finished migration.",
    "-- Review every statement. It was derived from the schema model and checked against synthetic users only.",
  ];
  for (const f of fixes) {
    lines.push("", commentLine(f.subject));
    for (const n of f.notes) lines.push(commentLine(n));
    for (const s of f.statements) lines.push(`${s};`);
  }
  for (const d of needsDecision) {
    lines.push("", commentLine(`${d.subject}: NEEDS A DECISION, no statements generated.`), commentLine(d.reason));
  }
  return {
    statements: fixes.flatMap((f) => f.statements),
    sql: `${lines.join("\n")}\n`,
    covered: fixes.map((f) => f.subject),
    needsDecision,
  };
}

/**
 * The part of a generated fix file that is about one subject: the comment header `-- <subject>`, its notes and its
 * statements, up to the next blank line. Null when the file has no such section (a subject that needs a decision has
 * a different header and no statements).
 */
export function fixSectionFor(sql: string, subject: string): string | null {
  const header = commentLine(subject);
  const block = sql.split("\n\n").find((b) => b.split("\n")[0] === header);
  return block === undefined ? null : `${block.trimEnd()}\n`;
}
