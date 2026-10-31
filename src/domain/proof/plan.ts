import type { Column, SchemaModel, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import { primaryOwnerColumn, type OwnerColumn } from "../schema/owner.js";
import { lookupFor, ownerText } from "../seed/plan.js";
import { insertStatement, planRow, type RowContext, type TableLookup } from "../seed/values.js";
import { quoteIdent, quoteLiteral, quoteQualified } from "../sql/quote.js";
import { ANON_CLAIMS, authenticatedClaims, USER_A, USER_B } from "../supabase/identities.js";
import type { Probe, ProbeKind } from "./types.js";

/** Rows each synthetic user ended up with in a table. For a table without an owner column `rowsUserA` is the total. */
export interface SeedCounts {
  readonly rowsUserA: number;
  readonly rowsUserB: number;
}

/** What the database holds behind a view, counted as the superuser. */
export interface ViewCounts {
  readonly total: number | null;
  readonly ownedByUserB: number | null;
  readonly ownedByUserA: number | null;
}

export interface PlanInput {
  readonly model: SchemaModel;
  readonly seed: ReadonlyMap<string, SeedCounts>;
  readonly views: ReadonlyMap<string, ViewCounts>;
  /** Subjects to plan first (tables the static auditor flagged), in order. */
  readonly priority?: readonly string[];
}

const ANON = { actor: "anon", role: "anon", claims: ANON_CLAIMS } as const;
const USER = { actor: "user-a", role: "authenticated", claims: authenticatedClaims(USER_A) } as const;

/** The column an `UPDATE ... SET c = c` should touch: the first writable column that is not a key. */
export function updatableColumn(table: Table): Column | null {
  const owner = primaryOwnerColumn(table);
  const writable = table.columns.filter((c) => !c.generated);
  return writable.find((c) => !c.primaryKey && c.name !== owner?.column) ?? writable.find((c) => c.name !== owner?.column) ?? writable[0] ?? null;
}

function insertProbeSql(table: Table, ctx: RowContext, lookup: TableLookup): { sql: string | null; reason: string | null } {
  const plan = planRow(table, ctx, lookup, "full");
  if (!plan.ok) {
    const minimal = planRow(table, ctx, lookup, "minimal");
    if (!minimal.ok) return { sql: null, reason: `no synthetic row could be built: ${plan.reason}` };
    return { sql: insertStatement(table, minimal, false), reason: null };
  }
  return { sql: insertStatement(table, plan, false), reason: null };
}

function probe(
  subject: string,
  subjectKind: "table" | "view",
  kind: ProbeKind,
  intent: Probe["intent"],
  command: Probe["command"],
  who: typeof ANON | typeof USER,
  title: string,
  sql: string | null,
  targetRows: number | null,
  blockedReason: string | null,
): Probe {
  return {
    id: `${subject}/${kind}`,
    subject,
    subjectKind,
    kind,
    intent,
    command,
    actor: who.actor,
    role: who.role,
    claims: who.claims,
    sql: sql ?? "",
    title,
    targetRows,
    blockedReason: sql === null ? (blockedReason ?? "probe could not be built") : blockedReason,
  };
}

function needRows(count: number, what: string): string | null {
  return count > 0 ? null : `${what}: nothing was seeded to aim at`;
}

function tableProbes(table: Table, counts: SeedCounts, lookup: TableLookup): Probe[] {
  const key = qualifiedKey(table.name);
  const target = quoteQualified(table.name.schema, table.name.name);
  const owner = primaryOwnerColumn(table);
  const column = updatableColumn(table);
  const total = owner ? counts.rowsUserA + counts.rowsUserB : counts.rowsUserA;
  const set = column ? `${quoteIdent(column.name)} = ${quoteIdent(column.name)}` : null;
  const out: Probe[] = [];

  const attackerCtx: RowContext = { salt: "probe:cross-insert", owner: USER_B, other: USER_A, tenant: USER_A, nullOwner: false };
  const anonInsert = insertProbeSql(table, { ...attackerCtx, salt: "probe:anon-insert" }, lookup);
  out.push(
    probe(key, "table", "anon-read", "exploit", "select", ANON, "Anonymous visitor reads rows", `SELECT * FROM ${target}`, total, needRows(total, "no rows exist")),
    probe(key, "table", "anon-insert", "exploit", "insert", ANON, "Anonymous visitor adds a row", anonInsert.sql, null, anonInsert.reason),
    probe(
      key,
      "table",
      "anon-update",
      "exploit",
      "update",
      ANON,
      "Anonymous visitor changes rows",
      set ? `UPDATE ${target} SET ${set}` : null,
      total,
      set ? needRows(total, "no rows exist") : "the table has no writable column to update",
    ),
    probe(key, "table", "anon-delete", "exploit", "delete", ANON, "Anonymous visitor deletes rows", `DELETE FROM ${target}`, total, needRows(total, "no rows exist")),
  );
  if (!owner) return out;

  const ownerCol = quoteIdent(owner.column);
  const rowsOf = (who: typeof USER_A | typeof USER_B): string => `${ownerCol}::text = ${quoteLiteral(ownerText(table, owner, who))}`;
  const ownerCanBeNull = !(table.columns.find((c) => c.name === owner.column)?.notNull ?? true);
  const crossInsert = insertProbeSql(table, attackerCtx, lookup);
  const nullInsert = insertProbeSql(table, { ...attackerCtx, salt: "probe:null-owner-insert", nullOwner: true }, lookup);
  const ownInsert = insertProbeSql(table, { salt: "probe:own-insert", owner: USER_A, other: USER_A, tenant: USER_A, nullOwner: false }, lookup);

  out.push(
    probe(key, "table", "cross-read", "exploit", "select", USER, "Signed-in user A reads user B's rows", `SELECT * FROM ${target} WHERE ${rowsOf(USER_B)}`, counts.rowsUserB, needRows(counts.rowsUserB, "user B has no rows")),
    probe(key, "table", "cross-insert", "exploit", "insert", USER, "Signed-in user A adds a row owned by user B", crossInsert.sql, null, crossInsert.reason),
  );
  if (ownerCanBeNull) {
    out.push(probe(key, "table", "null-owner-insert", "exploit", "insert", USER, "Signed-in user A adds a row with no owner", nullInsert.sql, null, nullInsert.reason));
  }
  out.push(
    probe(
      key,
      "table",
      "cross-update",
      "exploit",
      "update",
      USER,
      "Signed-in user A changes user B's rows",
      set ? `UPDATE ${target} SET ${set} WHERE ${rowsOf(USER_B)}` : null,
      counts.rowsUserB,
      set ? needRows(counts.rowsUserB, "user B has no rows") : "the table has no writable column to update",
    ),
    probe(key, "table", "cross-delete", "exploit", "delete", USER, "Signed-in user A deletes user B's rows", `DELETE FROM ${target} WHERE ${rowsOf(USER_B)}`, counts.rowsUserB, needRows(counts.rowsUserB, "user B has no rows")),
    probe(
      key,
      "table",
      "reassign-owner",
      "exploit",
      "update",
      USER,
      "Signed-in user A hands one of their rows to user B",
      `UPDATE ${target} SET ${ownerCol} = ${quoteLiteral(ownerText(table, owner, USER_B))} WHERE ${rowsOf(USER_A)}`,
      counts.rowsUserA,
      needRows(counts.rowsUserA, "user A has no rows"),
    ),
    probe(key, "table", "own-read", "legitimate", "select", USER, "Signed-in user A reads their own rows", `SELECT * FROM ${target} WHERE ${rowsOf(USER_A)}`, counts.rowsUserA, needRows(counts.rowsUserA, "user A has no rows")),
    probe(key, "table", "own-insert", "legitimate", "insert", USER, "Signed-in user A adds their own row", ownInsert.sql, null, ownInsert.reason),
    probe(
      key,
      "table",
      "own-update",
      "legitimate",
      "update",
      USER,
      "Signed-in user A changes their own rows",
      set ? `UPDATE ${target} SET ${set} WHERE ${rowsOf(USER_A)}` : null,
      counts.rowsUserA,
      set ? needRows(counts.rowsUserA, "user A has no rows") : "the table has no writable column to update",
    ),
    probe(key, "table", "own-delete", "legitimate", "delete", USER, "Signed-in user A deletes their own rows", `DELETE FROM ${target} WHERE ${rowsOf(USER_A)}`, counts.rowsUserA, needRows(counts.rowsUserA, "user A has no rows")),
  );
  return out;
}

/** Tables a view reads from, following views through views, with a depth guard. */
export function baseTables(view: View, model: SchemaModel, seen = new Set<string>()): readonly Table[] {
  const out: Table[] = [];
  for (const dep of view.dependsOn) {
    const key = `${dep.schema}.${dep.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const table = model.tables.find((t) => qualifiedKey(t.name) === key);
    if (table) {
      out.push(table);
      continue;
    }
    const inner = model.views.find((v) => qualifiedKey(v.name) === key);
    if (inner) out.push(...baseTables(inner, model, seen));
  }
  return out;
}

/** The view column that holds the owner, when the view exposes the owner column of one of its base tables. */
export function viewOwner(view: View, model: SchemaModel): OwnerColumn | null {
  for (const table of baseTables(view, model)) {
    const owner = primaryOwnerColumn(table);
    if (owner && view.columns.includes(owner.column)) return owner;
  }
  return null;
}

/** Views that sit on top of at least one table protected by row level security: the ones that can bypass it. */
export function viewsOverProtectedTables(model: SchemaModel): readonly View[] {
  return model.views.filter((v) => baseTables(v, model).some((t) => t.rlsEnabled));
}

function viewProbes(view: View, model: SchemaModel, counts: ViewCounts | undefined): Probe[] {
  const key = qualifiedKey(view.name);
  const target = quoteQualified(view.name.schema, view.name.name);
  const owner = viewOwner(view, model);
  const total = counts?.total ?? null;
  const rowsOf = (who: typeof USER_A | typeof USER_B): string | null => {
    if (!owner) return null;
    const base = baseTables(view, model).find((t) => primaryOwnerColumn(t)?.column === owner.column);
    return base ? `${quoteIdent(owner.column)}::text = ${quoteLiteral(ownerText(base, owner, who))}` : null;
  };
  const out: Probe[] = [
    probe(
      key,
      "view",
      "view-read-anon",
      "exploit",
      "select",
      ANON,
      "Anonymous visitor reads the view",
      `SELECT * FROM ${target}`,
      total,
      total === null || total === 0 ? "the view returns no rows even to the database owner" : null,
    ),
  ];
  const b = rowsOf(USER_B);
  const a = rowsOf(USER_A);
  out.push(
    probe(
      key,
      "view",
      "view-read-cross",
      "exploit",
      "select",
      USER,
      "Signed-in user A reads user B's rows through the view",
      b ? `SELECT * FROM ${target} WHERE ${b}` : null,
      counts?.ownedByUserB ?? null,
      b ? (counts?.ownedByUserB ? null : "the view returns none of user B's rows even to the database owner") : "the view does not expose an owner column, so whose rows it returns cannot be told",
    ),
    probe(
      key,
      "view",
      "view-read-own",
      "legitimate",
      "select",
      USER,
      "Signed-in user A reads their own rows through the view",
      a ? `SELECT * FROM ${target} WHERE ${a}` : null,
      counts?.ownedByUserA ?? null,
      a ? (counts?.ownedByUserA ? null : "the view returns none of user A's rows even to the database owner") : "the view does not expose an owner column",
    ),
  );
  return out;
}

/** Every probe for the model, in a stable order: priority subjects first, then by name; tables before views. */
export function planProbes(input: PlanInput): readonly Probe[] {
  const lookup = lookupFor(input.model);
  const priority = new Map((input.priority ?? []).map((s, i) => [s, i]));
  const rank = (subject: string): number => priority.get(subject) ?? Number.MAX_SAFE_INTEGER;
  const tables = [...input.model.tables].sort((a, b) => {
    const ka = qualifiedKey(a.name);
    const kb = qualifiedKey(b.name);
    return rank(ka) - rank(kb) || (ka < kb ? -1 : ka > kb ? 1 : 0);
  });
  const views = [...viewsOverProtectedTables(input.model)].sort((a, b) => {
    const ka = qualifiedKey(a.name);
    const kb = qualifiedKey(b.name);
    return rank(ka) - rank(kb) || (ka < kb ? -1 : ka > kb ? 1 : 0);
  });
  const out: Probe[] = [];
  for (const table of tables) out.push(...tableProbes(table, input.seed.get(qualifiedKey(table.name)) ?? { rowsUserA: 0, rowsUserB: 0 }, lookup));
  for (const view of views) out.push(...viewProbes(view, input.model, input.views.get(qualifiedKey(view.name))));
  return out;
}
