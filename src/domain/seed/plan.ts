import type { SchemaModel, Table } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import { primaryOwnerColumn, type OwnerColumn } from "../schema/owner.js";
import { quoteIdent, quoteLiteral, quoteQualified } from "../sql/quote.js";
import { IDENTITIES, type Identity } from "../supabase/identities.js";
import { insertStatement, planRow, seedContext, sharedContext, type RowMode, type TableLookup } from "./values.js";

export type SeedIdentity = "user-a" | "user-b" | "shared";

export interface SeedAttempt {
  readonly label: RowMode;
  readonly sql: string;
}

export interface SeedItem {
  /** `schema.name` */
  readonly table: string;
  readonly identity: SeedIdentity;
  /** Tried in order until one succeeds. */
  readonly attempts: readonly SeedAttempt[];
  /** Returns how many rows belong to this identity once seeding is done. */
  readonly countSql: string;
}

export interface SeedPlan {
  readonly items: readonly SeedItem[];
  readonly skipped: readonly { readonly table: string; readonly reason: string }[];
}

export function lookupFor(model: SchemaModel): TableLookup {
  const byKey = new Map(model.tables.map((t) => [qualifiedKey(t.name), t]));
  return { find: (schema, name) => byKey.get(`${schema}.${name}`) };
}

/** The text a row owned by `who` carries in the owner column, for `WHERE col::text = ...`. */
export function ownerText(table: Table, owner: OwnerColumn, who: Identity): string {
  const column = table.columns.find((c) => c.name === owner.column);
  const intLike = column !== undefined && /^(smallint|integer|bigint|int2|int4|int8|int)$/.test(column.type.replace(/\(.*\)/, "").trim());
  if (intLike) return String(who.ordinal);
  return owner.kind === "user" ? who.id : who.tenantId;
}

/** Tables ordered so that a table comes after the tables its foreign keys point at (cycles fall back to name order). */
export function orderTables(model: SchemaModel): readonly Table[] {
  const keys = new Set(model.tables.map((t) => qualifiedKey(t.name)));
  const deps = new Map<string, Set<string>>();
  for (const t of model.tables) {
    const own = qualifiedKey(t.name);
    const d = new Set<string>();
    for (const c of t.columns) {
      if (!c.references) continue;
      const target = `${c.references.schema}.${c.references.table}`;
      if (target !== own && keys.has(target)) d.add(target);
    }
    deps.set(own, d);
  }
  const done = new Set<string>();
  const out: Table[] = [];
  const pending = [...model.tables].sort((a, b) => (qualifiedKey(a.name) < qualifiedKey(b.name) ? -1 : 1));
  while (pending.length > 0) {
    const index = pending.findIndex((t) => [...(deps.get(qualifiedKey(t.name)) ?? [])].every((d) => done.has(d)));
    const next = pending.splice(index === -1 ? 0 : index, 1)[0];
    if (!next) break;
    done.add(qualifiedKey(next.name));
    out.push(next);
  }
  return out;
}

function itemFor(table: Table, identity: SeedIdentity, lookup: TableLookup): SeedItem | { readonly skipped: string } {
  const key = qualifiedKey(table.name);
  const person = IDENTITIES.find((i) => i.label === identity);
  const ctx = person ? seedContext(person) : sharedContext();
  const attempts: SeedAttempt[] = [];
  let firstReason: string | null = null;
  // ON CONFLICT DO NOTHING first (a trigger may already have created the row); a table with INSERT or UPDATE rules refuses
  // that clause, so the same rows are also offered as plain inserts.
  for (const onConflict of [true, false]) {
    for (const label of ["full", "minimal"] as const) {
      const plan = planRow(table, ctx, lookup, label);
      if (!plan.ok) {
        firstReason ??= plan.reason;
        continue;
      }
      const sql = insertStatement(table, plan, onConflict);
      if (!attempts.some((a) => a.sql === sql)) attempts.push({ label, sql });
    }
  }
  if (attempts.length === 0) return { skipped: firstReason ?? "no row could be planned" };
  const owner = primaryOwnerColumn(table);
  const target = quoteQualified(table.name.schema, table.name.name);
  const countSql =
    owner && person
      ? `SELECT count(*) FROM ${target} WHERE ${quoteIdent(owner.column)}::text = ${quoteLiteral(ownerText(table, owner, person))}`
      : `SELECT count(*) FROM ${target}`;
  return { table: key, identity, attempts, countSql };
}

/** One row per synthetic user in every table that has an owner column, one shared row in the others. */
export function planSeed(model: SchemaModel): SeedPlan {
  const lookup = lookupFor(model);
  const items: SeedItem[] = [];
  const skipped: { table: string; reason: string }[] = [];
  for (const table of orderTables(model)) {
    const key = qualifiedKey(table.name);
    const identities: SeedIdentity[] = primaryOwnerColumn(table) ? IDENTITIES.map((i) => i.label) : ["shared"];
    for (const identity of identities) {
      const item = itemFor(table, identity, lookup);
      if ("skipped" in item) skipped.push({ table: key, reason: `${identity}: ${item.skipped}` });
      else items.push(item);
    }
  }
  return { items, skipped };
}
