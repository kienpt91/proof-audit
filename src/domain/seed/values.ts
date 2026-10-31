import { sha256Hex } from "../hash/sha256.js";
import type { Column, Table } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import { detectOwnerColumns, primaryOwnerColumn } from "../schema/owner.js";
import { quoteIdent, quoteLiteral, quoteQualified } from "../sql/quote.js";
import type { Identity } from "../supabase/identities.js";
import { USER_A } from "../supabase/identities.js";
import { checkHints, type CheckHints } from "./hints.js";

/**
 * Synthetic values for one row. Everything is a pure function of the table, the column and a salt, so the
 * same input always produces the same rows. Values are plausible for the column's name and type and
 * satisfy the CHECK constraints the hint reader understands; when no honest value exists the answer is
 * `impossible` with a reason, never a guess.
 */
export interface RowContext {
  /** Makes unique values differ between rows: `seed:user-a`, `seed:user-b`, `seed:shared`, `probe:<kind>`. */
  readonly salt: string;
  /** Fills the table's primary owner column. */
  readonly owner: Identity;
  /** Fills every other user-like column (created_by next to user_id, foreign keys to auth.users) and parent rows. */
  readonly other: Identity;
  /** Fills tenant-style columns that are not the primary owner column. */
  readonly tenant: Identity;
  /** Write NULL into the primary owner column. */
  readonly nullOwner: boolean;
}

export type ColumnValue =
  | { readonly kind: "value"; readonly sql: string }
  | { readonly kind: "omit" }
  | { readonly kind: "impossible"; readonly reason: string };

export interface TableLookup {
  find(schema: string, name: string): Table | undefined;
}

export function seedContext(identity: Identity): RowContext {
  return { salt: `seed:${identity.label}`, owner: identity, other: identity, tenant: identity, nullOwner: false };
}

/** Context for tables without an owner column: one shared row. */
export function sharedContext(): RowContext {
  return { salt: "seed:shared", owner: USER_A, other: USER_A, tenant: USER_A, nullOwner: false };
}

type TypeKind = "uuid" | "text" | "integer" | "numeric" | "boolean" | "date" | "timestamp" | "time" | "json" | "bytea" | "inet" | "interval" | "array" | "enum" | "other";

interface TypeInfo {
  readonly kind: TypeKind;
  readonly length: number | null;
  readonly intMax: number;
  readonly precision: number | null;
  readonly scale: number | null;
  readonly withTz: boolean;
  readonly base: string;
}

function typeInfo(column: Column): TypeInfo {
  const type = column.type.trim().toLowerCase();
  const paren = /\((\d+)(?:\s*,\s*(\d+))?\)/.exec(type);
  const base = type.replace(/\(.*?\)/g, "").replace(/\s+/g, " ").trim();
  const length = paren ? Number(paren[1]) : null;
  const make = (kind: TypeKind, extra: Partial<TypeInfo> = {}): TypeInfo => ({ kind, length: null, intMax: 2147483647, precision: null, scale: null, withTz: false, base, ...extra });
  if (column.enumLabels && column.enumLabels.length > 0) return make("enum");
  if (base.endsWith("[]")) return make("array");
  switch (base) {
    case "uuid":
      return make("uuid");
    case "text":
    case "citext":
    case "name":
    case "character varying":
    case "varchar":
    case "character":
    case "char":
    case "bpchar":
      return make("text", { length: base.startsWith("char") || base === "bpchar" ? (length ?? 1) : length });
    case "smallint":
    case "int2":
      return make("integer", { intMax: 32767 });
    case "integer":
    case "int":
    case "int4":
      return make("integer");
    case "bigint":
    case "int8":
      return make("integer", { intMax: 9_007_199_254_740_991 });
    case "numeric":
    case "decimal":
      return make("numeric", { precision: paren ? Number(paren[1]) : null, scale: paren?.[2] !== undefined ? Number(paren[2]) : paren ? 0 : null });
    case "real":
    case "double precision":
    case "float4":
    case "float8":
    case "money":
      return make("numeric", { precision: null, scale: base === "money" ? 2 : null });
    case "boolean":
    case "bool":
      return make("boolean");
    case "date":
      return make("date");
    case "timestamp with time zone":
    case "timestamptz":
      return make("timestamp", { withTz: true });
    case "timestamp without time zone":
    case "timestamp":
      return make("timestamp");
    case "time without time zone":
    case "time with time zone":
    case "time":
      return make("time");
    case "json":
    case "jsonb":
      return make("json");
    case "bytea":
      return make("bytea");
    case "inet":
    case "cidr":
    case "macaddr":
      return make("inet");
    case "interval":
      return make("interval");
    default:
      return make("other");
  }
}

function hashHex(table: Table, column: string, salt: string): string {
  return sha256Hex(`${qualifiedKey(table.name)}|${column}|${salt}`);
}

function uuidFromHash(h: string): string {
  const variant = "89ab"[Number.parseInt(h[16] ?? "0", 16) % 4];
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function truncateTo(text: string, length: number | null): string {
  return length !== null && text.length > length ? text.slice(0, length) : text;
}

function identityValue(column: Column, uuid: string, ordinal: number): ColumnValue {
  const info = typeInfo(column);
  if (info.kind === "uuid") return { kind: "value", sql: quoteLiteral(uuid) };
  if (info.kind === "text") {
    if (info.length !== null && info.length < uuid.length) return { kind: "impossible", reason: `column ${column.name} is too short (${info.length}) for a synthetic user id` };
    return { kind: "value", sql: quoteLiteral(uuid) };
  }
  if (info.kind === "integer") return { kind: "value", sql: String(ordinal) };
  return { kind: "impossible", reason: `owner column ${column.name} has type ${column.type}, which cannot hold a synthetic user id` };
}

const isSeed = (ctx: RowContext): boolean => ctx.salt.startsWith("seed:");

function textFor(table: Table, column: Column, ctx: RowContext, info: TypeInfo, hints: CheckHints): string {
  const name = column.name.toLowerCase();
  const h = hashHex(table, column.name, ctx.salt);
  const suffix = h.slice(0, 6);
  const person = ctx.owner.label === "user-b" ? "Bob" : "Alice";
  const unique = column.primaryKey || column.unique;
  let text: string;
  if (hints.literals.length > 0) {
    text = hints.literals[0] ?? "";
  } else if (/e?-?mail/.test(name)) {
    text = isSeed(ctx) ? ctx.owner.email : `probe-${suffix}@example.test`;
  } else if (/(^|_)(url|uri|website|link|avatar|image|photo)(_|$)/.test(name)) {
    text = `https://example.test/${suffix}`;
  } else if (/phone|mobile|tel$/.test(name)) {
    text = "+15550100";
  } else if (/(^|_)(slug|handle|username|login|code|key|token|reference|ref|sku)(_|$)/.test(name)) {
    text = `${name}-${suffix}`;
  } else if (/^(status|state)$/.test(name)) {
    text = "active";
  } else if (/(^|_)(type|kind)$/.test(name)) {
    text = "standard";
  } else if (/^(role|user_role)$/.test(name)) {
    text = "member";
  } else if (/(^|_)plan$|^tier$/.test(name)) {
    text = "free";
  } else if (/category|topic|tag/.test(name)) {
    text = "general";
  } else if (/(first_|given_|last_|family_|full_|display_)?name$/.test(name)) {
    text = person;
  } else if (/title|subject|label|summary/.test(name)) {
    text = `Synthetic ${name} (${person})`;
  } else {
    text = `Synthetic ${name.replaceAll("_", " ")} from ${person}`;
  }
  if (unique && !text.includes(suffix)) text = `${text} ${suffix}`;
  if (hints.minLength !== null && text.length < hints.minLength) text = text.padEnd(hints.minLength, "x");
  return truncateTo(text, info.length);
}

function integerFor(table: Table, column: Column, ctx: RowContext, info: TypeInfo, hints: CheckHints): string {
  const name = column.name.toLowerCase();
  const h = hashHex(table, column.name, ctx.salt);
  let value: number;
  if (column.primaryKey || column.unique) {
    if (ctx.salt === "seed:user-a") value = 1001;
    else if (ctx.salt === "seed:user-b") value = 2001;
    else if (ctx.salt === "seed:shared") value = 3001;
    else {
      const span = Math.min(info.intMax, 1_000_000) - 5_000;
      value = 5_000 + (Number.parseInt(h.slice(0, 8), 16) % span);
    }
  } else if (/year/.test(name)) value = 2026;
  else if (/(^|_)(amount|price|cents|total|cost)(_|$)/.test(name)) value = ctx.owner.ordinal * 100;
  else if (/(^|_)age$/.test(name)) value = 30;
  else value = ctx.owner.ordinal;
  if (hints.min !== null && value < hints.min) value = Math.ceil(hints.min);
  if (hints.max !== null && value > hints.max) value = Math.floor(hints.max);
  return String(Math.min(value, info.intMax));
}

function numericFor(column: Column, ctx: RowContext, info: TypeInfo, hints: CheckHints): string {
  const digits = info.precision === null ? 8 : info.precision - (info.scale ?? 0);
  let value: number = digits >= 3 ? ctx.owner.ordinal * 10 + 0.5 : digits >= 1 ? ctx.owner.ordinal + 0.5 : 0.5;
  if (info.scale === 0) value = Math.floor(value);
  if (hints.min !== null && value < hints.min) value = hints.min;
  if (hints.max !== null && value > hints.max) value = hints.max;
  return column.type.startsWith("money") ? quoteLiteral(value.toFixed(2)) : String(value);
}

function booleanFor(column: Column): string {
  const name = column.name.toLowerCase();
  return /(^|_)(active|enabled|verified|confirmed|approved)$/.test(name) ? "true" : "false";
}

function dayFor(ctx: RowContext): string {
  return ctx.owner.label === "user-b" ? "2026-01-16" : isSeed(ctx) ? "2026-01-15" : "2026-01-17";
}

function simpleValue(table: Table, column: Column, ctx: RowContext, info: TypeInfo, hints: CheckHints): ColumnValue {
  const h = hashHex(table, column.name, ctx.salt);
  switch (info.kind) {
    case "uuid":
      return { kind: "value", sql: quoteLiteral(uuidFromHash(h)) };
    case "text":
      return { kind: "value", sql: quoteLiteral(textFor(table, column, ctx, info, hints)) };
    case "integer":
      return { kind: "value", sql: integerFor(table, column, ctx, info, hints) };
    case "numeric":
      return { kind: "value", sql: numericFor(column, ctx, info, hints) };
    case "boolean":
      return { kind: "value", sql: booleanFor(column) };
    case "date":
      return { kind: "value", sql: quoteLiteral(dayFor(ctx)) };
    case "timestamp":
      return { kind: "value", sql: quoteLiteral(`${dayFor(ctx)} 10:00:00${info.withTz ? "+00" : ""}`) };
    case "time":
      return { kind: "value", sql: quoteLiteral("10:00:00") };
    case "json":
      return { kind: "value", sql: quoteLiteral(JSON.stringify({ seed: ctx.salt })) };
    case "bytea":
      return { kind: "value", sql: quoteLiteral("\\x73656564") };
    case "inet":
      return { kind: "value", sql: quoteLiteral(info.base === "cidr" ? "192.0.2.0/24" : info.base === "macaddr" ? "08:00:2b:01:02:03" : "192.0.2.1") };
    case "interval":
      return { kind: "value", sql: quoteLiteral("1 day") };
    case "array":
      return { kind: "value", sql: quoteLiteral("{}") };
    case "enum": {
      const labels = column.enumLabels ?? [];
      const pick = hints.literals.find((l) => labels.includes(l)) ?? labels[0] ?? "";
      return { kind: "value", sql: quoteLiteral(pick) };
    }
    case "other":
      return { kind: "impossible", reason: `no synthetic value is defined for type ${column.type}` };
  }
}

/** The value one column gets in one row, or why it cannot get one. */
export function valueForColumn(table: Table, column: Column, ctx: RowContext, lookup: TableLookup, depth = 0): ColumnValue {
  if (column.generated) return { kind: "omit" };
  const owners = detectOwnerColumns(table);
  const primary = primaryOwnerColumn(table);
  const owner = owners.find((o) => o.column === column.name);
  if (owner) {
    const isPrimary = primary?.column === column.name;
    if (isPrimary && ctx.nullOwner) return column.notNull ? { kind: "impossible", reason: `owner column ${column.name} is NOT NULL` } : { kind: "value", sql: "NULL" };
    if (owner.kind === "user") {
      const who = isPrimary ? ctx.owner : ctx.other;
      return identityValue(column, who.id, who.ordinal);
    }
    const who = isPrimary ? ctx.owner : ctx.tenant;
    return identityValue(column, who.tenantId, who.ordinal);
  }
  if (column.references) {
    const ref = column.references;
    if (ref.schema === "auth" && ref.table === "users") return identityValue(column, ctx.other.id, ctx.other.ordinal);
    const optional = !column.notNull || column.hasDefault;
    const parent = lookup.find(ref.schema, ref.table);
    const refColumn = parent?.columns.find((c) => c.name === ref.column);
    if (!parent || !refColumn || depth > 3 || parent === table) {
      return optional ? { kind: "omit" } : { kind: "impossible", reason: `${column.name} references ${ref.schema}.${ref.table}, which has no seeded row to point at` };
    }
    if (refColumn.generated) {
      return { kind: "value", sql: `(SELECT ${quoteIdent(refColumn.name)} FROM ${quoteQualified(parent.name.schema, parent.name.name)} ORDER BY 1 LIMIT 1)` };
    }
    const parentCtx = primaryOwnerColumn(parent) === null ? sharedContext() : seedContext(ctx.other);
    return valueForColumn(parent, refColumn, parentCtx, lookup, depth + 1);
  }
  return simpleValue(table, column, ctx, typeInfo(column), checkHints(column.name, table.checks));
}

export type RowMode = "full" | "minimal";

export type RowPlan =
  | { readonly ok: true; readonly columns: readonly string[]; readonly values: readonly string[] }
  | { readonly ok: false; readonly reason: string };

function isKey(table: Table, column: Column): boolean {
  return column.primaryKey || column.references !== null || detectOwnerColumns(table).some((o) => o.column === column.name);
}

/** Which columns a row gets and what goes in them. `minimal` writes only keys, owners, foreign keys and required columns. */
export function planRow(table: Table, ctx: RowContext, lookup: TableLookup, mode: RowMode): RowPlan {
  const columns: string[] = [];
  const values: string[] = [];
  for (const column of table.columns) {
    if (column.generated) continue;
    const required = column.notNull && !column.hasDefault;
    const wanted = isKey(table, column) || column.unique || required || (mode === "full" && !column.hasDefault);
    if (!wanted) continue;
    const v = valueForColumn(table, column, ctx, lookup);
    if (v.kind === "omit") continue;
    if (v.kind === "impossible") {
      if (required) return { ok: false, reason: v.reason };
      continue;
    }
    columns.push(column.name);
    values.push(v.sql);
  }
  return { ok: true, columns, values };
}

export function insertStatement(table: Table, plan: Extract<RowPlan, { ok: true }>, onConflictDoNothing: boolean): string {
  const target = quoteQualified(table.name.schema, table.name.name);
  const tail = onConflictDoNothing ? " ON CONFLICT DO NOTHING" : "";
  if (plan.columns.length === 0) return `INSERT INTO ${target} DEFAULT VALUES${tail}`;
  return `INSERT INTO ${target} (${plan.columns.map(quoteIdent).join(", ")}) VALUES (${plan.values.join(", ")})${tail}`;
}
