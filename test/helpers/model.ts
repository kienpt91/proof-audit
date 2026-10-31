import type { Column, Command, Policy, SchemaModel, Table, View } from "../../src/domain/schema/model.js";

export const ALL: readonly Command[] = ["select", "insert", "update", "delete"];

export function col(name: string, type: string, options: Partial<Column> = {}): Column {
  return {
    name,
    type,
    notNull: false,
    hasDefault: false,
    defaultExpr: null,
    generated: false,
    primaryKey: false,
    unique: false,
    references: null,
    enumLabels: null,
    ...options,
  };
}

export function pk(name = "id", type = "uuid"): Column {
  return col(name, type, { primaryKey: true, notNull: true, unique: true, hasDefault: true, defaultExpr: "gen_random_uuid()" });
}

export function userFk(name = "user_id"): Column {
  return col(name, "uuid", { notNull: true, references: { schema: "auth", table: "users", column: "id" } });
}

export function policy(name: string, command: Policy["command"], roles: readonly string[], using: string | null, withCheck: string | null, permissive = true): Policy {
  return { name, command, permissive, roles, using, withCheck };
}

export function tbl(name: string, columns: readonly Column[], options: Partial<Table> = {}, schema = "public"): Table {
  return {
    name: { schema, name },
    columns,
    rlsEnabled: true,
    rlsForced: false,
    policies: [],
    checks: [],
    privileges: { anon: ALL, authenticated: ALL },
    origin: "catalog",
    ...options,
  };
}

export function view(name: string, options: Partial<View> = {}, schema = "public"): View {
  return {
    name: { schema, name },
    columns: ["id", "user_id"],
    securityInvoker: false,
    definition: null,
    dependsOn: [{ schema: "public", name: "notes" }],
    privileges: { anon: ["select"], authenticated: ["select"] },
    origin: "catalog",
    ...options,
  };
}

export function model(tables: readonly Table[], views: readonly View[] = []): SchemaModel {
  return { tables, views };
}

export const OWN = "(user_id = ( SELECT auth.uid() AS uid))";

/** A table with a correct owner policy for every command. */
export function notes(overrides: Partial<Table> = {}): Table {
  return tbl(
    "notes",
    [pk(), userFk(), col("title", "text", { notNull: true })],
    {
      policies: [policy("own", "all", ["authenticated"], OWN, OWN)],
      privileges: { anon: [], authenticated: ALL },
      ...overrides,
    },
  );
}
