import { LIMITS } from "../limits.js";
import type { Result } from "../result.js";
import { ok } from "../result.js";
import type { ClientRole, Column, Command, Policy, SchemaModel, Table, View } from "../schema/model.js";
import { array, boolean, literal, nullable, object, string, type Validator } from "../validate.js";

/**
 * What the throwaway database says about itself after the migrations ran: the authoritative picture of
 * tables, columns, policies and privileges, read from the catalogs rather than guessed from SQL text.
 * The adapter returns it as JSON; this module validates it strictly and maps it onto the schema model.
 */
export interface CatalogSnapshot {
  readonly serverVersion: string;
  /** True when more tables existed than the cap allows and the list was cut. */
  readonly truncated: boolean;
  readonly tables: readonly CatalogTable[];
  readonly views: readonly CatalogView[];
}

export interface CatalogColumn {
  readonly name: string;
  readonly type: string;
  readonly notNull: boolean;
  readonly default: string | null;
  readonly generated: boolean;
  readonly enumLabels: readonly string[] | null;
}

export interface CatalogForeignKey {
  readonly columns: readonly string[];
  readonly refSchema: string;
  readonly refTable: string;
  readonly refColumns: readonly string[];
}

export interface CatalogTable {
  readonly schema: string;
  readonly name: string;
  readonly rls: boolean;
  readonly forceRls: boolean;
  readonly columns: readonly CatalogColumn[];
  readonly primaryKey: readonly string[];
  readonly unique: readonly string[];
  readonly foreignKeys: readonly CatalogForeignKey[];
  readonly checks: readonly string[];
  readonly policies: readonly CatalogPolicy[];
  readonly privileges: Readonly<Record<ClientRole, readonly Command[]>>;
}

export interface CatalogPolicy {
  readonly name: string;
  readonly command: "select" | "insert" | "update" | "delete" | "all";
  readonly permissive: boolean;
  readonly roles: readonly string[];
  readonly using: string | null;
  readonly withCheck: string | null;
}

export interface CatalogView {
  readonly schema: string;
  readonly name: string;
  readonly columns: readonly string[];
  readonly securityInvoker: boolean;
  readonly definition: string;
  readonly dependsOn: readonly { readonly schema: string; readonly name: string }[];
  readonly privileges: Readonly<Record<ClientRole, readonly Command[]>>;
}

const ident = string({ max: 200, min: 1 });
const expr = nullable(string({ max: 20_000 }));
const commands = array(literal<Command>("select", "insert", "update", "delete"), { max: 4 });
const privileges = object({ anon: commands, authenticated: commands });

const column: Validator<CatalogColumn> = object({
  name: ident,
  type: string({ max: 300, min: 1 }),
  notNull: boolean,
  default: expr,
  generated: boolean,
  enumLabels: nullable(array(string({ max: 200 }), { max: 500 })),
});

const foreignKey: Validator<CatalogForeignKey> = object({
  columns: array(ident, { max: 32 }),
  refSchema: ident,
  refTable: ident,
  refColumns: array(ident, { max: 32 }),
});

const policy: Validator<CatalogPolicy> = object({
  name: string({ max: 300 }),
  command: literal("select", "insert", "update", "delete", "all"),
  permissive: boolean,
  roles: array(string({ max: 200 }), { max: 50 }),
  using: expr,
  withCheck: expr,
});

const table: Validator<CatalogTable> = object({
  schema: ident,
  name: ident,
  rls: boolean,
  forceRls: boolean,
  columns: array(column, { max: 1_000 }),
  primaryKey: array(ident, { max: 32 }),
  unique: array(ident, { max: 1_000 }),
  foreignKeys: array(foreignKey, { max: 200 }),
  checks: array(string({ max: 5_000 }), { max: 500 }),
  policies: array(policy, { max: 500 }),
  privileges,
});

const view: Validator<CatalogView> = object({
  schema: ident,
  name: ident,
  columns: array(string({ max: 200 }), { max: 1_000 }),
  securityInvoker: boolean,
  definition: string({ max: 100_000 }),
  dependsOn: array(object({ schema: ident, name: ident }), { max: 200 }),
  privileges,
});

const snapshot: Validator<CatalogSnapshot> = object({
  serverVersion: string({ max: 100 }),
  truncated: boolean,
  tables: array(table, { max: LIMITS.maxTables }),
  views: array(view, { max: LIMITS.maxTables }),
});

/** Validate the JSON the database returned. The error names a path, never the value. */
export function parseCatalog(value: unknown): Result<CatalogSnapshot, string> {
  return snapshot(value, "catalog");
}

function toTable(t: CatalogTable): Table {
  const refs = new Map<string, { schema: string; table: string; column: string }>();
  for (const fk of t.foreignKeys) {
    fk.columns.forEach((c, i) => {
      const target = fk.refColumns[i];
      if (target !== undefined) refs.set(c, { schema: fk.refSchema, table: fk.refTable, column: target });
    });
  }
  const pk = new Set(t.primaryKey);
  const unique = new Set(t.unique);
  const columns: Column[] = t.columns.map((c) => ({
    name: c.name,
    type: c.type.toLowerCase(),
    notNull: c.notNull || pk.has(c.name),
    hasDefault: c.default !== null,
    defaultExpr: c.default,
    generated: c.generated,
    primaryKey: pk.has(c.name),
    unique: unique.has(c.name) || (pk.size === 1 && pk.has(c.name)),
    references: refs.get(c.name) ?? null,
    enumLabels: c.enumLabels,
  }));
  const policies: Policy[] = t.policies.map((p) => ({
    name: p.name,
    command: p.command,
    permissive: p.permissive,
    roles: p.roles.map((r) => r.toLowerCase()),
    using: p.using,
    withCheck: p.withCheck,
  }));
  return {
    name: { schema: t.schema, name: t.name },
    columns,
    rlsEnabled: t.rls,
    rlsForced: t.forceRls,
    policies,
    checks: t.checks,
    privileges: t.privileges,
    origin: "catalog",
  };
}

function toView(v: CatalogView): View {
  return {
    name: { schema: v.schema, name: v.name },
    columns: v.columns,
    securityInvoker: v.securityInvoker,
    definition: v.definition,
    dependsOn: v.dependsOn.map((d) => ({ schema: d.schema, name: d.name })),
    privileges: v.privileges,
    origin: "catalog",
  };
}

/** Deterministic order: schema, then name. */
export function catalogToModel(s: CatalogSnapshot): SchemaModel {
  const byName = <T extends { name: { schema: string; name: string } }>(a: T, b: T): number =>
    a.name.schema === b.name.schema ? (a.name.name < b.name.name ? -1 : a.name.name > b.name.name ? 1 : 0) : a.name.schema < b.name.schema ? -1 : 1;
  return { tables: s.tables.map(toTable).sort(byName), views: s.views.map(toView).sort(byName) };
}

export function emptySnapshot(serverVersion: string): Result<CatalogSnapshot, never> {
  return ok({ serverVersion, truncated: false, tables: [], views: [] });
}
