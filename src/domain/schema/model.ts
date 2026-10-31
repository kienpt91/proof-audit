/**
 * The schema model every analysis works on. It is produced twice: once from the migration text by the
 * SQL reader (static view, `origin: "parsed"`) and once from the throwaway database's catalog after the
 * migrations were applied (`origin: "catalog"`). Both produce the same shapes so one set of rules
 * serves both.
 */

export type Command = "select" | "insert" | "update" | "delete";
export const COMMANDS: readonly Command[] = ["select", "insert", "update", "delete"];

/** A policy applies to one command, or to all of them. */
export type PolicyCommand = Command | "all";

/** The two roles a Supabase client key maps to. `service_role` bypasses RLS by design and is not probed. */
export type ClientRole = "anon" | "authenticated";
export const CLIENT_ROLES: readonly ClientRole[] = ["anon", "authenticated"];

export interface QualifiedName {
  readonly schema: string;
  readonly name: string;
}

export function qualified(schema: string, name: string): QualifiedName {
  return { schema, name };
}

/** Stable map key, e.g. `public.notes`. Not for use in SQL (identifiers are not quoted). */
export function qualifiedKey(q: QualifiedName): string {
  return `${q.schema}.${q.name}`;
}

export interface ColumnRef {
  readonly schema: string;
  readonly table: string;
  readonly column: string;
}

export interface Column {
  readonly name: string;
  /** Lower-case type text as Postgres prints it, e.g. `uuid`, `character varying(255)`, `timestamp with time zone`, `text[]`. */
  readonly type: string;
  readonly notNull: boolean;
  readonly hasDefault: boolean;
  readonly defaultExpr: string | null;
  /** `GENERATED ALWAYS` (stored or identity): the column cannot be written by an INSERT or UPDATE. */
  readonly generated: boolean;
  readonly primaryKey: boolean;
  readonly unique: boolean;
  readonly references: ColumnRef | null;
  /** Labels when the type is an enum (catalog model only). */
  readonly enumLabels: readonly string[] | null;
}

export interface Policy {
  readonly name: string;
  readonly command: PolicyCommand;
  readonly permissive: boolean;
  /** Lower-case role names; `["public"]` when the policy names no role. */
  readonly roles: readonly string[];
  readonly using: string | null;
  readonly withCheck: string | null;
}

export interface Table {
  readonly name: QualifiedName;
  readonly columns: readonly Column[];
  readonly rlsEnabled: boolean;
  readonly rlsForced: boolean;
  readonly policies: readonly Policy[];
  /** Text of CHECK constraints, e.g. `CHECK ((status = ANY (ARRAY['draft'::text, 'live'::text])))`. */
  readonly checks: readonly string[];
  /** Table-level privileges each client role holds. */
  readonly privileges: Readonly<Record<ClientRole, readonly Command[]>>;
  readonly origin: "parsed" | "catalog";
}

export interface View {
  readonly name: QualifiedName;
  readonly columns: readonly string[];
  /** `security_invoker = true`: the view runs with the caller's rights and RLS applies. */
  readonly securityInvoker: boolean;
  readonly definition: string | null;
  /** Tables and views the definition reads. */
  readonly dependsOn: readonly QualifiedName[];
  readonly privileges: Readonly<Record<ClientRole, readonly Command[]>>;
  readonly origin: "parsed" | "catalog";
}

export interface SchemaModel {
  readonly tables: readonly Table[];
  readonly views: readonly View[];
}

export const EMPTY_MODEL: SchemaModel = { tables: [], views: [] };

export function findTable(model: SchemaModel, key: string): Table | undefined {
  return model.tables.find((t) => qualifiedKey(t.name) === key);
}

/** A problem met while reading input, with enough position to find it. Never aborts a run. */
export interface Warning {
  readonly file: string;
  /** 1-based line of the start of the statement, 0 when not tied to a line. */
  readonly line: number;
  readonly message: string;
}
