/**
 * Guesses which column says "who owns this row": a user column (`user_id`, `created_by`, a foreign key to
 * `auth.users`) or a tenant column (`org_id`, `workspace_id`). Probes use the best guess to plant rows
 * for two different users and check whether one can reach the other's.
 */
import { tokenize } from "../sql/tokenizer.js";
import type { Column, Table } from "./model.js";

export type OwnerKind = "user" | "tenant";
export type OwnerConfidence = "high" | "medium" | "low";

export interface OwnerColumn {
  readonly column: string;
  readonly kind: OwnerKind;
  readonly confidence: OwnerConfidence;
  /** Human-readable evidence, one entry per heuristic that fired. */
  readonly reasons: readonly string[];
}

const STRONG_USER_NAMES: Record<string, true> = {
  user_id: true,
  owner_id: true,
  created_by: true,
  author_id: true,
  profile_id: true,
  creator_id: true,
  uid: true,
};
const WEAK_USER_NAMES: Record<string, true> = { user: true, owner: true };
const TENANT_NAMES: Record<string, true> = {
  tenant_id: true,
  org_id: true,
  organization_id: true,
  organisation_id: true,
  workspace_id: true,
  team_id: true,
  account_id: true,
  company_id: true,
};

const RANK: Record<OwnerConfidence, number> = { high: 3, medium: 2, low: 1 };

type TypeClass = "uuid" | "text" | "integer" | "other";

/** Groups a column type into the families an owner column can be made of. */
function typeClass(type: string): TypeClass {
  const t = type.trim().toLowerCase();
  if (t.endsWith("]")) return "other";
  if (t === "uuid") return "uuid";
  if (t === "text" || t === "citext" || t.startsWith("character") || t.startsWith("varchar") || t.startsWith("char(") || t === "char" || t === "bpchar") {
    return "text";
  }
  if (t === "bigint" || t === "integer" || t === "smallint" || t === "int" || t === "int4" || t === "int8" || t === "int2") return "integer";
  return "other";
}

/** `auth.uid()`, `(select auth.uid())`, `auth.uid()::uuid`. */
function defaultsToAuthUid(expr: string | null): boolean {
  if (expr === null) return false;
  const toks = tokenize(expr);
  let i = 0;
  const at = (k: number): string => toks[i + k]?.text.toLowerCase() ?? "";
  while (at(0) === "(" || at(0) === "select") i++;
  if (at(0) !== "auth" || at(1) !== "." || at(2) !== "uid" || at(3) !== "(" || at(4) !== ")") return false;
  i += 5;
  if (at(0) === "as" && toks[i + 1] !== undefined) i += 2; // `( SELECT auth.uid() AS uid)`
  while (at(0) === ")") i++;
  return i >= toks.length || at(0) === "::";
}

function referencesAuthUsers(column: Column): boolean {
  const ref = column.references;
  return ref !== null && ref.schema === "auth" && ref.table === "users";
}

interface Candidate {
  kind: OwnerKind;
  confidence: OwnerConfidence;
  reasons: string[];
}

function raise(current: OwnerConfidence | undefined, next: OwnerConfidence): OwnerConfidence {
  return current === undefined || RANK[next] > RANK[current] ? next : current;
}

function inspectColumn(column: Column): Candidate | null {
  const name = column.name.toLowerCase();
  const family = typeClass(column.type);
  const found: { candidate: Candidate | null } = { candidate: null };
  const add = (kind: OwnerKind, confidence: OwnerConfidence, ...reasons: string[]): void => {
    const current = found.candidate;
    if (current === null) {
      found.candidate = { kind, confidence, reasons: [...reasons] };
      return;
    }
    current.reasons.push(...reasons);
    if (current.kind === kind) current.confidence = raise(current.confidence, confidence);
  };

  // Identity-derived evidence first: it fixes the kind to `user` whatever the column is called.
  if (referencesAuthUsers(column)) add("user", "high", `references auth.users(${column.references?.column ?? "id"})`);
  if (defaultsToAuthUid(column.defaultExpr)) add("user", "high", "default is auth.uid()");

  if (family === "other") return found.candidate;
  const uuidNote = family === "uuid" ? [`uuid column named ${name}`] : [];

  if (STRONG_USER_NAMES[name] === true) {
    add("user", family === "uuid" ? "high" : "medium", `column name ${name} is a common owner column`, ...uuidNote);
  } else if (name.endsWith("_user_id") && name.length > "_user_id".length) {
    add("user", "medium", `column name ${name} ends in _user_id`);
  } else if (WEAK_USER_NAMES[name] === true) {
    add("user", "low", `column name ${name} may name an owner`);
  } else if (TENANT_NAMES[name] === true) {
    add("tenant", family === "uuid" || family === "text" ? "high" : "medium", `column name ${name} is a common tenant column`, ...uuidNote);
  }
  return found.candidate;
}

function compare(a: { owner: OwnerColumn; order: number }, b: { owner: OwnerColumn; order: number }): number {
  const byConfidence = RANK[b.owner.confidence] - RANK[a.owner.confidence];
  if (byConfidence !== 0) return byConfidence;
  if (a.owner.kind !== b.owner.kind) return a.owner.kind === "user" ? -1 : 1;
  return a.order - b.order;
}

/** Every plausible owner column, best first; ties keep table column order. */
export function detectOwnerColumns(table: Table): readonly OwnerColumn[] {
  const found: Array<{ owner: OwnerColumn; order: number }> = [];
  table.columns.forEach((column, order) => {
    const candidate = inspectColumn(column);
    // Profile-style table: the primary key `id` is itself the user's id.
    if (column.name.toLowerCase() === "id" && column.primaryKey && referencesAuthUsers(column)) {
      if (candidate !== null) {
        candidate.reasons.push("primary key id is the auth user, so each row is a user's profile");
      }
    }
    if (candidate !== null) {
      found.push({ owner: { column: column.name, kind: candidate.kind, confidence: candidate.confidence, reasons: candidate.reasons }, order });
    }
  });
  return found.sort(compare).map((f) => f.owner);
}

/** The column probes treat as "who owns this row": the best user column, else the best tenant column, at least medium confidence. */
export function primaryOwnerColumn(table: Table): OwnerColumn | null {
  const usable = detectOwnerColumns(table).filter((o) => o.confidence !== "low");
  return usable.find((o) => o.kind === "user") ?? usable.find((o) => o.kind === "tenant") ?? null;
}
