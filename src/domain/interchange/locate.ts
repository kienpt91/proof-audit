import { baseTables } from "../proof/plan.js";
import type { SchemaModel, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import type { SourceIndex, SourceSpot, SqlStatement } from "../sql/statement.js";
import { tokenize } from "../sql/tokenizer.js";
import type { RootCause } from "./rootcause.js";
import type { TraceStep } from "./records.js";

/** What the SQL reader knows about where things are declared. */
export interface SourceMap {
  readonly statements: readonly SqlStatement[];
  readonly sources: SourceIndex;
}

/** A trace into the migration SQL and the statement the record's evidence should point at. */
export interface Located {
  readonly trace: readonly TraceStep[];
  readonly anchor: SourceSpot;
}

/**
 * The first statement that names every one of `names` as an identifier. This is the fallback for an object the
 * reader did not see declared (created by a statement it could not read); it finds a real statement rather than
 * guessing a line.
 */
export function findMention(statements: readonly SqlStatement[], names: readonly string[]): SourceSpot | null {
  for (const s of statements) {
    if (s.kind !== "sql") continue;
    const idents = tokenize(s.text).filter((t) => t.kind === "word" || t.kind === "quoted-ident");
    const mentions = (name: string): boolean => idents.some((t) => t.value === (t.kind === "word" ? name.toLowerCase() : name));
    if (names.every(mentions)) return { file: s.file, line: s.line };
  }
  return null;
}

function step(kind: TraceStep["kind"], spot: SourceSpot, scope: string, description: string): TraceStep {
  return { kind, file: spot.file, line: spot.line, scope, description };
}

function dedupe(steps: readonly TraceStep[]): TraceStep[] {
  const seen = new Set<string>();
  return steps.filter((s) => {
    const key = JSON.stringify(s);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Where the statement for a policy is: the reader's index, else the first statement that names both the policy and the table. */
function policySpot(src: SourceMap, tableKey: string, tableName: string, policy: string): SourceSpot | null {
  return src.sources.tables.get(tableKey)?.policies.get(policy) ?? findMention(src.statements, [policy, tableName]);
}

function createdSpot(src: SourceMap, key: string, name: string): SourceSpot | null {
  return src.sources.tables.get(key)?.created ?? findMention(src.statements, [name]);
}

const SINK = "The table that holds the rows the probes read and changed.";

/**
 * The trace of one table-level root cause: where access is granted (entrypoint), the statements that carry it
 * (propagation) and the table whose rows are exposed (sink). Null only when no statement of the migrations
 * can be found for the table.
 */
export function locateTableCause(src: SourceMap, table: Table, cause: RootCause | null, untested: boolean): Located | null {
  const key = qualifiedKey(table.name);
  const created = createdSpot(src, key, table.name.name);
  if (created === null) return null;
  const scope = `table ${key}`;
  const rls = src.sources.tables.get(key)?.rowSecurity ?? null;
  const sink = step("sink", created, scope, SINK);

  if (cause === null) {
    const what = untested ? "The table that could not be fully tested." : "The table the proven attacks ran against; no policy or setting the static reader found explains them.";
    return { trace: [step("sink", created, scope, what)], anchor: created };
  }
  if (cause.kind === "rls-disabled") {
    const entry = step("entrypoint", created, scope, "CREATE TABLE exposes the table to the anon and authenticated roles through the Supabase default privileges, and row level security is not on for it.");
    const middle = rls === null ? [] : [step("propagation", rls, scope, "The last ALTER TABLE that changed row level security on this table leaves it switched off.")];
    return { trace: dedupe([entry, ...middle, sink]), anchor: created };
  }
  if (cause.policy !== null) {
    const spot = policySpot(src, key, table.name.name, cause.policy.name);
    const located = spot ?? created;
    const note = spot === null ? " The statement that defines the policy could not be found; this is the table declaration." : "";
    const entry = step("entrypoint", located, `policy "${cause.policy.name}" on ${key}`, `${cause.text}${note}`);
    const middle = rls === null ? [] : [step("propagation", rls, scope, "Row level security is on, so policies decide access; this policy admits the rows.")];
    return { trace: dedupe([entry, ...middle, sink]), anchor: located };
  }
  // owner-not-compared: every policy of the table is part of the cause.
  const first = rls ?? created;
  const entry = step("entrypoint", first, scope, cause.text);
  const policies = [...table.policies]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .slice(0, 10)
    .flatMap((p) => {
      const spot = policySpot(src, key, table.name.name, p.name);
      return spot === null ? [] : [step("propagation", spot, `policy "${p.name}" on ${key}`, "This policy never compares the owner column with the signed-in user.")];
    });
  return { trace: dedupe([entry, ...policies, sink]), anchor: first };
}

/** The trace of a view that bypasses row level security: the view, then the protected tables it reads. */
export function locateViewCause(src: SourceMap, view: View, model: SchemaModel, cause: RootCause | null, untested: boolean): Located | null {
  const key = qualifiedKey(view.name);
  const spot = src.sources.views.get(key) ?? findMention(src.statements, [view.name.name]);
  if (spot === null) return null;
  const scope = `view ${key}`;
  if (cause === null) {
    const what = untested ? "The view that could not be fully tested." : "The view the proven attacks ran against; no setting the static reader found explains them.";
    return { trace: [step("sink", spot, scope, what)], anchor: spot };
  }
  const entry = step("entrypoint", spot, scope, cause.text);
  const bases = baseTables(view, model)
    .filter((t) => t.rlsEnabled)
    .flatMap((t) => {
      const base = createdSpot(src, qualifiedKey(t.name), t.name.name);
      return base === null ? [] : [{ t, base }];
    });
  const steps = bases.map(({ t, base }, i) => step(i === bases.length - 1 ? "sink" : "propagation", base, `table ${qualifiedKey(t.name)}`, "A table with row level security that the view reads with its owner's rights."));
  return { trace: dedupe([entry, ...steps]), anchor: spot };
}

/** The trace of a finding of the static auditor: the policy it flagged (or the table), then the table. */
export function locateStatic(src: SourceMap, table: string, policy: string | null, flagged: string): Located | null {
  const name = table.slice(table.indexOf(".") + 1);
  const created = createdSpot(src, table, name);
  if (created === null) return null;
  const scope = `table ${table}`;
  const sink = step("sink", created, scope, SINK);
  const spot = policy === null ? null : policySpot(src, table, name, policy);
  if (spot === null) return { trace: dedupe([step("entrypoint", created, scope, flagged), sink]), anchor: created };
  return { trace: dedupe([step("entrypoint", spot, `policy "${policy}" on ${table}`, flagged), sink]), anchor: spot };
}
