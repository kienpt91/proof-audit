import type { GroupOutcome, ProbeRun, Sandbox, ScalarOutcome, StatementOutcome } from "../../src/application/ports.js";
import type { CatalogSnapshot } from "../../src/domain/catalog/snapshot.js";
import type { ProbeObservation } from "../../src/domain/proof/types.js";
import { analyzeExpression } from "../../src/domain/schema/expression.js";
import { detectOwnerColumns } from "../../src/domain/schema/owner.js";
import type { Command, SchemaModel, Table } from "../../src/domain/schema/model.js";
import { USER_A, USER_B } from "../../src/domain/supabase/identities.js";

/** The catalog JSON the real database would return for this model. */
export function modelToCatalog(model: SchemaModel, serverVersion = "16.14"): CatalogSnapshot {
  return {
    serverVersion,
    truncated: false,
    tables: model.tables.map((t) => ({
      schema: t.name.schema,
      name: t.name.name,
      rls: t.rlsEnabled,
      forceRls: t.rlsForced,
      columns: t.columns.map((c) => ({ name: c.name, type: c.type, notNull: c.notNull, default: c.defaultExpr ?? (c.hasDefault ? "default_value()" : null), generated: c.generated, enumLabels: c.enumLabels })),
      primaryKey: t.columns.filter((c) => c.primaryKey).map((c) => c.name),
      unique: t.columns.filter((c) => c.unique).map((c) => c.name),
      foreignKeys: t.columns.flatMap((c) => (c.references ? [{ columns: [c.name], refSchema: c.references.schema, refTable: c.references.table, refColumns: [c.references.column] }] : [])),
      checks: [...t.checks],
      policies: t.policies.map((p) => ({ name: p.name, command: p.command, permissive: p.permissive, roles: [...p.roles], using: p.using, withCheck: p.withCheck })),
      privileges: { anon: [...t.privileges.anon], authenticated: [...t.privileges.authenticated] },
    })),
    views: model.views.map((v) => ({
      schema: v.name.schema,
      name: v.name.name,
      columns: [...v.columns],
      securityInvoker: v.securityInvoker,
      definition: v.definition ?? "",
      dependsOn: v.dependsOn.map((d) => ({ ...d })),
      privileges: { anon: [...v.privileges.anon], authenticated: [...v.privileges.authenticated] },
    })),
  };
}

type Selector = "all" | "own" | "other";

interface Parsed {
  readonly command: Command;
  readonly target: string;
  readonly selector: Selector;
  readonly reassign: boolean;
  readonly nullOwner: boolean;
  readonly insertsOther: boolean;
}

function parse(sql: string): Parsed {
  const m = /^(SELECT \* FROM|INSERT INTO|UPDATE|DELETE FROM) "([^"]+)"\."([^"]+)"/.exec(sql);
  if (!m) throw new Error(`ModelSandbox cannot read probe SQL: ${sql}`);
  const command: Command = m[1] === "INSERT INTO" ? "insert" : m[1] === "UPDATE" ? "update" : m[1] === "DELETE FROM" ? "delete" : "select";
  const where = /WHERE "[^"]+"::text = '([^']+)'/.exec(sql)?.[1];
  const selector: Selector = where === undefined ? "all" : where === USER_A.id || where === "1" ? "own" : "other";
  return {
    command,
    target: `${m[2]}.${m[3]}`,
    selector,
    reassign: /SET "[^"]+" = '(bbbb|2)/.test(sql) && command === "update",
    nullOwner: command === "insert" && /\bNULL\b/.test(sql),
    insertsOther: command === "insert" && sql.includes(USER_B.id),
  };
}

function grantFor(table: Table, role: "anon" | "authenticated", command: Command, check: boolean): "all" | "own" | "none" {
  const owners = detectOwnerColumns(table).map((o) => o.column);
  let best: "all" | "own" | "none" = "none";
  for (const p of table.policies) {
    if (!p.permissive || !(p.roles.includes(role) || p.roles.includes("public"))) continue;
    if (!(p.command === "all" || p.command === command)) continue;
    const expr = check ? (p.withCheck ?? (p.command === "all" || command === "update" ? p.using : null)) : p.using;
    const facts = analyzeExpression(expr, owners);
    if (facts.alwaysTrue) return "all";
    if (facts.callerBoundColumns.length > 0 && role === "authenticated") best = "own";
  }
  return best;
}

const DENIED: ProbeObservation = { status: "error", sqlstate: "42501", message: "permission denied" };

/** What the platform fingerprint looks like in the fake; `tamperedAfter` makes it differ from that call on. */
const FINGERPRINT = [{ key: "function auth.uid()", value: "owner=supabase_admin;sha=1" }, { key: "role anon", value: "super=false" }];

export interface ModelSandboxOptions {
  /** Return a different fingerprint from this call (1-based) on, as if something had changed the platform. */
  readonly tamperedAfter?: number;
  readonly model: SchemaModel;
  /** What the database looks like after the proposed fix is applied. */
  readonly fixed?: SchemaModel;
  readonly rejectStatement?: RegExp;
  readonly rowsPerOwner?: number;
}

/** A small stand-in for Postgres that answers probes from the policies in a schema model. Only for offline tests. */
export class ModelSandbox implements Sandbox {
  readonly applied: string[] = [];
  disposed = false;
  forks = 0;

  constructor(private readonly options: ModelSandboxOptions, private readonly isFork = false) {}

  private get model(): SchemaModel {
    return this.isFork && this.options.fixed ? this.options.fixed : this.options.model;
  }

  async apply(statements: readonly string[]): Promise<StatementOutcome[]> {
    return statements.map((s) => {
      this.applied.push(s);
      return this.options.rejectStatement?.test(s) ? { ok: false, sqlstate: "42P01", message: "relation does not exist" } : { ok: true, sqlstate: null, message: null };
    });
  }

  async applyFirstSuccess(groups: readonly (readonly string[])[]): Promise<GroupOutcome[]> {
    return groups.map(() => ({ ok: true, attempt: 0, sqlstate: null, message: null }));
  }

  async scalars(queries: readonly string[]): Promise<ScalarOutcome[]> {
    const per = this.options.rowsPerOwner ?? 1;
    return queries.map((q) => {
      if (q === "SELECT NULL") return { ok: true, value: null };
      return { ok: true, value: q.includes("WHERE") ? per : per * 2 };
    });
  }

  fingerprintCalls = 0;

  async fingerprint(): Promise<unknown> {
    this.fingerprintCalls += 1;
    const tampered = this.options.tamperedAfter !== undefined && this.fingerprintCalls >= this.options.tamperedAfter;
    return { entries: tampered ? [...FINGERPRINT, { key: "event trigger evil", value: "enabled=O" }] : FINGERPRINT };
  }

  async catalog(): Promise<unknown> {
    return modelToCatalog(this.model);
  }

  async run(probes: readonly ProbeRun[]): Promise<ProbeObservation[]> {
    return probes.map((p) => this.observe(p));
  }

  private observe(run: ProbeRun): ProbeObservation {
    const q = parse(run.sql);
    const per = this.options.rowsPerOwner ?? 1;
    const key = q.target;
    const view = this.model.views.find((v) => `${v.name.schema}.${v.name.name}` === key);
    if (view) {
      if (!view.privileges[run.role].includes("select")) return DENIED;
      if (!view.securityInvoker) return { status: "rows", rows: q.selector === "all" ? per * 2 : per };
      return run.role === "anon" || q.selector === "other" ? { status: "rows", rows: 0 } : { status: "rows", rows: per };
    }
    const table = this.model.tables.find((t) => `${t.name.schema}.${t.name.name}` === key);
    if (!table) return { status: "error", sqlstate: "42P01", message: "relation does not exist" };
    if (!table.privileges[run.role].includes(q.command)) return DENIED;
    const total = table.columns.some((c) => c.name === "user_id") ? per * 2 : per;
    const rowsFor = q.selector === "all" ? total : per;
    if (!table.rlsEnabled) return q.command === "insert" ? { status: "rows", rows: 1 } : { status: "rows", rows: rowsFor };
    const grant = grantFor(table, run.role, q.command, q.command === "insert");
    if (q.command === "insert") {
      if (grant === "all") return { status: "rows", rows: 1 };
      if (grant === "own" && !q.insertsOther && !q.nullOwner) return { status: "rows", rows: 1 };
      return DENIED;
    }
    if (grant === "none") return { status: "rows", rows: 0 };
    if (q.command === "update" && q.reassign) {
      const check = grantFor(table, run.role, "update", true);
      return check === "all" ? { status: "rows", rows: per } : DENIED;
    }
    if (grant === "all") return { status: "rows", rows: rowsFor };
    return { status: "rows", rows: q.selector === "own" ? per : 0 };
  }

  async fork(): Promise<Sandbox> {
    this.forks += 1;
    return new ModelSandbox(this.options, true);
  }

  async dispose(): Promise<void> {
    this.disposed = true;
  }
}
