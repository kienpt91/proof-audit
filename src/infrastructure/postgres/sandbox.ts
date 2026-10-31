import type { GroupOutcome, ProbeRun, Sandbox, ScalarOutcome, StatementOutcome } from "../../application/ports.js";
import type { ProbeObservation } from "../../domain/proof/types.js";
import { dollarQuote, quoteIdent, quoteLiteral } from "../../domain/sql/quote.js";
import { HARNESS_STATEMENTS } from "./harness.js";
import { TransportError, type SqlTransport } from "./transport.js";

interface Reply {
  readonly ok?: unknown;
  readonly sqlstate?: unknown;
  readonly message?: unknown;
  readonly rows?: unknown;
  readonly attempt?: unknown;
  readonly value?: unknown;
}

function reply(cell: string | undefined): Reply {
  if (cell === undefined) throw new TransportError("the database returned fewer results than statements sent");
  try {
    const parsed: unknown = JSON.parse(cell);
    if (typeof parsed === "object" && parsed !== null) return parsed as Reply;
  } catch {
    // fall through
  }
  throw new TransportError("the database returned something that is not a harness reply");
}

const text = (v: unknown, fallback: string): string => (typeof v === "string" ? v : fallback);

export interface SandboxNaming {
  /** Creates database names; injected so the adapter stays free of randomness in tests. */
  readonly nextName: () => string;
  /** The database to connect to for CREATE and DROP DATABASE. */
  readonly maintenanceDatabase: string;
  /** Server-side limit for any single statement; defaults to 20 s. */
  readonly statementTimeoutMs?: number;
}

/** Per-database settings. They are not copied by CREATE DATABASE ... TEMPLATE, so forks get them again. */
function settings(database: string, naming: SandboxNaming): string[] {
  const db = quoteIdent(database);
  const timeout = Math.max(100, Math.floor(naming.statementTimeoutMs ?? 20_000));
  return [
    `ALTER DATABASE ${db} SET search_path TO "$user", public, extensions`,
    `ALTER DATABASE ${db} SET statement_timeout = ${timeout}`,
    `ALTER DATABASE ${db} SET lock_timeout = 5000`,
    `ALTER DATABASE ${db} SET idle_in_transaction_session_timeout = 30000`,
  ];
}

/**
 * The sandbox on top of any transport. Each operation is one SELECT per item against the harness functions,
 * so the SQL under analysis only ever runs inside `proof_audit.try_exec` / `run_probe` as a string.
 */
export class PostgresSandbox implements Sandbox {
  private disposed = false;

  constructor(
    private readonly transport: SqlTransport,
    private readonly database: string,
    private readonly naming: SandboxNaming,
    private readonly onDispose: () => Promise<void> = async () => undefined,
  ) {}

  /** Create the database, install the harness and return a sandbox for it. */
  static async create(transport: SqlTransport, naming: SandboxNaming, onDispose?: () => Promise<void>): Promise<PostgresSandbox> {
    const name = naming.nextName();
    await transport.execute(naming.maintenanceDatabase, [`CREATE DATABASE ${quoteIdent(name)}`]);
    const sandbox = new PostgresSandbox(transport, name, naming, onDispose);
    try {
      await transport.execute(name, HARNESS_STATEMENTS);
      await transport.execute(naming.maintenanceDatabase, settings(name, naming));
    } catch (e) {
      await sandbox.dispose();
      throw e;
    }
    return sandbox;
  }

  async apply(statements: readonly string[]): Promise<StatementOutcome[]> {
    if (statements.length === 0) return [];
    const cells = await this.transport.query(this.database, statements.map((s) => `SELECT proof_audit.try_exec(${dollarQuote(s)})::text`));
    return cells.map((c) => {
      const r = reply(c);
      return r.ok === true ? { ok: true, sqlstate: null, message: null } : { ok: false, sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
    });
  }

  async applyFirstSuccess(groups: readonly (readonly string[])[]): Promise<GroupOutcome[]> {
    if (groups.length === 0) return [];
    const cells = await this.transport.query(
      this.database,
      groups.map((g) => `SELECT proof_audit.try_first(ARRAY[${g.map(dollarQuote).join(", ")}]::text[])::text`),
    );
    return cells.map((c) => {
      const r = reply(c);
      if (r.ok === true) return { ok: true, attempt: typeof r.attempt === "number" ? r.attempt : 0, sqlstate: null, message: null };
      return { ok: false, attempt: null, sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
    });
  }

  async scalars(queries: readonly string[]): Promise<ScalarOutcome[]> {
    if (queries.length === 0) return [];
    const cells = await this.transport.query(this.database, queries.map((q) => `SELECT proof_audit.scalar(${dollarQuote(q)})::text`));
    return cells.map((c): ScalarOutcome => {
      const r = reply(c);
      if (r.ok === true) return { ok: true, value: typeof r.value === "string" || typeof r.value === "number" ? r.value : null };
      return { ok: false, sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
    });
  }

  async catalog(): Promise<unknown> {
    const [cell] = await this.transport.query(this.database, ["SELECT proof_audit.catalog()::text"]);
    if (cell === undefined) throw new TransportError("the database returned no catalog");
    return JSON.parse(cell) as unknown;
  }

  async run(probes: readonly ProbeRun[]): Promise<ProbeObservation[]> {
    if (probes.length === 0) return [];
    const statements = probes.map((p) => `SELECT proof_audit.run_probe(${quoteLiteral(p.role)}, ${quoteLiteral(p.claims)}, ${dollarQuote(p.sql)})::text`);
    let cells: string[];
    try {
      cells = await this.transport.query(this.database, statements);
    } catch (e) {
      const why = e instanceof Error ? e.message : "unknown error";
      return probes.map(() => ({ status: "not-run", reason: `the batch did not finish: ${why}` }));
    }
    return probes.map((_, i): ProbeObservation => {
      try {
        const r = reply(cells[i]);
        if (r.ok === true) return { status: "rows", rows: typeof r.rows === "number" ? r.rows : Number(r.rows ?? 0) };
        return { status: "error", sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
      } catch (e) {
        return { status: "not-run", reason: e instanceof Error ? e.message : "unreadable reply" };
      }
    });
  }

  async fork(): Promise<Sandbox> {
    const name = this.naming.nextName();
    await this.transport.execute(this.naming.maintenanceDatabase, [`CREATE DATABASE ${quoteIdent(name)} TEMPLATE ${quoteIdent(this.database)}`]);
    await this.transport.execute(this.naming.maintenanceDatabase, settings(name, this.naming));
    return new PostgresSandbox(this.transport, name, this.naming);
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    try {
      await this.transport.execute(this.naming.maintenanceDatabase, [`DROP DATABASE IF EXISTS ${quoteIdent(this.database)} WITH (FORCE)`]);
    } finally {
      await this.onDispose();
    }
  }
}
