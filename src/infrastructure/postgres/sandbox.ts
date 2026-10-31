import type { GroupOutcome, ProbeRun, Sandbox, ScalarOutcome, StatementOutcome } from "../../application/ports.js";
import type { ProbeObservation } from "../../domain/proof/types.js";
import { quoteIdent } from "../../domain/sql/quote.js";
import { platformStatements, roleStatements, type PlatformNames, type RolePasswords } from "../../domain/supabase/shim.js";
import { CATALOG_QUERY, fingerprintQuery } from "./catalog-sql.js";
import * as sql from "./statements.js";
import { TransportError, type Accounts, type SessionSpec, type SqlTransport, type Step } from "./transport.js";

interface Reply {
  readonly ok?: unknown;
  readonly sqlstate?: unknown;
  readonly message?: unknown;
  readonly rows?: unknown;
  readonly attempt?: unknown;
  readonly value?: unknown;
}

function reply(cell: string | undefined): Reply {
  if (cell === undefined || cell === "") throw new TransportError("the database returned no reply for a statement");
  try {
    const parsed: unknown = JSON.parse(cell);
    if (typeof parsed === "object" && parsed !== null) return parsed as Reply;
  } catch {
    // fall through
  }
  throw new TransportError("the database returned something that is not a reply");
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

export interface SandboxSetup {
  readonly accounts: Accounts;
  readonly passwords: RolePasswords;
}

const DEFAULT_TIMEOUT = 20_000;

/**
 * The sandbox on top of any transport. Three database roles keep the project's SQL away from anything the verdicts
 * depend on: the migrator runs everything from the project and has no superuser rights, the prober runs the probes, the
 * admin only runs statements written by this tool (provisioning, the catalog read, the fingerprint, CREATE and DROP
 * DATABASE). No function is stored in the database for the tool to call; see `statements.ts`.
 */
export class PostgresSandbox implements Sandbox {
  private disposed = false;

  constructor(
    private readonly transport: SqlTransport,
    private readonly database: string,
    private readonly naming: SandboxNaming,
    private readonly accounts: Accounts,
    private readonly onDispose: () => Promise<void> = async () => undefined,
  ) {}

  private spec(database: string, principal: SessionSpec["principal"], pin: SessionSpec["pin"]): SessionSpec {
    return { database, principal, pin, statementTimeoutMs: this.naming.statementTimeoutMs ?? DEFAULT_TIMEOUT };
  }

  private static async admin(transport: SqlTransport, naming: SandboxNaming, database: string, statements: readonly string[]): Promise<void> {
    const steps: Step[] = statements.map((s) => ({ sql: s, fetch: false }));
    await transport.run({ database, principal: "admin", pin: "catalog", statementTimeoutMs: naming.statementTimeoutMs ?? DEFAULT_TIMEOUT }, steps);
  }

  private static names(accounts: Accounts): PlatformNames {
    return { admin: accounts.admin.user, migrator: accounts.migrator.user, prober: accounts.prober.user };
  }

  /** Create the sandbox's roles and database and provision the platform in it. The returned sandbox owns the database. */
  static async create(transport: SqlTransport, naming: SandboxNaming, setup: SandboxSetup, onDispose?: () => Promise<void>): Promise<PostgresSandbox> {
    const names = PostgresSandbox.names(setup.accounts);
    const name = naming.nextName();
    const maintenance = naming.maintenanceDatabase;
    const sandbox = new PostgresSandbox(transport, name, naming, setup.accounts, onDispose);
    try {
      await PostgresSandbox.admin(transport, naming, maintenance, roleStatements(names, setup.passwords));
      await PostgresSandbox.admin(transport, naming, maintenance, [`CREATE DATABASE ${quoteIdent(name)}`]);
      await PostgresSandbox.admin(transport, naming, name, platformStatements(names));
    } catch (e) {
      await sandbox.dispose().catch(() => undefined);
      throw e;
    }
    return sandbox;
  }

  private async fetchAll(session: SessionSpec, steps: readonly Step[]): Promise<string[]> {
    return this.transport.run(session, steps);
  }

  async apply(statements: readonly string[]): Promise<StatementOutcome[]> {
    if (statements.length === 0) return [];
    const cells = await this.fetchAll(this.spec(this.database, "migrator", "session"), statements.flatMap((s) => sql.tryExec(s)));
    return cells.map((c) => {
      const r = reply(c);
      return r.ok === true ? { ok: true, sqlstate: null, message: null } : { ok: false, sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
    });
  }

  async applyFirstSuccess(groups: readonly (readonly string[])[]): Promise<GroupOutcome[]> {
    if (groups.length === 0) return [];
    const cells = await this.fetchAll(this.spec(this.database, "migrator", "session"), groups.flatMap((g) => sql.tryFirst(g)));
    return cells.map((c) => {
      const r = reply(c);
      if (r.ok === true) return { ok: true, attempt: typeof r.attempt === "number" ? r.attempt : 0, sqlstate: null, message: null };
      return { ok: false, attempt: null, sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
    });
  }

  async scalars(queries: readonly string[]): Promise<ScalarOutcome[]> {
    if (queries.length === 0) return [];
    const cells = await this.fetchAll(this.spec(this.database, "migrator", "session"), queries.flatMap((q) => sql.scalar(q)));
    return cells.map((c): ScalarOutcome => {
      const r = reply(c);
      if (r.ok === true) return { ok: true, value: typeof r.value === "string" || typeof r.value === "number" ? r.value : null };
      return { ok: false, sqlstate: text(r.sqlstate, "?????"), message: text(r.message, "") };
    });
  }

  async catalog(): Promise<unknown> {
    const [cell] = await this.fetchAll(this.spec(this.database, "admin", "catalog"), [{ sql: CATALOG_QUERY, fetch: true }]);
    if (cell === undefined) throw new TransportError("the database returned no catalog");
    return JSON.parse(cell) as unknown;
  }

  async fingerprint(): Promise<unknown> {
    const names = [this.accounts.admin.user, this.accounts.migrator.user, this.accounts.prober.user];
    const [cell] = await this.fetchAll(this.spec(this.database, "admin", "catalog"), [{ sql: fingerprintQuery(names), fetch: true }]);
    if (cell === undefined) throw new TransportError("the database returned no fingerprint");
    return JSON.parse(cell) as unknown;
  }

  async run(probes: readonly ProbeRun[]): Promise<ProbeObservation[]> {
    if (probes.length === 0) return [];
    let cells: string[];
    try {
      cells = await this.fetchAll(this.spec(this.database, "prober", "probe"), probes.flatMap((p) => sql.probe(p.role, p.claims, p.sql)));
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
    await PostgresSandbox.admin(this.transport, this.naming, this.naming.maintenanceDatabase, [`CREATE DATABASE ${quoteIdent(name)} TEMPLATE ${quoteIdent(this.database)}`]);
    // Per-database settings are not copied by CREATE DATABASE ... TEMPLATE; the sessions pin what they need themselves.
    await PostgresSandbox.admin(this.transport, this.naming, name, [
      `DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET search_path TO "$user", public, extensions', current_database()); END $$`,
    ]);
    return new PostgresSandbox(this.transport, name, this.naming, this.accounts);
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    try {
      await PostgresSandbox.admin(this.transport, this.naming, this.naming.maintenanceDatabase, [`DROP DATABASE IF EXISTS ${quoteIdent(this.database)} WITH (FORCE)`]);
    } finally {
      await this.onDispose();
    }
  }
}
