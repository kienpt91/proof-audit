/**
 * How SQL reaches a throwaway database. Two implementations exist: `psql` run inside the sandbox container
 * through `docker exec` (no network at all), and a `pg` client for a loopback URL. Everything above this
 * interface is identical for both.
 *
 * Every call names the database role to log in as. The sandbox has three (see `src/domain/supabase/shim.ts`):
 * the admin (a superuser that only runs statements written by this tool), the migrator (a non-superuser that runs
 * everything that comes from the project under analysis) and the prober. Sessions are opened with their
 * settings pinned in the connection itself, which overrides anything a migration stored with `ALTER DATABASE ... SET`.
 */
export interface Account {
  readonly user: string;
  /** Null when the server trusts the connection (the container's unix socket). */
  readonly password: string | null;
}

export interface Accounts {
  readonly admin: Account;
  readonly migrator: Account;
  readonly prober: Account;
}

export type Principal = keyof Accounts;

/**
 * - `session`: search_path as on the platform, for the migrator.
 * - `probe`: the same, for the prober.
 * - `catalog`: `pg_catalog` only, for the admin's reads and provisioning, so nothing the migrations create can be resolved.
 */
export type Pin = "session" | "probe" | "catalog";

export interface SessionSpec {
  readonly database: string;
  readonly principal: Principal;
  readonly pin: Pin;
  readonly statementTimeoutMs: number;
}

/** One statement. When `fetch` is set it must return one text value, which is handed back. */
export interface Step {
  readonly sql: string;
  readonly fetch: boolean;
}

export interface SqlTransport {
  /** Run the steps in order in ONE session. Returns the value of every `fetch` step. Throws on the first error of a step that is not wrapped. */
  run(session: SessionSpec, steps: readonly Step[]): Promise<string[]>;
}

export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransportError";
  }
}

/** The connection-level settings of a session, as name/value pairs. */
export function pinnedSettings(session: SessionSpec): readonly (readonly [string, string])[] {
  const timeout = String(Math.max(100, Math.floor(session.statementTimeoutMs)));
  if (session.pin === "catalog") return [["search_path", "pg_catalog"], ["statement_timeout", "60000"], ["row_security", "on"]];
  return [
    ["search_path", "public,extensions"],
    ["statement_timeout", timeout],
    ["lock_timeout", "5000"],
    ["idle_in_transaction_session_timeout", "30000"],
    ["row_security", "on"],
  ];
}
