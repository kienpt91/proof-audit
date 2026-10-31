import { randomBytes } from "node:crypto";
import { SandboxError, type CreatedSandbox, type SandboxProvider } from "../../application/ports.js";
import type { LoopbackEndpoint } from "../../domain/safety/loopback.js";
import { quoteIdent } from "../../domain/sql/quote.js";
import { randomNaming } from "./names.js";
import { PgTransport } from "./pg-transport.js";
import { PostgresSandbox } from "./sandbox.js";
import type { Accounts } from "./transport.js";

export interface UrlProviderOptions {
  readonly statementTimeoutMs?: number;
  /** Allow the server to hold databases other than `postgres` and this tool's own: the user says it is a throwaway. */
  readonly yesThisIsThrowaway?: boolean;
}

/**
 * Uses a Postgres server the user started on this machine for testing. The analysis runs in a database of its
 * own inside that server and drops it afterwards. The connecting role must be a superuser (it creates roles and
 * databases), but it only ever runs statements written by this tool: everything from the project runs as a role
 * created for this run without superuser rights, so `COPY ... PROGRAM`, server-side files, `ALTER SYSTEM` and
 * untrusted extensions are not available to it. The roles anon, authenticated and service_role are created in the
 * server if they are missing. Loopback does not mean local (a tunnel or a published port can lead anywhere), so the
 * server is refused unless it holds nothing besides `postgres` and this tool's own databases, or the user passed
 * `yesThisIsThrowaway`.
 */
export class UrlSandboxProvider implements SandboxProvider {
  private readonly live = new Set<PostgresSandbox>();

  constructor(
    private readonly endpoint: LoopbackEndpoint,
    private readonly options: UrlProviderOptions = {},
  ) {}

  async create(): Promise<CreatedSandbox> {
    const suffix = randomBytes(5).toString("hex");
    const accounts: Accounts = {
      admin: { user: this.endpoint.user, password: this.endpoint.password },
      migrator: { user: `pa_migrator_${suffix}`, password: randomBytes(16).toString("hex") },
      prober: { user: `pa_prober_${suffix}`, password: randomBytes(16).toString("hex") },
    };
    const transport = new PgTransport(this.endpoint, accounts);
    const spec = { database: this.endpoint.database, principal: "admin", pin: "catalog", statementTimeoutMs: 20_000 } as const;
    const [isSuper, others] = await transport.run(spec, [
      { sql: "SELECT pg_catalog.current_setting('is_superuser')", fetch: true },
      { sql: "SELECT coalesce(pg_catalog.string_agg(datname, ', ' ORDER BY datname), '') FROM pg_catalog.pg_database WHERE NOT datistemplate AND datname <> 'postgres' AND datname <> pg_catalog.current_database() AND datname NOT LIKE 'proof\\_audit\\_%'", fetch: true },
    ]);
    if (isSuper !== "on") throw new SandboxError("the database role in the URL must be a superuser of the throwaway server");
    if (!this.options.yesThisIsThrowaway && others !== undefined && others !== "") {
      const shown = others.split(", ").slice(0, 5).join(", ");
      throw new SandboxError(`refusing to use this server: it holds other databases (${shown}). Loopback does not prove a server is a throwaway (a tunnel or a published port can lead anywhere). If it is, pass --yes-this-is-throwaway`);
    }
    const sandbox = await PostgresSandbox.create(transport, randomNaming(this.endpoint.database, this.options.statementTimeoutMs), { accounts, passwords: { migrator: accounts.migrator.password, prober: accounts.prober.password } }, async () => {
      this.live.delete(sandbox);
      await transport
        .run({ ...spec, database: this.endpoint.database }, [`DROP ROLE IF EXISTS ${quoteIdent(accounts.prober.user)}`, `DROP ROLE IF EXISTS ${quoteIdent(accounts.migrator.user)}`].map((s) => ({ sql: s, fetch: false })))
        .catch(() => undefined);
    });
    this.live.add(sandbox);
    return { sandbox, environment: { mode: "url", image: "loopback" } };
  }

  async disposeAll(): Promise<void> {
    await Promise.all([...this.live].map((s) => s.dispose()));
  }
}
