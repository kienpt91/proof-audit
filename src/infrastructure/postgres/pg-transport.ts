import pg from "pg";
import { LIMITS } from "../../domain/limits.js";
import { assertLoopbackHost, type LoopbackEndpoint } from "../../domain/safety/loopback.js";
import { pinnedSettings, TransportError, type Accounts, type SessionSpec, type SqlTransport, type Step } from "./transport.js";

/**
 * Talks to a Postgres server on this machine's loopback interface. The endpoint can only be built by
 * `parseLoopbackUrl`, and the host is checked again here, so no code path can point this at another machine.
 * Each call opens a session as the account of the requested role, with the session settings pinned in the
 * connection itself, and closes it afterwards.
 */
export class PgTransport implements SqlTransport {
  constructor(
    private readonly endpoint: LoopbackEndpoint,
    private readonly accounts: Accounts,
  ) {
    assertLoopbackHost(endpoint.host);
  }

  private async connect(session: SessionSpec): Promise<pg.Client> {
    const account = this.accounts[session.principal];
    const options = pinnedSettings(session).map(([name, value]) => `-c ${name}=${value}`).join(" ");
    const client = new pg.Client({
      host: this.endpoint.host,
      port: this.endpoint.port,
      user: account.user,
      ...(account.password === null ? {} : { password: account.password }),
      database: session.database,
      ssl: false,
      options,
      connectionTimeoutMillis: 10_000,
      query_timeout: LIMITS.batchTimeoutMs,
      application_name: "proof-audit",
    });
    client.on("error", () => undefined);
    try {
      await client.connect();
    } catch (e) {
      throw new TransportError(`could not connect to the loopback database: ${e instanceof Error ? e.message.slice(0, 200) : "unknown error"}`);
    }
    return client;
  }

  async run(session: SessionSpec, steps: readonly Step[]): Promise<string[]> {
    const client = await this.connect(session);
    try {
      const out: string[] = [];
      for (const step of steps) {
        if (!step.fetch) {
          await client.query(step.sql);
          continue;
        }
        const res = await client.query({ text: step.sql, rowMode: "array" });
        const cell: unknown = res.rows[0]?.[0];
        out.push(typeof cell === "string" ? cell : "");
      }
      return out;
    } catch (e) {
      throw new TransportError(e instanceof Error ? e.message.slice(0, 300) : "query failed");
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
