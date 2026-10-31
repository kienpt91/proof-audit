import pg from "pg";
import { LIMITS } from "../../domain/limits.js";
import { assertLoopbackHost, type LoopbackEndpoint } from "../../domain/safety/loopback.js";
import { TransportError, type SqlTransport } from "./transport.js";

/**
 * Talks to a Postgres server on this machine's loopback interface. The endpoint can only be built by
 * `parseLoopbackUrl`, and the host is checked again here, so no code path can point this at another machine.
 */
export class PgTransport implements SqlTransport {
  constructor(private readonly endpoint: LoopbackEndpoint) {
    assertLoopbackHost(endpoint.host);
  }

  private async connect(database: string): Promise<pg.Client> {
    const client = new pg.Client({
      host: this.endpoint.host,
      port: this.endpoint.port,
      user: this.endpoint.user,
      ...(this.endpoint.password === null ? {} : { password: this.endpoint.password }),
      database,
      ssl: false,
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

  async query(database: string, statements: readonly string[]): Promise<string[]> {
    const client = await this.connect(database);
    try {
      const out: string[] = [];
      for (const text of statements) {
        const res = await client.query({ text, rowMode: "array" });
        const cell: unknown = res.rows[0]?.[0];
        if (typeof cell !== "string") throw new TransportError("a statement did not return one text value");
        out.push(cell);
      }
      return out;
    } catch (e) {
      if (e instanceof TransportError) throw e;
      throw new TransportError(e instanceof Error ? e.message.slice(0, 300) : "query failed");
    } finally {
      await client.end().catch(() => undefined);
    }
  }

  async execute(database: string, statements: readonly string[]): Promise<void> {
    const client = await this.connect(database);
    try {
      for (const text of statements) await client.query(text);
    } catch (e) {
      throw new TransportError(e instanceof Error ? e.message.slice(0, 300) : "statement failed");
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
