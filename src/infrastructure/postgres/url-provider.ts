import { SandboxError, type CreatedSandbox, type SandboxProvider } from "../../application/ports.js";
import type { LoopbackEndpoint } from "../../domain/safety/loopback.js";
import { randomNaming } from "./names.js";
import { PgTransport } from "./pg-transport.js";
import { PostgresSandbox } from "./sandbox.js";

/**
 * Uses a Postgres server the user started on this machine for testing. The analysis runs in a database of its
 * own inside that server and drops it afterwards. The connecting role must be a superuser (it creates
 * databases and switches to the roles anon and authenticated), and the roles anon, authenticated and
 * service_role are created in the server if they are missing.
 */
export class UrlSandboxProvider implements SandboxProvider {
  private readonly live = new Set<PostgresSandbox>();

  constructor(
    private readonly endpoint: LoopbackEndpoint,
    private readonly statementTimeoutMs?: number,
  ) {}

  async create(): Promise<CreatedSandbox> {
    const transport = new PgTransport(this.endpoint);
    const [isSuper] = await transport.query(this.endpoint.database, ["SELECT current_setting('is_superuser')"]);
    if (isSuper !== "on") throw new SandboxError("the database role in the URL must be a superuser of the throwaway server");
    const sandbox = await PostgresSandbox.create(transport, randomNaming(this.endpoint.database, this.statementTimeoutMs), async () => {
      this.live.delete(sandbox);
    });
    this.live.add(sandbox);
    return { sandbox, environment: { mode: "url", image: "loopback" } };
  }

  async disposeAll(): Promise<void> {
    await Promise.all([...this.live].map((s) => s.dispose()));
  }
}
