import { LIMITS } from "../../domain/limits.js";
import type { DockerRunner } from "../process/runner.js";
import { pinnedSettings, TransportError, type Accounts, type SessionSpec, type SqlTransport, type Step } from "./transport.js";

const MAX_OUTPUT = 32 * 1024 * 1024;

/** Runs `psql` inside the sandbox container through `docker exec`, over the container's unix socket. */
export class DockerPsqlTransport implements SqlTransport {
  constructor(
    private readonly docker: DockerRunner,
    private readonly container: string,
    private readonly accounts: Accounts,
  ) {}

  /** The fixed argument vector: nothing from the analysed project is ever part of it. */
  argv(session: SessionSpec): string[] {
    const options = pinnedSettings(session).map(([name, value]) => `-c ${name}=${value}`).join(" ");
    return [
      "exec", "-i", "-e", `PGOPTIONS=${options}`, this.container,
      "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", this.accounts[session.principal].user, "-d", session.database, "-f", "-",
    ];
  }

  async run(session: SessionSpec, steps: readonly Step[]): Promise<string[]> {
    const script = `${steps.map((s) => `${s.sql};`).join("\n")}\n`;
    const r = await this.docker.run(this.argv(session), { stdin: script, timeoutMs: LIMITS.batchTimeoutMs, maxOutputBytes: MAX_OUTPUT });
    if (r.timedOut) {
      await this.terminateBackends();
      throw new TransportError(`the database did not answer within ${LIMITS.batchTimeoutMs / 1000}s`);
    }
    if (r.truncated) throw new TransportError("the database produced more output than the cap allows");
    if (r.code !== 0) throw new TransportError(`psql failed: ${r.stderr.replace(/\s+/g, " ").trim().slice(0, 300)}`);
    const lines = r.stdout.split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    const expected = steps.filter((s) => s.fetch).length;
    if (lines.length !== expected) throw new TransportError("the database returned a different number of results than statements sent");
    return lines;
  }

  /**
   * Killing the local `docker exec` client does not stop the server-side backend. Ask the server to end every session
   * of a sandbox database, as the admin, with a fixed statement.
   */
  private async terminateBackends(): Promise<void> {
    const admin = this.accounts.admin.user;
    await this.docker
      .run(
        ["exec", "-i", this.container, "psql", "-X", "-q", "-A", "-t", "-U", admin, "-d", "postgres", "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname LIKE 'proof\\_audit\\_%'"],
        { timeoutMs: 15_000, maxOutputBytes: 1024 * 1024 },
      )
      .catch(() => undefined);
  }
}
