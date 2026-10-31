import { LIMITS } from "../../domain/limits.js";
import type { DockerRunner } from "../process/runner.js";
import { TransportError, type SqlTransport } from "./transport.js";

const MAX_OUTPUT = 32 * 1024 * 1024;

/** Runs `psql` inside the sandbox container through `docker exec`, over the container's unix socket. */
export class DockerPsqlTransport implements SqlTransport {
  constructor(
    private readonly docker: DockerRunner,
    private readonly container: string,
  ) {}

  /** The fixed argument vector: nothing from the analysed project is ever part of it. */
  argv(database: string, tuplesOnly: boolean): string[] {
    return ["exec", "-i", this.container, "psql", "-X", "-q", ...(tuplesOnly ? ["-A", "-t"] : []), "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-f", "-"];
  }

  private async run(database: string, statements: readonly string[], tuplesOnly: boolean): Promise<string> {
    const script = `${statements.map((s) => `${s};`).join("\n")}\n`;
    const r = await this.docker.run(this.argv(database, tuplesOnly), { stdin: script, timeoutMs: LIMITS.batchTimeoutMs, maxOutputBytes: MAX_OUTPUT });
    if (r.timedOut) throw new TransportError(`the database did not answer within ${LIMITS.batchTimeoutMs / 1000}s`);
    if (r.truncated) throw new TransportError("the database produced more output than the cap allows");
    if (r.code !== 0) throw new TransportError(`psql failed: ${r.stderr.replace(/\s+/g, " ").trim().slice(0, 300)}`);
    return r.stdout;
  }

  async query(database: string, statements: readonly string[]): Promise<string[]> {
    const out = await this.run(database, statements, true);
    const lines = out.split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    if (lines.length !== statements.length) throw new TransportError("the database returned a different number of results than statements sent");
    return lines;
  }

  async execute(database: string, statements: readonly string[]): Promise<void> {
    await this.run(database, statements, false);
  }
}
