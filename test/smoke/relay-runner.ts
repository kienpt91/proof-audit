import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { DockerRunner, ProcessResult, RunOptions } from "../../src/infrastructure/process/runner.js";

/**
 * A DockerRunner that hands every call to scripts/docker-relay.py through files, so the real provider and
 * the real docker CLI can be exercised from a container that has neither docker nor network access.
 */
export class RelayDockerRunner implements DockerRunner {
  private n = 0;
  private readonly prefix = randomBytes(4).toString("hex");
  readonly argvs: (readonly string[])[] = [];

  constructor(private readonly dir: string) {}

  async run(argv: readonly string[], options: RunOptions): Promise<ProcessResult> {
    const id = `${this.prefix}-${String((this.n += 1)).padStart(6, "0")}`;
    this.argvs.push(argv);
    writeFileSync(join(this.dir, `req-${id}.json.tmp`), JSON.stringify({ argv, stdin: options.stdin ?? null, timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes }));
    const req = join(this.dir, `req-${id}.json`);
    renameSync(`${req}.tmp`, req);
    const resp = join(this.dir, `resp-${id}.json`);
    const deadline = Date.now() + options.timeoutMs + 10_000;
    while (!existsSync(resp)) {
      if (Date.now() > deadline) throw new Error("the relay did not answer");
      await new Promise((r) => setTimeout(r, 15));
    }
    return JSON.parse(readFileSync(resp, "utf8")) as ProcessResult;
  }
}
