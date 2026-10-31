import { randomBytes } from "node:crypto";
import { SandboxError, type CreatedSandbox, type SandboxProvider } from "../../application/ports.js";
import type { DockerRunner } from "../process/runner.js";
import { DockerPsqlTransport } from "./docker-transport.js";
import { randomNaming } from "./names.js";
import { PostgresSandbox } from "./sandbox.js";

/** Official postgres:16.14 image, pinned by digest (multi-arch index published 2026-08-05). */
export const POSTGRES_IMAGE = "postgres@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b";

/**
 * The container that holds the throwaway database. No network at all (so no published port and no way for
 * the SQL under analysis to reach out), a read-only root file system, memory-backed data directory, no
 * capabilities, bounded processes, memory and CPU, and an unprivileged user. The server does not listen on
 * TCP; psql reaches it over the unix socket from inside the container.
 */
export function containerRunArgs(name: string): string[] {
  return [
    "run", "-d", "--pull", "never",
    "--name", name,
    "--label", "proof-audit=1",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256",
    "--memory", "1g", "--memory-swap", "1g",
    "--cpus", "1",
    "--user", "999:999",
    "--tmpfs", "/var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700,size=512m",
    "--tmpfs", "/var/run/postgresql:rw,uid=999,gid=999,mode=0755,size=1m",
    "--tmpfs", "/tmp:rw,mode=1777,size=64m",
    "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
    POSTGRES_IMAGE,
    "-c", "listen_addresses=",
    "-c", "fsync=off",
    "-c", "synchronous_commit=off",
    "-c", "full_page_writes=off",
    "-c", "max_connections=20",
    "-c", "shared_buffers=64MB",
    "-c", "log_min_messages=warning",
  ];
}

export interface DockerProviderOptions {
  readonly docker: DockerRunner;
  readonly sleep: (ms: number) => Promise<void>;
  readonly now: () => number;
  /** How long to wait for the database to accept connections. */
  readonly readyTimeoutMs?: number;
}

const QUICK = { timeoutMs: 30_000, maxOutputBytes: 1024 * 1024 } as const;

export class DockerSandboxProvider implements SandboxProvider {
  private readonly live = new Set<string>();

  constructor(private readonly options: DockerProviderOptions) {}

  private async remove(name: string): Promise<void> {
    this.live.delete(name);
    await this.options.docker.run(["rm", "-f", "-v", name], QUICK).catch(() => undefined);
  }

  private async waitReady(name: string): Promise<void> {
    const deadline = this.options.now() + (this.options.readyTimeoutMs ?? 90_000);
    while (this.options.now() < deadline) {
      const state = await this.options.docker.run(["inspect", "-f", "{{.State.Running}}", name], QUICK);
      if (state.stdout.trim() !== "true") throw new SandboxError("the database container stopped before it was ready");
      const logs = await this.options.docker.run(["logs", name], QUICK);
      const text = `${logs.stdout}\n${logs.stderr}`;
      // The entrypoint starts a temporary server to initialise, then the real one: ready twice means the real one is up.
      if (text.includes("PostgreSQL init process complete") && (text.match(/ready to accept connections/g) ?? []).length >= 2) return;
      await this.options.sleep(400);
    }
    throw new SandboxError("the database container did not become ready in time");
  }

  async create(): Promise<CreatedSandbox> {
    const name = `proof-audit-${randomBytes(6).toString("hex")}`;
    const started = await this.options.docker.run(containerRunArgs(name), QUICK);
    if (started.code !== 0) {
      const hint = /No such image|pull access denied|not found/i.test(started.stderr) ? ` Fetch it once with: docker pull ${POSTGRES_IMAGE}` : "";
      throw new SandboxError(`could not start the database container: ${started.stderr.replace(/\s+/g, " ").trim().slice(0, 200)}.${hint}`);
    }
    this.live.add(name);
    try {
      await this.waitReady(name);
      const transport = new DockerPsqlTransport(this.options.docker, name);
      const sandbox = await PostgresSandbox.create(transport, randomNaming("postgres"), () => this.remove(name));
      return { sandbox, environment: { mode: "docker", image: POSTGRES_IMAGE } };
    } catch (e) {
      await this.remove(name);
      throw e;
    }
  }

  /** Remove every container this provider started and has not removed yet. Safe to call from a signal handler. */
  async disposeAll(): Promise<void> {
    await Promise.all([...this.live].map((n) => this.remove(n)));
  }
}
