import { randomBytes } from "node:crypto";
import { SandboxError, type CreatedSandbox, type SandboxProvider } from "../../application/ports.js";
import type { DockerRunner } from "../process/runner.js";
import { DockerPsqlTransport } from "./docker-transport.js";
import { randomNaming } from "./names.js";
import { PostgresSandbox } from "./sandbox.js";
import type { Accounts } from "./transport.js";

/** Official postgres:16.14 image, pinned by digest (multi-arch index published 2026-08-05). */
export const POSTGRES_IMAGE = "postgres@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b";

/** In the container the roles are named as on a Supabase project: `supabase_admin` (superuser) and `postgres` (not a superuser). */
export const CONTAINER_ACCOUNTS: Accounts = {
  admin: { user: "supabase_admin", password: null },
  migrator: { user: "postgres", password: null },
  prober: { user: "proof_audit_prober", password: null },
};

/**
 * The container that holds the throwaway database. No network at all (so no published port and no way for
 * the SQL under analysis to reach out), a read-only root file system, memory-backed data directory, no
 * capabilities, bounded processes, memory, CPU and log size, and an unprivileged user. The server does not listen on
 * TCP; psql reaches it over the unix socket from inside the container. `--rm` removes it when it stops.
 */
export function containerRunArgs(name: string, pid: number): string[] {
  return [
    "run", "-d", "--rm", "--pull", "never",
    "--name", name,
    "--label", "proof-audit=1",
    "--label", `proof-audit.pid=${pid}`,
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256",
    "--memory", "1g", "--memory-swap", "1g",
    "--cpus", "1",
    "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
    "--user", "999:999",
    "--tmpfs", "/var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700,size=512m",
    "--tmpfs", "/var/run/postgresql:rw,uid=999,gid=999,mode=0755,size=1m",
    "--tmpfs", "/tmp:rw,mode=1777,size=64m",
    "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
    "-e", `POSTGRES_USER=${CONTAINER_ACCOUNTS.admin.user}`,
    "-e", "POSTGRES_DB=postgres",
    POSTGRES_IMAGE,
    "-c", "listen_addresses=",
    "-c", "fsync=off",
    "-c", "synchronous_commit=off",
    "-c", "full_page_writes=off",
    "-c", "max_connections=20",
    "-c", "shared_buffers=64MB",
    "-c", "log_min_messages=panic",
    "-c", "log_statement=none",
  ];
}

export interface DockerProviderOptions {
  readonly docker: DockerRunner;
  readonly sleep: (ms: number) => Promise<void>;
  readonly now: () => number;
  /** The process environment, read only to refuse a docker daemon that is not on this machine. */
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The pid recorded on the containers this process starts. */
  readonly pid: number;
  /** Whether a process is still running; used to remove containers left by a process that is gone. */
  readonly isAlive: (pid: number) => boolean;
  /** How long to wait for the database to accept connections. */
  readonly readyTimeoutMs?: number;
}

const QUICK = { timeoutMs: 30_000, maxOutputBytes: 1024 * 1024 } as const;
const REMOTE = /^(tcp|ssh|http|https|fd):/i;

export class DockerSandboxProvider implements SandboxProvider {
  private readonly live = new Set<string>();

  constructor(private readonly options: DockerProviderOptions) {}

  private async forceRemove(name: string): Promise<void> {
    await this.options.docker.run(["rm", "-f", "-v", name], QUICK).catch(() => undefined);
  }

  /** Remove a container this provider started, once. */
  private async remove(name: string): Promise<void> {
    if (this.live.delete(name)) await this.forceRemove(name);
  }

  /** The docker CLI honours DOCKER_HOST and the current context: refuse a daemon on another machine, because the migrations would be sent to it. */
  private async assertLocalDaemon(): Promise<void> {
    const host = this.options.env.DOCKER_HOST;
    if (host !== undefined && host !== "" && REMOTE.test(host)) throw new SandboxError("refusing to run: DOCKER_HOST points at a docker daemon that is not on this machine");
    if (host === undefined || host === "") {
      const ctx = await this.options.docker.run(["context", "inspect", "--format", '{{(index .Endpoints "docker").Host}}'], QUICK).catch(() => null);
      if (ctx !== null && ctx.code === 0 && REMOTE.test(ctx.stdout.trim())) throw new SandboxError("refusing to run: the current docker context points at a docker daemon that is not on this machine");
    }
  }

  /** Remove containers of this tool whose process no longer exists (a crash, a kill -9, a closed terminal). */
  private async sweepStale(): Promise<void> {
    const listed = await this.options.docker
      .run(["ps", "-a", "--filter", "label=proof-audit=1", "--format", '{{.Names}} {{.Label "proof-audit.pid"}}'], QUICK)
      .catch(() => null);
    if (listed === null || listed.code !== 0) return;
    for (const line of listed.stdout.split("\n")) {
      const [name, pidText] = line.trim().split(" ");
      const pid = Number(pidText);
      if (name && /^proof-audit-[0-9a-f]{12}$/.test(name) && Number.isInteger(pid) && pid > 0 && !this.options.isAlive(pid)) await this.forceRemove(name);
    }
  }

  private async waitReady(name: string): Promise<void> {
    const deadline = this.options.now() + (this.options.readyTimeoutMs ?? 90_000);
    const admin = CONTAINER_ACCOUNTS.admin.user;
    let initDone = false;
    while (this.options.now() < deadline) {
      const state = await this.options.docker.run(["inspect", "-f", "{{.State.Running}}", name], QUICK);
      if (state.stdout.trim() !== "true") throw new SandboxError("the database container stopped before it was ready");
      if (!initDone) {
        const logs = await this.options.docker.run(["logs", name], QUICK);
        // The entrypoint starts a temporary server to initialise, stops it, prints this line and starts the real one.
        initDone = `${logs.stdout}\n${logs.stderr}`.includes("PostgreSQL init process complete");
      }
      if (initDone) {
        const ping = await this.options.docker.run(["exec", "-i", name, "psql", "-X", "-q", "-A", "-t", "-U", admin, "-d", "postgres", "-c", "SELECT 1"], QUICK);
        if (ping.code === 0 && ping.stdout.trim() === "1") return;
      }
      await this.options.sleep(400);
    }
    throw new SandboxError("the database container did not become ready in time");
  }

  async create(): Promise<CreatedSandbox> {
    await this.assertLocalDaemon();
    await this.sweepStale();
    const name = `proof-audit-${randomBytes(6).toString("hex")}`;
    const started = await this.options.docker.run(containerRunArgs(name, this.options.pid), QUICK);
    if (started.code !== 0) {
      const hint = /No such image|pull access denied|not found/i.test(started.stderr) ? ` Fetch it once with: docker pull ${POSTGRES_IMAGE}` : "";
      throw new SandboxError(`could not start the database container: ${started.stderr.replace(/\s+/g, " ").trim().slice(0, 200)}.${hint}`);
    }
    this.live.add(name);
    try {
      await this.waitReady(name);
      const transport = new DockerPsqlTransport(this.options.docker, name, CONTAINER_ACCOUNTS);
      const sandbox = await PostgresSandbox.create(transport, randomNaming("postgres"), { accounts: CONTAINER_ACCOUNTS, passwords: { migrator: null, prober: null } }, () => this.remove(name));
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
