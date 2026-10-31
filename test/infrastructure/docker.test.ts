import { describe, expect, it } from "vitest";
import { SandboxError } from "../../src/application/ports.js";
import { CONTAINER_ACCOUNTS, containerRunArgs, DockerSandboxProvider, POSTGRES_IMAGE } from "../../src/infrastructure/postgres/docker-provider.js";
import { DockerPsqlTransport } from "../../src/infrastructure/postgres/docker-transport.js";
import { TransportError, type SessionSpec } from "../../src/infrastructure/postgres/transport.js";
import type { DockerRunner, ProcessResult, RunOptions } from "../../src/infrastructure/process/runner.js";

const ok = (stdout = "", stderr = ""): ProcessResult => ({ code: 0, stdout, stderr, timedOut: false, truncated: false });

class FakeDocker implements DockerRunner {
  readonly calls: { argv: readonly string[]; stdin: string | undefined }[] = [];
  handler: (argv: readonly string[], stdin: string | undefined) => ProcessResult = (argv) => {
    if (argv[0] === "inspect") return ok("true\n");
    if (argv[0] === "logs") return ok("", "PostgreSQL init process complete; ready for start up.\n");
    if (argv[0] === "exec" && argv.includes("SELECT 1")) return ok("1\n");
    if (argv[0] === "ps" || argv[0] === "context") return ok();
    return ok();
  };

  async run(argv: readonly string[], options: RunOptions): Promise<ProcessResult> {
    this.calls.push({ argv, stdin: options.stdin });
    return this.handler(argv, options.stdin);
  }

  argvs(verb: string): (readonly string[])[] {
    return this.calls.filter((c) => c.argv[0] === verb).map((c) => c.argv);
  }
}

function provider(docker: FakeDocker, over: Partial<ConstructorParameters<typeof DockerSandboxProvider>[0]> = {}) {
  let t = 0;
  return new DockerSandboxProvider({ docker, sleep: async (ms) => void (t += ms), now: () => t, env: {}, pid: 4242, isAlive: () => true, readyTimeoutMs: 5_000, ...over });
}

describe("containerRunArgs", () => {
  const args = containerRunArgs("proof-audit-test", 4242);
  const has = (...seq: string[]) => args.some((_, i) => seq.every((s, j) => args[i + j] === s));

  it("runs the image pinned by digest and never pulls", () => {
    expect(POSTGRES_IMAGE).toMatch(/^postgres@sha256:[0-9a-f]{64}$/);
    expect(args).toContain(POSTGRES_IMAGE);
    expect(has("--pull", "never")).toBe(true);
  });

  it("has no network, no capabilities, a read-only root and an unprivileged user", () => {
    expect(has("--network", "none")).toBe(true);
    expect(has("--cap-drop", "ALL")).toBe(true);
    expect(has("--security-opt", "no-new-privileges")).toBe(true);
    expect(args).toContain("--read-only");
    expect(has("--user", "999:999")).toBe(true);
  });

  it("bounds processes, memory, CPU and the size of the container log", () => {
    expect(has("--pids-limit", "256")).toBe(true);
    expect(has("--memory", "1g")).toBe(true);
    expect(has("--cpus", "1")).toBe(true);
    expect(has("--log-opt", "max-size=1m")).toBe(true);
    expect(has("--log-opt", "max-file=1")).toBe(true);
    expect(has("-c", "log_min_messages=panic")).toBe(true);
  });

  it("removes itself when it stops and records the owning process", () => {
    expect(args).toContain("--rm");
    expect(has("--label", "proof-audit=1")).toBe(true);
    expect(has("--label", "proof-audit.pid=4242")).toBe(true);
  });

  it("publishes nothing, mounts nothing from the host and is not privileged", () => {
    for (const forbidden of ["-p", "--publish", "-P", "-v", "--volume", "--mount", "--privileged", "--network=host", "--pid", "--cap-add"]) expect(args).not.toContain(forbidden);
  });

  it("keeps the data directory in memory and the server off TCP", () => {
    expect(args.some((a) => a.startsWith("/var/lib/postgresql/data:rw"))).toBe(true);
    expect(has("-c", "listen_addresses=")).toBe(true);
  });

  it("uses trust auth only, with no password in the arguments, and names the superuser like a Supabase project", () => {
    expect(has("-e", "POSTGRES_HOST_AUTH_METHOD=trust")).toBe(true);
    expect(has("-e", "POSTGRES_USER=supabase_admin")).toBe(true);
    expect(args.join(" ")).not.toMatch(/PASSWORD/);
  });

  it("names the migration role postgres and keeps it apart from the superuser", () => {
    expect(CONTAINER_ACCOUNTS.migrator.user).toBe("postgres");
    expect(CONTAINER_ACCOUNTS.admin.user).toBe("supabase_admin");
    expect(new Set(Object.values(CONTAINER_ACCOUNTS).map((a) => a.user)).size).toBe(3);
  });
});

describe("DockerPsqlTransport", () => {
  const session = (over: Partial<SessionSpec> = {}): SessionSpec => ({ database: "db", principal: "migrator", pin: "session", statementTimeoutMs: 20_000, ...over });
  const transport = (d: FakeDocker) => new DockerPsqlTransport(d, "c1", CONTAINER_ACCOUNTS);

  it("builds a fixed psql vector with the role's login and the pinned settings in PGOPTIONS", () => {
    const t = transport(new FakeDocker());
    expect(t.argv(session())).toEqual([
      "exec", "-i", "-e", "PGOPTIONS=-c search_path=public,extensions -c statement_timeout=20000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000 -c row_security=on",
      "c1", "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "db", "-f", "-",
    ]);
    expect(t.argv(session({ principal: "admin", pin: "catalog" }))).toContain("supabase_admin");
    expect(t.argv(session({ principal: "admin", pin: "catalog" }))[3]).toBe("PGOPTIONS=-c search_path=pg_catalog -c statement_timeout=60000 -c row_security=on");
    expect(t.argv(session({ principal: "prober", pin: "probe" }))).toContain("proof_audit_prober");
  });

  it("sends statements on stdin, not in the argument vector, and reads one line per fetch step", async () => {
    const d = new FakeDocker();
    d.handler = () => ok('{"ok": true}\n{"ok": true}\n');
    const out = await transport(d).run(session(), [
      { sql: "DO $x$ select a; DROP x $x$", fetch: false },
      { sql: "SELECT 1", fetch: true },
      { sql: "SELECT 2", fetch: true },
    ]);
    expect(out).toEqual(['{"ok": true}', '{"ok": true}']);
    expect(d.calls[0]?.stdin).toBe("DO $x$ select a; DROP x $x$;\nSELECT 1;\nSELECT 2;\n");
    expect(d.calls[0]?.argv.join(" ")).not.toContain("DROP");
  });

  it("fails when the number of result lines differs from the number of fetch steps", async () => {
    const d = new FakeDocker();
    d.handler = () => ok("one\n");
    await expect(transport(d).run(session(), [{ sql: "a", fetch: true }, { sql: "b", fetch: true }])).rejects.toBeInstanceOf(TransportError);
  });

  it("fails with the first part of stderr when psql exits non-zero", async () => {
    const d = new FakeDocker();
    d.handler = () => ({ code: 3, stdout: "", stderr: 'psql: ERROR:  database "x" already exists\n', timedOut: false, truncated: false });
    await expect(transport(d).run(session(), [{ sql: "CREATE DATABASE x", fetch: false }])).rejects.toThrow('database "x" already exists');
  });

  it("ends the server-side sessions after a timeout, as the admin, with a fixed statement, and reports it", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv.includes("-c") ? ok() : { code: null, stdout: "", stderr: "", timedOut: true, truncated: false });
    await expect(transport(d).run(session(), [{ sql: "a", fetch: true }])).rejects.toThrow("did not answer");
    const kill = d.calls.find((c) => c.argv.includes("-c"));
    expect(kill?.argv).toContain("supabase_admin");
    expect(kill?.argv.at(-1)).toContain("pg_terminate_backend");
    expect(kill?.argv.at(-1)).not.toContain("postgres_");
  });

  it("reports oversized output", async () => {
    const d = new FakeDocker();
    d.handler = () => ({ code: null, stdout: "", stderr: "", timedOut: false, truncated: true });
    await expect(transport(d).run(session(), [{ sql: "a", fetch: true }])).rejects.toThrow("more output");
  });
});

describe("DockerSandboxProvider", () => {
  it("starts the container, waits for the init message and a working connection, then provisions roles, database and platform as the admin", async () => {
    const d = new FakeDocker();
    const created = await provider(d).create();
    expect(created.environment).toEqual({ mode: "docker", image: POSTGRES_IMAGE });
    const run = d.argvs("run")[0] ?? [];
    expect(run).toEqual(containerRunArgs(run[run.indexOf("--name") + 1] ?? "", 4242));
    const execs = d.calls.filter((c) => c.argv[0] === "exec" && c.stdin !== undefined && c.stdin !== "");
    expect(execs[0]?.stdin).toContain("CREATE ROLE \"postgres\" LOGIN NOSUPERUSER");
    expect(execs[1]?.stdin).toMatch(/^CREATE DATABASE "proof_audit_[0-9a-f]{12}";\n$/);
    expect(execs[2]?.stdin).toContain("CREATE TABLE IF NOT EXISTS auth.users");
    for (const e of execs) expect(e.argv).toContain("supabase_admin");
  });

  it("does not report ready until the init message has been printed", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv[0] === "inspect" ? ok("true\n") : argv[0] === "logs" ? ok("", "starting\n") : ok());
    await expect(provider(d, { readyTimeoutMs: 2_000 }).create()).rejects.toThrow("did not become ready");
    expect(d.argvs("rm")).toHaveLength(1);
  });

  it("does not report ready while the server still refuses connections", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv[0] === "inspect" ? ok("true\n") : argv[0] === "logs" ? ok("", "PostgreSQL init process complete\n") : argv[0] === "exec" ? { code: 2, stdout: "", stderr: "no connection", timedOut: false, truncated: false } : ok());
    await expect(provider(d, { readyTimeoutMs: 2_000 }).create()).rejects.toThrow("did not become ready");
  });

  it("removes the container with its volumes when the sandbox is disposed, after dropping the database", async () => {
    const d = new FakeDocker();
    const { sandbox } = await provider(d).create();
    await sandbox.dispose();
    const verbs = d.calls.map((c) => c.argv[0]);
    expect(verbs.lastIndexOf("rm")).toBeGreaterThan(verbs.lastIndexOf("exec"));
    expect(d.argvs("rm")[0]?.slice(0, 3)).toEqual(["rm", "-f", "-v"]);
  });

  it("removes the container when startup fails halfway", async () => {
    const d = new FakeDocker();
    const base = d.handler;
    d.handler = (argv, stdin) => (argv[0] === "exec" && (stdin ?? "").includes("CREATE ROLE") ? { code: 3, stdout: "", stderr: "boom", timedOut: false, truncated: false } : base(argv, stdin));
    await expect(provider(d).create()).rejects.toThrow("psql failed");
    expect(d.argvs("rm")).toHaveLength(1);
  });

  it("explains how to fetch a missing image", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv[0] === "run" ? { code: 125, stdout: "", stderr: "Unable to find image locally: No such image", timedOut: false, truncated: false } : ok());
    const e = await provider(d).create().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(SandboxError);
    expect((e as Error).message).toContain(`docker pull ${POSTGRES_IMAGE}`);
    expect(d.argvs("rm")).toHaveLength(0);
  });

  it("fails fast when the container stops", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv[0] === "inspect" ? ok("false\n") : ok());
    await expect(provider(d).create()).rejects.toThrow("stopped before it was ready");
  });

  it("disposeAll removes every container still alive", async () => {
    const d = new FakeDocker();
    const p = provider(d);
    await p.create();
    await p.create();
    await p.disposeAll();
    expect(d.argvs("rm")).toHaveLength(2);
    await p.disposeAll();
    expect(d.argvs("rm")).toHaveLength(2);
  });
});

describe("DockerSandboxProvider: a docker daemon on another machine", () => {
  it.each(["tcp://10.0.0.5:2375", "ssh://user@build-host", "http://example.test:2375", "TCP://x"])("refuses DOCKER_HOST=%s without starting anything", async (host) => {
    const d = new FakeDocker();
    await expect(provider(d, { env: { DOCKER_HOST: host } }).create()).rejects.toThrow("not on this machine");
    expect(d.calls).toHaveLength(0);
  });

  it("accepts a local unix socket", async () => {
    const d = new FakeDocker();
    await expect(provider(d, { env: { DOCKER_HOST: "unix:///var/run/docker.sock" } }).create()).resolves.toBeDefined();
  });

  it("refuses a current docker context whose endpoint is remote", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv[0] === "context" ? ok("ssh://deploy@prod.example.test\n") : ok());
    await expect(provider(d).create()).rejects.toThrow("docker context");
    expect(d.argvs("run")).toHaveLength(0);
  });

  it("accepts a local context endpoint and a context command that fails", async () => {
    const local = new FakeDocker();
    local.handler = (argv) => (argv[0] === "context" ? ok("unix:///var/run/docker.sock\n") : new FakeDocker().handler(argv, undefined));
    await expect(provider(local).create()).resolves.toBeDefined();
  });
});

describe("DockerSandboxProvider: containers left by a process that is gone", () => {
  it("removes them before starting and leaves the ones whose process is alive", async () => {
    const d = new FakeDocker();
    d.handler = (argv) =>
      argv[0] === "ps"
        ? ok("proof-audit-aaaaaaaaaaaa 111\nproof-audit-bbbbbbbbbbbb 222\nproof-audit-cccccccccccc \nother-container 333\nproof-audit-dddddddddddd notapid\n")
        : argv[0] === "inspect"
          ? ok("true\n")
          : argv[0] === "logs"
            ? ok("", "PostgreSQL init process complete\n")
            : argv.includes("SELECT 1")
              ? ok("1\n")
              : ok();
    await provider(d, { isAlive: (pid) => pid === 222 }).create();
    expect(d.argvs("rm").map((a) => a[3])).toEqual(["proof-audit-aaaaaaaaaaaa"]);
  });

  it("filters by label and prints the pid label", async () => {
    const d = new FakeDocker();
    await provider(d).create();
    expect(d.argvs("ps")[0]).toEqual(["ps", "-a", "--filter", "label=proof-audit=1", "--format", '{{.Names}} {{.Label "proof-audit.pid"}}']);
  });
});
