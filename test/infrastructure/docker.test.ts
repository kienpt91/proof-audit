import { describe, expect, it } from "vitest";
import { SandboxError } from "../../src/application/ports.js";
import { containerRunArgs, DockerSandboxProvider, POSTGRES_IMAGE } from "../../src/infrastructure/postgres/docker-provider.js";
import { DockerPsqlTransport } from "../../src/infrastructure/postgres/docker-transport.js";
import { TransportError } from "../../src/infrastructure/postgres/transport.js";
import type { DockerRunner, ProcessResult, RunOptions } from "../../src/infrastructure/process/runner.js";

const ok = (stdout = "", stderr = ""): ProcessResult => ({ code: 0, stdout, stderr, timedOut: false, truncated: false });

class FakeDocker implements DockerRunner {
  readonly calls: { argv: readonly string[]; stdin: string | undefined }[] = [];
  handler: (argv: readonly string[], stdin: string | undefined) => ProcessResult = (argv) => {
    if (argv[0] === "inspect") return ok("true\n");
    if (argv[0] === "logs") return ok("", "PostgreSQL init process complete; ready for start up.\nready to accept connections\nready to accept connections\n");
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

function provider(docker: FakeDocker, readyTimeoutMs = 5_000) {
  let t = 0;
  return new DockerSandboxProvider({ docker, sleep: async (ms) => void (t += ms), now: () => t, readyTimeoutMs });
}

describe("containerRunArgs", () => {
  const args = containerRunArgs("proof-audit-test");
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

  it("bounds processes, memory and CPU", () => {
    expect(has("--pids-limit", "256")).toBe(true);
    expect(has("--memory", "1g")).toBe(true);
    expect(has("--cpus", "1")).toBe(true);
  });

  it("publishes nothing, mounts nothing from the host and is not privileged", () => {
    for (const forbidden of ["-p", "--publish", "-P", "-v", "--volume", "--mount", "--privileged", "--network=host", "--pid", "--cap-add"]) expect(args).not.toContain(forbidden);
  });

  it("keeps the data directory in memory and the server off TCP", () => {
    expect(args.some((a) => a.startsWith("/var/lib/postgresql/data:rw"))).toBe(true);
    expect(has("-c", "listen_addresses=")).toBe(true);
  });

  it("uses trust auth only, with no password in the arguments", () => {
    expect(has("-e", "POSTGRES_HOST_AUTH_METHOD=trust")).toBe(true);
    expect(args.join(" ")).not.toMatch(/PASSWORD/);
  });

  it("labels the container so leftovers can be found", () => {
    expect(has("--label", "proof-audit=1")).toBe(true);
  });
});

describe("DockerPsqlTransport", () => {
  it("builds a fixed psql vector that never contains caller text", () => {
    const t = new DockerPsqlTransport(new FakeDocker(), "c1");
    expect(t.argv("db", true)).toEqual(["exec", "-i", "c1", "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "db", "-f", "-"]);
    expect(t.argv("db", false)).not.toContain("-A");
  });

  it("sends statements on stdin, not in the argument vector, and reads one line per statement", async () => {
    const d = new FakeDocker();
    d.handler = () => ok('{"ok": true}\n{"ok": true}\n');
    const out = await new DockerPsqlTransport(d, "c1").query("db", ["SELECT a; DROP x", "SELECT b"]);
    expect(out).toEqual(['{"ok": true}', '{"ok": true}']);
    expect(d.calls[0]?.stdin).toBe("SELECT a; DROP x;\nSELECT b;\n");
    expect(d.calls[0]?.argv.join(" ")).not.toContain("DROP");
  });

  it("fails when the number of result lines differs", async () => {
    const d = new FakeDocker();
    d.handler = () => ok("one\n");
    await expect(new DockerPsqlTransport(d, "c1").query("db", ["a", "b"])).rejects.toBeInstanceOf(TransportError);
  });

  it("fails with the first part of stderr when psql exits non-zero", async () => {
    const d = new FakeDocker();
    d.handler = () => ({ code: 3, stdout: "", stderr: "psql: ERROR:  database \"x\" already exists\n", timedOut: false, truncated: false });
    await expect(new DockerPsqlTransport(d, "c1").execute("db", ["CREATE DATABASE x"])).rejects.toThrow('database "x" already exists');
  });

  it("reports timeouts and oversized output", async () => {
    const d = new FakeDocker();
    d.handler = () => ({ code: null, stdout: "", stderr: "", timedOut: true, truncated: false });
    await expect(new DockerPsqlTransport(d, "c1").query("db", ["a"])).rejects.toThrow("did not answer");
    d.handler = () => ({ code: null, stdout: "", stderr: "", timedOut: false, truncated: true });
    await expect(new DockerPsqlTransport(d, "c1").query("db", ["a"])).rejects.toThrow("more output");
  });
});

describe("DockerSandboxProvider", () => {
  it("starts the container, waits for the second ready message, creates a database and installs the harness", async () => {
    const d = new FakeDocker();
    const created = await provider(d).create();
    expect(created.environment).toEqual({ mode: "docker", image: POSTGRES_IMAGE });
    expect(d.argvs("run")[0]).toEqual(containerRunArgs(d.argvs("run")[0]?.[5] ?? ""));
    const execs = d.calls.filter((c) => c.argv[0] === "exec");
    expect(execs[0]?.stdin).toMatch(/^CREATE DATABASE "proof_audit_[0-9a-f]{12}";\n$/);
    expect(execs[1]?.stdin).toContain("CREATE SCHEMA IF NOT EXISTS proof_audit");
  });

  it("does not report ready after only one ready message", async () => {
    const d = new FakeDocker();
    d.handler = (argv) => (argv[0] === "inspect" ? ok("true\n") : argv[0] === "logs" ? ok("", "PostgreSQL init process complete\nready to accept connections\n") : ok());
    await expect(provider(d, 2_000).create()).rejects.toThrow("did not become ready");
    expect(d.argvs("rm")).toHaveLength(1);
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
    d.handler = (argv) => (argv[0] === "exec" ? { code: 3, stdout: "", stderr: "boom", timedOut: false, truncated: false } : argv[0] === "inspect" ? ok("true\n") : argv[0] === "logs" ? ok("", "PostgreSQL init process complete\nready to accept connections\nready to accept connections\n") : ok());
    await expect(provider(d).create()).rejects.toThrow("psql failed");
    expect(d.argvs("rm")).toHaveLength(1);
  });

  it("explains how to fetch a missing image", async () => {
    const d = new FakeDocker();
    d.handler = () => ({ code: 125, stdout: "", stderr: "Unable to find image locally: No such image", timedOut: false, truncated: false });
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
