import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SpawnDockerRunner } from "../../src/infrastructure/process/runner.js";
import { PgTransport } from "../../src/infrastructure/postgres/pg-transport.js";

let dir = "";
let oldPath = "";
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "proof-audit-docker-"));
  oldPath = process.env.PATH ?? "";
  process.env.PATH = `${dir}:${oldPath}`;
});
afterEach(() => {
  process.env.PATH = oldPath;
  rmSync(dir, { recursive: true, force: true });
});

function fakeDocker(script: string): void {
  const file = join(dir, "docker");
  writeFileSync(file, `#!/bin/sh\n${script}\n`);
  chmodSync(file, 0o755);
}

describe("SpawnDockerRunner", () => {
  it("passes the argument vector verbatim, without a shell, and feeds stdin", async () => {
    fakeDocker('printf "%s|" "$@"; cat');
    const r = await new SpawnDockerRunner().run(["a b", "$(whoami)", ";rm"], { stdin: "IN", timeoutMs: 5000, maxOutputBytes: 1000 });
    expect(r).toMatchObject({ code: 0, stdout: "a b|$(whoami)|;rm|IN", timedOut: false, truncated: false });
  });

  it("returns the exit code and stderr", async () => {
    fakeDocker("echo oops >&2; exit 7");
    const r = await new SpawnDockerRunner().run([], { timeoutMs: 5000, maxOutputBytes: 1000 });
    expect(r.code).toBe(7);
    expect(r.stderr).toBe("oops\n");
  });

  it("kills a process that runs past the timeout", async () => {
    fakeDocker("sleep 5");
    const r = await new SpawnDockerRunner().run([], { timeoutMs: 100, maxOutputBytes: 1000 });
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
  });

  it("kills a process whose output passes the cap", async () => {
    fakeDocker("yes x");
    const r = await new SpawnDockerRunner().run([], { timeoutMs: 5000, maxOutputBytes: 1000 });
    expect(r.truncated).toBe(true);
  });

  it("rejects when docker is not installed", async () => {
    process.env.PATH = dir;
    await expect(new SpawnDockerRunner().run([], { timeoutMs: 1000, maxOutputBytes: 10 })).rejects.toThrow("could not run docker");
  });
});

describe("PgTransport", () => {
  it("refuses to be built for a host that is not loopback", () => {
    expect(() => new PgTransport({ host: "db.example.com", port: 5432, user: "u", password: null, database: "d" })).toThrow("loopback");
  });

  it("accepts loopback hosts", () => {
    expect(() => new PgTransport({ host: "127.0.0.1", port: 5432, user: "u", password: null, database: "d" })).not.toThrow();
    expect(() => new PgTransport({ host: "::1", port: 5432, user: "u", password: null, database: "d" })).not.toThrow();
  });
});
