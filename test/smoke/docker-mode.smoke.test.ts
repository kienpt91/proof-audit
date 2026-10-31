import { describe, expect, it } from "vitest";
import { analyzeRls } from "../../src/application/analyze.js";
import { loadSqlInputs } from "../../src/infrastructure/fs/files.js";
import { DockerSandboxProvider, POSTGRES_IMAGE } from "../../src/infrastructure/postgres/docker-provider.js";
import { RelayDockerRunner } from "./relay-runner.js";

const relay = process.env.PROOF_AUDIT_RELAY_DIR ?? "";

describe.skipIf(relay === "")("default mode: the throwaway container, driven through the relay", () => {
  it("analyses the vulnerable example, verifies the fix and leaves no container behind", async () => {
    const docker = new RelayDockerRunner(relay);
    const provider = new DockerSandboxProvider({ docker, sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now(), env: {}, pid: process.pid, isAlive: () => true });
    const { files } = await loadSqlInputs(["examples/vulnerable-app/supabase/migrations"], process.cwd());
    const report = await analyzeRls(
      { files, loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool: { name: "proof-audit", version: "0.1.0" } },
      { provider, clock: { now: () => Date.now() } },
    );
    expect(report.environment).toEqual({ mode: "docker", image: POSTGRES_IMAGE, postgresVersion: expect.stringMatching(/^16\.14/) });
    expect(report.summary).toMatchObject({ proven: 6, clean: 1 });
    expect(report.verification?.status).toBe("VERIFIED");
    expect(report.complete).toBe(true);
    const verbs = docker.argvs.map((a) => a[0]);
    expect(verbs.indexOf("run")).toBeGreaterThan(-1);
    expect(verbs.indexOf("exec")).toBeGreaterThan(verbs.indexOf("run"));
    expect(verbs.at(-1)).toBe("rm");
  });

  it("analyses the fixed example against a second container", async () => {
    const docker = new RelayDockerRunner(relay);
    const provider = new DockerSandboxProvider({ docker, sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now(), env: {}, pid: process.pid, isAlive: () => true });
    const { files } = await loadSqlInputs(["examples/fixed-app/supabase/migrations"], process.cwd());
    const report = await analyzeRls(
      { files, loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool: { name: "proof-audit", version: "0.1.0" } },
      { provider, clock: { now: () => Date.now() } },
    );
    expect(report.summary).toMatchObject({ proven: 0, clean: 7 });
  });
});

describe.skipIf(relay === "")("default mode: hostile migrations in the real container", () => {
  it("refuses every attempt to leave the sandbox role, flags the run INTEGRITY_VIOLATION and still removes the container", async () => {
    const docker = new RelayDockerRunner(relay);
    const provider = new DockerSandboxProvider({ docker, sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now(), env: {}, pid: process.pid, isAlive: () => true });
    const hostile = [
      "copy (select 1) to program 'touch /tmp/proof-audit-pwned'",
      "alter system set work_mem = '8MB'",
      "create extension dblink",
      "select pg_read_file('/etc/passwd')",
      "set role supabase_admin",
      "alter role supabase_admin password 'x'",
      "create event trigger evil on ddl_command_end execute function pg_catalog.pg_event_trigger_ddl_commands()",
      "create or replace function auth.uid() returns uuid language sql as $$ select null::uuid $$",
      "create table public.secrets (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id))",
    ].join(";\n");
    const report = await analyzeRls(
      { files: [{ path: "m/001.sql", content: `${hostile};\n`, bytes: hostile.length }], loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool: { name: "proof-audit", version: "0.1.0" } },
      { provider, clock: { now: () => Date.now() } },
    );
    expect(report.migrationErrors.filter((e) => e.sqlstate === "42501" || e.sqlstate === "25001" || e.sqlstate === "0A000").length).toBeGreaterThanOrEqual(7);
    expect(report.integrity.status).toBe("INTEGRITY_VIOLATION");
    expect(report.integrity.violations.filter((v) => v.kind === "platform-changed")).toEqual([]);
    expect(report.proofs.find((p) => p.id === "public.secrets/anon-read")?.verdict).toBe("PROVEN_VULNERABLE");
    expect(docker.argvs.at(-1)?.[0]).toBe("rm");
  });
});
