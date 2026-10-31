import { describe, expect, it } from "vitest";
import { platformStatements, roleStatements } from "../../src/domain/supabase/shim.js";
import { PostgresSandbox } from "../../src/infrastructure/postgres/sandbox.js";
import { TransportError, type Accounts } from "../../src/infrastructure/postgres/transport.js";
import { defineSandboxContract } from "../contract/sandbox.contract.js";
import { FakeTransport } from "../helpers/fake-transport.js";
import { ModelSandbox } from "../helpers/model-sandbox.js";
import { model, notes } from "../helpers/model.js";

const accounts: Accounts = {
  admin: { user: "supabase_admin", password: null },
  migrator: { user: "postgres", password: null },
  prober: { user: "proof_audit_prober", password: null },
};
const names = { admin: "supabase_admin", migrator: "postgres", prober: "proof_audit_prober" };
const setup = { accounts, passwords: { migrator: null, prober: null } };

function naming() {
  let n = 0;
  return { nextName: () => `db${(n += 1)}`, maintenanceDatabase: "maint" };
}

async function sandbox(t = new FakeTransport()) {
  return { t, s: await PostgresSandbox.create(t, naming(), setup) };
}

defineSandboxContract("in-memory model", async () => new ModelSandbox({ model: model([notes()]) }));
defineSandboxContract("PostgresSandbox over a fake transport", async () => (await sandbox()).s);

describe("PostgresSandbox.create", () => {
  it("creates the roles and the database as the admin in the maintenance database, then provisions the platform in it", async () => {
    const { t } = await sandbox();
    expect(t.calls.map((c) => [c.session.database, c.session.principal, c.session.pin])).toEqual([
      ["maint", "admin", "catalog"],
      ["maint", "admin", "catalog"],
      ["db1", "admin", "catalog"],
    ]);
    expect(t.calls[0]?.steps.map((s) => s.sql)).toEqual([...roleStatements(names, { migrator: null, prober: null })]);
    expect(t.calls[1]?.steps.map((s) => s.sql)).toEqual(['CREATE DATABASE "db1"']);
    expect(t.calls[2]?.steps.map((s) => s.sql)).toEqual([...platformStatements(names)]);
  });

  it("never runs anything from the project as the admin", async () => {
    const { t, s } = await sandbox();
    await s.apply(["create table x (id int)"]);
    await s.applyFirstSuccess([["insert into x values (1)"]]);
    await s.scalars(["select 1"]);
    await s.run([{ role: "anon", claims: "{}", sql: "select 1" }]);
    const adminSql = t.by("admin").flatMap((c) => c.steps.map((x) => x.sql)).join("\n");
    expect(adminSql).not.toContain("create table x");
    expect(adminSql).not.toContain("insert into x");
    expect(t.by("migrator")).toHaveLength(3);
    expect(t.by("prober")).toHaveLength(1);
  });

  it("drops the database again when provisioning fails", async () => {
    const t = new FakeTransport();
    t.failOn = /CREATE EXTENSION IF NOT EXISTS pgcrypto/;
    await expect(PostgresSandbox.create(t, naming(), setup)).rejects.toThrow("step failed");
    expect(t.sent).toContain('DROP DATABASE IF EXISTS "db1" WITH (FORCE)');
  });
});

describe("PostgresSandbox.apply", () => {
  it("runs each statement as the migrator, in one session with the platform's search_path, through a DO block", async () => {
    const { t, s } = await sandbox();
    await s.apply(["CREATE TABLE a (x int)", "DROP TABLE a"]);
    const call = t.calls.at(-1);
    expect(call?.session).toEqual({ database: "db1", principal: "migrator", pin: "session", statementTimeoutMs: 20_000 });
    expect(call?.steps).toHaveLength(4);
    expect(call?.steps[0]?.sql).toContain("CREATE TABLE a (x int)");
    expect(call?.steps[2]?.sql).toContain("DROP TABLE a");
    expect(call?.steps.filter((x) => x.fetch)).toHaveLength(2);
  });

  it("cannot be broken out of by a statement that contains any dollar-quote tag", async () => {
    const { t, s } = await sandbox();
    const hostile = "select $pa$ x $pa$; select $pa1$ y $pa1$; drop table users; --";
    await s.apply([hostile]);
    const block = t.calls.at(-1)?.steps[0]?.sql ?? "";
    const outer = /^DO (\$[a-z0-9_]*\$)/.exec(block)?.[1] ?? "";
    expect(block.slice(outer.length + 3, -outer.length).includes(outer)).toBe(false);
    expect(block.endsWith(outer)).toBe(true);
  });

  it("reports failures with their SQLSTATE and message", async () => {
    const t = new FakeTransport();
    t.replyOverride = (_f, block) => (block.includes("bad") ? '{"ok": false, "sqlstate": "42601", "message": "syntax error"}' : undefined);
    const { s } = await sandbox(t);
    expect(await s.apply(["good", "bad"])).toEqual([
      { ok: true, sqlstate: null, message: null },
      { ok: false, sqlstate: "42601", message: "syntax error" },
    ]);
  });

  it("throws when a statement gets no reply or a reply that is not JSON", async () => {
    const t = new FakeTransport();
    const { s } = await sandbox(t);
    t.replyOverride = () => "";
    await expect(s.apply(["x"])).rejects.toBeInstanceOf(TransportError);
    t.replyOverride = () => "not json";
    await expect(s.apply(["x"])).rejects.toBeInstanceOf(TransportError);
  });

  it("does not call the transport for an empty list", async () => {
    const { t, s } = await sandbox();
    const before = t.calls.length;
    await s.apply([]);
    await s.applyFirstSuccess([]);
    await s.scalars([]);
    await s.run([]);
    expect(t.calls).toHaveLength(before);
  });
});

describe("PostgresSandbox.applyFirstSuccess and scalars", () => {
  it("passes the alternatives to one block and reads the winning attempt", async () => {
    const t = new FakeTransport();
    t.replyOverride = (_f, block) => (block.includes('"attempt"') ? '{"ok": true, "attempt": 1}' : undefined);
    const { s } = await sandbox(t);
    expect(await s.applyFirstSuccess([["a", "b"]])).toEqual([{ ok: true, attempt: 1, sqlstate: null, message: null }]);
    expect(t.calls.at(-1)?.session.principal).toBe("migrator");
  });

  it("reports when no alternative worked", async () => {
    const t = new FakeTransport();
    t.replyOverride = () => '{"ok": false, "sqlstate": "23502", "message": "null value"}';
    const { s } = await sandbox(t);
    expect(await s.applyFirstSuccess([["a"]])).toEqual([{ ok: false, attempt: null, sqlstate: "23502", message: "null value" }]);
  });

  it("reads scalar values and errors", async () => {
    const t = new FakeTransport();
    t.replyOverride = (_f, block) => (block.includes("bad") ? '{"ok": false, "sqlstate": "42P01", "message": "gone"}' : undefined);
    const { s } = await sandbox(t);
    expect(await s.scalars(["SELECT 1", "bad"])).toEqual([
      { ok: true, value: "1" },
      { ok: false, sqlstate: "42P01", message: "gone" },
    ]);
  });
});

describe("PostgresSandbox.run", () => {
  it("runs probes as the prober with the probe pin, switching to the client role inside the block", async () => {
    const { t, s } = await sandbox();
    await s.run([{ role: "authenticated", claims: `{"sub":"it's"}`, sql: "SELECT 1" }]);
    const call = t.calls.at(-1);
    expect(call?.session).toEqual({ database: "db1", principal: "prober", pin: "probe", statementTimeoutMs: 20_000 });
    expect(call?.steps[0]?.sql).toContain("SET LOCAL ROLE authenticated;");
    expect(call?.steps[0]?.sql).toContain(`'{"sub":"it''s"}'`);
  });

  it("maps rows and errors to observations", async () => {
    const t = new FakeTransport();
    let i = 0;
    t.replyOverride = () => (i++ === 0 ? '{"ok": true, "rows": 4}' : '{"ok": false, "sqlstate": "42501", "message": "denied"}');
    const { s } = await sandbox(t);
    expect(await s.run([{ role: "anon", claims: "{}", sql: "a" }, { role: "anon", claims: "{}", sql: "b" }])).toEqual([
      { status: "rows", rows: 4 },
      { status: "error", sqlstate: "42501", message: "denied" },
    ]);
  });

  it("records every probe of a failed batch as not run instead of throwing", async () => {
    const t = new FakeTransport();
    const { s } = await sandbox(t);
    t.failAll = new TransportError("timed out");
    expect(await s.run([{ role: "anon", claims: "{}", sql: "a" }, { role: "anon", claims: "{}", sql: "b" }])).toEqual([
      { status: "not-run", reason: "the batch did not finish: timed out" },
      { status: "not-run", reason: "the batch did not finish: timed out" },
    ]);
  });

  it("records an unreadable or empty reply as not run for that probe only", async () => {
    const t = new FakeTransport();
    let i = 0;
    t.replyOverride = () => (i++ === 0 ? "" : '{"ok": true, "rows": 1}');
    const { s } = await sandbox(t);
    const out = await s.run([{ role: "anon", claims: "{}", sql: "a" }, { role: "anon", claims: "{}", sql: "b" }]);
    expect(out[0]?.status).toBe("not-run");
    expect(out[1]).toEqual({ status: "rows", rows: 1 });
  });
});

describe("PostgresSandbox catalog and fingerprint", () => {
  it("reads the catalog as the admin in a session whose search_path is pg_catalog", async () => {
    const { t, s } = await sandbox();
    expect(await s.catalog()).toMatchObject({ serverVersion: "16.14" });
    expect(t.calls.at(-1)?.session).toMatchObject({ principal: "admin", pin: "catalog" });
    expect(t.calls.at(-1)?.steps[0]?.sql).toContain("pg_catalog.jsonb_build_object");
  });

  it("reads the fingerprint as the admin with the sandbox's role names in the query", async () => {
    const { t, s } = await sandbox();
    expect(await s.fingerprint()).toEqual({ entries: [{ key: "role anon", value: "super=false" }] });
    expect(t.calls.at(-1)?.session).toMatchObject({ principal: "admin", pin: "catalog" });
    expect(t.calls.at(-1)?.steps[0]?.sql).toContain("'supabase_admin', 'postgres', 'proof_audit_prober'");
  });
});

describe("PostgresSandbox lifecycle", () => {
  it("forks from a template as the admin and restores the per-database search_path", async () => {
    const { t, s } = await sandbox();
    const child = await s.fork();
    expect(t.sent).toContain('CREATE DATABASE "db2" TEMPLATE "db1"');
    expect(t.sent.some((x) => x.includes("ALTER DATABASE %I SET search_path"))).toBe(true);
    await child.apply(["x"]);
    expect(t.calls.at(-1)?.session.database).toBe("db2");
  });

  it("drops its own database once, with force, and runs the dispose hook once", async () => {
    const t = new FakeTransport();
    let hooks = 0;
    const s = await PostgresSandbox.create(t, naming(), setup, async () => void (hooks += 1));
    await s.dispose();
    await s.dispose();
    expect(t.sent.filter((e) => e.startsWith("DROP DATABASE"))).toEqual(['DROP DATABASE IF EXISTS "db1" WITH (FORCE)']);
    expect(hooks).toBe(1);
  });

  it("runs the dispose hook even when the drop fails", async () => {
    const t = new FakeTransport();
    let hooks = 0;
    const s = await PostgresSandbox.create(t, naming(), setup, async () => void (hooks += 1));
    t.failOn = /DROP DATABASE/;
    await expect(s.dispose()).rejects.toThrow();
    expect(hooks).toBe(1);
  });
});
