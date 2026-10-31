import { describe, expect, it } from "vitest";
import { TransportError } from "../../src/infrastructure/postgres/transport.js";
import { PostgresSandbox } from "../../src/infrastructure/postgres/sandbox.js";
import { HARNESS_STATEMENTS } from "../../src/infrastructure/postgres/harness.js";
import { defineSandboxContract } from "../contract/sandbox.contract.js";
import { FakeTransport } from "../helpers/fake-transport.js";
import { ModelSandbox } from "../helpers/model-sandbox.js";
import { model, notes } from "../helpers/model.js";

function naming() {
  let n = 0;
  return { nextName: () => `db${(n += 1)}`, maintenanceDatabase: "maint" };
}

async function sandbox(t = new FakeTransport()) {
  return { t, s: await PostgresSandbox.create(t, naming()) };
}

defineSandboxContract("in-memory model", async () => new ModelSandbox({ model: model([notes()]) }));
defineSandboxContract("PostgresSandbox over a fake transport", async () => (await sandbox()).s);

describe("PostgresSandbox.create", () => {
  it("creates the database from the maintenance database, then installs the harness in it", async () => {
    const { t } = await sandbox();
    expect(t.calls[0]).toEqual({ kind: "execute", database: "maint", statements: ['CREATE DATABASE "db1"'] });
    expect(t.calls[1]).toEqual({ kind: "execute", database: "db1", statements: HARNESS_STATEMENTS });
  });

  it("limits statement time, lock waits and idle transactions in the new database", async () => {
    const { t } = await sandbox();
    expect(t.calls[2]?.database).toBe("maint");
    expect(t.calls[2]?.statements).toEqual([
      'ALTER DATABASE "db1" SET search_path TO "$user", public, extensions',
      'ALTER DATABASE "db1" SET statement_timeout = 20000',
      'ALTER DATABASE "db1" SET lock_timeout = 5000',
      'ALTER DATABASE "db1" SET idle_in_transaction_session_timeout = 30000',
    ]);
  });

  it("drops the database again when the harness cannot be installed", async () => {
    const t = new FakeTransport();
    t.failExecute = /CREATE SCHEMA IF NOT EXISTS proof_audit/;
    await expect(PostgresSandbox.create(t, naming())).rejects.toThrow("execute failed");
    expect(t.executed).toContain('DROP DATABASE IF EXISTS "db1" WITH (FORCE)');
  });
});

describe("PostgresSandbox.apply", () => {
  it("sends each statement dollar-quoted through try_exec in one session", async () => {
    const { t, s } = await sandbox();
    await s.apply(["CREATE TABLE a (x int)", "DROP TABLE a"]);
    const call = t.calls.at(-1);
    expect(call?.kind).toBe("query");
    expect(call?.database).toBe("db1");
    expect(call?.statements).toEqual(["SELECT proof_audit.try_exec($pa$CREATE TABLE a (x int)$pa$)::text", "SELECT proof_audit.try_exec($pa$DROP TABLE a$pa$)::text"]);
  });

  it("cannot be broken out of by a statement that contains the quote tag", async () => {
    const { t, s } = await sandbox();
    await s.apply(["select $pa$ x $pa$; drop table users; --"]);
    const sent = t.calls.at(-1)?.statements[0] ?? "";
    const tag = /try_exec\(\$(pa\d*)\$/.exec(sent)?.[1];
    expect(tag).not.toBe("pa");
    expect(sent.split(`$${tag}$`)).toHaveLength(3);
  });

  it("reports failures with their SQLSTATE and message", async () => {
    const t = new FakeTransport();
    t.replyOverride = (q) => (q.includes("bad") ? '{"ok": false, "sqlstate": "42601", "message": "syntax error"}' : undefined);
    const { s } = await sandbox(t);
    expect(await s.apply(["good", "bad"])).toEqual([
      { ok: true, sqlstate: null, message: null },
      { ok: false, sqlstate: "42601", message: "syntax error" },
    ]);
  });

  it("throws when the reply is not a harness reply", async () => {
    const t = new FakeTransport();
    t.replyOverride = () => "not json";
    const { s } = await sandbox(t);
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
  it("passes alternatives as one array and reads the winning attempt", async () => {
    const t = new FakeTransport();
    t.replyOverride = (q) => (q.includes("try_first") ? '{"ok": true, "attempt": 1}' : undefined);
    const { s } = await sandbox(t);
    const out = await s.applyFirstSuccess([["a", "b"]]);
    expect(out).toEqual([{ ok: true, attempt: 1, sqlstate: null, message: null }]);
    expect(t.calls.at(-1)?.statements[0]).toBe("SELECT proof_audit.try_first(ARRAY[$pa$a$pa$, $pa$b$pa$]::text[])::text");
  });

  it("reports when no alternative worked", async () => {
    const t = new FakeTransport();
    t.replyOverride = () => '{"ok": false, "sqlstate": "23502", "message": "null value"}';
    const { s } = await sandbox(t);
    expect(await s.applyFirstSuccess([["a"]])).toEqual([{ ok: false, attempt: null, sqlstate: "23502", message: "null value" }]);
  });

  it("reads scalar values and errors", async () => {
    const t = new FakeTransport();
    t.replyOverride = (q) => (q.includes("bad") ? '{"ok": false, "sqlstate": "42P01", "message": "gone"}' : undefined);
    const { s } = await sandbox(t);
    expect(await s.scalars(["SELECT 1", "bad"])).toEqual([
      { ok: true, value: "1" },
      { ok: false, sqlstate: "42P01", message: "gone" },
    ]);
  });
});

describe("PostgresSandbox.run", () => {
  it("quotes role and claims as literals and the SQL as a dollar-quoted string", async () => {
    const { t, s } = await sandbox();
    await s.run([{ role: "authenticated", claims: `{"sub":"it's"}`, sql: "SELECT 1" }]);
    expect(t.calls.at(-1)?.statements[0]).toBe(`SELECT proof_audit.run_probe('authenticated', '{"sub":"it''s"}', $pa$SELECT 1$pa$)::text`);
  });

  it("maps rows and errors to observations", async () => {
    const t = new FakeTransport();
    let i = 0;
    t.replyOverride = (q) => (q.includes("run_probe") ? (i++ === 0 ? '{"ok": true, "rows": 4}' : '{"ok": false, "sqlstate": "42501", "message": "denied"}') : undefined);
    const { s } = await sandbox(t);
    expect(await s.run([{ role: "anon", claims: "{}", sql: "a" }, { role: "anon", claims: "{}", sql: "b" }])).toEqual([
      { status: "rows", rows: 4 },
      { status: "error", sqlstate: "42501", message: "denied" },
    ]);
  });

  it("records every probe of a failed batch as not run instead of throwing", async () => {
    const t = new FakeTransport();
    const { s } = await sandbox(t);
    t.failQuery = new TransportError("timed out");
    const out = await s.run([{ role: "anon", claims: "{}", sql: "a" }, { role: "anon", claims: "{}", sql: "b" }]);
    expect(out).toEqual([
      { status: "not-run", reason: "the batch did not finish: timed out" },
      { status: "not-run", reason: "the batch did not finish: timed out" },
    ]);
  });

  it("records an unreadable reply as not run for that probe only", async () => {
    const t = new FakeTransport();
    let i = 0;
    t.replyOverride = () => (i++ === 0 ? "garbage" : '{"ok": true, "rows": 1}');
    const { s } = await sandbox(t);
    const out = await s.run([{ role: "anon", claims: "{}", sql: "a" }, { role: "anon", claims: "{}", sql: "b" }]);
    expect(out[0]?.status).toBe("not-run");
    expect(out[1]).toEqual({ status: "rows", rows: 1 });
  });
});

describe("PostgresSandbox lifecycle", () => {
  it("forks from a template and restores the per-database search_path", async () => {
    const { t, s } = await sandbox();
    const child = await s.fork();
    expect(t.executed).toContain('CREATE DATABASE "db2" TEMPLATE "db1"');
    expect(t.executed).toContain('ALTER DATABASE "db2" SET search_path TO "$user", public, extensions');
    expect(t.executed).toContain('ALTER DATABASE "db2" SET statement_timeout = 20000');
    await child.apply(["x"]);
    expect(t.calls.at(-1)?.database).toBe("db2");
  });

  it("drops its own database once, with force, and runs the dispose hook once", async () => {
    const t = new FakeTransport();
    let hooks = 0;
    const s = await PostgresSandbox.create(t, naming(), async () => void (hooks += 1));
    await s.dispose();
    await s.dispose();
    expect(t.executed.filter((e) => e.startsWith("DROP DATABASE"))).toEqual(['DROP DATABASE IF EXISTS "db1" WITH (FORCE)']);
    expect(hooks).toBe(1);
  });

  it("runs the dispose hook even when the drop fails", async () => {
    const t = new FakeTransport();
    let hooks = 0;
    const s = await PostgresSandbox.create(t, naming(), async () => void (hooks += 1));
    t.failExecute = /DROP DATABASE/;
    await expect(s.dispose()).rejects.toThrow();
    expect(hooks).toBe(1);
  });

  it("reads the catalog as parsed JSON", async () => {
    const { s } = await sandbox();
    expect(await s.catalog()).toMatchObject({ serverVersion: "16.14" });
  });
});
