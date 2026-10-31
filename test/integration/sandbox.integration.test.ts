import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { prepareSandbox } from "../../src/application/prepare.js";
import type { Sandbox } from "../../src/application/ports.js";
import { catalogToModel, parseCatalog } from "../../src/domain/catalog/snapshot.js";
import { parseMigrations } from "../../src/domain/sql/parser.js";
import { SHIM_STATEMENTS } from "../../src/domain/supabase/shim.js";
import { PgTransport } from "../../src/infrastructure/postgres/pg-transport.js";
import { randomNaming } from "../../src/infrastructure/postgres/names.js";
import { PostgresSandbox } from "../../src/infrastructure/postgres/sandbox.js";
import { UrlSandboxProvider } from "../../src/infrastructure/postgres/url-provider.js";
import { defineSandboxContract } from "../contract/sandbox.contract.js";
import { endpoint, haveDatabase } from "./support.js";

const make = async (timeoutMs?: number): Promise<PostgresSandbox> =>
  PostgresSandbox.create(new PgTransport(endpoint()), randomNaming(endpoint().database, timeoutMs));

const withShim = async (s: Sandbox): Promise<void> => {
  const out = await s.apply(SHIM_STATEMENTS);
  if (out.some((o) => !o.ok)) throw new Error("shim failed");
  await s.apply(['create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null, title text)']);
};

describe.skipIf(!haveDatabase)("real PostgreSQL", () => {
  if (haveDatabase) defineSandboxContract("PostgresSandbox over pg on loopback", () => make(), withShim);

  it("records each failing statement and runs the rest in the same session", async () => {
    const s = await make();
    try {
      const out = await s.apply(["create schema s1", "select * from nope", "set search_path to s1", "create table made_in_session (x int)"]);
      expect(out.map((o) => o.ok)).toEqual([true, false, true, true]);
      expect(out[1]).toMatchObject({ sqlstate: "42P01" });
      const where = await s.scalars(["select table_schema from information_schema.tables where table_name = 'made_in_session'"]);
      expect(where).toEqual([{ ok: true, value: "s1" }]);
    } finally {
      await s.dispose();
    }
  });

  it("returns the row count of reads and writes and always rolls the probe back", async () => {
    const s = await make();
    try {
      await withShim(s);
      await s.apply(["insert into public.notes (user_id, title) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'x')"]);
      const claims = '{"role":"anon"}';
      const out = await s.run([
        { role: "anon", claims, sql: "select * from public.notes" },
        { role: "anon", claims, sql: "update public.notes set title = 'y'" },
        { role: "anon", claims, sql: "delete from public.notes" },
        { role: "anon", claims, sql: "insert into public.notes (user_id) values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')" },
      ]);
      expect(out).toEqual([{ status: "rows", rows: 1 }, { status: "rows", rows: 1 }, { status: "rows", rows: 1 }, { status: "rows", rows: 1 }]);
      expect(await s.scalars(["select count(*) from public.notes", "select title from public.notes"])).toEqual([
        { ok: true, value: "1" },
        { ok: true, value: "x" },
      ]);
    } finally {
      await s.dispose();
    }
  });

  it("reports permission errors as 42501 and applies row level security to the switched role", async () => {
    const s = await make();
    try {
      await withShim(s);
      await s.apply([
        "revoke all on public.notes from anon",
        "alter table public.notes enable row level security",
        "create policy own on public.notes for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()))",
        "insert into public.notes (user_id, title) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'mine'), ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'theirs')",
      ]);
      const a = '{"role":"authenticated","sub":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}';
      const out = await s.run([
        { role: "anon", claims: '{"role":"anon"}', sql: "select * from public.notes" },
        { role: "authenticated", claims: a, sql: "select * from public.notes" },
        { role: "authenticated", claims: a, sql: "insert into public.notes (user_id) values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')" },
        { role: "authenticated", claims: a, sql: "update public.notes set title = 'x' where user_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'" },
      ]);
      expect(out[0]).toMatchObject({ status: "error", sqlstate: "42501" });
      expect(out[1]).toEqual({ status: "rows", rows: 1 });
      expect(out[2]).toMatchObject({ status: "error", sqlstate: "42501" });
      expect(out[3]).toEqual({ status: "rows", rows: 0 });
    } finally {
      await s.dispose();
    }
  });

  it("evaluates row level security before table constraints, which the verdict logic relies on", async () => {
    const s = await make();
    try {
      await withShim(s);
      await s.apply(["alter table public.notes enable row level security", "create policy deny on public.notes for insert to authenticated with check (false)"]);
      const claims = '{"role":"authenticated","sub":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}';
      const [denied] = await s.run([{ role: "authenticated", claims, sql: "insert into public.notes (title) values (null)" }]);
      expect(denied).toMatchObject({ status: "error", sqlstate: "42501" });
      await s.apply(["drop policy deny on public.notes", "create policy allow on public.notes for insert to authenticated with check (true)"]);
      const [admitted] = await s.run([{ role: "authenticated", claims, sql: "insert into public.notes (user_id, title) values (null, 'x')" }]);
      expect(admitted).toMatchObject({ status: "error", sqlstate: "23502" });
    } finally {
      await s.dispose();
    }
  });

  it("keeps a fork independent of its parent, with the parent's data", async () => {
    const s = await make();
    try {
      await withShim(s);
      await s.apply(["insert into public.notes (user_id, title) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'x')"]);
      const child = await s.fork();
      await child.apply(["delete from public.notes"]);
      expect(await child.scalars(["select count(*) from public.notes"])).toEqual([{ ok: true, value: "0" }]);
      expect(await s.scalars(["select count(*) from public.notes"])).toEqual([{ ok: true, value: "1" }]);
      expect(await child.scalars(["show statement_timeout"])).toEqual([{ ok: true, value: "20s" }]);
      await child.dispose();
    } finally {
      await s.dispose();
    }
  });

  it("leaves no database behind after dispose", async () => {
    const provider = new UrlSandboxProvider(endpoint());
    const created = await provider.create();
    const child = await created.sandbox.fork();
    await child.dispose();
    await created.sandbox.dispose();
    const probe = await make();
    try {
      const [left] = await probe.scalars(["select count(*) from pg_database where datname like 'proof_audit_%' and datname <> current_database()"]);
      expect(left).toEqual({ ok: true, value: "0" });
    } finally {
      await probe.dispose();
    }
  });

  it("reads tables, views, policies, privileges, enums, generated and identity columns from the catalog", async () => {
    const s = await make();
    try {
      await withShim(s);
      const statements = [
        "create type public.mood as enum ('calm', 'tense')",
        `create table public.rich (
           id bigint generated always as identity primary key,
           code text generated always as ('c' || id::text) stored,
           seq int generated by default as identity,
           mood public.mood not null default 'calm',
           user_id uuid references auth.users (id),
           a int, b int,
           unique (a, b),
           constraint positive check (a > 0)
         )`,
        "alter table public.rich enable row level security",
        "create policy p on public.rich as restrictive for select to anon, authenticated using (a > 0)",
        "revoke delete on public.rich from anon",
        "create view public.rich_v with (security_invoker = on) as select id, user_id from public.rich",
      ];
      const out = await s.apply(statements);
      expect(out.map((o) => o.ok)).toEqual(statements.map(() => true));
      const parsed = parseCatalog(await s.catalog());
      if (!parsed.ok) throw new Error(parsed.error);
      const model = catalogToModel(parsed.value);
      const rich = model.tables.find((t) => t.name.name === "rich");
      const col = (n: string) => rich?.columns.find((c) => c.name === n);
      expect(rich).toMatchObject({ rlsEnabled: true, rlsForced: false, origin: "catalog" });
      expect(col("id")).toMatchObject({ type: "bigint", primaryKey: true, generated: true });
      expect(col("code")).toMatchObject({ generated: true, hasDefault: false });
      expect(col("seq")).toMatchObject({ generated: false, hasDefault: true });
      expect(col("mood")).toMatchObject({ type: "mood", enumLabels: ["calm", "tense"], notNull: true, hasDefault: true });
      expect(col("user_id")?.references).toEqual({ schema: "auth", table: "users", column: "id" });
      expect(col("a")?.unique).toBe(false);
      expect(rich?.checks).toEqual(["CHECK ((a > 0))"]);
      expect(rich?.policies).toEqual([{ name: "p", command: "select", permissive: false, roles: ["anon", "authenticated"], using: "(a > 0)", withCheck: null }]);
      expect(rich?.privileges.anon).toEqual(["select", "insert", "update"]);
      expect(rich?.privileges.authenticated).toEqual(["select", "insert", "update", "delete"]);
      const view = model.views.find((v) => v.name.name === "rich_v");
      expect(view).toMatchObject({ securityInvoker: true, columns: ["id", "user_id"], dependsOn: [{ schema: "public", name: "rich" }] });
      expect(model.tables.some((t) => t.name.schema === "auth")).toBe(false);
    } finally {
      await s.dispose();
    }
  });

  it("applies the shim, the migrations and the seed rows through prepareSandbox", async () => {
    const s = await make();
    try {
      const parsed = parseMigrations([{ path: "a.sql", content: "create table public.n (id uuid primary key, user_id uuid not null references auth.users (id), title text);" }]);
      const prepared = await prepareSandbox(s, parsed.statements);
      expect(prepared.seeding).toEqual([{ table: "public.n", rowsUserA: 1, rowsUserB: 1, status: "ok", reason: null }]);
      expect(prepared.serverVersion).toMatch(/^16\./);
    } finally {
      await s.dispose();
    }
  });

  it("refuses a connecting role that is not a superuser", async () => {
    const admin = await make();
    const role = `pa_low_${randomBytes(4).toString("hex")}`;
    const password = randomBytes(12).toString("hex");
    try {
      await admin.apply([`create role ${role} login password '${password}'`]);
      const e = endpoint();
      const provider = new UrlSandboxProvider({ ...e, user: role, password });
      await expect(provider.create()).rejects.toThrow("superuser");
    } finally {
      await admin.apply([`drop role if exists ${role}`]);
      await admin.dispose();
    }
  });
});
