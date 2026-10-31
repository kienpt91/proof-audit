import { describe, expect, it } from "vitest";
import { scanForTampering } from "../../../src/domain/integrity/attempts.js";
import type { SqlStatement } from "../../../src/domain/sql/statement.js";

const stmt = (text: string, line = 1): SqlStatement => ({ file: "m/1.sql", line, text, kind: "sql" });
const kinds = (text: string) => scanForTampering([stmt(text)]).map((a) => `${a.kind}: ${a.detail}`);

describe("scanForTampering", () => {
  it("is silent for ordinary migrations", () => {
    expect(kinds("create table public.t (id uuid primary key, user_id uuid references auth.users (id))")).toEqual([]);
    expect(kinds("create policy p on public.t for select using (auth.uid() = user_id)")).toEqual([]);
    expect(kinds("create trigger on_signup after insert on auth.users for each row execute function public.handle()")).toEqual([]);
    expect(kinds("alter database postgres set \"app.settings.x\" = 'y'")).toEqual([]);
    expect(kinds("set search_path to public")).toEqual([]);
    expect(kinds("grant select on auth.users to anon")).toEqual([]);
  });

  it("flags redefining the platform's auth functions in every form", () => {
    expect(kinds("create or replace function auth.uid() returns uuid language sql as $$ select null::uuid $$")).toEqual(["redefines-platform-object: CREATE FUNCTION auth.uid"]);
    expect(kinds('drop function if exists "auth"."jwt"()')).toEqual(["redefines-platform-object: DROP FUNCTION auth.jwt"]);
    expect(kinds("alter function auth.role() security definer")).toEqual(["redefines-platform-object: ALTER FUNCTION auth.role"]);
    expect(kinds("alter table auth.users add column x int")).toEqual(["redefines-platform-object: ALTER TABLE auth.users"]);
    expect(kinds("create schema if not exists auth")).toEqual([]);
    expect(kinds("create view pg_catalog.v as select 1")).toEqual(["redefines-platform-object: CREATE VIEW pg_catalog.v"]);
  });

  it("flags any mention of the tool's own schema, however it is written", () => {
    expect(kinds("create or replace function proof_audit.run_probe(p_role text) returns jsonb language sql as $$ select 1 $$")).toContain("targets-tool-internals: mentions the tool's own schema proof_audit");
    expect(kinds('select "proof_audit".try_exec(1)')).toHaveLength(1);
  });

  it("flags moving objects into or out of an extension, which is how a table can be hidden from a catalog filter", () => {
    expect(kinds("alter extension pgcrypto add table public.secrets")).toEqual(["redefines-platform-object: ALTER EXTENSION pgcrypto ADD"]);
    expect(kinds("alter extension pgcrypto drop function f()")).toEqual(["redefines-platform-object: ALTER EXTENSION pgcrypto DROP"]);
    expect(kinds("alter extension pgcrypto update")).toEqual([]);
    expect(kinds("create extension if not exists pgcrypto")).toEqual([]);
  });

  it("flags event triggers", () => {
    expect(kinds("create event trigger t on ddl_command_end execute function f()")).toEqual(["event-trigger: CREATE EVENT TRIGGER"]);
    expect(kinds("alter event trigger t disable")).toEqual(["event-trigger: ALTER EVENT TRIGGER"]);
  });

  it("flags changes to settings that decide how probes resolve names and apply rules", () => {
    expect(kinds("alter database postgres set search_path = public, pg_catalog")).toEqual(["alters-protected-setting: ALTER DATABASE ... SET search_path"]);
    expect(kinds("alter role anon set session_replication_role = replica")).toEqual(["alters-protected-setting: ALTER ROLE ... SET session_replication_role", "alters-protected-setting: SET session_replication_role"]);
    expect(kinds("alter system set work_mem = '1MB'")).toEqual(["alters-protected-setting: ALTER SYSTEM"]);
    expect(kinds("set session_replication_role = replica")).toEqual(["alters-protected-setting: SET session_replication_role"]);
    expect(kinds("set local session_authorization postgres")).toEqual(["alters-protected-setting: SET session_authorization"]);
    expect(kinds("select set_config('session_replication_role', 'replica', false)")).toEqual(["alters-protected-setting: set_config('session_replication_role')"]);
  });

  it("flags direct writes to catalog tables", () => {
    expect(kinds("update pg_catalog.pg_proc set prosrc = 'x' where proname = 'set_config'")).toEqual(["catalog-write: UPDATE on pg_catalog.pg_proc"]);
    expect(kinds("delete from pg_policy")).toEqual(["catalog-write: DELETE on pg_catalog.pg_policy"]);
    expect(kinds("insert into pg_catalog.pg_authid select 1")).toEqual(["catalog-write: INSERT on pg_catalog.pg_authid"]);
    expect(kinds("update public.pg_notes set x = 1")).toEqual([]);
  });

  it("sees through DO blocks and EXECUTE strings", () => {
    expect(kinds("do $$ begin execute 'alter database ' || current_database() || ' set search_path = evil'; end $$")).toEqual(["alters-protected-setting: ALTER DATABASE ... SET search_path"]);
    expect(kinds("do $a$ begin execute $b$ create or replace function auth.uid() returns uuid language sql as 'select null::uuid' $b$; end $a$")).toEqual(["redefines-platform-object: CREATE FUNCTION auth.uid"]);
  });

  it("reports each kind once per statement, with the statement's file and line", () => {
    const found = scanForTampering([stmt("select 1", 1), stmt("alter system set a = 1; alter system set b = 2", 7)]);
    expect(found).toEqual([{ kind: "alters-protected-setting", detail: "ALTER SYSTEM", file: "m/1.sql", line: 7 }]);
  });

  it("ignores transaction control and psql meta statements", () => {
    expect(scanForTampering([{ file: "a", line: 1, text: "alter system set a = 1", kind: "psql-meta" }])).toEqual([]);
  });

  it("ignores words inside comments and ordinary strings", () => {
    expect(kinds("-- alter system set x = 1\nselect 'alter systematic'")).toEqual([]);
  });
});
