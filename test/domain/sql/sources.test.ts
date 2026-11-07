import { describe, expect, it } from "vitest";
import { parseMigrations } from "../../../src/domain/sql/parser.js";

const index = (sql: string, path = "m.sql") => parseMigrations([{ path, content: sql }]).sources;
const spot = (file: string, line: number) => ({ file, line });

describe("source index", () => {
  it("records where a table, its row level security switch and its policies were written", () => {
    const sources = index(`-- header
create table public.notes (
  id uuid primary key
);

alter table public.notes enable row level security;
create policy "Read all" on public.notes
  for select using (true);
create policy own on public.notes for all to authenticated using (true);
`);
    const notes = sources.tables.get("public.notes");
    expect(notes?.created).toEqual(spot("m.sql", 2));
    expect(notes?.rowSecurity).toEqual(spot("m.sql", 6));
    expect([...(notes?.policies ?? [])]).toEqual([["Read all", spot("m.sql", 7)], ["own", spot("m.sql", 9)]]);
  });

  it("points at the first token of the statement, not at a comment above it", () => {
    const sources = index("-- one\n/* two\n three */\n\ncreate table t (a int);\n");
    expect(sources.tables.get("public.t")?.created.line).toBe(5);
  });

  it("follows files in the order given and keeps each path", () => {
    const parsed = parseMigrations([
      { path: "a.sql", content: "create table public.t (id int);\n" },
      { path: "b/c.sql", content: "\n\nalter table public.t enable row level security;\ncreate policy p on public.t using (true);\n" },
    ]);
    const t = parsed.sources.tables.get("public.t");
    expect(t?.created).toEqual(spot("a.sql", 1));
    expect(t?.rowSecurity).toEqual(spot("b/c.sql", 3));
    expect(t?.policies.get("p")).toEqual(spot("b/c.sql", 4));
  });

  it("reports the last statement that switched row level security", () => {
    const sources = index("create table t (id int);\nalter table t enable row level security;\nalter table t disable row level security;\nalter table t force row level security;\n");
    expect(sources.tables.get("public.t")?.rowSecurity?.line).toBe(3);
  });

  it("has no switch for a table that never had one", () => {
    expect(index("create table t (id int);\n").tables.get("public.t")?.rowSecurity).toBeNull();
  });

  it("gives a policy the line of the statement that last defined it", () => {
    const sources = index("create table t (id int);\ncreate policy p on t using (false);\ncreate policy p on t using (true);\n");
    expect(sources.tables.get("public.t")?.policies.get("p")?.line).toBe(3);
    const altered = index("create table t (id int);\ncreate policy p on t using (false);\nalter policy p on t using (true);\n");
    expect(altered.tables.get("public.t")?.policies.get("p")?.line).toBe(3);
  });

  it("follows a renamed policy and forgets a dropped one", () => {
    const renamed = index("create table t (id int);\ncreate policy p on t using (true);\nalter policy p on t rename to q;\n");
    expect([...(renamed.tables.get("public.t")?.policies.keys() ?? [])]).toEqual(["q"]);
    expect(renamed.tables.get("public.t")?.policies.get("q")?.line).toBe(3);
    const dropped = index("create table t (id int);\ncreate policy p on t using (true);\ndrop policy p on t;\n");
    expect(dropped.tables.get("public.t")?.policies.size).toBe(0);
  });

  it("follows a renamed or moved table and forgets a dropped one", () => {
    const renamed = index("create table old_name (id int);\nalter table old_name rename to new_name;\n");
    expect([...renamed.tables.keys()]).toEqual(["public.new_name"]);
    expect(renamed.tables.get("public.new_name")?.created.line).toBe(1);
    const moved = index("create table t (id int);\nalter table t set schema app;\n");
    expect([...moved.tables.keys()]).toEqual(["app.t"]);
    expect(index("create table t (id int);\ndrop table t;\n").tables.size).toBe(0);
  });

  it("records views, and the latest definition of a replaced view", () => {
    const sources = index("create table t (id int);\ncreate view v as select * from t;\ncreate or replace view v as select id from t;\n");
    expect(sources.views.get("public.v")).toEqual(spot("m.sql", 3));
    expect([...index("create table t (id int);\ncreate view v as select 1;\ndrop view v;\n").views.keys()]).toEqual([]);
  });

  it("does not index a table whose CREATE was skipped by IF NOT EXISTS", () => {
    const sources = index("create table t (id int);\ncreate table if not exists t (id int, extra int);\n");
    expect(sources.tables.get("public.t")?.created.line).toBe(1);
  });

  it("is empty for input with no objects", () => {
    const sources = index("select 1;\n");
    expect(sources.tables.size).toBe(0);
    expect(sources.views.size).toBe(0);
  });
});
