import { describe, expect, it } from "vitest";
import { COMMANDS, qualifiedKey, type Column, type Table, type View } from "../../../src/domain/schema/model.js";
import { parseMigrations } from "../../../src/domain/sql/parser.js";

const parse = (sql: string) => parseMigrations([{ path: "m.sql", content: sql }]);

function table(sql: string, key = "public.t"): Table {
  const found = parse(sql).model.tables.find((t) => qualifiedKey(t.name) === key);
  if (found === undefined) throw new Error(`no table ${key} in model of: ${sql}`);
  return found;
}

function column(sql: string, name: string, key = "public.t"): Column {
  const found = table(sql, key).columns.find((c) => c.name === name);
  if (found === undefined) throw new Error(`no column ${name}`);
  return found;
}

function view(sql: string, key = "public.v"): View {
  const found = parse(sql).model.views.find((v) => qualifiedKey(v.name) === key);
  if (found === undefined) throw new Error(`no view ${key}`);
  return found;
}

describe("CREATE TABLE", () => {
  it("reads a table with columns in order", () => {
    const t = table("create table public.t (id uuid, name text, n int);");
    expect(t.columns.map((c) => [c.name, c.type])).toEqual([["id", "uuid"], ["name", "text"], ["n", "integer"]]);
    expect(t.origin).toBe("parsed");
    expect(t.rlsEnabled).toBe(false);
    expect(t.rlsForced).toBe(false);
    expect(t.policies).toEqual([]);
  });

  it("resolves unqualified names to public and keeps explicit schemas", () => {
    const { tables } = parse("create table a (x int); create table private.b (x int);").model;
    expect(tables.map((t) => qualifiedKey(t.name))).toEqual(["public.a", "private.b"]);
  });

  it("lower-cases unquoted identifiers and keeps quoted ones exact", () => {
    const t = table('create table "Public"."MyT" (ID int, "Mixed Case" int);', "Public.MyT");
    expect(t.columns.map((c) => c.name)).toEqual(["id", "Mixed Case"]);
  });

  it("accepts IF NOT EXISTS and keeps the first definition", () => {
    const t = table("create table t (a int); create table if not exists t (b int);");
    expect(t.columns.map((c) => c.name)).toEqual(["a"]);
  });

  it("replaces a table that is created again without IF NOT EXISTS", () => {
    expect(table("create table t (a int); create table t (b int);").columns.map((c) => c.name)).toEqual(["b"]);
  });

  it("reads UNLOGGED tables and skips TEMP tables", () => {
    const { tables } = parse("create unlogged table u (a int); create temp table x (a int); create temporary table y (a int); create global temporary table z (a int);").model;
    expect(tables.map((t) => t.name.name)).toEqual(["u"]);
  });

  it.each([
    ["varchar(255)", "character varying(255)"],
    ["character varying(10)", "character varying(10)"],
    ["character   varying", "character varying"],
    ["varchar", "character varying"],
    ["char(3)", "character(3)"],
    ["char", "character(1)"],
    ["int", "integer"],
    ["int4", "integer"],
    ["INTEGER", "integer"],
    ["int8", "bigint"],
    ["int2", "smallint"],
    ["timestamptz", "timestamp with time zone"],
    ["timestamp", "timestamp without time zone"],
    ["timestamp with time zone", "timestamp with time zone"],
    ["timestamp(3) with time zone", "timestamp(3) with time zone"],
    ["timestamp without time zone", "timestamp without time zone"],
    ["time", "time without time zone"],
    ["timetz", "time with time zone"],
    ["bool", "boolean"],
    ["float8", "double precision"],
    ["double precision", "double precision"],
    ["float4", "real"],
    ["float(53)", "double precision"],
    ["float(10)", "real"],
    ["decimal(10, 2)", "numeric(10,2)"],
    ["numeric(10,2)", "numeric(10,2)"],
    ["text[]", "text[]"],
    ["int[]", "integer[]"],
    ["uuid ARRAY", "uuid[]"],
    ["integer[3]", "integer[]"],
    ["public.mood", "mood"],
    ["extensions.vector(3)", "extensions.vector(3)"],
    ['"MyEnum"', '"MyEnum"'],
    ["jsonb", "jsonb"],
    ["serial", "integer"],
    ["bigserial", "bigint"],
    ["smallserial", "smallint"],
  ])("normalises column type %s to %s", (written, expected) => {
    expect(column(`create table t (c ${written} not null);`, "c").type).toBe(expected);
  });

  it("marks serial columns as defaulted and not null", () => {
    const c = column("create table t (id serial, big bigserial);", "id");
    expect(c).toMatchObject({ hasDefault: true, notNull: true, type: "integer" });
    expect(column("create table t (id serial, big bigserial);", "big")).toMatchObject({ hasDefault: true, type: "bigint" });
  });

  it("reads NOT NULL and explicit NULL", () => {
    const t = table("create table t (a int not null, b int null, c int);");
    expect(t.columns.map((c) => c.notNull)).toEqual([true, false, false]);
  });

  it("reads DEFAULT expressions up to the next constraint", () => {
    const c = column("create table t (a timestamptz not null default now() unique);", "a");
    expect(c).toMatchObject({ hasDefault: true, defaultExpr: "now()", notNull: true, unique: true });
  });

  it("keeps defaults with parentheses, casts and strings intact", () => {
    expect(column("create table t (a text default ('x' || 'y')::text not null);", "a").defaultExpr).toBe("('x' || 'y')::text");
    expect(column("create table t (a int[] default array[1, 2] not null);", "a").defaultExpr).toBe("array[1, 2]");
    expect(column("create table t (a text default 'not null');", "a").defaultExpr).toBe("'not null'");
  });

  it("treats DEFAULT NULL as a default of null", () => {
    expect(column("create table t (a int default null not null);", "a")).toMatchObject({ hasDefault: true, defaultExpr: "null", notNull: true });
  });

  it("keeps IS NOT NULL inside a default expression", () => {
    expect(column("create table t (a boolean default (1 is not null) not null);", "a").defaultExpr).toBe("(1 is not null)");
  });

  it("collapses whitespace and comments in default expressions", () => {
    expect(column("create table t (a int default ( 1  /* c */\n + 2 ));", "a").defaultExpr).toBe("( 1 + 2 )");
  });

  it("marks a primary key column as not null and primary", () => {
    expect(column("create table t (id uuid primary key);", "id")).toMatchObject({ primaryKey: true, notNull: true });
  });

  it("reads UNIQUE and named constraints", () => {
    expect(column("create table t (a int constraint t_a_key unique);", "a").unique).toBe(true);
  });

  it("reads GENERATED ALWAYS AS (expr) STORED as generated with its expression", () => {
    const c = column("create table t (a int, b int generated always as (a * 2) stored);", "b");
    expect(c).toMatchObject({ generated: true, hasDefault: true, defaultExpr: "a * 2" });
  });

  it("marks only GENERATED ALWAYS identity columns as generated", () => {
    const sql = "create table t (a bigint generated always as identity, b bigint generated by default as identity (start with 5), c int);";
    expect(column(sql, "a")).toMatchObject({ generated: true, hasDefault: true, defaultExpr: null });
    expect(column(sql, "b")).toMatchObject({ generated: false, hasDefault: true });
    expect(column(sql, "c")).toMatchObject({ generated: false, hasDefault: false });
  });

  it("reads inline foreign keys, with and without a column list", () => {
    const sql = "create table t (a uuid references auth.users(id) on delete cascade, b uuid references other, c int references \"Odd\".\"T\" (\"K\") not null);";
    expect(column(sql, "a").references).toEqual({ schema: "auth", table: "users", column: "id" });
    expect(column(sql, "b").references).toEqual({ schema: "public", table: "other", column: "id" });
    expect(column(sql, "c").references).toEqual({ schema: "Odd", table: "T", column: "K" });
    expect(column(sql, "c").notNull).toBe(true);
  });

  it("reads table-level primary key, unique, foreign key and check constraints", () => {
    const t = table(`create table t (
      a int, b int, c uuid, d int,
      constraint pk primary key (a, b),
      unique (c),
      unique (a, d),
      foreign key (c) references auth.users (id),
      constraint pos check (d > 0)
    );`);
    const by = Object.fromEntries(t.columns.map((c) => [c.name, c]));
    expect(by.a).toMatchObject({ primaryKey: true, notNull: true, unique: false });
    expect(by.b).toMatchObject({ primaryKey: true, notNull: true });
    expect(by.c).toMatchObject({ unique: true, references: { schema: "auth", table: "users", column: "id" } });
    expect(by.d).toMatchObject({ unique: false, primaryKey: false });
    expect(t.checks).toEqual(["CHECK (d > 0)"]);
  });

  it("collects column-level CHECK constraints as text", () => {
    const t = table("create table t (status text check (status in ('a', 'b')), n int check (n > 0 and n < 10));");
    expect(t.checks).toEqual(["CHECK (status in ('a', 'b'))", "CHECK (n > 0 and n < 10)"]);
  });

  it("points a table-level foreign key without columns at id", () => {
    expect(column("create table t (a uuid, foreign key (a) references p);", "a").references).toEqual({ schema: "public", table: "p", column: "id" });
  });

  it("ignores constraints that name unknown columns", () => {
    expect(() => parse("create table t (a int, primary key (nope), unique (nope), foreign key (nope) references p(id));")).not.toThrow();
    expect(table("create table t (a int, primary key (nope));").columns[0]?.primaryKey).toBe(false);
  });

  it("copes with a trailing comma and empty items", () => {
    expect(table("create table t (a int,, b int,);").columns.map((c) => c.name)).toEqual(["a", "b"]);
  });

  it("warns for LIKE and keeps the readable columns", () => {
    const r = parse("create table t (like other including all, a int);");
    expect(r.model.tables[0]?.columns.map((c) => c.name)).toEqual(["a"]);
    expect(r.warnings.some((w) => w.message.includes("LIKE"))).toBe(true);
  });

  it("warns for PARTITION OF and copies the parent's columns when known", () => {
    const r = parse("create table p (a int, b int) partition by range (a); create table c partition of p for values from (1) to (2);");
    expect(r.model.tables.find((t) => t.name.name === "c")?.columns.map((c) => c.name)).toEqual(["a", "b"]);
    expect(r.warnings.some((w) => w.message.includes("PARTITION OF"))).toBe(true);
  });

  it("warns for AS SELECT and names the columns it can read", () => {
    const r = parse("create table t as select a, b as renamed, c.d from x;");
    expect(r.model.tables[0]?.columns.map((c) => c.name)).toEqual(["a", "renamed", "d"]);
    expect(r.warnings).toHaveLength(1);
    const named = parse("create table t (x, y) as select 1, 2;");
    expect(named.model.tables[0]?.columns.map((c) => c.name)).toEqual(["x", "y"]);
  });

  it("warns for INHERITS", () => {
    expect(parse("create table t (a int) inherits (p);").warnings).toHaveLength(1);
  });

  it("starts privileges from the Supabase defaults for public and none elsewhere", () => {
    expect(table("create table t (a int);").privileges).toEqual({ anon: [...COMMANDS], authenticated: [...COMMANDS] });
    expect(table("create table private.t (a int);", "private.t").privileges).toEqual({ anon: [], authenticated: [] });
  });

  it("survives a statement that is cut off", () => {
    const r = parse("create table t (a int, b");
    expect(r.model.tables[0]?.columns.map((c) => c.name)).toEqual(["a", "b"]);
  });
});

describe("search_path", () => {
  it("resolves unqualified names to the first schema of SET search_path", () => {
    const { tables } = parse("set search_path to app, public; create table t (a int); reset search_path; create table u (a int);").model;
    expect(tables.map((t) => qualifiedKey(t.name))).toEqual(["app.t", "public.u"]);
  });

  it("supports SET LOCAL, SESSION and the = form", () => {
    const { tables } = parse("set local search_path = a; create table x (c int); set session search_path to \"B\"; create table y (c int);").model;
    expect(tables.map((t) => qualifiedKey(t.name))).toEqual(["a.x", "B.y"]);
  });

  it("skips $user and an empty path", () => {
    expect(parse("set search_path to \"$user\", app; create table t (a int);").model.tables[0]?.name.schema).toBe("app");
    expect(parse("set search_path = ''; create table t (a int);").model.tables[0]?.name.schema).toBe("public");
  });

  it("applies the path to policies, grants and views too", () => {
    const m = parse(
      "set search_path to app; create table t (a int); alter table t enable row level security; create policy p on t using (true); revoke all on t from anon; create view v as select a from t;",
    ).model;
    expect(m.tables[0]?.rlsEnabled).toBe(true);
    expect(m.tables[0]?.policies).toHaveLength(1);
    expect(m.tables[0]?.privileges.anon).toEqual([]);
    expect(m.views[0]?.name).toEqual({ schema: "app", name: "v" });
    expect(m.views[0]?.dependsOn).toEqual([{ schema: "app", name: "t" }]);
  });

  it("does not carry the path into the next file", () => {
    const r = parseMigrations([
      { path: "a.sql", content: "set search_path to app; create table t (a int);" },
      { path: "b.sql", content: "create table u (a int);" },
    ]);
    expect(r.model.tables.map((t) => qualifiedKey(t.name))).toEqual(["app.t", "public.u"]);
  });
});

describe("ALTER TABLE", () => {
  const base = "create table t (id uuid primary key, a int);";

  it("enables, forces and disables row level security", () => {
    expect(table(`${base} alter table t enable row level security;`)).toMatchObject({ rlsEnabled: true, rlsForced: false });
    expect(table(`${base} alter table t enable row level security; alter table t force row level security;`)).toMatchObject({ rlsEnabled: true, rlsForced: true });
    expect(table(`${base} alter table t force row level security; alter table t no force row level security;`).rlsForced).toBe(false);
    expect(table(`${base} alter table t enable row level security; alter table t disable row level security;`).rlsEnabled).toBe(false);
  });

  it("accepts IF EXISTS, ONLY and a schema-qualified name", () => {
    expect(table(`${base} alter table if exists only public.t enable row level security;`).rlsEnabled).toBe(true);
    expect(table(`${base} alter table only t * enable row level security;`).rlsEnabled).toBe(true);
  });

  it("runs several comma-separated actions in one statement", () => {
    const t = table(`${base} alter table t enable row level security, add column b numeric(10, 2) default 0, drop column a, force row level security;`);
    expect(t).toMatchObject({ rlsEnabled: true, rlsForced: true });
    expect(t.columns.map((c) => [c.name, c.type])).toEqual([["id", "uuid"], ["b", "numeric(10,2)"]]);
  });

  it("adds columns with their constraints, with and without COLUMN / IF NOT EXISTS", () => {
    const t = table(`${base} alter table t add column b text not null default 'x', add if not exists a text, add c int unique;`);
    expect(t.columns.map((c) => c.name)).toEqual(["id", "a", "b", "c"]);
    expect(t.columns[1]?.type).toBe("integer");
    expect(t.columns[2]).toMatchObject({ notNull: true, defaultExpr: "'x'" });
    expect(t.columns[3]?.unique).toBe(true);
  });

  it("replaces an existing column on ADD COLUMN without IF NOT EXISTS", () => {
    expect(column(`${base} alter table t add column a text;`, "a").type).toBe("text");
  });

  it("drops columns, with IF EXISTS and CASCADE", () => {
    expect(table(`${base} alter table t drop column if exists a cascade, drop column nope;`).columns.map((c) => c.name)).toEqual(["id"]);
    expect(table(`${base} alter table t drop a;`).columns.map((c) => c.name)).toEqual(["id"]);
  });

  it("sets and drops NOT NULL and DEFAULT", () => {
    const t = table(`${base} alter table t alter column a set not null, alter a set default 5; alter table t alter column id drop not null; alter table t alter column a drop default;`);
    expect(t.columns.find((c) => c.name === "a")).toMatchObject({ notNull: true, hasDefault: false, defaultExpr: null });
    expect(t.columns.find((c) => c.name === "id")?.notNull).toBe(false);
  });

  it("changes column types with and without SET DATA and USING", () => {
    expect(column(`${base} alter table t alter column a type bigint using a::bigint;`, "a").type).toBe("bigint");
    expect(column(`${base} alter table t alter column a set data type varchar(20);`, "a").type).toBe("character varying(20)");
  });

  it("adds and drops identity", () => {
    const sql = `${base} alter table t alter column a add generated always as identity;`;
    expect(column(sql, "a")).toMatchObject({ generated: true, hasDefault: true });
    expect(column(`${sql} alter table t alter column a drop identity;`, "a")).toMatchObject({ generated: false, hasDefault: false });
  });

  it("adds constraints after the fact", () => {
    const t = table(`create table t (a int, b uuid); alter table t add constraint pk primary key (a); alter table t add unique (b); alter table t add foreign key (b) references auth.users(id); alter table t add check (a > 0);`);
    expect(t.columns[0]).toMatchObject({ primaryKey: true, notNull: true });
    expect(t.columns[1]).toMatchObject({ unique: true, references: { schema: "auth", table: "users", column: "id" } });
    expect(t.checks).toEqual(["CHECK (a > 0)"]);
  });

  it("renames columns and follows them in foreign keys", () => {
    const r = parse("create table p (id int primary key); create table c (pid int references p(id)); alter table p rename column id to pk; alter table p rename to q;");
    const c = r.model.tables.find((t) => t.name.name === "c");
    expect(c?.columns[0]?.references).toEqual({ schema: "public", table: "q", column: "pk" });
    expect(r.model.tables.map((t) => t.name.name)).toEqual(["q", "c"]);
    expect(r.model.tables[0]?.columns[0]?.name).toBe("pk");
  });

  it("renames a column with the short RENAME a TO b form", () => {
    expect(table(`${base} alter table t rename a to b;`).columns.map((c) => c.name)).toEqual(["id", "b"]);
  });

  it("moves a table with SET SCHEMA", () => {
    const r = parse("create table t (a int); alter table t set schema private;");
    expect(r.model.tables.map((t) => qualifiedKey(t.name))).toEqual(["private.t"]);
  });

  it("ignores harmless actions without warnings", () => {
    const r = parse(`${base} alter table t owner to postgres; alter table t replica identity full; alter table t drop constraint if exists x; alter table t set (fillfactor = 70); alter table t cluster on i; alter table t alter column a set statistics 100; alter table t disable trigger all; alter table t validate constraint c;`);
    expect(r.warnings).toEqual([]);
  });

  it("warns when an action cannot be read and keeps going", () => {
    const r = parse(`${base} alter table t frobnicate widgets; alter table t enable row level security;`);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toMatchObject({ file: "m.sql", line: 1 });
    expect(r.model.tables[0]?.rlsEnabled).toBe(true);
  });

  it("warns for an unknown public table but not for other schemas", () => {
    expect(parse("alter table missing enable row level security;").warnings).toHaveLength(1);
    expect(parse("alter table auth.users enable row level security;").warnings).toEqual([]);
  });

  it("warns about a column that does not exist", () => {
    expect(parse(`${base} alter table t alter column nope set not null;`).warnings).toHaveLength(1);
  });
});

describe("DROP TABLE", () => {
  it("drops one or several tables, with IF EXISTS and CASCADE", () => {
    const r = parse("create table a (x int); create table b (x int); create table c (x int); drop table if exists a, public.b cascade; drop table nope;");
    expect(r.model.tables.map((t) => t.name.name)).toEqual(["c"]);
    expect(r.warnings).toEqual([]);
  });

  it("drops views that depend on a table dropped with CASCADE, transitively", () => {
    const r = parse("create table t (a int); create view v1 as select a from t; create view v2 as select a from v1; create view other as select 1 as x; drop table t cascade;");
    expect(r.model.views.map((v) => v.name.name)).toEqual(["other"]);
  });

  it("keeps dependent views when the drop is not cascading", () => {
    const r = parse("create table t (a int); create view v as select a from t; drop table t;");
    expect(r.model.views).toHaveLength(1);
  });
});

describe("policies", () => {
  const base = "create table t (id uuid, user_id uuid); alter table t enable row level security;";

  it("reads a fully specified policy", () => {
    const t = table(`${base} create policy "Owner reads" on public.t as restrictive for select to authenticated, anon using (user_id = (select auth.uid())) with check (true);`);
    expect(t.policies).toEqual([
      {
        name: "Owner reads",
        command: "select",
        permissive: false,
        roles: ["authenticated", "anon"],
        using: "user_id = (select auth.uid())",
        withCheck: "true",
      },
    ]);
  });

  it("defaults to permissive, ALL commands and the public role", () => {
    expect(table(`${base} create policy p on t using (true);`).policies[0]).toEqual({
      name: "p",
      command: "all",
      permissive: true,
      roles: ["public"],
      using: "true",
      withCheck: null,
    });
  });

  it("reads each command", () => {
    const sql = ["all", "select", "insert", "update", "delete"].map((c) => `create policy p_${c} on t for ${c} using (true);`).join(" ");
    expect(table(`${base} ${sql}`).policies.map((p) => p.command)).toEqual(["all", "select", "insert", "update", "delete"]);
  });

  it("maps PUBLIC and CURRENT_USER to public and lower-cases role names", () => {
    const t = table(`${base} create policy a on t to PUBLIC using (true); create policy b on t to current_user using (true); create policy c on t to Anon, "MixedRole" using (true); create policy d on t to anon, public using (true);`);
    expect(t.policies.map((p) => p.roles)).toEqual([["public"], ["public"], ["anon", "MixedRole"], ["anon", "public"]]);
  });

  it("collapses whitespace and removes comments in expressions but keeps strings verbatim", () => {
    const t = table(`${base} create policy p on t using (
      user_id   =  auth.uid() -- the owner
      /* or admin */ OR role = 'a  b
c'
    );`);
    expect(t.policies[0]?.using).toBe("user_id = auth.uid() OR role = 'a  b\nc'");
  });

  it("handles nested parentheses and semicolons in strings inside expressions", () => {
    const t = table(`${base} create policy p on t using ((a = ';') and (b in (select x from y where (z = 1)))) with check ((c));`);
    expect(t.policies[0]?.using).toBe("(a = ';') and (b in (select x from y where (z = 1)))");
    expect(t.policies[0]?.withCheck).toBe("(c)");
  });

  it("alters a policy, keeping what is not mentioned", () => {
    const t = table(`${base} create policy p on t for select to anon using (false); alter policy p on t to authenticated using (true); alter policy p on t rename to q;`);
    expect(t.policies).toEqual([
      { name: "q", command: "select", permissive: true, roles: ["authenticated"], using: "true", withCheck: null },
    ]);
  });

  it("drops policies, with IF EXISTS", () => {
    const t = table(`${base} create policy p on t using (true); create policy q on t using (true); drop policy if exists p on t; drop policy if exists nope on t;`);
    expect(t.policies.map((p) => p.name)).toEqual(["q"]);
  });

  it("warns when dropping or altering a policy that does not exist", () => {
    expect(parse(`${base} drop policy nope on t;`).warnings).toHaveLength(1);
    expect(parse(`${base} alter policy nope on t using (true);`).warnings).toHaveLength(1);
  });

  it("replaces a policy created again under the same name", () => {
    const t = table(`${base} create policy p on t using (false); create policy p on t using (true);`);
    expect(t.policies.map((p) => p.using)).toEqual(["true"]);
  });

  it("warns for unreadable policy clauses and for policies on unknown public tables", () => {
    expect(parse(`${base} create policy p on t using true;`).warnings).toHaveLength(1);
    expect(parse("create policy p on nowhere using (true);").warnings).toHaveLength(1);
    expect(parse("create policy p on storage.objects using (true);").warnings).toEqual([]);
  });
});

describe("GRANT and REVOKE", () => {
  const base = "create table t (a int);";
  const anon = (sql: string) => table(`${base} ${sql}`).privileges.anon;
  const authed = (sql: string) => table(`${base} ${sql}`).privileges.authenticated;

  it("revoking everything from anon empties its privileges only", () => {
    expect(anon("revoke all on t from anon;")).toEqual([]);
    expect(authed("revoke all on t from anon;")).toEqual([...COMMANDS]);
  });

  it("applies statements in order", () => {
    expect(anon("revoke all on t from anon; grant select on t to anon;")).toEqual(["select"]);
    expect(anon("grant select on t to anon; revoke all on t from anon;")).toEqual([]);
    expect(anon("revoke all on t from anon; grant select, insert on t to anon; revoke insert on t from anon;")).toEqual(["select"]);
  });

  it("treats PUBLIC as both client roles", () => {
    const t = table(`${base} revoke all on t from public; grant update on t to public;`);
    expect(t.privileges).toEqual({ anon: ["update"], authenticated: ["update"] });
  });

  it("reads ALL PRIVILEGES, the TABLE keyword and several tables and roles", () => {
    const r = parse("create table a (x int); create table b (x int); revoke all privileges on table a, public.b from anon, authenticated;");
    expect(r.model.tables.map((t) => t.privileges)).toEqual([{ anon: [], authenticated: [] }, { anon: [], authenticated: [] }]);
  });

  it("ignores roles other than anon, authenticated and PUBLIC", () => {
    expect(anon("revoke all on t from service_role, postgres, somebody;")).toEqual([...COMMANDS]);
    expect(anon("grant all on t to service_role;")).toEqual([...COMMANDS]);
  });

  it("reads roles case-insensitively and quoted", () => {
    expect(anon('revoke all on t from "anon";')).toEqual([]);
    expect(anon("REVOKE ALL ON T FROM ANON;")).toEqual([]);
  });

  it("ignores truncate, references and trigger", () => {
    expect(anon("revoke truncate, references, trigger on t from anon;")).toEqual([...COMMANDS]);
    expect(anon("revoke all on t from anon; grant truncate, references, trigger on t to anon;")).toEqual([]);
  });

  it("does not count a column-level grant as a table privilege", () => {
    expect(anon("revoke all on t from anon; grant update (a) on t to anon;")).toEqual([]);
    expect(anon("revoke all on t from anon; grant select, update (a) on t to anon;")).toEqual(["select"]);
    expect(anon("revoke update (a) on t from anon;")).toEqual([...COMMANDS]);
  });

  it("ignores WITH GRANT OPTION, GRANTED BY, CASCADE and GRANT OPTION FOR", () => {
    expect(anon("revoke all on t from anon; grant select on t to anon with grant option;")).toEqual(["select"]);
    expect(anon("revoke all on t from anon; grant select on t to anon granted by postgres;")).toEqual(["select"]);
    expect(anon("revoke grant option for select on t from anon cascade;")).toEqual([...COMMANDS]);
    expect(anon("revoke select on t from anon cascade;")).toEqual(["insert", "update", "delete"]);
  });

  it("reads ALL TABLES IN SCHEMA for tables and views", () => {
    const r = parse("create table a (x int); create table private.p (x int); create view v as select x from a; grant select on all tables in schema private to anon; revoke all on all tables in schema public from anon, authenticated;");
    const privileges = [...r.model.tables, ...r.model.views].map((x) => [x.name.name, x.privileges.anon, x.privileges.authenticated]);
    expect(privileges).toEqual([["a", [], []], ["p", ["select"], []], ["v", [], []]]);
  });

  it("skips grants on schemas, sequences and functions and role membership", () => {
    const r = parse(`${base} grant usage on schema public to anon; grant all on all sequences in schema public to anon; grant execute on function f() to anon; grant authenticated to postgres; grant usage on sequence s to anon;`);
    expect(r.warnings).toEqual([]);
    expect(r.model.tables[0]?.privileges.anon).toEqual([...COMMANDS]);
  });

  it("warns when a grant names an unknown public relation, and for a missing role list", () => {
    expect(parse("grant select on nowhere to anon;").warnings).toHaveLength(1);
    expect(parse("grant select on nowhere to service_role;").warnings).toEqual([]);
    expect(parse(`${base} grant select on t;`).warnings).toHaveLength(1);
  });

  it("applies grants made before a rename or move to the renamed table", () => {
    const r = parse("create table t (a int); revoke all on t from anon; alter table t rename to u;");
    expect(r.model.tables[0]?.privileges.anon).toEqual([]);
  });
});

describe("ALTER DEFAULT PRIVILEGES", () => {
  it("changes the privileges of tables created later in that schema only", () => {
    const r = parse(`create table before_ (a int);
      alter default privileges in schema public revoke all on tables from anon, authenticated;
      create table after_ (a int);
      create table private.other (a int);`);
    const by = Object.fromEntries(r.model.tables.map((t) => [t.name.name, t.privileges]));
    expect(by.before_).toEqual({ anon: [...COMMANDS], authenticated: [...COMMANDS] });
    expect(by.after_).toEqual({ anon: [], authenticated: [] });
    expect(by.other).toEqual({ anon: [], authenticated: [] });
  });

  it("applies grants to other schemas and honours FOR ROLE", () => {
    const r = parse("alter default privileges for role postgres in schema private grant select on tables to anon; create table private.t (a int);");
    expect(r.model.tables[0]?.privileges).toEqual({ anon: ["select"], authenticated: [] });
  });

  it("without IN SCHEMA, applies to every schema", () => {
    const r = parse("alter default privileges revoke insert, update, delete on tables from anon; create table t (a int);");
    expect(r.model.tables[0]?.privileges).toEqual({ anon: ["select"], authenticated: [...COMMANDS] });
  });

  it("applies several changes in order and to views", () => {
    const r = parse(`alter default privileges in schema public revoke all on tables from anon;
      alter default privileges in schema public grant select on tables to anon;
      create table t (a int); create view v as select a from t;`);
    expect(r.model.tables[0]?.privileges.anon).toEqual(["select"]);
    expect(r.model.views[0]?.privileges.anon).toEqual(["select"]);
  });

  it("ignores defaults for sequences and functions", () => {
    const r = parse("alter default privileges in schema public revoke all on sequences from anon; alter default privileges in schema public revoke execute on functions from public; create table t (a int);");
    expect(r.warnings).toEqual([]);
    expect(r.model.tables[0]?.privileges.anon).toEqual([...COMMANDS]);
  });

  it("does not change defaults for REVOKE GRANT OPTION FOR", () => {
    const r = parse("alter default privileges in schema public revoke grant option for select on tables from anon; create table t (a int);");
    expect(r.model.tables[0]?.privileges.anon).toEqual([...COMMANDS]);
  });

  it("warns when the action is neither GRANT nor REVOKE", () => {
    expect(parse("alter default privileges in schema public frob;").warnings).toHaveLength(1);
  });

  it("lets a later explicit REVOKE win over the defaults", () => {
    const r = parse("create table t (a int); alter default privileges in schema public grant all on tables to anon; revoke all on t from anon;");
    expect(r.model.tables[0]?.privileges.anon).toEqual([]);
  });
});

describe("views", () => {
  it("reads explicit column lists and ignores the select list then", () => {
    expect(view("create view v (a, b) as select x, y from t;").columns).toEqual(["a", "b"]);
  });

  it("derives output names from the select list", () => {
    const v = view(`create view v as select
      t.id, t.name as label, name, u.profile.email, upper(x.k), count(*), a + b as total, c::text, d::int as dd, e e_alias, 1 + 2, case when x then 1 end, "Quoted"
      from t join u on t.id = u.id;`);
    expect(v.columns).toEqual(["id", "label", "name", "email", "upper", "count", "total", "c", "dd", "e_alias", "?column?", "case", "Quoted"]);
  });

  it("returns no columns when the select list has a star", () => {
    expect(view("create view v as select * from t;").columns).toEqual([]);
    expect(view("create view v as select a, t.* from t;").columns).toEqual([]);
    expect(view("create view v as select count(*) as n from t;").columns).toEqual(["n"]);
  });

  it("skips DISTINCT, DISTINCT ON and ALL before the list", () => {
    expect(view("create view v as select distinct on (a, b) a, b from t;").columns).toEqual(["a", "b"]);
    expect(view("create view v as select all a from t;").columns).toEqual(["a"]);
    expect(view("create view v as select distinct a from t;").columns).toEqual(["a"]);
  });

  it("finds the select after a WITH clause", () => {
    expect(view("create view v as with c as (select 1 as inner_col) select a from c;").columns).toEqual(["a"]);
  });

  it("reads security_invoker in all spellings and defaults to false", () => {
    expect(view("create view v as select 1 as a;").securityInvoker).toBe(false);
    for (const value of ["true", "on", "TRUE", "'true'", "1"]) {
      expect(view(`create view v with (security_invoker = ${value}) as select 1 as a;`).securityInvoker).toBe(true);
    }
    expect(view("create view v with (security_invoker = false) as select 1 as a;").securityInvoker).toBe(false);
    expect(view("create view v with (security_invoker) as select 1 as a;").securityInvoker).toBe(true);
    expect(view("create view v with (security_barrier = true, security_invoker = on) as select 1 as a;").securityInvoker).toBe(true);
    expect(view("create view v with (security_barrier = true) as select 1 as a;").securityInvoker).toBe(false);
    expect(view("create view v(a) with (security_invoker=on) as select 1;").columns).toEqual(["a"]);
  });

  it("reads ALTER VIEW SET and RESET of security_invoker", () => {
    const base = "create view v as select 1 as a;";
    expect(view(`${base} alter view v set (security_invoker = true);`).securityInvoker).toBe(true);
    expect(view(`${base} alter view v set (security_invoker = true); alter view v set (security_invoker = false);`).securityInvoker).toBe(false);
    expect(view(`${base} alter view v set (security_invoker = on); alter view v reset (security_invoker);`).securityInvoker).toBe(false);
    expect(view(`${base} alter view if exists public.v set (security_barrier = true);`).securityInvoker).toBe(false);
  });

  it("renames and moves views", () => {
    const r = parse("create view v as select 1 as a; alter view v rename to w; alter view w set schema private;");
    expect(r.model.views.map((v) => qualifiedKey(v.name))).toEqual(["private.w"]);
  });

  it("collects dependencies after FROM, JOIN and comma joins", () => {
    const v = view(`create view v as select a.x from a
      join private.b on a.id = b.id left outer join "C" c on true, d dd, only e
      where a.x in (select y from f);`);
    expect(v.dependsOn.map(qualifiedKey)).toEqual(["public.a", "private.b", "public.C", "public.d", "public.e", "public.f"]);
  });

  it("does not count CTE names, functions or FROM inside functions as tables", () => {
    const v = view(`create view v as with c as (select 1 as x) select extract(epoch from created_at), substring(s from 2), t.a is distinct from 1
      from c cross join generate_series(1, 3) g, t;`);
    expect(v.dependsOn.map(qualifiedKey)).toEqual(["public.t"]);
  });

  it("counts each dependency once", () => {
    expect(view("create view v as select 1 as x from t union all select 2 from t;").dependsOn).toHaveLength(1);
  });

  it("stores the definition with collapsed whitespace", () => {
    expect(view("create view v as\n  select a\n    from t;").definition).toBe("select a from t");
  });

  it("starts view privileges from the defaults and follows grants", () => {
    const v = view("create view v as select 1 as a; revoke all on v from anon; grant select on v to authenticated;");
    expect(v.privileges).toEqual({ anon: [], authenticated: [...COMMANDS] });
    expect(view("create view v as select 1 as a;").privileges.anon).toEqual([...COMMANDS]);
  });

  it("CREATE OR REPLACE keeps privileges but resets options", () => {
    const v = view("create view v with (security_invoker = on) as select 1 as a; revoke all on v from anon; create or replace view v as select 2 as b;");
    expect(v.securityInvoker).toBe(false);
    expect(v.columns).toEqual(["b"]);
    expect(v.privileges.anon).toEqual([]);
  });

  it("reads materialized views and skips temporary ones", () => {
    expect(view("create materialized view if not exists v as select a from t with no data;").columns).toEqual(["a"]);
    expect(parse("create temp view v as select 1 as a; create temporary view w as select 1 as a;").model.views).toEqual([]);
    expect(view("create recursive view v (n) as select 1;").columns).toEqual(["n"]);
  });

  it("drops views, including materialized ones and those depending on them with CASCADE", () => {
    const r = parse("create view a as select 1 as x; create view b as select x from a; create materialized view c as select 1 as x; drop view if exists a cascade; drop materialized view c;");
    expect(r.model.views).toEqual([]);
    expect(parse("create view a as select 1 as x; create view b as select x from a; drop view a;").model.views.map((v) => v.name.name)).toEqual(["b"]);
  });

  it("warns for a view it cannot read", () => {
    expect(parse("create view v;").warnings).toHaveLength(1);
  });
});

describe("statements that are skipped or warned about", () => {
  it.each([
    "create index i on t (a)",
    "create unique index concurrently i on t (a)",
    "drop index i",
    "create or replace function f() returns int language sql as 'select 1'",
    "alter function f() owner to postgres",
    "drop function if exists f()",
    "create procedure p() language sql as 'select 1'",
    "create trigger tr before insert on t for each row execute function f()",
    "drop trigger tr on t",
    "create type mood as enum ('a', 'b')",
    "alter type mood add value 'c'",
    "create domain d as int",
    "create sequence s",
    "alter sequence s restart",
    "create extension if not exists pgcrypto",
    "create schema private",
    "drop schema private cascade",
    "create role r",
    "alter role r set x = 1",
    "create publication p for all tables",
    "alter publication supabase_realtime add table t",
    "insert into t values (1)",
    "update t set a = 1",
    "delete from t",
    "copy t from stdin",
    "select 1",
    "with x as (select 1) select * from x",
    "do $$ begin null; end $$",
    "comment on table t is 'x'",
    "set statement_timeout = 0",
    "set role postgres",
    "reset all",
    "analyze t",
    "vacuum t",
    "notify chan",
    "listen chan",
    "truncate t",
    "(select 1)",
  ])("skips %s without a warning", (sql) => {
    const r = parse(`${sql};`);
    expect(r.warnings).toEqual([]);
    expect(r.model).toEqual({ tables: [], views: [] });
  });

  it("warns about an unknown top-level command with a short message", () => {
    const r = parse("frobnicate the widgets because we can and this statement is far longer than sixty characters in total;");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]?.message.length).toBeLessThan(100);
    expect(r.warnings[0]?.message).toContain("…");
  });

  it("never echoes more than about sixty characters of statement text", () => {
    const secret = "x".repeat(500);
    const r = parse(`create policy ${secret} on public.nowhere using (true); alter table ${secret} frob; grant select on ${secret} to anon; unknown ${secret};`);
    for (const w of r.warnings) expect(w.message.length).toBeLessThan(250);
    expect(r.warnings.every((w) => !w.message.includes("x".repeat(100)))).toBe(true);
  });

  it("warns about CREATE RULE and CREATE FOREIGN TABLE, which can change access", () => {
    expect(parse("create rule r as on insert to t do instead nothing;").warnings).toHaveLength(1);
    expect(parse("create foreign table ft (a int) server s;").warnings).toHaveLength(1);
    expect(parse("create foreign data wrapper w;").warnings).toEqual([]);
  });

  it("carries the file and the line of the statement in warnings", () => {
    const r = parseMigrations([{ path: "supabase/migrations/001.sql", content: "select 1;\n\n\nbogus thing;" }]);
    expect(r.warnings).toEqual([{ file: "supabase/migrations/001.sql", line: 4, message: "unrecognised statement: bogus thing" }]);
  });
});

describe("statements, files and caps", () => {
  it("returns every statement in order with its kind, and keeps control statements out of the model", () => {
    const r = parse("begin;\ncreate table t (a int);\n\\connect x\ncommit;");
    expect(r.statements.map((s) => [s.kind, s.line])).toEqual([["transaction-control", 1], ["sql", 2], ["psql-meta", 3], ["transaction-control", 4]]);
    expect(r.model.tables).toHaveLength(1);
    expect(r.warnings.map((w) => w.message)).toEqual(["psql meta-command skipped"]);
  });

  it("replays files in the given order", () => {
    const files = [
      { path: "1.sql", content: "create table t (a int);" },
      { path: "2.sql", content: "alter table t enable row level security; alter table t add column b int;" },
      { path: "3.sql", content: "alter table t disable row level security;" },
    ];
    const t = parseMigrations(files).model.tables[0];
    expect(t).toMatchObject({ rlsEnabled: false });
    expect(t?.columns.map((c) => c.name)).toEqual(["a", "b"]);
    const reversed = parseMigrations([...files].reverse());
    expect(reversed.model.tables[0]?.rlsEnabled).toBe(false);
    expect(reversed.model.tables[0]?.columns.map((c) => c.name)).toEqual(["a"]);
    expect(reversed.warnings.length).toBeGreaterThan(0);
  });

  it("attributes statements and warnings to their own file", () => {
    const r = parseMigrations([
      { path: "a.sql", content: "select 1;" },
      { path: "b.sql", content: "bogus;" },
    ]);
    expect(r.statements.map((s) => s.file)).toEqual(["a.sql", "b.sql"]);
    expect(r.warnings.map((w) => w.file)).toEqual(["b.sql"]);
  });

  it("is complete for ordinary input and for no files", () => {
    expect(parse("create table t (a int);").complete).toBe(true);
    expect(parseMigrations([]).complete).toBe(true);
    expect(parseMigrations([]).model).toEqual({ tables: [], views: [] });
  });

  it("marks the result incomplete when a statement is too long, but reads the rest", () => {
    const r = parseMigrations([{ path: "a.sql", content: `create table big (a text default '${"x".repeat(200)}'); create table small (a int);` }], { maxStatementBytes: 100 });
    expect(r.complete).toBe(false);
    expect(r.model.tables.map((t) => t.name.name)).toEqual(["small"]);
    expect(r.warnings).toHaveLength(1);
  });

  it("applies the statement cap across files", () => {
    const r = parseMigrations(
      [
        { path: "a.sql", content: "select 1; select 2;" },
        { path: "b.sql", content: "select 3; select 4;" },
      ],
      { maxStatements: 3 },
    );
    expect(r.statements).toHaveLength(3);
    expect(r.complete).toBe(false);
    expect(r.warnings.some((w) => w.file === "b.sql")).toBe(true);
  });
});

describe("robustness", () => {
  const fragments = [
    "create table", "t", "(", ")", ",", ";", "a", "int", "primary key", "references", "alter table", "enable row level security",
    "create policy", "on", "using", "with check", "grant", "revoke", "all", "to", "from", "anon", "view", "as", "select", "'", '"',
    "$$", "/*", "--", "\n", "default", "not null", "generated always as identity", "add column", "drop", "rename to", "set schema",
    "default privileges", "in schema", "for", "security_invoker", "=", "::", "[", "]", "\\", "begin atomic", "end", "case",
  ];

  it("never throws on random fragments of SQL", () => {
    let seed = 987654321;
    const next = (n: number): number => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed % n;
    };
    for (let i = 0; i < 400; i++) {
      let sql = "";
      for (let j = 0, len = 1 + next(30); j < len; j++) sql += `${fragments[next(fragments.length)]} `;
      expect(() => parse(sql)).not.toThrow();
    }
  });

  it("never throws on random bytes", () => {
    let seed = 42;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed;
    };
    for (let i = 0; i < 200; i++) {
      let s = "";
      for (let j = 0; j < 120; j++) s += String.fromCharCode(next() % 256);
      expect(() => parse(s)).not.toThrow();
    }
  });

  it("never throws on every truncation of a realistic migration", () => {
    const sql = `create table public.notes (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references auth.users (id) on delete cascade,
      title varchar(200) not null default 'x',
      body text check (length(body) < 1000)
    );
    alter table public.notes enable row level security;
    create policy "own" on public.notes for all to authenticated using ((select auth.uid()) = user_id) with check (user_id = (select auth.uid()));
    revoke all on public.notes from anon;
    create view public.v with (security_invoker = on) as select n.id, n.title from public.notes n join auth.users u on u.id = n.user_id;
    alter default privileges in schema public revoke all on tables from anon;`;
    for (let n = 0; n <= sql.length; n += 3) expect(() => parse(sql.slice(0, n))).not.toThrow();
  });

  it("copes with a table that references itself and with duplicate renames", () => {
    expect(() => parse("create table t (p int references t(a), a int); alter table t rename to t; alter table t rename a to a;")).not.toThrow();
  });

  it("handles very deep parentheses in column defaults without overflowing the stack", () => {
    const deep = `create table t (a int default ${"(".repeat(20000)}1${")".repeat(20000)});`;
    expect(() => parse(deep)).not.toThrow();
    expect(parse(deep).model.tables[0]?.columns[0]?.name).toBe("a");
  });

  it("handles a huge number of columns quickly", () => {
    const columns = Array.from({ length: 5000 }, (_, i) => `c${i} int`).join(", ");
    const started = Date.now();
    expect(parse(`create table t (${columns});`).model.tables[0]?.columns).toHaveLength(5000);
    expect(Date.now() - started).toBeLessThan(3000);
  });
});
