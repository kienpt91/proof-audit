import { describe, expect, it } from "vitest";
import { lookupFor, orderTables, planSeed } from "../../../src/domain/seed/plan.js";
import { insertStatement, planRow, seedContext, valueForColumn } from "../../../src/domain/seed/values.js";
import { USER_A, USER_B } from "../../../src/domain/supabase/identities.js";
import { col, model, notes, pk, tbl, userFk } from "../../helpers/model.js";

const lookup = (...tables: ReturnType<typeof tbl>[]) => lookupFor(model(tables));

function value(table: ReturnType<typeof tbl>, name: string, ctx = seedContext(USER_A)) {
  const column = table.columns.find((c) => c.name === name);
  if (!column) throw new Error(`no column ${name}`);
  return valueForColumn(table, column, ctx, lookup(table));
}

describe("valueForColumn", () => {
  it("puts the identity's uuid in a user owner column", () => {
    expect(value(notes(), "user_id")).toEqual({ kind: "value", sql: `'${USER_A.id}'` });
    expect(value(notes(), "user_id", seedContext(USER_B))).toEqual({ kind: "value", sql: `'${USER_B.id}'` });
  });

  it("puts the tenant id in a tenant column", () => {
    const t = tbl("projects", [pk(), col("org_id", "uuid", { notNull: true })]);
    expect(value(t, "org_id", seedContext(USER_B))).toEqual({ kind: "value", sql: `'${USER_B.tenantId}'` });
  });

  it("writes NULL into a nullable owner column on request and refuses for NOT NULL", () => {
    const nullable = tbl("a", [pk(), col("user_id", "uuid")]);
    expect(value(nullable, "user_id", { ...seedContext(USER_A), nullOwner: true })).toEqual({ kind: "value", sql: "NULL" });
    expect(value(notes(), "user_id", { ...seedContext(USER_A), nullOwner: true }).kind).toBe("impossible");
  });

  it("uses small integers for integer owner columns", () => {
    const t = tbl("legacy", [pk("id", "integer"), col("owner_id", "integer", { notNull: true })]);
    expect(value(t, "owner_id", seedContext(USER_B))).toEqual({ kind: "value", sql: "2" });
  });

  it("refuses an owner column that cannot hold an id", () => {
    const t = tbl("odd", [pk(), col("user_id", "jsonb", { notNull: true, references: { schema: "auth", table: "users", column: "id" } })]);
    expect(value(t, "user_id").kind).toBe("impossible");
  });

  it("is deterministic and differs between salts", () => {
    const a = value(notes(), "id");
    expect(value(notes(), "id")).toEqual(a);
    expect(value(notes(), "id", seedContext(USER_B))).not.toEqual(a);
  });

  it("produces a well-formed v4 uuid for uuid keys", () => {
    const v = value(notes(), "id");
    expect(v.kind === "value" && v.sql).toMatch(/^'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'$/);
  });

  it("derives plausible text from the column name", () => {
    const t = tbl("profiles", [pk(), userFk("id2"), col("email", "text"), col("website_url", "text"), col("full_name", "text"), col("status", "text")]);
    expect(value(t, "email")).toEqual({ kind: "value", sql: "'alice@example.test'" });
    expect(value(t, "email", seedContext(USER_B))).toEqual({ kind: "value", sql: "'bob@example.test'" });
    expect(value(t, "website_url").kind === "value" && (value(t, "website_url") as { sql: string }).sql).toMatch(/^'https:\/\/example\.test\//);
    expect(value(t, "full_name")).toEqual({ kind: "value", sql: "'Alice'" });
    expect(value(t, "status")).toEqual({ kind: "value", sql: "'active'" });
  });

  it("respects varchar length limits", () => {
    const t = tbl("x", [pk(), col("summary", "character varying(8)")]);
    const v = value(t, "summary");
    expect(v.kind === "value" && v.sql.length).toBeLessThanOrEqual(10);
  });

  it("follows CHECK constraints for enumerated strings, bounds and minimum length", () => {
    const t = tbl("x", [pk(), col("state", "text"), col("rating", "integer"), col("title", "text")], {
      checks: ["CHECK ((state = ANY (ARRAY['draft'::text, 'live'::text])))", "CHECK ((rating >= 3))", "CHECK ((char_length(title) > 40))"],
    });
    expect(value(t, "state")).toEqual({ kind: "value", sql: "'draft'" });
    expect(value(t, "rating")).toEqual({ kind: "value", sql: "3" });
    const title = value(t, "title");
    expect(title.kind === "value" && title.sql.length).toBeGreaterThan(40);
  });

  it("picks the first enum label", () => {
    const t = tbl("x", [pk(), col("mood", "mood", { enumLabels: ["calm", "tense"] })]);
    expect(value(t, "mood")).toEqual({ kind: "value", sql: "'calm'" });
  });

  it("covers dates, timestamps, booleans, json, arrays and numerics", () => {
    const t = tbl("x", [pk(), col("d", "date"), col("ts", "timestamp with time zone"), col("flag", "boolean"), col("active", "boolean"), col("j", "jsonb"), col("tags", "text[]"), col("price", "numeric(10,2)"), col("n", "bigint")]);
    expect(value(t, "d")).toEqual({ kind: "value", sql: "'2026-01-15'" });
    expect(value(t, "ts")).toEqual({ kind: "value", sql: "'2026-01-15 10:00:00+00'" });
    expect(value(t, "flag")).toEqual({ kind: "value", sql: "false" });
    expect(value(t, "active")).toEqual({ kind: "value", sql: "true" });
    expect(value(t, "j").kind).toBe("value");
    expect(value(t, "tags")).toEqual({ kind: "value", sql: "'{}'" });
    expect(value(t, "price")).toEqual({ kind: "value", sql: "10.5" });
    expect(value(t, "n")).toEqual({ kind: "value", sql: "1" });
  });

  it("keeps numerics inside a tight precision", () => {
    const t = tbl("x", [pk(), col("ratio", "numeric(2,2)")]);
    expect(value(t, "ratio")).toEqual({ kind: "value", sql: "0.5" });
  });

  it("says so when a type has no synthetic value", () => {
    const t = tbl("x", [pk(), col("shape", "geometry")]);
    expect(value(t, "shape")).toEqual({ kind: "impossible", reason: "no synthetic value is defined for type geometry" });
  });

  it("never writes generated columns", () => {
    const t = tbl("x", [pk(), col("total", "integer", { generated: true })]);
    expect(value(t, "total")).toEqual({ kind: "omit" });
  });

  it("points a foreign key at the parent's seeded key", () => {
    const parent = tbl("projects", [pk(), userFk()]);
    const child = tbl("tasks", [pk(), userFk(), col("project_id", "uuid", { notNull: true, references: { schema: "public", table: "projects", column: "id" } })]);
    const l = lookup(parent, child);
    const parentId = valueForColumn(parent, parent.columns[0] as never, seedContext(USER_A), l);
    expect(valueForColumn(child, child.columns[2] as never, seedContext(USER_A), l)).toEqual(parentId);
  });

  it("uses a subquery for a generated parent key", () => {
    const parent = tbl("projects", [col("id", "integer", { primaryKey: true, notNull: true, generated: true }), userFk()]);
    const child = tbl("tasks", [pk(), userFk(), col("project_id", "integer", { notNull: true, references: { schema: "public", table: "projects", column: "id" } })]);
    const v = valueForColumn(child, child.columns[2] as never, seedContext(USER_A), lookup(parent, child));
    expect(v.kind === "value" && v.sql).toBe('(SELECT "id" FROM "public"."projects" ORDER BY 1 LIMIT 1)');
  });

  it("reports a required foreign key to an unknown table and omits an optional one", () => {
    const required = tbl("t", [pk(), col("x_id", "uuid", { notNull: true, references: { schema: "other", table: "x", column: "id" } })]);
    const optional = tbl("t", [pk(), col("x_id", "uuid", { references: { schema: "other", table: "x", column: "id" } })]);
    expect(value(required, "x_id").kind).toBe("impossible");
    expect(value(optional, "x_id")).toEqual({ kind: "omit" });
  });
});

describe("planRow and insertStatement", () => {
  const t = tbl("notes", [pk(), userFk(), col("title", "text", { notNull: true }), col("body", "text"), col("created_at", "timestamptz", { hasDefault: true, defaultExpr: "now()" })]);

  it("full mode fills optional columns without defaults and skips defaulted ones", () => {
    const plan = planRow(t, seedContext(USER_A), lookup(t), "full");
    expect(plan.ok && plan.columns).toEqual(["id", "user_id", "title", "body"]);
  });

  it("minimal mode writes keys, owners and required columns only", () => {
    const plan = planRow(t, seedContext(USER_A), lookup(t), "minimal");
    expect(plan.ok && plan.columns).toEqual(["id", "user_id", "title"]);
  });

  it("fails the row when a required column has no value", () => {
    const bad = tbl("x", [pk(), col("shape", "geometry", { notNull: true })]);
    expect(planRow(bad, seedContext(USER_A), lookup(bad), "full")).toEqual({ ok: false, reason: "no synthetic value is defined for type geometry" });
  });

  it("renders quoted identifiers and ON CONFLICT DO NOTHING", () => {
    const plan = planRow(t, seedContext(USER_A), lookup(t), "minimal");
    if (!plan.ok) throw new Error("plan failed");
    const sql = insertStatement(t, plan, true);
    expect(sql.startsWith('INSERT INTO "public"."notes" ("id", "user_id", "title") VALUES (')).toBe(true);
    expect(sql.endsWith(" ON CONFLICT DO NOTHING")).toBe(true);
    expect(insertStatement(t, plan, false)).not.toContain("ON CONFLICT");
  });

  it("uses DEFAULT VALUES for a table with nothing to write", () => {
    const d = tbl("flags", [col("id", "integer", { generated: true })]);
    const plan = planRow(d, seedContext(USER_A), lookup(d), "full");
    if (!plan.ok) throw new Error("plan failed");
    expect(insertStatement(d, plan, false)).toBe('INSERT INTO "public"."flags" DEFAULT VALUES');
  });

  it("quotes hostile identifiers", () => {
    const h = tbl('we"ird', [col('co"l', "uuid", { primaryKey: true, notNull: true })]);
    const plan = planRow(h, seedContext(USER_A), lookup(h), "full");
    if (!plan.ok) throw new Error("plan failed");
    expect(insertStatement(h, plan, false)).toContain('"public"."we""ird" ("co""l")');
  });
});

describe("planSeed", () => {
  it("seeds one row per user for owned tables and one shared row otherwise", () => {
    const shared = tbl("plans", [pk(), col("name", "text")]);
    const plan = planSeed(model([notes(), shared]));
    expect(plan.items.map((i) => `${i.table}:${i.identity}`)).toEqual(["public.notes:user-a", "public.notes:user-b", "public.plans:shared"]);
  });

  it("counts a user's rows through the owner column", () => {
    const item = planSeed(model([notes()])).items[1];
    expect(item?.countSql).toBe(`SELECT count(*) FROM "public"."notes" WHERE "user_id"::text = '${USER_B.id}'`);
  });

  it("orders parents before children", () => {
    const parent = tbl("projects", [pk(), userFk()]);
    const child = tbl("a_tasks", [pk(), userFk(), col("project_id", "uuid", { notNull: true, references: { schema: "public", table: "projects", column: "id" } })]);
    expect(orderTables(model([child, parent])).map((t) => t.name.name)).toEqual(["projects", "a_tasks"]);
  });

  it("survives foreign key cycles", () => {
    const a = tbl("a", [pk(), col("b_id", "uuid", { references: { schema: "public", table: "b", column: "id" } })]);
    const b = tbl("b", [pk(), col("a_id", "uuid", { references: { schema: "public", table: "a", column: "id" } })]);
    expect(orderTables(model([a, b])).map((t) => t.name.name).sort()).toEqual(["a", "b"]);
  });

  it("lists a table whose required column cannot be filled as skipped", () => {
    const bad = tbl("bad", [pk(), userFk(), col("shape", "geometry", { notNull: true })]);
    const plan = planSeed(model([bad]));
    expect(plan.items).toHaveLength(0);
    expect(plan.skipped.map((s) => s.table)).toEqual(["public.bad", "public.bad"]);
  });

  it("offers a minimal retry only when it differs from the full attempt", () => {
    const plan = planSeed(model([notes()]));
    expect(plan.items[0]?.attempts.map((a) => a.label)).toEqual(["full"]);
    const t = tbl("n2", [pk(), userFk(), col("body", "text")]);
    expect(planSeed(model([t])).items[0]?.attempts.map((a) => a.label)).toEqual(["full", "minimal"]);
  });

  it("is deterministic", () => {
    const m = model([notes(), tbl("plans", [pk(), col("name", "text")])]);
    expect(planSeed(m)).toEqual(planSeed(m));
  });
});
