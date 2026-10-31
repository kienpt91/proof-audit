import { describe, expect, it } from "vitest";
import { baseTables, planProbes, updatableColumn, viewCountQueries, viewOwner, viewsOverProtectedTables, type SeedCounts } from "../../../src/domain/proof/plan.js";
import { USER_A, USER_B } from "../../../src/domain/supabase/identities.js";
import { col, model, notes, pk, tbl, userFk, view } from "../../helpers/model.js";

const seeded = (key = "public.notes", counts: SeedCounts = { rowsUserA: 1, rowsUserB: 1 }) => new Map([[key, counts]]);
const plan = (m = model([notes()]), seed = seeded()) => planProbes({ model: m, seed, views: new Map() });
const byKind = (probes: ReturnType<typeof plan>) => Object.fromEntries(probes.map((p) => [p.kind, p]));

describe("planProbes for an owned table", () => {
  const probes = byKind(plan());

  it("plans every exploit and legitimate probe", () => {
    expect(Object.keys(probes)).toEqual(["anon-read", "anon-insert", "anon-update", "anon-delete", "cross-read", "cross-insert", "cross-update", "cross-delete", "reassign-owner", "own-read", "own-insert", "own-update", "own-delete"]);
  });

  it("runs anonymous probes as anon with a role-only token", () => {
    expect(probes["anon-read"]).toMatchObject({ role: "anon", actor: "anon", claims: '{"role":"anon"}', sql: 'SELECT * FROM "public"."notes"', targetRows: 2 });
  });

  it("aims cross-user probes at user B's rows as user A", () => {
    const p = probes["cross-read"];
    expect(p?.role).toBe("authenticated");
    expect(JSON.parse(p?.claims ?? "{}").sub).toBe(USER_A.id);
    expect(p?.sql).toBe(`SELECT * FROM "public"."notes" WHERE "user_id"::text = '${USER_B.id}'`);
    expect(p?.targetRows).toBe(1);
  });

  it("builds the cross-user insert with B as owner and A everywhere else", () => {
    const sql = probes["cross-insert"]?.sql ?? "";
    expect(sql).toContain(USER_B.id);
    expect(sql.startsWith('INSERT INTO "public"."notes"')).toBe(true);
    expect(sql).not.toContain("ON CONFLICT");
  });

  it("hands a row to B by updating A's own row", () => {
    expect(probes["reassign-owner"]?.sql).toBe(`UPDATE "public"."notes" SET "user_id" = '${USER_B.id}' WHERE "user_id"::text = '${USER_A.id}'`);
  });

  it("marks the own-* probes legitimate", () => {
    for (const k of ["own-read", "own-insert", "own-update", "own-delete"]) expect(probes[k]?.intent).toBe("legitimate");
    for (const k of ["anon-read", "cross-read", "reassign-owner"]) expect(probes[k]?.intent).toBe("exploit");
  });

  it("gives every probe a stable id of subject/kind and no block when data exists", () => {
    for (const p of Object.values(probes)) {
      expect(p.id).toBe(`public.notes/${p.kind}`);
      expect(p.blockedReason).toBeNull();
    }
  });

  it("plans no own-insert when the owner column is the key, since a user can only have one row", () => {
    const profiles = tbl("profiles", [col("id", "uuid", { primaryKey: true, notNull: true, unique: true, references: { schema: "auth", table: "users", column: "id" } }), col("name", "text")]);
    const kinds = plan(model([profiles]), seeded("public.profiles")).map((p) => p.kind);
    expect(kinds).not.toContain("own-insert");
    expect(kinds).toContain("own-read");
    expect(kinds).toContain("cross-insert");
  });

  it("updates a non-key column to itself", () => {
    expect(probes["cross-update"]?.sql).toContain('SET "title" = "title" WHERE');
  });
});

describe("planProbes blocking", () => {
  it("blocks row-targeting probes when nothing was seeded", () => {
    const p = byKind(plan(model([notes()]), seeded("public.notes", { rowsUserA: 0, rowsUserB: 0 })));
    expect(p["anon-read"]?.blockedReason).toContain("nothing was seeded");
    expect(p["cross-read"]?.blockedReason).toContain("user B has no rows");
    expect(p["own-read"]?.blockedReason).toContain("user A has no rows");
    expect(p["anon-insert"]?.blockedReason).toBeNull();
  });

  it("blocks inserts whose row cannot be built and says why", () => {
    const bad = tbl("bad", [pk(), userFk(), col("shape", "geometry", { notNull: true })]);
    const p = byKind(plan(model([bad]), seeded("public.bad")));
    expect(p["cross-insert"]?.blockedReason).toContain("no synthetic value");
    expect(p["cross-insert"]?.sql).toBe("");
  });

  it("blocks update probes on a table with no writable column", () => {
    const t = tbl("only_gen", [col("id", "integer", { generated: true, primaryKey: true, notNull: true }), userFk()]);
    expect(updatableColumn(t)?.name).toBe("user_id");
    const g = tbl("gen", [col("id", "integer", { generated: true, primaryKey: true, notNull: true })]);
    expect(updatableColumn(g)).toBeNull();
    expect(byKind(plan(model([g]), seeded("public.gen")))["anon-update"]?.blockedReason).toContain("no writable column");
  });
});

describe("planProbes for other table shapes", () => {
  it("plans only anonymous probes for a table without an owner column", () => {
    const t = tbl("plans", [pk(), col("name", "text")]);
    const p = plan(model([t]), seeded("public.plans", { rowsUserA: 1, rowsUserB: 0 }));
    expect(p.map((x) => x.kind)).toEqual(["anon-read", "anon-insert", "anon-update", "anon-delete"]);
    expect(p[0]?.targetRows).toBe(1);
  });

  it("adds a null-owner insert only when the owner column is nullable", () => {
    const nullable = tbl("posts", [pk(), col("user_id", "uuid", { references: { schema: "auth", table: "users", column: "id" } }), col("title", "text")]);
    expect(plan(model([nullable]), seeded("public.posts")).some((p) => p.kind === "null-owner-insert")).toBe(true);
    expect(plan().some((p) => p.kind === "null-owner-insert")).toBe(false);
  });

  it("writes the null-owner insert with NULL in the owner column", () => {
    const nullable = tbl("posts", [pk(), col("user_id", "uuid", { references: { schema: "auth", table: "users", column: "id" } }), col("title", "text")]);
    const p = plan(model([nullable]), seeded("public.posts")).find((x) => x.kind === "null-owner-insert");
    expect(p?.sql).toContain("NULL");
  });

  it("uses numeric owner values for integer owner columns", () => {
    const t = tbl("legacy", [pk("id", "integer"), col("owner_id", "integer", { notNull: true }), col("note", "text")]);
    const p = byKind(plan(model([t]), seeded("public.legacy")));
    expect(p["cross-read"]?.sql).toContain(`"owner_id"::text = '2'`);
  });

  it("orders tables by name and puts priority subjects first", () => {
    const m = model([notes(), tbl("a_things", [pk(), userFk(), col("x", "text")])]);
    const seed = new Map<string, SeedCounts>([["public.notes", { rowsUserA: 1, rowsUserB: 1 }], ["public.a_things", { rowsUserA: 1, rowsUserB: 1 }]]);
    const normal = planProbes({ model: m, seed, views: new Map() });
    expect(normal[0]?.subject).toBe("public.a_things");
    const prioritised = planProbes({ model: m, seed, views: new Map(), priority: ["public.notes"] });
    expect(prioritised[0]?.subject).toBe("public.notes");
  });

  it("quotes hostile table and column names in generated SQL", () => {
    const t = tbl('n"x', [pk(), userFk(), col('ti"tle', "text")]);
    const p = plan(model([t]), seeded('public.n"x'));
    expect(p.find((x) => x.kind === "anon-read")?.sql).toBe('SELECT * FROM "public"."n""x"');
    expect(p.find((x) => x.kind === "cross-update")?.sql).toContain('"ti""tle" = "ti""tle"');
  });

  it("is deterministic", () => {
    expect(plan()).toEqual(plan());
  });
});

describe("view probes", () => {
  const base = notes();
  const m = model([base], [view("v_notes")]);
  const counts = new Map([["public.v_notes", { total: 2, ownedByUserA: 1, ownedByUserB: 1 }]]);

  it("finds the base tables behind nested views", () => {
    const inner = view("inner");
    const outer = view("outer", { dependsOn: [{ schema: "public", name: "inner" }] });
    expect(baseTables(outer, model([base], [inner, outer])).map((t) => t.name.name)).toEqual(["notes"]);
  });

  it("stops on cyclic view definitions", () => {
    const a = view("a", { dependsOn: [{ schema: "public", name: "b" }] });
    const b = view("b", { dependsOn: [{ schema: "public", name: "a" }] });
    expect(baseTables(a, model([], [a, b]))).toEqual([]);
  });

  it("only considers views over tables with row level security", () => {
    expect(viewsOverProtectedTables(m)).toHaveLength(1);
    expect(viewsOverProtectedTables(model([notes({ rlsEnabled: false })], [view("v_notes")]))).toHaveLength(0);
  });

  it("plans anonymous, cross-user and own reads through the view", () => {
    const probes = planProbes({ model: m, seed: seeded(), views: counts }).filter((p) => p.subjectKind === "view");
    expect(probes.map((p) => p.kind)).toEqual(["view-read-anon", "view-read-cross", "view-read-own"]);
    expect(probes[1]?.sql).toBe(`SELECT * FROM "public"."v_notes" WHERE "user_id"::text = '${USER_B.id}'`);
    expect(probes[0]?.targetRows).toBe(2);
  });

  it("blocks the cross-user probe when the view hides the owner column", () => {
    const hidden = model([base], [view("v_notes", { columns: ["id"] })]);
    const probes = planProbes({ model: hidden, seed: seeded(), views: counts }).filter((p) => p.kind === "view-read-cross");
    expect(viewOwner(hidden.views[0]!, hidden)).toBeNull();
    expect(probes[0]?.blockedReason).toContain("does not expose an owner column");
  });

  it("blocks view probes when the view is empty even for the database owner", () => {
    const empty = new Map([["public.v_notes", { total: 0, ownedByUserA: 0, ownedByUserB: 0 }]]);
    const probes = planProbes({ model: m, seed: seeded(), views: empty }).filter((p) => p.subjectKind === "view");
    expect(probes.every((p) => p.blockedReason !== null)).toBe(true);
  });
});

describe("viewCountQueries", () => {
  it("counts the whole view and each user's rows through the owner column", () => {
    const m = model([notes()], [view("v_notes")]);
    const q = viewCountQueries(m.views[0]!, m);
    expect(q.total).toBe('SELECT count(*) FROM "public"."v_notes"');
    expect(q.userB).toBe(`SELECT count(*) FROM "public"."v_notes" WHERE "user_id"::text = '${USER_B.id}'`);
    expect(q.userA).toContain(USER_A.id);
  });

  it("has no per-user counts when the view hides the owner column", () => {
    const m = model([notes()], [view("v_notes", { columns: ["id"] })]);
    expect(viewCountQueries(m.views[0]!, m)).toMatchObject({ userA: null, userB: null });
  });
});
