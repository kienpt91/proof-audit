import { describe, expect, it } from "vitest";
import { catalogToModel, emptySnapshot, parseCatalog } from "../../../src/domain/catalog/snapshot.js";

const privileges = { anon: [], authenticated: ["select"] };

function rawTable(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "public",
    name: "notes",
    rls: true,
    forceRls: false,
    columns: [
      { name: "id", type: "uuid", notNull: true, default: "gen_random_uuid()", generated: false, enumLabels: null },
      { name: "user_id", type: "uuid", notNull: true, default: null, generated: false, enumLabels: null },
      { name: "state", type: "note_state", notNull: false, default: null, generated: false, enumLabels: ["draft", "live"] },
    ],
    primaryKey: ["id"],
    unique: [],
    foreignKeys: [{ columns: ["user_id"], refSchema: "auth", refTable: "users", refColumns: ["id"] }],
    checks: ["CHECK ((char_length(title) > 0))"],
    policies: [{ name: "own", command: "all", permissive: true, roles: ["Authenticated"], using: "(user_id = auth.uid())", withCheck: null }],
    privileges,
    ...overrides,
  };
}

function raw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { serverVersion: "16.14", truncated: false, tables: [rawTable()], views: [], ...overrides };
}

describe("parseCatalog", () => {
  it("accepts a well-formed snapshot", () => {
    expect(parseCatalog(raw()).ok).toBe(true);
  });

  it("rejects a snapshot with an unknown key", () => {
    const r = parseCatalog(raw({ extra: 1 }));
    expect(r.ok).toBe(false);
  });

  it("rejects an unknown policy command and names the path", () => {
    const bad = rawTable({ policies: [{ name: "x", command: "merge", permissive: true, roles: [], using: null, withCheck: null }] });
    const r = parseCatalog(raw({ tables: [bad] }));
    expect(r).toEqual({ ok: false, error: expect.stringContaining("catalog.tables[0].policies[0].command") });
  });

  it("rejects more tables than the cap allows", () => {
    const tables = Array.from({ length: 301 }, (_, i) => rawTable({ name: `t${i}` }));
    expect(parseCatalog(raw({ tables })).ok).toBe(false);
  });

  it("rejects non-objects", () => {
    expect(parseCatalog(null).ok).toBe(false);
    expect(parseCatalog("x").ok).toBe(false);
  });
});

describe("catalogToModel", () => {
  function model() {
    const r = parseCatalog(raw());
    if (!r.ok) throw new Error(r.error);
    return catalogToModel(r.value);
  }

  it("maps columns with primary key, default and generated flags", () => {
    const t = model().tables[0];
    const id = t?.columns.find((c) => c.name === "id");
    expect(id).toMatchObject({ primaryKey: true, notNull: true, hasDefault: true, defaultExpr: "gen_random_uuid()", unique: true });
  });

  it("maps a single-column foreign key onto the column", () => {
    const t = model().tables[0];
    expect(t?.columns.find((c) => c.name === "user_id")?.references).toEqual({ schema: "auth", table: "users", column: "id" });
  });

  it("keeps enum labels and lower-cases type text", () => {
    const t = model().tables[0];
    expect(t?.columns.find((c) => c.name === "state")?.enumLabels).toEqual(["draft", "live"]);
  });

  it("lower-cases policy roles and keeps expressions verbatim", () => {
    const p = model().tables[0]?.policies[0];
    expect(p?.roles).toEqual(["authenticated"]);
    expect(p?.using).toBe("(user_id = auth.uid())");
  });

  it("marks the model as coming from the catalog", () => {
    expect(model().tables[0]?.origin).toBe("catalog");
  });

  it("pairs composite foreign key columns positionally", () => {
    const t = rawTable({
      columns: [
        { name: "a", type: "integer", notNull: true, default: null, generated: false, enumLabels: null },
        { name: "b", type: "integer", notNull: true, default: null, generated: false, enumLabels: null },
      ],
      primaryKey: [],
      foreignKeys: [{ columns: ["a", "b"], refSchema: "public", refTable: "p", refColumns: ["x", "y"] }],
    });
    const r = parseCatalog(raw({ tables: [t] }));
    if (!r.ok) throw new Error(r.error);
    const cols = catalogToModel(r.value).tables[0]?.columns;
    expect(cols?.map((c) => c.references?.column)).toEqual(["x", "y"]);
  });

  it("orders tables by schema then name", () => {
    const r = parseCatalog(raw({ tables: [rawTable({ name: "b" }), rawTable({ name: "a" }), rawTable({ schema: "app", name: "z" })] }));
    if (!r.ok) throw new Error(r.error);
    expect(catalogToModel(r.value).tables.map((t) => `${t.name.schema}.${t.name.name}`)).toEqual(["app.z", "public.a", "public.b"]);
  });

  it("maps views", () => {
    const view = {
      schema: "public",
      name: "v",
      columns: ["id"],
      securityInvoker: false,
      definition: "SELECT id FROM notes",
      dependsOn: [{ schema: "public", name: "notes" }],
      privileges,
    };
    const r = parseCatalog(raw({ views: [view] }));
    if (!r.ok) throw new Error(r.error);
    expect(catalogToModel(r.value).views[0]).toMatchObject({ securityInvoker: false, dependsOn: [{ schema: "public", name: "notes" }] });
  });

  it("builds an empty snapshot", () => {
    const e = emptySnapshot("16.0");
    expect(e.ok && catalogToModel(e.value)).toEqual({ tables: [], views: [] });
  });
});
