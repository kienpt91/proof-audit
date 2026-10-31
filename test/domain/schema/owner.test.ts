import { describe, expect, it } from "vitest";
import type { Column, Table } from "../../../src/domain/schema/model.js";
import { detectOwnerColumns, primaryOwnerColumn } from "../../../src/domain/schema/owner.js";

function column(name: string, type: string, extra: Partial<Column> = {}): Column {
  return {
    name,
    type,
    notNull: false,
    hasDefault: false,
    defaultExpr: null,
    generated: false,
    primaryKey: false,
    unique: false,
    references: null,
    enumLabels: null,
    ...extra,
  };
}

function table(...columns: Column[]): Table {
  return {
    name: { schema: "public", name: "t" },
    columns,
    rlsEnabled: true,
    rlsForced: false,
    policies: [],
    checks: [],
    privileges: { anon: [], authenticated: [] },
    origin: "parsed",
  };
}

const authUsers = { schema: "auth", table: "users", column: "id" };

describe("detectOwnerColumns user kind", () => {
  it.each(["user_id", "owner_id", "created_by", "author_id", "profile_id", "creator_id", "uid"])("%s uuid is a high-confidence user column", (name) => {
    const [found] = detectOwnerColumns(table(column("id", "uuid", { primaryKey: true }), column(name, "uuid")));
    expect(found).toMatchObject({ column: name, kind: "user", confidence: "high" });
  });

  it("explains the evidence for a named uuid column", () => {
    const [found] = detectOwnerColumns(table(column("created_by", "uuid")));
    expect(found?.reasons).toEqual(["column name created_by is a common owner column", "uuid column named created_by"]);
  });

  it("rates a strong name on a text column as medium", () => {
    expect(detectOwnerColumns(table(column("user_id", "text")))[0]).toMatchObject({ kind: "user", confidence: "medium" });
  });

  it("rates a strong name on an integer column as medium", () => {
    expect(detectOwnerColumns(table(column("owner_id", "bigint")))[0]).toMatchObject({ kind: "user", confidence: "medium" });
  });

  it("rates the *_user_id suffix as medium even on uuid", () => {
    const [found] = detectOwnerColumns(table(column("assignee_user_id", "uuid")));
    expect(found).toMatchObject({ kind: "user", confidence: "medium" });
    expect(found?.reasons[0]).toContain("_user_id");
  });

  it("does not treat a bare _user_id as a suffix match", () => {
    expect(detectOwnerColumns(table(column("_user_id", "uuid")))).toEqual([]);
  });

  it("rates the weak names user and owner as low", () => {
    expect(detectOwnerColumns(table(column("user", "text")))[0]).toMatchObject({ kind: "user", confidence: "low" });
    expect(detectOwnerColumns(table(column("owner", "uuid")))[0]).toMatchObject({ kind: "user", confidence: "low" });
  });

  it("matches names regardless of case", () => {
    expect(detectOwnerColumns(table(column("User_ID", "uuid")))[0]).toMatchObject({ column: "User_ID", kind: "user", confidence: "high" });
  });

  it("rejects name matches on non-id types", () => {
    for (const type of ["jsonb", "boolean", "timestamp with time zone", "text[]", "uuid[]", "mood"]) {
      expect(detectOwnerColumns(table(column("user_id", type)))).toEqual([]);
    }
  });

  it("finds a foreign key to auth.users whatever the name", () => {
    const [found] = detectOwnerColumns(table(column("reporter", "uuid", { references: authUsers })));
    expect(found).toMatchObject({ column: "reporter", kind: "user", confidence: "high" });
    expect(found?.reasons).toContain("references auth.users(id)");
  });

  it("ignores foreign keys to other tables", () => {
    expect(detectOwnerColumns(table(column("reporter", "uuid", { references: { schema: "public", table: "users", column: "id" } })))).toEqual([]);
  });

  it("finds a default of auth.uid() in its common spellings", () => {
    for (const expr of ["auth.uid()", "(select auth.uid())", "( SELECT auth.uid() AS uid)", "auth.uid()::uuid", "AUTH.UID()"]) {
      const [found] = detectOwnerColumns(table(column("who", "uuid", { hasDefault: true, defaultExpr: expr })));
      expect(found).toMatchObject({ kind: "user", confidence: "high" });
      expect(found?.reasons).toContain("default is auth.uid()");
    }
  });

  it("does not take other defaults as ownership", () => {
    for (const expr of ["gen_random_uuid()", "auth.role()", "myauth.uid()", "auth.uid() + 1", "auth.uid"]) {
      expect(detectOwnerColumns(table(column("who", "uuid", { hasDefault: true, defaultExpr: expr })))).toEqual([]);
    }
  });

  it("treats a primary key id that references auth.users as a profile", () => {
    const [found] = detectOwnerColumns(table(column("id", "uuid", { primaryKey: true, references: authUsers })));
    expect(found).toMatchObject({ column: "id", kind: "user", confidence: "high" });
    expect(found?.reasons.at(-1)).toContain("profile");
  });

  it("merges name, foreign key and default evidence into one entry per column", () => {
    const found = detectOwnerColumns(table(column("user_id", "uuid", { references: authUsers, hasDefault: true, defaultExpr: "auth.uid()" })));
    expect(found).toHaveLength(1);
    expect(found[0]?.reasons).toHaveLength(4);
  });

  it("lets a foreign key to auth.users lift a low name to high", () => {
    expect(detectOwnerColumns(table(column("owner", "uuid", { references: authUsers })))[0]).toMatchObject({ confidence: "high" });
  });
});

describe("detectOwnerColumns tenant kind", () => {
  it.each(["tenant_id", "org_id", "organization_id", "organisation_id", "workspace_id", "team_id", "account_id", "company_id"])("%s uuid is a high tenant column", (name) => {
    expect(detectOwnerColumns(table(column(name, "uuid")))[0]).toMatchObject({ column: name, kind: "tenant", confidence: "high" });
  });

  it("is high for text and character varying, medium for integers", () => {
    expect(detectOwnerColumns(table(column("org_id", "text")))[0]?.confidence).toBe("high");
    expect(detectOwnerColumns(table(column("org_id", "character varying(36)")))[0]?.confidence).toBe("high");
    expect(detectOwnerColumns(table(column("org_id", "bigint")))[0]?.confidence).toBe("medium");
    expect(detectOwnerColumns(table(column("org_id", "integer")))[0]?.confidence).toBe("medium");
  });

  it("rejects tenant names on boolean, json and timestamp columns", () => {
    for (const type of ["boolean", "jsonb", "json", "timestamp without time zone", "numeric(10,2)"]) {
      expect(detectOwnerColumns(table(column("org_id", type)))).toEqual([]);
    }
  });

  it("gives a plain foreign key to a non-auth table no tenant meaning", () => {
    expect(detectOwnerColumns(table(column("parent_id", "uuid", { references: { schema: "public", table: "orgs", column: "id" } })))).toEqual([]);
  });
});

describe("detectOwnerColumns ordering", () => {
  it("returns an empty list for a table with no candidates", () => {
    expect(detectOwnerColumns(table(column("id", "uuid", { primaryKey: true }), column("title", "text")))).toEqual([]);
    expect(detectOwnerColumns(table())).toEqual([]);
  });

  it("sorts by confidence, then user before tenant, then column order", () => {
    const found = detectOwnerColumns(
      table(
        column("org_id", "uuid"), // tenant high
        column("owner", "text"), // user low
        column("user_id", "uuid"), // user high
        column("author_id", "text"), // user medium
        column("created_by", "uuid"), // user high
      ),
    );
    expect(found.map((f) => f.column)).toEqual(["user_id", "created_by", "org_id", "author_id", "owner"]);
  });

  it("is deterministic for the same input", () => {
    const t = table(column("team_id", "uuid"), column("user_id", "uuid"), column("owner", "text"));
    expect(detectOwnerColumns(t)).toEqual(detectOwnerColumns(t));
  });
});

describe("primaryOwnerColumn", () => {
  it("returns null when nothing qualifies", () => {
    expect(primaryOwnerColumn(table(column("title", "text")))).toBeNull();
  });

  it("prefers a user column over a higher-ranked tenant column", () => {
    const primary = primaryOwnerColumn(table(column("org_id", "uuid"), column("author_id", "text")));
    expect(primary).toMatchObject({ column: "author_id", kind: "user", confidence: "medium" });
  });

  it("falls back to a tenant column when there is no user column of medium confidence", () => {
    const primary = primaryOwnerColumn(table(column("owner", "text"), column("workspace_id", "bigint")));
    expect(primary).toMatchObject({ column: "workspace_id", kind: "tenant" });
  });

  it("never returns a low-confidence column", () => {
    expect(primaryOwnerColumn(table(column("owner", "uuid"), column("user", "text")))).toBeNull();
  });

  it("breaks ties by column order", () => {
    expect(primaryOwnerColumn(table(column("created_by", "uuid"), column("user_id", "uuid")))?.column).toBe("created_by");
    expect(primaryOwnerColumn(table(column("user_id", "uuid"), column("created_by", "uuid")))?.column).toBe("user_id");
  });

  it("picks the profile id of a profile-style table", () => {
    expect(primaryOwnerColumn(table(column("id", "uuid", { primaryKey: true, references: authUsers }), column("org_id", "uuid")))?.column).toBe("id");
  });
});
