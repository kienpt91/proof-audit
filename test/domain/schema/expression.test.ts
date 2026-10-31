import { describe, expect, it } from "vitest";
import { analyzeExpression } from "../../../src/domain/schema/expression.js";

const COLS = ["id", "user_id", "org_id", "owner", "is_public", "email"];
const facts = (expr: string | null, cols: readonly string[] = COLS) => analyzeExpression(expr, cols);

describe("analyzeExpression constants", () => {
  it.each([
    "true",
    "(true)",
    "((true))",
    "TRUE",
    "true::boolean",
    "(true)::boolean",
    "1 = 1",
    "(1 = 1)",
    "'x' = 'x'",
    "'x'::text = 'x'::text",
    "1 <> 2",
    "2 > 1",
    "1 <= 1",
    "NOT false",
    "not (1 = 2)",
    "true OR user_id = auth.uid()",
    "user_id = auth.uid() OR true",
    "is_public OR (1 = 1)",
    "true AND true",
    "(true AND (1 = 1))",
    "'t'::boolean",
    "'yes'::bool",
    "1 = 1 OR 2 = 3",
    "cast(true as boolean)",
    "true /* always */",
    "-1 < 0",
    "(( true ))::boolean",
    "1 = 1.0",
  ])("folds %s to always true", (expr) => {
    const f = facts(expr);
    expect(f.alwaysTrue).toBe(true);
    expect(f.alwaysFalse).toBe(false);
  });

  it.each([
    "false",
    "(false)",
    "1 = 0",
    "'a' = 'b'",
    "NOT true",
    "false AND user_id = auth.uid()",
    "user_id = auth.uid() AND false",
    "false OR false",
    "1 <> 1",
    "null",
    "NULL::boolean",
    "1 = NULL",
  ])("folds %s to always false", (expr) => {
    const f = facts(expr);
    expect(f.alwaysFalse).toBe(true);
    expect(f.alwaysTrue).toBe(false);
  });

  it.each([
    "user_id = auth.uid()",
    "true AND user_id = auth.uid()",
    "false OR user_id = auth.uid()",
    "1 = 1 AND is_public",
    "x OR y",
    "auth.role() = 'authenticated'",
    "user_id IS NOT NULL",
    "(select true from t)",
    "random() < 2",
    "'a' < 'b'",
    "1 = '1'",
    "id = id",
    "coalesce(true, false)",
    "true IS TRUE",
    "",
  ])("does not fold %s", (expr) => {
    const f = facts(expr);
    expect(f.alwaysTrue).toBe(false);
    expect(f.alwaysFalse).toBe(false);
  });

  it("treats NOT of an unknown as unknown", () => {
    expect(facts("NOT is_public").alwaysTrue).toBe(false);
    expect(facts("NOT (is_public OR true)").alwaysFalse).toBe(true);
  });

  it("does not let a BETWEEN's AND split the expression", () => {
    expect(facts("id BETWEEN 1 AND 2 OR true").alwaysTrue).toBe(true);
    expect(facts("false AND id BETWEEN 1 AND 2").alwaysFalse).toBe(true);
    expect(facts("true AND id BETWEEN 1 AND 2").alwaysTrue).toBe(false);
  });

  it("does not fold inside a CASE expression", () => {
    expect(facts("case when true then false else true end").alwaysTrue).toBe(false);
    expect(facts("case when 1 = 1 then is_public end OR false").alwaysTrue).toBe(false);
  });

  it("returns every fact empty for null", () => {
    expect(facts(null)).toEqual({
      alwaysTrue: false,
      alwaysFalse: false,
      usesCallerIdentity: false,
      callerBoundColumns: [],
      mentionedColumns: [],
    });
  });

  it("stays conservative for nesting far deeper than the limit", () => {
    const deep = `${"(true AND ".repeat(5000)}true${")".repeat(5000)}`;
    expect(() => facts(deep)).not.toThrow();
    expect(facts(deep).alwaysTrue).toBe(false);
  });

  it("handles unbalanced parentheses without throwing", () => {
    expect(() => facts("((true")).not.toThrow();
    expect(() => facts("true))) and (")).not.toThrow();
    expect(facts("(((").alwaysTrue).toBe(false);
  });
});

describe("analyzeExpression caller identity", () => {
  it.each([
    "user_id = auth.uid()",
    "auth.role() = 'authenticated'",
    "auth.jwt() ->> 'role' = 'admin'",
    "auth.email() = email",
    "current_setting('request.jwt.claim.sub', true) = id::text",
    "current_setting('request.jwt.claims', true)::json ->> 'sub' = id::text",
    "owner = current_user",
    "(SELECT auth.uid() AS uid) = user_id",
    '"auth"."uid"() = user_id',
    "AUTH.UID() = user_id",
  ])("detects identity use in %s", (expr) => {
    expect(facts(expr).usesCallerIdentity).toBe(true);
  });

  it.each([
    "true",
    "is_public",
    "user_id = 'a'",
    "current_setting('app.tenant') = org_id::text",
    "myauth.uid() = user_id",
    "auth.uid = user_id",
    "auth.other() = user_id",
  ])("finds no identity in %s", (expr) => {
    expect(facts(expr).usesCallerIdentity).toBe(false);
  });
});

describe("analyzeExpression caller-bound columns", () => {
  it.each([
    ["user_id = auth.uid()", ["user_id"]],
    ["auth.uid() = user_id", ["user_id"]],
    ["(auth.uid() = user_id)", ["user_id"]],
    ["user_id = (select auth.uid())", ["user_id"]],
    ["user_id = ( SELECT auth.uid() AS uid)", ["user_id"]],
    ["(user_id = ( SELECT auth.uid() AS uid))", ["user_id"]],
    ["user_id::text = auth.uid()::text", ["user_id"]],
    ["(user_id)::uuid = auth.uid()", ["user_id"]],
    ["t.user_id = auth.uid()", ["user_id"]],
    ["public.t.user_id = auth.uid()", ["user_id"]],
    ['"user_id" = auth.uid()', ["user_id"]],
    ["USER_ID = auth.uid()", ["user_id"]],
    ["org_id = (auth.jwt() ->> 'org_id')::uuid", ["org_id"]],
    ["org_id = ((auth.jwt() -> 'app_metadata') ->> 'org_id')::uuid", ["org_id"]],
    ["(((auth.jwt() -> 'app_metadata'::text) ->> 'org_id'::text))::uuid = org_id", ["org_id"]],
    ["user_id::text = current_setting('request.jwt.claim.sub', true)", ["user_id"]],
    ["user_id = nullif(current_setting('request.jwt.claim.sub', true), '')::uuid", ["user_id"]],
    ["user_id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid", ["user_id"]],
    ["email = auth.email()", ["email"]],
    ["user_id IN (auth.uid())", ["user_id"]],
    ["user_id = ANY (ARRAY[auth.uid()])", ["user_id"]],
    ["(user_id = ANY (ARRAY[(select auth.uid()), auth.uid()]))", ["user_id"]],
    ["auth.uid() = ANY (id)", ["id"]],
    ["user_id = auth.uid() AND org_id = (auth.jwt() ->> 'org_id')::uuid", ["user_id", "org_id"]],
    ["user_id = auth.uid() OR is_public", ["user_id"]],
    ["user_id = auth.uid() AND true", ["user_id"]],
  ])("binds columns in %s", (expr, expected) => {
    expect(facts(expr).callerBoundColumns).toEqual(expected);
  });

  it.each([
    "auth.uid() IS NOT NULL",
    "auth.role() = 'authenticated'",
    "(auth.role() = 'authenticated'::text)",
    "auth.uid() = id_missing",
    "user_id <> auth.uid()",
    "user_id = auth.uid() + 1",
    "user_id = coalesce(auth.uid(), id)",
    "lower(email) = auth.email()",
    "NOT (user_id = auth.uid())",
    "user_id NOT IN (auth.uid())",
    "user_id IN (auth.uid(), id)",
    "user_id = ANY (ARRAY[auth.uid(), '00000000-0000-0000-0000-000000000001'::uuid])",
    "user_id = 'x'",
    "user_id = id",
    "auth.jwt() ->> 'role' = 'service_role'",
    "user_id = (auth.jwt())",
  ])("binds nothing in %s", (expr) => {
    expect(facts(expr).callerBoundColumns).toEqual([]);
  });

  it("requires the compared name to be one of the given columns", () => {
    expect(facts("auth.uid() = id", ["user_id"]).callerBoundColumns).toEqual([]);
    expect(facts("auth.uid() = id", ["id"]).callerBoundColumns).toEqual(["id"]);
  });

  it("reports columns in the spelling the caller gave", () => {
    expect(facts("user_id = auth.uid()", ["User_Id"]).callerBoundColumns).toEqual(["User_Id"]);
  });

  it("binds a column through an IN subquery that filters by the caller", () => {
    const f = facts("org_id IN (SELECT org_id FROM members WHERE user_id = auth.uid())");
    expect(f.callerBoundColumns).toEqual(["org_id"]);
  });

  it("binds through the pg_get_expr form of the membership subquery", () => {
    const f = facts("(org_id IN ( SELECT members.org_id FROM members WHERE (members.user_id = ( SELECT auth.uid() AS uid))))");
    expect(f.callerBoundColumns).toEqual(["org_id"]);
  });

  it("binds through = ANY (subquery) with a caller filter", () => {
    const f = facts("org_id = ANY (SELECT org_id FROM members WHERE user_id = (select auth.uid()))");
    expect(f.callerBoundColumns).toEqual(["org_id"]);
  });

  it("does not bind through a membership subquery without a caller filter", () => {
    const f = facts("org_id IN (SELECT org_id FROM members)");
    expect(f.callerBoundColumns).toEqual([]);
    expect(f.usesCallerIdentity).toBe(false);
  });

  it("does not bind through a subquery whose filter ignores the caller", () => {
    const f = facts("org_id IN (SELECT org_id FROM members WHERE role = 'admin')");
    expect(f.callerBoundColumns).toEqual([]);
  });

  it("does not bind through a subquery whose caller filter sits after GROUP BY", () => {
    const f = facts("org_id IN (SELECT org_id FROM members WHERE active GROUP BY org_id HAVING count(*) > auth.uid()::int)");
    expect(f.callerBoundColumns).toEqual([]);
  });

  it("does not bind an IN subquery that is negated", () => {
    const f = facts("org_id NOT IN (SELECT org_id FROM members WHERE user_id = auth.uid())");
    expect(f.callerBoundColumns).toEqual([]);
  });

  it("does not count an EXISTS filter as binding a column", () => {
    const f = facts("EXISTS (SELECT 1 FROM members m WHERE m.user_id = auth.uid() AND m.org_id = org_id)");
    expect(f.callerBoundColumns).toEqual([]);
    expect(f.usesCallerIdentity).toBe(true);
  });
});

describe("analyzeExpression mentioned columns", () => {
  it("lists columns that appear as identifiers, in the order of the column list", () => {
    expect(facts("owner = 1 AND user_id = auth.uid()").mentionedColumns).toEqual(["user_id", "owner"]);
  });

  it("matches case-insensitively and through qualifiers and quotes", () => {
    expect(facts('T.USER_ID = 1 OR "Org_Id" = 2').mentionedColumns).toEqual(["user_id", "org_id"]);
  });

  it("does not count function names or qualifiers as columns", () => {
    expect(facts("email(1) = 1", COLS).mentionedColumns).toEqual([]);
    expect(facts("email.x = 1", COLS).mentionedColumns).toEqual([]);
    expect(facts("auth.role() = 'x'", ["role"]).mentionedColumns).toEqual([]);
  });

  it("ignores columns that only appear inside strings", () => {
    expect(facts("x = 'user_id'").mentionedColumns).toEqual([]);
  });

  it("does not count the columns of a subquery's own tables", () => {
    const f = facts("org_id IN (SELECT org_id FROM members WHERE members.user_id = auth.uid())");
    expect(f.mentionedColumns).toEqual(["org_id"]);
  });

  it("counts a qualified reference to the outer table from inside a subquery", () => {
    const f = facts("EXISTS (SELECT 1 FROM members m WHERE m.org_id = notes.org_id)");
    expect(f.mentionedColumns).toEqual(["org_id"]);
  });

  it("does not count unqualified names inside a subquery", () => {
    expect(facts("EXISTS (SELECT 1 FROM members WHERE user_id = 1)").mentionedColumns).toEqual([]);
  });

  it("returns nothing when no columns are given", () => {
    expect(facts("user_id = auth.uid()", []).mentionedColumns).toEqual([]);
  });

  it("copes with duplicate column names in the list", () => {
    expect(facts("user_id = 1", ["user_id", "USER_ID"]).mentionedColumns).toEqual(["user_id"]);
  });
});

describe("analyzeExpression on text printed by Postgres", () => {
  it("reads the typical normalised owner policy", () => {
    const f = facts("(auth.uid() = user_id)");
    expect(f).toMatchObject({ alwaysTrue: false, usesCallerIdentity: true, callerBoundColumns: ["user_id"], mentionedColumns: ["user_id"] });
  });

  it("reads a normalised role check", () => {
    const f = facts("(auth.role() = 'authenticated'::text)");
    expect(f).toMatchObject({ usesCallerIdentity: true, callerBoundColumns: [], alwaysTrue: false });
  });

  it("reads a normalised always-true policy", () => {
    expect(facts("true").alwaysTrue).toBe(true);
  });

  it("reads an ANY(ARRAY[...]) membership test", () => {
    const f = facts("(status = ANY (ARRAY['a'::text, 'b'::text]))", ["status"]);
    expect(f).toMatchObject({ alwaysTrue: false, usesCallerIdentity: false, mentionedColumns: ["status"] });
  });

  it("reads a nested boolean with extra parentheses", () => {
    const f = facts("((user_id = ( SELECT auth.uid() AS uid)) AND (is_public OR (org_id IS NOT NULL)))");
    expect(f.callerBoundColumns).toEqual(["user_id"]);
    expect(f.mentionedColumns).toEqual(["user_id", "org_id", "is_public"]);
  });
});
