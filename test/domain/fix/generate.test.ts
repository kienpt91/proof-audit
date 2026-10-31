import { describe, expect, it } from "vitest";
import type { Finding } from "../../../src/domain/analysis/types.js";
import { applyFixOutcome } from "../../../src/domain/fix/outcome.js";
import { generateFix } from "../../../src/domain/fix/generate.js";
import { ALL, col, model, notes, OWN, pk, policy, tbl, userFk, view } from "../../helpers/model.js";

function finding(subject: string, tier: Finding["tier"] = "PROVEN", kind: Finding["subjectKind"] = "table"): Finding {
  return { id: `rls:${subject}`, subject, subjectKind: kind, tier, severity: "high", title: "t", attackerCan: "x", causes: [], provenBy: [], notReproduced: [], inconclusive: [], fixStatus: "not-proposed", fixNote: "n" };
}

describe("generateFix for owned tables", () => {
  it("enables RLS, writes owner policies with (select auth.uid()) and revokes anon when nothing exists", () => {
    const t = notes({ rlsEnabled: false, policies: [], privileges: { anon: ALL, authenticated: ALL } });
    const fix = generateFix(model([t]), [finding("public.notes")]);
    expect(fix.statements).toEqual([
      'ALTER TABLE "public"."notes" ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY "notes_select_own" ON "public"."notes" FOR SELECT TO authenticated USING ("user_id" = (select auth.uid()))',
      'CREATE POLICY "notes_insert_own" ON "public"."notes" FOR INSERT TO authenticated WITH CHECK ("user_id" = (select auth.uid()))',
      'CREATE POLICY "notes_update_own" ON "public"."notes" FOR UPDATE TO authenticated USING ("user_id" = (select auth.uid())) WITH CHECK ("user_id" = (select auth.uid()))',
      'CREATE POLICY "notes_delete_own" ON "public"."notes" FOR DELETE TO authenticated USING ("user_id" = (select auth.uid()))',
      'REVOKE ALL ON TABLE "public"."notes" FROM anon',
    ]);
    expect(fix.covered).toEqual(["public.notes"]);
  });

  it("drops an always-true policy and replaces it", () => {
    const t = notes({ policies: [policy("everyone", "all", ["public"], "true", "true")] });
    const fix = generateFix(model([t]), [finding("public.notes")]);
    expect(fix.statements[0]).toBe('DROP POLICY IF EXISTS "everyone" ON "public"."notes"');
    expect(fix.statements.filter((s) => s.startsWith("CREATE POLICY"))).toHaveLength(4);
  });

  it("replaces a policy that compares the wrong column with the caller", () => {
    const wrong = "(customer_id = ( SELECT auth.uid() AS uid))";
    const t = tbl("projects", [pk(), userFk("owner_id"), userFk("customer_id")], { policies: [policy("mine", "all", ["authenticated"], wrong, wrong)] });
    const fix = generateFix(model([t]), [finding("public.projects")]);
    expect(fix.statements[0]).toBe('DROP POLICY IF EXISTS "mine" ON "public"."projects"');
    expect(fix.statements.find((s) => s.includes("FOR SELECT"))).toContain('"owner_id" = (select auth.uid())');
  });

  it("keeps a correct policy and only adds the missing commands", () => {
    const t = notes({ policies: [policy("read own", "select", ["authenticated"], OWN, null)] });
    const fix = generateFix(model([t]), [finding("public.notes")]);
    expect(fix.statements.some((s) => s.startsWith("DROP POLICY"))).toBe(false);
    expect(fix.statements.filter((s) => s.startsWith("CREATE POLICY")).map((s) => /FOR (\w+)/.exec(s)?.[1])).toEqual(["INSERT", "UPDATE", "DELETE"]);
  });

  it("replaces an update policy whose WITH CHECK ignores the owner", () => {
    const t = notes({ policies: [policy("own", "all", ["authenticated"], OWN, OWN), policy("loose", "update", ["authenticated"], OWN, "true")] });
    const fix = generateFix(model([t]), [finding("public.notes")]);
    expect(fix.statements).toContain('DROP POLICY IF EXISTS "loose" ON "public"."notes"');
    expect(fix.statements.some((s) => s.includes("CREATE POLICY"))).toBe(false);
  });

  it("casts auth.uid() for text owner columns and refuses incomparable types", () => {
    const text = tbl("a", [pk(), col("user_id", "text", { notNull: true, references: { schema: "auth", table: "users", column: "id" } })], { policies: [] });
    expect(generateFix(model([text]), [finding("public.a")]).statements[1]).toContain('"user_id" = (select auth.uid())::text');
    const int = tbl("b", [pk(), col("owner_id", "integer", { notNull: true })], { policies: [] });
    const fix = generateFix(model([int]), [finding("public.b")]);
    expect(fix.statements).toEqual([]);
    expect(fix.needsDecision[0]?.reason).toContain("cannot be compared with auth.uid()");
  });

  it("uses a membership table for tenant-owned tables", () => {
    const members = tbl("members", [pk(), userFk(), col("org_id", "uuid", { notNull: true })]);
    const docs = tbl("docs", [pk(), col("org_id", "uuid", { notNull: true }), col("name", "text")], { policies: [] });
    const fix = generateFix(model([members, docs]), [finding("public.docs")]);
    const select = fix.statements.find((s) => s.includes("FOR SELECT"));
    expect(select).toContain('"org_id" IN (SELECT m."org_id" FROM "public"."members" m WHERE m."user_id" = (select auth.uid()))');
  });

  it("asks for a decision when a tenant table has no membership table", () => {
    const docs = tbl("docs", [pk(), col("org_id", "uuid", { notNull: true }), col("name", "text")], { policies: [] });
    const fix = generateFix(model([docs]), [finding("public.docs")]);
    expect(fix.statements).toEqual([]);
    expect(fix.needsDecision).toEqual([{ subject: "public.docs", reason: expect.stringContaining("no membership table") }]);
  });

  it("asks for a decision when the table has no owner column", () => {
    const t = tbl("plans", [pk(), col("name", "text")]);
    const fix = generateFix(model([t]), [finding("public.plans")]);
    expect(fix.needsDecision[0]?.reason).toContain("no owner column");
    expect(fix.sql).toContain("NEEDS A DECISION");
  });

  it("ignores findings that are not PROVEN", () => {
    const fix = generateFix(model([notes({ rlsEnabled: false })]), [finding("public.notes", "SUSPECTED")]);
    expect(fix.statements).toEqual([]);
    expect(fix.covered).toEqual([]);
  });

  it("quotes hostile names, writing unsafe characters as Unicode escapes so no raw control character or newline reaches the SQL", () => {
    const name = 'x"\n; DROP TABLE users; --\u001b[31m';
    const t = tbl(name, [pk(), userFk()], { policies: [], rlsEnabled: false });
    const fix = generateFix(model([t]), [finding(`public.${name}`)]);
    expect(fix.statements[0]).toBe('ALTER TABLE "public".U&"x""\\000a; DROP TABLE users; --\\001b[31m" ENABLE ROW LEVEL SECURITY');
    expect(fix.sql).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f]/);
    expect(fix.sql.split("\n").filter((l) => !l.startsWith("--") && l !== "").every((l) => /^(ALTER|CREATE|DROP|REVOKE)\b/.test(l) && l.endsWith(";"))).toBe(true);
    expect(fix.sql.split("\n").filter((l) => l.startsWith("-- public.x"))).toHaveLength(1);
  });

  it("marks the SQL as a starting point", () => {
    const fix = generateFix(model([notes({ rlsEnabled: false, policies: [] })]), [finding("public.notes")]);
    expect(fix.sql.split("\n")[0]).toContain("STARTING POINT");
    expect(fix.sql.endsWith("\n")).toBe(true);
  });
});

describe("generateFix for views", () => {
  it("switches the view to security_invoker and revokes anon", () => {
    const m = model([notes()], [view("v")]);
    const fix = generateFix(m, [finding("public.v", "PROVEN", "view")]);
    expect(fix.statements).toEqual(['ALTER VIEW "public"."v" SET (security_invoker = true)', 'REVOKE ALL ON TABLE "public"."v" FROM anon']);
  });
});

describe("applyFixOutcome", () => {
  const f = finding("public.notes");
  const plan = { statements: ["x"], sql: "x", covered: ["public.notes"], needsDecision: [] };
  const sub = (status: "VERIFIED" | "BREAKS_ACCESS" | "STILL_VULNERABLE" | "UNVERIFIED" | "NO_FIX") => ({ subject: "public.notes", status, closed: [], stillProven: [], broken: [], unresolved: [], reason: "why" });
  const verification = (status: "VERIFIED" | "FIX_FAILED" | "BREAKS_ACCESS", s: ReturnType<typeof sub>) => ({ status, applyErrors: [], subjects: [s], after: [] });

  it("marks verified findings", () => {
    expect(applyFixOutcome([f], plan, verification("VERIFIED", sub("VERIFIED")))[0]).toMatchObject({ fixStatus: "verified", fixNote: "Fix verified: why." });
  });

  it("never says verified for a fix that breaks access", () => {
    const out = applyFixOutcome([f], plan, verification("BREAKS_ACCESS", sub("BREAKS_ACCESS")))[0];
    expect(out?.fixStatus).toBe("breaks-access");
    expect(out?.fixNote).toContain("not verified");
  });

  it("reports a fix that failed to apply as unverified", () => {
    expect(applyFixOutcome([f], plan, verification("FIX_FAILED", sub("VERIFIED")))[0]?.fixStatus).toBe("unverified");
  });

  it("maps decisions, unfixed and non-proven findings", () => {
    const decisionPlan = { ...plan, covered: [], needsDecision: [{ subject: "public.notes", reason: "pick" }] };
    expect(applyFixOutcome([f], decisionPlan, null)[0]?.fixStatus).toBe("needs-decision");
    expect(applyFixOutcome([f], null, null)[0]).toBe(f);
    expect(applyFixOutcome([f], plan, null)[0]).toBe(f);
    const clean = finding("public.notes", "CLEAN");
    expect(applyFixOutcome([clean], plan, verification("VERIFIED", sub("VERIFIED")))[0]).toBe(clean);
  });
});
