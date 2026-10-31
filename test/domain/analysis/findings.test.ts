import { describe, expect, it } from "vitest";
import { explainTable, explainView, policySoundFor } from "../../../src/domain/analysis/causes.js";
import { attackerSentence, buildFindings, severityOf } from "../../../src/domain/analysis/findings.js";
import { sealProof } from "../../../src/domain/proof/hash.js";
import type { Phase, ProbeKind, Proof, Verdict } from "../../../src/domain/proof/types.js";
import { ALL, col, model, notes, OWN, pk, policy, tbl, userFk, view } from "../../helpers/model.js";

function proof(subject: string, kind: ProbeKind, verdict: Verdict, phase: Phase = "before"): Proof {
  return sealProof({
    id: `${subject}/${kind}`,
    subject,
    subjectKind: "table",
    kind,
    intent: kind.startsWith("own") ? "legitimate" : "exploit",
    command: "select",
    actor: "anon",
    role: "anon",
    claims: "{}",
    sql: "SELECT 1",
    title: kind,
    targetRows: 1,
    observation: { status: "rows", rows: 1 },
    verdict,
    reason: `reason of ${kind}`,
    phase,
  });
}

const codes = (t: ReturnType<typeof notes>) => explainTable(t).map((c) => c.code);

describe("explainTable", () => {
  it("is silent for a table with a correct owner policy", () => {
    expect(codes(notes())).toEqual([]);
  });

  it("reports disabled row level security when clients hold privileges", () => {
    expect(codes(notes({ rlsEnabled: false }))).toContain("rls-disabled");
    expect(codes(notes({ rlsEnabled: false, privileges: { anon: [], authenticated: [] } }))).not.toContain("rls-disabled");
  });

  it("reports row level security with no policies", () => {
    expect(codes(notes({ policies: [] }))).toContain("rls-no-policies");
  });

  it("reports an always-true policy and names it", () => {
    const t = notes({ policies: [policy("everyone", "select", ["authenticated"], "true", null)] });
    const causes = explainTable(t);
    expect(causes.map((c) => c.code)).toContain("policy-always-true");
    expect(causes.find((c) => c.code === "policy-always-true")?.text).toContain('"everyone"');
  });

  it("reports an always-true write policy reachable by anon as an anon write", () => {
    const t = notes({ policies: [policy("open", "all", ["anon"], "true", "true")] });
    expect(codes(t)).toContain("policy-anon-write");
  });

  it("treats a policy without a role as reaching everyone", () => {
    const t = notes({ policies: [policy("open", "insert", ["public"], null, "true")] });
    expect(codes(t)).toContain("policy-anon-write");
  });

  it("reports anon write privileges on owned tables", () => {
    expect(codes(notes({ privileges: { anon: ["insert", "delete"], authenticated: ALL } }))).toContain("anon-grant");
    expect(codes(notes({ privileges: { anon: ["select"], authenticated: ALL } }))).not.toContain("anon-grant");
  });

  it("reports a write policy that does not tie the owner column to the caller", () => {
    const t = notes({ policies: [policy("read", "select", ["authenticated"], OWN, null), policy("write", "insert", ["authenticated"], null, "(auth.role() = 'authenticated'::text)")] });
    const c = explainTable(t).find((x) => x.code === "owner-not-checked");
    expect(c?.text).toContain('"write"');
  });

  it("reports when no policy compares the owner column with the caller", () => {
    const t = notes({ policies: [policy("signed in", "select", ["authenticated"], "(auth.uid() IS NOT NULL)", null)] });
    expect(codes(t)).toContain("owner-not-compared");
  });

  it("reports a table with no owner column", () => {
    expect(explainTable(tbl("plans", [pk(), col("name", "text")])).map((c) => c.code)).toContain("no-owner-column");
  });

  it("reports a policy that compares the wrong column with the caller", () => {
    const t = tbl("projects", [pk(), userFk("owner_id"), userFk("customer_id")], {
      policies: [policy("mine", "all", ["authenticated"], "(customer_id = ( SELECT auth.uid() AS uid))", "(customer_id = ( SELECT auth.uid() AS uid))")],
    });
    const c = explainTable(t).map((x) => x.code);
    expect(c).toContain("owner-not-checked");
    expect(c).toContain("owner-not-compared");
  });

  it("ignores restrictive policies when looking for grants", () => {
    const t = notes({ policies: [policy("own", "all", ["authenticated"], OWN, OWN), policy("r", "select", ["public"], "true", null, false)] });
    expect(codes(t)).toEqual([]);
  });
});

describe("policySoundFor", () => {
  const owners = ["user_id"];
  it("accepts an ALL policy that binds the owner for every command", () => {
    const p = policy("own", "all", ["authenticated"], OWN, OWN);
    for (const c of ["select", "insert", "update", "delete"] as const) expect(policySoundFor(p, c, owners)).toBe(true);
  });

  it("accepts an ALL policy with only USING for inserts, since USING then doubles as the check", () => {
    expect(policySoundFor(policy("own", "all", ["authenticated"], OWN, null), "insert", owners)).toBe(true);
  });

  it("rejects an update policy whose WITH CHECK ignores the owner", () => {
    expect(policySoundFor(policy("u", "update", ["authenticated"], OWN, "true"), "update", owners)).toBe(false);
  });

  it("accepts an update policy with USING only", () => {
    expect(policySoundFor(policy("u", "update", ["authenticated"], OWN, null), "update", owners)).toBe(true);
  });

  it("rejects insert policies with no check, restrictive policies and other commands", () => {
    expect(policySoundFor(policy("i", "insert", ["authenticated"], null, null), "insert", owners)).toBe(false);
    expect(policySoundFor(policy("r", "all", ["authenticated"], OWN, OWN, false), "select", owners)).toBe(false);
    expect(policySoundFor(policy("s", "select", ["authenticated"], OWN, null), "delete", owners)).toBe(false);
  });
});

describe("explainView", () => {
  const m = model([notes()], [view("v")]);
  it("flags a view without security_invoker over a protected table", () => {
    expect(explainView(m.views[0]!, m).map((c) => c.code)).toEqual(["view-bypasses-rls"]);
  });
  it("is silent for security_invoker views and views over unprotected tables", () => {
    expect(explainView(view("v", { securityInvoker: true }), m)).toEqual([]);
    const open = model([notes({ rlsEnabled: false })], [view("v")]);
    expect(explainView(open.views[0]!, open)).toEqual([]);
  });
});

describe("attackerSentence and severityOf", () => {
  it("names the anonymous capabilities in one sentence", () => {
    expect(attackerSentence("public.notes", ["anon-read", "anon-insert", "anon-delete"])).toBe(
      "Anyone with your public anon key can read rows of public.notes, add rows to public.notes and delete rows from public.notes.",
    );
  });

  it("names signed-in capabilities and combines both", () => {
    expect(attackerSentence("public.notes", ["cross-read", "cross-update"])).toBe("Any signed-in user can read other users' rows and change other users' rows in public.notes.");
    expect(attackerSentence("t", ["anon-read", "cross-delete"])).toBe("Anyone with your public anon key can read rows of t, and any signed-in user can delete other users' rows.");
  });

  it("rates anonymous writes critical and anonymous reads of owned data critical", () => {
    expect(severityOf(["anon-insert"], true, "table")).toBe("critical");
    expect(severityOf(["anon-read"], true, "table")).toBe("critical");
    expect(severityOf(["anon-read"], false, "table")).toBe("medium");
  });

  it("rates cross-user access high and an unowned-row insert medium", () => {
    expect(severityOf(["cross-read"], true, "table")).toBe("high");
    expect(severityOf(["reassign-owner"], true, "table")).toBe("high");
    expect(severityOf(["null-owner-insert"], true, "table")).toBe("medium");
  });
});

describe("buildFindings", () => {
  const m = model([notes(), tbl("invoices", [pk(), userFk("owner_id")], { rlsEnabled: false })]);

  it("is PROVEN when any exploit probe reproduced, with the proving probe ids", () => {
    const f = buildFindings(m, [proof("public.invoices", "anon-read", "PROVEN_VULNERABLE"), proof("public.invoices", "cross-read", "NOT_REPRODUCED")]).find((x) => x.subject === "public.invoices");
    expect(f).toMatchObject({ tier: "PROVEN", severity: "critical", provenBy: ["public.invoices/anon-read"], notReproduced: ["public.invoices/cross-read"], fixStatus: "not-proposed" });
    expect(f?.causes.map((c) => c.code)).toContain("rls-disabled");
  });

  it("is CLEAN when every exploit probe was refused, even if the static pattern looked bad", () => {
    const f = buildFindings(m, [proof("public.invoices", "anon-read", "NOT_REPRODUCED"), proof("public.invoices", "cross-read", "NOT_REPRODUCED")]).find((x) => x.subject === "public.invoices");
    expect(f).toMatchObject({ tier: "CLEAN", severity: "info", causes: [], fixStatus: "not-needed" });
  });

  it("is SUSPECTED when probes were inconclusive and a static pattern exists", () => {
    const f = buildFindings(m, [proof("public.invoices", "anon-read", "INCONCLUSIVE")]).find((x) => x.subject === "public.invoices");
    expect(f?.tier).toBe("SUSPECTED");
    expect(f?.attackerCan).toContain("not reproduced");
    expect(f?.inconclusive).toEqual([{ id: "public.invoices/anon-read", reason: "reason of anon-read" }]);
  });

  it("is INCONCLUSIVE when probes were inconclusive and nothing looks wrong", () => {
    const f = buildFindings(m, [proof("public.notes", "anon-read", "INCONCLUSIVE")]).find((x) => x.subject === "public.notes");
    expect(f?.tier).toBe("INCONCLUSIVE");
  });

  it("does not count legitimate probes as exploits", () => {
    const f = buildFindings(m, [proof("public.notes", "anon-read", "NOT_REPRODUCED"), proof("public.notes", "own-read", "ACCESS_BROKEN")]).find((x) => x.subject === "public.notes");
    expect(f?.tier).toBe("CLEAN");
  });

  it("orders PROVEN before CLEAN, then by severity and name", () => {
    const proofs = [proof("public.notes", "anon-read", "NOT_REPRODUCED"), proof("public.invoices", "anon-read", "PROVEN_VULNERABLE")];
    expect(buildFindings(m, proofs).map((f) => f.subject)).toEqual(["public.invoices", "public.notes"]);
  });

  it("honours priority only as a tie-break", () => {
    const both = model([notes(), notes({ name: { schema: "public", name: "a_notes" } })]);
    const proofs = [proof("public.a_notes", "anon-read", "PROVEN_VULNERABLE"), proof("public.notes", "anon-read", "PROVEN_VULNERABLE")];
    expect(buildFindings(both, proofs).map((f) => f.subject)).toEqual(["public.a_notes", "public.notes"]);
    expect(buildFindings(both, proofs, ["public.notes"]).map((f) => f.subject)).toEqual(["public.notes", "public.a_notes"]);
  });

  it("creates view findings only for views that were probed", () => {
    const withView = model([notes()], [view("v")]);
    expect(buildFindings(withView, []).some((f) => f.subjectKind === "view")).toBe(false);
    const vp = { ...proof("public.v", "view-read-anon", "PROVEN_VULNERABLE"), subjectKind: "view" as const };
    const f = buildFindings(withView, [vp]).find((x) => x.subjectKind === "view");
    expect(f).toMatchObject({ tier: "PROVEN", severity: "critical" });
    expect(f?.causes.map((c) => c.code)).toEqual(["view-bypasses-rls"]);
  });
});
