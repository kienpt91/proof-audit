import { describe, expect, it } from "vitest";
import type { FixPlan } from "../../../src/domain/analysis/types.js";
import { verifyFix } from "../../../src/domain/fix/verify.js";
import { sealProof } from "../../../src/domain/proof/hash.js";
import type { Phase, ProbeKind, Proof, Verdict } from "../../../src/domain/proof/types.js";

function proof(subject: string, kind: ProbeKind, verdict: Verdict, phase: Phase): Proof {
  const legit = kind.startsWith("own") || kind === "view-read-own";
  return sealProof({
    id: `${subject}/${kind}`,
    subject,
    subjectKind: "table",
    kind,
    intent: legit ? "legitimate" : "exploit",
    command: "select",
    actor: "user-a",
    role: "authenticated",
    claims: "{}",
    sql: "SELECT 1",
    title: kind,
    targetRows: 1,
    observation: { status: "rows", rows: verdict === "PROVEN_VULNERABLE" || verdict === "ACCESS_OK" ? 1 : 0 },
    verdict,
    reason: "r",
    phase,
  });
}

const plan = (covered: string[]): FixPlan => ({ statements: ["x"], sql: "x", covered, needsDecision: [] });
const T = "public.notes";

const before = [proof(T, "cross-read", "PROVEN_VULNERABLE", "before"), proof(T, "anon-read", "PROVEN_VULNERABLE", "before"), proof(T, "own-read", "ACCESS_OK", "before")];

describe("verifyFix", () => {
  it("verifies when every proven probe is closed and legitimate access survives", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "ACCESS_OK", "after")];
    const v = verifyFix(before, after, plan([T]), []);
    expect(v.status).toBe("VERIFIED");
    expect(v.subjects[0]).toMatchObject({ status: "VERIFIED", closed: [`${T}/cross-read`, `${T}/anon-read`], broken: [], stillProven: [] });
  });

  it("refuses to verify a fix that closes the hole but breaks legitimate access", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "ACCESS_BROKEN", "after")];
    const v = verifyFix(before, after, plan([T]), []);
    expect(v.status).toBe("BREAKS_ACCESS");
    expect(v.subjects[0]?.broken).toEqual([`${T}/own-read`]);
  });

  it("refuses to verify when one proven probe still works", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "PROVEN_VULNERABLE", "after"), proof(T, "own-read", "ACCESS_OK", "after")];
    const v = verifyFix(before, after, plan([T]), []);
    expect(v.status).toBe("NOT_VERIFIED");
    expect(v.subjects[0]).toMatchObject({ status: "STILL_VULNERABLE", stillProven: [`${T}/anon-read`] });
  });

  it("does not verify when a probe gives no clear answer after the fix", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "INCONCLUSIVE", "after"), proof(T, "own-read", "ACCESS_OK", "after")];
    expect(verifyFix(before, after, plan([T]), []).subjects[0]?.status).toBe("UNVERIFIED");
  });

  it("does not verify without a legitimate-access baseline", () => {
    const noBaseline = before.slice(0, 2);
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "NOT_REPRODUCED", "after")];
    const v = verifyFix(noBaseline, after, plan([T]), []);
    expect(v.status).toBe("NOT_VERIFIED");
    expect(v.subjects[0]?.reason).toContain("legitimate-access");
  });

  it("does not verify when the legitimate probe was inconclusive after the fix", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "INCONCLUSIVE", "after")];
    expect(verifyFix(before, after, plan([T]), []).status).toBe("NOT_VERIFIED");
  });

  it("does not verify when an after-probe is missing", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "ACCESS_OK", "after")];
    expect(verifyFix(before, after, plan([T]), []).subjects[0]?.unresolved).toEqual([`${T}/anon-read`]);
  });

  it("is FIX_FAILED when a fix statement did not apply, even if probes look closed", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "ACCESS_OK", "after")];
    const v = verifyFix(before, after, plan([T]), [{ statement: "S", sqlstate: "42601", message: "syntax" }]);
    expect(v.status).toBe("FIX_FAILED");
  });

  it("is PARTIAL when only some subjects verify", () => {
    const U = "public.tasks";
    const b = [...before, proof(U, "cross-read", "PROVEN_VULNERABLE", "before"), proof(U, "own-read", "ACCESS_OK", "before")];
    const after = [
      proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "anon-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "ACCESS_OK", "after"),
      proof(U, "cross-read", "PROVEN_VULNERABLE", "after"), proof(U, "own-read", "ACCESS_OK", "after"),
    ];
    const v = verifyFix(b, after, plan([T, U]), []);
    expect(v.status).toBe("PARTIAL");
    expect(v.subjects.map((s) => s.status)).toEqual(["VERIFIED", "STILL_VULNERABLE"]);
  });

  it("treats a subject without a fix as not verified", () => {
    const v = verifyFix(before, [], plan([]), []);
    expect(v.status).toBe("NOT_VERIFIED");
    expect(v.subjects[0]?.status).toBe("NO_FIX");
  });

  it("is NOT_APPLICABLE when nothing was proven", () => {
    const clean = [proof(T, "cross-read", "NOT_REPRODUCED", "before"), proof(T, "own-read", "ACCESS_OK", "before")];
    expect(verifyFix(clean, clean, plan([]), []).status).toBe("NOT_APPLICABLE");
  });

  it("ignores legitimate probes that were already broken before the fix", () => {
    const b = [proof(T, "cross-read", "PROVEN_VULNERABLE", "before"), proof(T, "own-read", "ACCESS_BROKEN", "before"), proof(T, "own-insert", "ACCESS_OK", "before")];
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after"), proof(T, "own-read", "ACCESS_BROKEN", "after"), proof(T, "own-insert", "ACCESS_OK", "after")];
    expect(verifyFix(b, after, plan([T]), []).status).toBe("VERIFIED");
  });

  it("keeps the after proofs on the result", () => {
    const after = [proof(T, "cross-read", "NOT_REPRODUCED", "after")];
    expect(verifyFix(before, after, plan([T]), []).after).toBe(after);
  });
});
