import type { FixPlan, Finding, Verification } from "../analysis/types.js";

/** Copy the fix and verification outcome onto each finding so every report reads the same story. */
export function applyFixOutcome(findings: readonly Finding[], plan: FixPlan | null, verification: Verification | null): readonly Finding[] {
  return findings.map((f) => {
    if (f.tier !== "PROVEN" || plan === null) return f;
    const decision = plan.needsDecision.find((d) => d.subject === f.subject);
    if (decision) return { ...f, fixStatus: "needs-decision", fixNote: `Needs your decision: ${decision.reason}.` };
    if (verification === null) return f;
    if (verification.status === "FIX_FAILED") {
      return { ...f, fixStatus: "unverified", fixNote: "The proposed fix did not apply cleanly in the test database, so it is not verified." };
    }
    const s = verification.subjects.find((v) => v.subject === f.subject);
    if (!s) return f;
    const map: Record<typeof s.status, Finding["fixStatus"]> = {
      VERIFIED: "verified",
      STILL_VULNERABLE: "still-vulnerable",
      BREAKS_ACCESS: "breaks-access",
      UNVERIFIED: "unverified",
      NO_FIX: "needs-decision",
    };
    return { ...f, fixStatus: map[s.status], fixNote: s.status === "VERIFIED" ? `Fix verified: ${s.reason}.` : `Fix not verified: ${s.reason}.` };
  });
}
