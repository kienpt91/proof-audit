import type { FixPlan, SubjectVerification, Verification, VerificationStatus } from "../analysis/types.js";
import type { Proof } from "../proof/types.js";

function bySubject(proofs: readonly Proof[]): Map<string, Proof[]> {
  const map = new Map<string, Proof[]>();
  for (const p of proofs) map.set(p.subject, [...(map.get(p.subject) ?? []), p]);
  return map;
}

const names = (proofs: readonly Proof[]): string[] => proofs.map((p) => p.id);
const count = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

function verifySubject(subject: string, before: readonly Proof[], after: readonly Proof[], covered: boolean): SubjectVerification {
  const afterById = new Map(after.map((p) => [p.id, p]));
  const proven = before.filter((p) => p.intent === "exploit" && p.verdict === "PROVEN_VULNERABLE");
  const worked = before.filter((p) => p.intent === "legitimate" && p.verdict === "ACCESS_OK");
  const closed = proven.filter((p) => afterById.get(p.id)?.verdict === "NOT_REPRODUCED");
  const stillProven = proven.filter((p) => afterById.get(p.id)?.verdict === "PROVEN_VULNERABLE");
  const broken = worked.filter((p) => afterById.get(p.id)?.verdict === "ACCESS_BROKEN");
  const unresolved = [
    ...proven.filter((p) => !closed.includes(p) && !stillProven.includes(p)),
    ...worked.filter((p) => !broken.includes(p) && afterById.get(p.id)?.verdict !== "ACCESS_OK"),
  ];
  const base = { subject, closed: names(closed), stillProven: names(stillProven), broken: names(broken), unresolved: names(unresolved) };
  if (!covered) return { ...base, status: "NO_FIX", reason: "no fix was proposed for this subject; a decision is needed" };
  if (stillProven.length > 0) return { ...base, status: "STILL_VULNERABLE", reason: `${count(stillProven.length, "attack that worked", "attacks that worked")} before still ${stillProven.length === 1 ? "works" : "work"} after the fix` };
  if (broken.length > 0) return { ...base, status: "BREAKS_ACCESS", reason: `the fix closes the hole but ${count(broken.length, "normal action", "normal actions")} of a legitimate user stopped working` };
  if (unresolved.length > 0) return { ...base, status: "UNVERIFIED", reason: `${count(unresolved.length, "probe gave", "probes gave")} no clear answer after the fix` };
  if (worked.length === 0) {
    return { ...base, status: "UNVERIFIED", reason: "no legitimate-access probe worked before the fix, so breaking normal use cannot be ruled out" };
  }
  return { ...base, status: "VERIFIED", reason: `${count(closed.length, "attack now fails", "attacks now fail")} and ${count(worked.length, "legitimate action still works", "legitimate actions still work")}` };
}

/**
 * Decides whether a fix may be called verified. All of these must hold for every proven subject: each probe
 * that was PROVEN_VULNERABLE is now NOT_REPRODUCED, and each legitimate probe that worked before still works.
 * Anything unclear, or any subject the fix does not cover, stops the overall status from being VERIFIED.
 */
export function verifyFix(
  before: readonly Proof[],
  after: readonly Proof[],
  plan: FixPlan,
  applyErrors: Verification["applyErrors"],
): Verification {
  const beforeBy = bySubject(before);
  const afterBy = bySubject(after);
  const provenSubjects = [...beforeBy.entries()]
    .filter(([, ps]) => ps.some((p) => p.intent === "exploit" && p.verdict === "PROVEN_VULNERABLE"))
    .map(([s]) => s)
    .sort();
  const subjects = provenSubjects.map((s) => verifySubject(s, beforeBy.get(s) ?? [], afterBy.get(s) ?? [], plan.covered.includes(s)));
  let status: VerificationStatus;
  if (provenSubjects.length === 0) status = "NOT_APPLICABLE";
  else if (applyErrors.length > 0) status = "FIX_FAILED";
  else if (subjects.every((s) => s.status === "VERIFIED")) status = "VERIFIED";
  else if (subjects.some((s) => s.status === "BREAKS_ACCESS")) status = "BREAKS_ACCESS";
  else if (subjects.some((s) => s.status === "VERIFIED")) status = "PARTIAL";
  else status = "NOT_VERIFIED";
  return { status, applyErrors, subjects, after };
}
