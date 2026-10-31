import { sealProof } from "./hash.js";
import type { Phase, Probe, ProbeObservation, Proof, Verdict } from "./types.js";

/** PostgreSQL's "insufficient_privilege": raised for missing grants and for row-level-security violations. */
const DENIED = "42501";

function rowWord(rows: number): string {
  return rows === 1 ? "1 row" : `${rows} rows`;
}

function wording(probe: Probe, rows: number): string {
  return probe.command === "select" ? `the statement returned ${rowWord(rows)}` : `the statement changed ${rowWord(rows)}`;
}

/**
 * Turns what the database did into a verdict. The rules are deliberately conservative: anything that is not
 * a clear "it worked" or a clear "it was refused" is INCONCLUSIVE with the reason, never a guess.
 */
export function judge(probe: Probe, observation: ProbeObservation): { readonly verdict: Verdict; readonly reason: string } {
  const exploit = probe.intent === "exploit";
  const yes: Verdict = exploit ? "PROVEN_VULNERABLE" : "ACCESS_OK";
  const no: Verdict = exploit ? "NOT_REPRODUCED" : "ACCESS_BROKEN";
  if (probe.blockedReason !== null) return { verdict: "INCONCLUSIVE", reason: probe.blockedReason };
  if (observation.status === "not-run") return { verdict: "INCONCLUSIVE", reason: observation.reason };
  if (observation.status === "error") {
    if (observation.sqlstate === DENIED) {
      return { verdict: no, reason: "the database refused the statement (permission denied or a row-level security rule)" };
    }
    if (exploit && probe.command === "insert" && observation.sqlstate.startsWith("23")) {
      // Postgres checks row-level-security policies before table constraints, so an integrity error here means the policy let the row through.
      return { verdict: "PROVEN_VULNERABLE", reason: `the access policy let the row through; only a table constraint (SQLSTATE ${observation.sqlstate}) stopped the insert` };
    }
    return { verdict: "INCONCLUSIVE", reason: `the statement failed with SQLSTATE ${observation.sqlstate} before access could be judged` };
  }
  const rows = observation.rows;
  if (probe.command === "insert") {
    if (rows >= 1) return { verdict: yes, reason: wording(probe, rows) };
    return { verdict: "INCONCLUSIVE", reason: "the insert reported no rows and no error" };
  }
  if (rows > 0) return { verdict: yes, reason: wording(probe, rows) };
  if (probe.targetRows !== null && probe.targetRows > 0) {
    return { verdict: no, reason: `${wording(probe, 0)} although ${rowWord(probe.targetRows)} existed to ${probe.command === "select" ? "read" : "change"}` };
  }
  return { verdict: "INCONCLUSIVE", reason: "there were no rows to aim at" };
}

/** Record what happened, with the verdict and a content hash. */
export function recordProof(probe: Probe, observation: ProbeObservation, phase: Phase): Proof {
  const effective: ProbeObservation = probe.blockedReason !== null ? { status: "not-run", reason: probe.blockedReason } : observation;
  const { verdict, reason } = judge(probe, effective);
  return sealProof({
    id: probe.id,
    subject: probe.subject,
    subjectKind: probe.subjectKind,
    kind: probe.kind,
    intent: probe.intent,
    command: probe.command,
    actor: probe.actor,
    role: probe.role,
    claims: probe.claims,
    sql: probe.sql,
    title: probe.title,
    targetRows: probe.targetRows,
    observation: effective,
    verdict,
    reason,
    phase,
  });
}
