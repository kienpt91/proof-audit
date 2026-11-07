import { severityAnchor, type SeverityAnchorId } from "../analysis/findings.js";
import type { Severity as ReportSeverity } from "../analysis/types.js";
import type { ProbeKind } from "../proof/types.js";
import type { Score, Severity } from "./records.js";

/**
 * The severity anchor table for confirmed records (docs: "Severity anchors"). The impact, and with it the
 * overall severity, is fixed by the attacks that were proven for the record, the owner column and whether the
 * subject is a table or a view; it is the same rule that gives the severity in `report.json`, so the two files
 * agree. Nothing is decided per case.
 */
export const IMPACT_ANCHORS: Readonly<Record<SeverityAnchorId, { readonly impact: Score; readonly reason: string }>> = {
  "anon-write": {
    impact: "critical",
    reason: "Anyone holding the public anon key could add, change or delete rows of this table without signing in.",
  },
  "anon-read-owned": {
    impact: "critical",
    reason: "Anyone holding the public anon key could read rows that belong to individual users (or the rows behind a view over them) without signing in.",
  },
  "anon-read-unowned": {
    impact: "medium",
    reason: "Anyone holding the public anon key could read rows of a table that has no owner column, so it may be meant to be public; nothing was written.",
  },
  "cross-user": {
    impact: "high",
    reason: "A signed-in user could read or change rows that belong to another user, or give a row away.",
  },
  other: {
    impact: "medium",
    reason: "The proven attack is narrower than reading or changing another user's rows (for example adding a row with no owner).",
  },
};

const ANONYMOUS: readonly ProbeKind[] = ["anon-read", "anon-insert", "anon-update", "anon-delete", "view-read-anon"];

const SCALE: Readonly<Record<ReportSeverity, Score>> = { info: "informational", low: "low", medium: "medium", high: "high", critical: "critical" };

export function toScore(severity: ReportSeverity): Score {
  return SCALE[severity];
}

/**
 * Likelihood anchors: `high` when an attack needs nothing but the public anon key (it ships in every client
 * bundle and one request is enough), `medium` when it needs a signed-in account (the tool does not check
 * whether sign-up is open). The likelihood is reported for context; it does not lower the overall severity.
 */
export function severityFor(proven: readonly ProbeKind[], hasOwnerColumn: boolean, subjectKind: "table" | "view"): Severity {
  const anchor = severityAnchor(proven, hasOwnerColumn, subjectKind);
  const impact = IMPACT_ANCHORS[anchor.id];
  const anonymous = proven.some((k) => ANONYMOUS.includes(k));
  return {
    likelihood: anonymous
      ? { score: "high", reason: "The attack needs only the public anon key, which ships in every client bundle, and a single request; it was reproduced against a real database." }
      : { score: "medium", reason: "The attack needs a signed-in account; the tool did not check whether anyone can sign up. It was reproduced against a real database with an ordinary user." },
    impact: { score: toScore(anchor.severity), reason: impact.reason },
    overall_severity: toScore(anchor.severity),
  };
}
