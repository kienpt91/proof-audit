/**
 * The shape of the records in `findings.json`: an array of records with one of three verdicts, as published
 * for Cloudflare's open source security-audit-skill (https://github.com/cloudflare/security-audit-skill,
 * MIT licence). The types below are this project's own description of that published shape. They are
 * written so that a value of the right type has the right fields and no others; `conformance.ts` checks the
 * rest (patterns, uniqueness, ordering) on the encoded text.
 */

export type Score = "informational" | "low" | "medium" | "high" | "critical";

export type TraceKind = "entrypoint" | "propagation" | "sink";

export interface TraceStep {
  readonly kind: TraceKind;
  readonly file: string;
  readonly line: number;
  readonly scope: string;
  readonly description: string;
}

export interface EvidenceItem {
  readonly file: string;
  readonly line: number;
  readonly description: string;
}

export type ConditionKind =
  | "authentication_level"
  | "authorization_role"
  | "user_interaction"
  | "system_configuration"
  | "network_routing"
  | "environmental_dependency"
  | "data_state"
  | "timing_dependency"
  | "third_party_dependency";

export interface Condition {
  readonly kind: ConditionKind;
  readonly description: string;
}

export interface Execution {
  readonly attacker_perspective: string;
  readonly payloads: readonly string[];
  readonly instructions: readonly string[];
  readonly observed_result: string;
}

export interface Remediation {
  readonly strategy: string;
  readonly code_changes?: readonly { readonly file_name: string; readonly fixed_code: string }[];
}

export interface Severity {
  readonly likelihood: { readonly score: Score; readonly reason: string };
  readonly impact: { readonly score: Score; readonly reason: string };
  readonly overall_severity: Score;
}

export interface Confidence {
  readonly score: "low" | "medium" | "high";
  readonly reason: string;
}

/** A vulnerability that a probe demonstrated against a real database. */
export interface ConfirmedRecord {
  readonly verdict: "confirmed";
  readonly fingerprint: string;
  readonly title: string;
  readonly description: string;
  readonly root_cause: string;
  readonly intended_behavior: string;
  readonly trace: readonly TraceStep[];
  readonly evidence: readonly EvidenceItem[];
  readonly conditions: readonly Condition[];
  readonly execution: Execution;
  readonly remediation: Remediation;
  readonly severity: Severity;
  readonly confidence: Confidence;
}

/** A candidate that no probe could confirm. It carries no severity. */
export interface NeedsValidationRecord {
  readonly verdict: "needs_validation";
  readonly fingerprint: string;
  readonly title: string;
  readonly description: string;
  readonly claimed_root_cause: string;
  readonly trace: readonly TraceStep[];
  readonly evidence: readonly EvidenceItem[];
  readonly blockers: readonly string[];
  readonly validation_plan: { readonly local?: string; readonly deployment?: string };
}

/** A candidate that validation refuted. */
export interface RejectedRecord {
  readonly verdict: "rejected";
  readonly fingerprint: string;
  readonly title: string;
  readonly description: string;
  readonly claimed_root_cause: string;
  readonly trace: readonly TraceStep[];
  readonly evidence: readonly EvidenceItem[];
  readonly reason: string;
}

export type FindingRecord = ConfirmedRecord | NeedsValidationRecord | RejectedRecord;

/** Records sorted by fingerprint (the order the format requires), two-space indent, trailing newline. */
export function encodeFindings(records: readonly FindingRecord[]): string {
  const sorted = [...records].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));
  return `${JSON.stringify(sorted, null, 2)}\n`;
}
