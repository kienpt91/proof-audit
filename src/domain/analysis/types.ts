import type { Proof } from "../proof/types.js";

export type Tier = "PROVEN" | "SUSPECTED" | "CLEAN" | "INCONCLUSIVE";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export type CauseCode =
  | "rls-disabled"
  | "rls-no-policies"
  | "policy-always-true"
  | "policy-anon-write"
  | "anon-grant"
  | "owner-not-checked"
  | "owner-not-compared"
  | "view-bypasses-rls"
  | "no-owner-column";

/** A static observation that explains why a probe succeeded (or why we suspect it would). */
export interface Cause {
  readonly code: CauseCode;
  readonly text: string;
}

export type FixStatus = "verified" | "unverified" | "breaks-access" | "still-vulnerable" | "not-proposed" | "needs-decision" | "not-needed";

export interface Finding {
  /** `rls:<schema.name>` */
  readonly id: string;
  readonly subject: string;
  readonly subjectKind: "table" | "view";
  readonly tier: Tier;
  readonly severity: Severity;
  readonly title: string;
  /** One plain-language sentence: what an attacker could do. For SUSPECTED it says what might be possible. */
  readonly attackerCan: string;
  readonly causes: readonly Cause[];
  /** Ids of exploit probes that reproduced the problem. */
  readonly provenBy: readonly string[];
  /** Ids of exploit probes the database denied. */
  readonly notReproduced: readonly string[];
  readonly inconclusive: readonly { readonly id: string; readonly reason: string }[];
  readonly fixStatus: FixStatus;
  readonly fixNote: string;
}

export interface StatementError {
  readonly file: string;
  readonly line: number;
  /** Start of the statement, single line, truncated. */
  readonly statement: string;
  readonly sqlstate: string;
  readonly message: string;
}

export interface SeedTableResult {
  readonly table: string;
  /** Rows present for each synthetic user after seeding. */
  readonly rowsUserA: number;
  readonly rowsUserB: number;
  /** `ok`, or why the table could not be seeded for one or both users. */
  readonly status: "ok" | "partial" | "failed" | "skipped";
  readonly reason: string | null;
}

export interface FixPlan {
  /** Statements as applied in the verification sandbox, in order. */
  readonly statements: readonly string[];
  /** The same statements as a commented SQL file for a human. */
  readonly sql: string;
  /** Tables or views the fix covers. */
  readonly covered: readonly string[];
  /** Subjects with a proven problem that the tool cannot fix without a decision only the owner of the app can make. */
  readonly needsDecision: readonly { readonly subject: string; readonly reason: string }[];
}

export type VerificationStatus = "VERIFIED" | "PARTIAL" | "NOT_VERIFIED" | "BREAKS_ACCESS" | "FIX_FAILED" | "NOT_APPLICABLE";
export type SubjectVerificationStatus = "VERIFIED" | "STILL_VULNERABLE" | "BREAKS_ACCESS" | "UNVERIFIED" | "NO_FIX";

export interface SubjectVerification {
  readonly subject: string;
  readonly status: SubjectVerificationStatus;
  /** Exploit probes that were PROVEN before and are denied after. */
  readonly closed: readonly string[];
  readonly stillProven: readonly string[];
  /** Legitimate probes that worked before and no longer do. */
  readonly broken: readonly string[];
  /** Probes (exploit or legitimate) that did not give a clear answer after the fix. */
  readonly unresolved: readonly string[];
  readonly reason: string;
}

export interface Verification {
  readonly status: VerificationStatus;
  /** Fix statements that failed to apply. */
  readonly applyErrors: readonly { readonly statement: string; readonly sqlstate: string; readonly message: string }[];
  readonly subjects: readonly SubjectVerification[];
  /** Every probe re-run on the fixed copy. */
  readonly after: readonly Proof[];
}

export type AuditProofStatus = "PROVEN" | "NOT_REPRODUCED" | "INCONCLUSIVE" | "STATIC_ONLY";

export interface CorrelatedAuditFinding {
  readonly rule: string;
  readonly severity: string;
  readonly file: string;
  readonly line: number;
  readonly title: string;
  /** Qualified table the static finding is about, when it could be determined. */
  readonly table: string | null;
  readonly proofStatus: AuditProofStatus;
  readonly proofIds: readonly string[];
  readonly note: string;
}

export interface AuditCorrelation {
  readonly sourceTool: string;
  readonly sourceVersion: string | null;
  readonly project: string | null;
  readonly findings: readonly CorrelatedAuditFinding[];
  /** Tables named by the static auditor, most severe first; these are probed first and listed first. */
  readonly priorityTables: readonly string[];
  /** Static findings that are not about row level security (secrets, webhooks, ...): not tested here. */
  readonly outOfScope: number;
  readonly warnings: readonly string[];
}

export interface InputFileRecord {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface Environment {
  readonly mode: "docker" | "url";
  /** Image reference (digest-pinned) in docker mode; `loopback` in url mode. */
  readonly image: string;
  /** `server_version` of the throwaway database, or null if it could not be read. */
  readonly postgresVersion: string | null;
}

export interface AnalysisSummary {
  readonly subjects: number;
  readonly proven: number;
  readonly suspected: number;
  readonly clean: number;
  readonly inconclusive: number;
  readonly probesRun: number;
  readonly probesProven: number;
}

export type IntegrityKind =
  | "platform-changed"
  | "targets-tool-internals"
  | "redefines-platform-object"
  | "event-trigger"
  | "alters-protected-setting"
  | "catalog-write";

/** Something that touched, or tried to touch, the test environment the verdicts depend on. */
export interface IntegrityViolation {
  readonly kind: IntegrityKind;
  readonly detail: string;
  readonly file: string | null;
  readonly line: number | null;
  /** `blocked`: the database refused the statement; `succeeded`: it ran; `state-changed`: a fingerprint differs; `unknown`: not applied (no outcome). */
  readonly outcome: "blocked" | "succeeded" | "state-changed" | "unknown";
}

export interface IntegrityReport {
  /** `INTEGRITY_VIOLATION` when the migrations touched or tried to touch the test environment: every finding is then INCONCLUSIVE. */
  readonly status: "INTACT" | "INTEGRITY_VIOLATION";
  readonly violations: readonly IntegrityViolation[];
}

export interface AnalysisReport {
  readonly tool: { readonly name: string; readonly version: string };
  readonly inputs: readonly InputFileRecord[];
  readonly environment: Environment;
  /** False when a cap was hit or the sandbox could not run everything: results may be partial. */
  readonly complete: boolean;
  readonly summary: AnalysisSummary;
  /** Ordered: tier (PROVEN first), severity, then name. */
  readonly findings: readonly Finding[];
  /** Every probe run against the original schema. */
  readonly proofs: readonly Proof[];
  readonly seeding: readonly SeedTableResult[];
  readonly fix: FixPlan | null;
  readonly verification: Verification | null;
  readonly audit: AuditCorrelation | null;
  /** Statements of the user's migrations that the sandbox rejected. */
  readonly migrationErrors: readonly StatementError[];
  /** Reader and runner warnings (skipped statements, caps, divergence between reader and database). */
  readonly warnings: readonly string[];
  /** What this run did not and cannot check. */
  readonly notChecked: readonly string[];
}
