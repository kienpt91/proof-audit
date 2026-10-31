import type {
  AnalysisReport,
  AuditProofStatus,
  Finding,
  FixStatus,
  IntegrityViolation,
  SubjectVerificationStatus,
  Tier,
  VerificationStatus,
} from "../../domain/analysis/types.js";
import type { Proof } from "../../domain/proof/types.js";
import { truncateCodePoints } from "../../domain/text/sanitize.js";

/**
 * A run of report text. Plain strings are written by this tool and are emitted as they are; `input`
 * parts come from the audited repository or the database and MUST go through a sanitizer. `code` marks
 * identifiers and SQL fragments that the markdown renderer shows in a code span.
 */
export type Part = string | { readonly input: string; readonly code?: boolean };

export interface PartRenderers {
  readonly text: (s: string) => string;
  readonly code: (s: string) => string;
}

export function renderParts(parts: readonly Part[], r: PartRenderers): string {
  let out = "";
  for (const part of parts) {
    if (typeof part === "string") out += part;
    else out += part.code === true ? r.code(part.input) : r.text(part.input);
  }
  return out;
}

/** Limits that keep a report readable when the input is huge. */
export const LIMITS = {
  migrationErrors: 10,
  warnings: 20,
  proofSqlLines: 20,
  fixSqlLines: 200,
  sqlLineLength: 300,
  text: 400,
  code: 160,
} as const;

export const TIER_ORDER: readonly Tier[] = ["PROVEN", "SUSPECTED", "INCONCLUSIVE", "CLEAN"];

export function tierHeadline(tier: Tier): string {
  switch (tier) {
    case "PROVEN":
      return "PROVEN: reproduced against a real database";
    case "SUSPECTED":
      return "SUSPECTED: NOT proven, low confidence";
    case "INCONCLUSIVE":
      return "INCONCLUSIVE: NOT proven, the test gave no clear answer";
    case "CLEAN":
      return "CLEAN";
  }
}

export function tierCaveat(tier: Tier): string | null {
  if (tier === "SUSPECTED") {
    return "Reading the SQL suggests a problem, but the database did not confirm it. Treat this as a lead to check, not as a fact.";
  }
  if (tier === "INCONCLUSIVE") {
    return "The test could not be completed, so we cannot say whether this is a problem. Treat this as unknown, not as safe.";
  }
  return null;
}

export function headlineCounts(report: AnalysisReport): string {
  const s = report.summary;
  return `${s.proven} PROVEN, ${s.suspected} SUSPECTED, ${s.inconclusive} INCONCLUSIVE, ${s.clean} CLEAN`;
}

export function resultParagraph(report: AnalysisReport): string {
  const s = report.summary;
  const parts: string[] = [];
  if (s.proven > 0) {
    parts.push(
      `${s.proven} of ${s.subjects} checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves.`,
    );
  } else if (s.suspected + s.inconclusive > 0) {
    parts.push("No problem was proven.");
  } else {
    parts.push("No problem could be reproduced.");
  }
  if (s.suspected + s.inconclusive > 0) {
    parts.push(
      `${s.suspected + s.inconclusive} more need a look: SUSPECTED and INCONCLUSIVE items are NOT proven and carry low confidence.`,
    );
  }
  if (!report.complete) parts.push("The run is incomplete, so results may be partial.");
  return parts.join(" ");
}

export function databaseParts(report: AnalysisReport): Part[] {
  const env = report.environment;
  const version: Part[] = env.postgresVersion === null ? ["version unknown"] : ["version ", { input: env.postgresVersion }];
  return [
    "a throwaway PostgreSQL database (",
    ...version,
    env.mode === "docker" ? ", docker image " : ", local connection ",
    { input: env.image, code: true },
    ")",
  ];
}

/** Title of the probe `id`, looking at the fixed copy first, then the original run; the id itself as a last resort. */
export function probeTitle(report: AnalysisReport, id: string): string {
  const after = report.verification?.after.find((p) => p.id === id);
  const before = report.proofs.find((p) => p.id === id);
  return (after ?? before)?.title ?? id;
}

/** "Title: what the database did" for a probe id, or just the id when the report has no record of it. */
export function attemptParts(report: AnalysisReport, id: string): Part[] {
  const found = report.proofs.find((p) => p.id === id) ?? report.verification?.after.find((p) => p.id === id);
  if (found === undefined) return [{ input: id }];
  return [{ input: found.title }, ": ", ...narrateProof(found).outcome];
}

function actorWords(p: Proof): string {
  if (p.actor === "anon") return "an anonymous visitor (no login, only the public key)";
  return p.intent === "exploit"
    ? "a signed-in user trying to reach someone else's data"
    : "a normal signed-in user working with their own data";
}

function verdictWords(p: Proof): string {
  switch (p.verdict) {
    case "PROVEN_VULNERABLE":
      return "Access was ALLOWED. That is the problem.";
    case "NOT_REPRODUCED":
      return "Access was denied, so this attack did not work.";
    case "ACCESS_OK":
      return "Access was allowed, as it should be for a normal user.";
    case "ACCESS_BROKEN":
      return "Access was denied, but a normal user needs it.";
    case "INCONCLUSIVE":
      return "No clear answer.";
  }
}

export interface ProofNarrative {
  /** `We acted as ... and ran:` */
  readonly lead: string;
  readonly sql: string;
  readonly outcome: Part[];
  readonly meaning: string;
  readonly reason: Part[];
  readonly evidence: string;
}

/** `the statement returned 2 rows` style reasons only repeat the Result line. */
const REDUNDANT_REASON = /^the statement (returned|changed) \d+ rows?\.?$/i;

function sentence(text: string): string {
  const trimmed = text.trim();
  if (trimmed.length === 0) return "";
  const first = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(first) ? first : `${first}.`;
}

export function narrateProof(p: Proof): ProofNarrative {
  const o = p.observation;
  const outcome: Part[] = [];
  let reason: Part[] = [{ input: sentence(p.reason) }];
  if (REDUNDANT_REASON.test(p.reason.trim()) || p.reason.trim().length === 0) reason = [];
  if (o.status === "rows") {
    const noun = o.rows === 1 ? "row" : "rows";
    const verb = p.command === "select" ? "returned" : o.rows === 0 ? "ran it but changed" : "accepted it and changed";
    outcome.push(`the database ${verb} ${o.rows} ${noun}`);
    if (p.targetRows !== null) outcome.push(` (${plural(p.targetRows, "row", "rows")} seeded for this test)`);
  } else if (o.status === "error") {
    if (p.verdict === "PROVEN_VULNERABLE") {
      // The policy admitted the statement; a table rule (key, check, not-null) rejected it afterwards.
      outcome.push("the access policy let the row through; only a table constraint stopped it (error ", { input: o.sqlstate }, ": ", { input: o.message }, ")");
      reason = [];
    } else {
      outcome.push("the database refused it (error ", { input: o.sqlstate }, ": ", { input: o.message }, ")");
    }
  } else {
    outcome.push("it was not run (", { input: o.reason }, ")");
  }
  return {
    lead: `We acted as ${actorWords(p)} and ran:`,
    sql: p.sql,
    outcome,
    meaning: verdictWords(p),
    reason,
    evidence: `sha256 ${p.hash.slice(0, 12)}`,
  };
}

/** True only when the fix check itself confirmed the subject (or the whole run). */
export function fixIsConfirmed(report: AnalysisReport, subject: string): boolean {
  const v = report.verification;
  if (v === null) return false;
  return v.status === "VERIFIED" || v.subjects.some((s) => s.subject === subject && s.status === "VERIFIED");
}

const CONFIRMED_PREFIX = /^fix verified\\?:\s*/i;

/**
 * One "How to fix" detail line: the status once, then the finding's own note. `note` is already safe text.
 * The word VERIFIED appears only when the fix check confirmed the subject; a leading "Fix verified:" in the
 * note is dropped because the status already says it.
 */
export function fixLine(status: FixStatus, confirmed: boolean, note: string): string {
  if (status === "verified" && confirmed) {
    const detail = note.replace(CONFIRMED_PREFIX, "");
    return detail.length > 0 ? `Fix VERIFIED: ${detail}` : "Fix VERIFIED: the attacks now fail and normal use still works.";
  }
  const label = fixStatusWords(status, confirmed);
  return note.length > 0 ? `${label} ${note}` : label;
}

function fixStatusWords(status: FixStatus, confirmed: boolean): string {
  switch (status) {
    case "verified":
    case "unverified":
      return "A fix was proposed but is not yet confirmed.";
    case "breaks-access":
      return "The proposed fix closes the hole but breaks normal use. Do not apply it as it is.";
    case "still-vulnerable":
      return "The proposed fix does NOT close the hole yet.";
    case "not-proposed":
      return "No fix was proposed automatically.";
    case "needs-decision":
      return "A fix needs a decision from you (see below).";
    case "not-needed":
      return "No fix needed.";
  }
}

export function checkHeadline(status: VerificationStatus): string {
  switch (status) {
    case "VERIFIED":
      return "VERIFIED: every attack that worked before now fails, and a normal signed-in user can still read and write their own rows.";
    case "PARTIAL":
      return "PARTIAL: only some tables are fixed and confirmed. See the table below. The rest still need work.";
    case "NOT_VERIFIED":
      return "NOT CONFIRMED: the fix could not be checked end to end, so we cannot say it works.";
    case "BREAKS_ACCESS":
      return "BREAKS ACCESS: the attacks are blocked, but normal users lost access they need. Do not ship this fix as it is.";
    case "FIX_FAILED":
      return "FIX FAILED: the database rejected part of the fix, so it was not checked as a whole.";
    case "NOT_APPLICABLE":
      return "NOT APPLICABLE: nothing needed fixing.";
  }
}

export function subjectCheckWords(status: SubjectVerificationStatus): string {
  switch (status) {
    case "VERIFIED":
      return "VERIFIED (attacks closed, normal use works)";
    case "STILL_VULNERABLE":
      return "STILL VULNERABLE";
    case "BREAKS_ACCESS":
      return "BREAKS ACCESS (attack closed, normal use broken)";
    case "UNVERIFIED":
      return "NOT CONFIRMED";
    case "NO_FIX":
      return "NO FIX PROPOSED";
  }
}

export function auditStatusWords(status: AuditProofStatus): string {
  switch (status) {
    case "PROVEN":
      return "PROVEN by our test";
    case "NOT_REPRODUCED":
      return "could not be reproduced";
    case "INCONCLUSIVE":
      return "our test gave no clear answer";
    case "STATIC_ONLY":
      return "static finding only, not tested";
  }
}

/** Findings that deserve a block of their own. */
export function nonClean(findings: readonly Finding[]): Finding[] {
  return findings.filter((f) => f.tier !== "CLEAN");
}

export interface SqlLines {
  readonly lines: string[];
  readonly omitted: number;
}

/** Splits SQL into lines, truncating long lines and capping the line count. */
export function sqlLines(sql: string, maxLines: number): SqlLines {
  const all = sql.replace(/\r\n/g, "\n").split("\n");
  const kept = all.slice(0, maxLines).map((l) => truncateCodePoints(l, LIMITS.sqlLineLength));
  return { lines: kept, omitted: Math.max(0, all.length - maxLines) };
}

export function seedingProblems(report: AnalysisReport) {
  return report.seeding.filter((s) => s.status !== "ok");
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

export const INTEGRITY_HEADLINE = "INTEGRITY_VIOLATION: do not trust these results";

export const INTEGRITY_EXPLANATION =
  "The migrations touched, or tried to touch, the test environment that every verdict depends on (the platform functions and roles, the settings that decide how queries are resolved, the tool's own objects). Nothing can be concluded from this run: every table and view is reported as could not be judged, and no fix is proposed.";

/** How a violation reads in a list: what, whether the database allowed it, and where. */
export function violationParts(v: IntegrityViolation): Part[] {
  const outcome = v.outcome === "blocked" ? "the database refused it" : v.outcome === "succeeded" ? "the database accepted it" : v.outcome === "state-changed" ? "the environment changed" : "outcome unknown";
  const where = v.file === null ? "" : [" at ", { input: `${v.file}:${v.line ?? 0}`, code: true } as Part];
  return [{ input: v.detail }, ` (${v.kind}; ${outcome})`, ...(where === "" ? [] : where)];
}
