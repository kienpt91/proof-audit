import { attackerSentence } from "../analysis/findings.js";
import type { AnalysisReport, CorrelatedAuditFinding, Finding } from "../analysis/types.js";
import { policyFromTitle, staticSubject, type ParsedAudit, type ParsedAuditFinding } from "../audit/import.js";
import { fixSectionFor } from "../fix/generate.js";
import type { Proof } from "../proof/types.js";
import type { QualifiedName, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import { primaryOwnerColumn } from "../schema/owner.js";
import { truncateCodePoints } from "../text/sanitize.js";
import { hasVisible } from "./conformance.js";
import { rlsFingerprint, staticFingerprint, type RootCauseKind } from "./fingerprint.js";
import { locateStatic, locateTableCause, locateViewCause, type Located, type SourceMap } from "./locate.js";
import type { Condition, ConfirmedRecord, EvidenceItem, FindingRecord, NeedsValidationRecord, RejectedRecord } from "./records.js";
import { groupByRootCause, tableRootCauses, viewRootCauses, type RootCause } from "./rootcause.js";
import { severityFor } from "./severity.js";

/** The file the fix sections are taken from; written next to `findings.json`. */
export const FIX_FILE = "fix.sql";

export interface ExportInput {
  readonly report: AnalysisReport;
  readonly source: SourceMap;
  /** The static auditor report given with `--from-audit`, if any. */
  readonly audit: ParsedAudit | null;
  /** The input files with their number of lines, to check a position reported by the static auditor. */
  readonly inputs: readonly { readonly path: string; readonly lines: number }[];
}

/** A table, view or static finding that has no record, and why. */
export interface Omitted {
  readonly subject: string;
  readonly reason: string;
}

export interface ExportResult {
  readonly records: readonly FindingRecord[];
  readonly omitted: readonly Omitted[];
}

const unique = (items: readonly string[]): string[] => [...new Set(items)];

function titleFor(kind: RootCauseKind, key: string, subjectKind: "table" | "view", policy: string | null): string {
  switch (kind) {
    case "rls-disabled":
      return `Row level security is off on ${key}`;
    case "policy-always-true":
      return `Policy "${policy}" on ${key} admits every row`;
    case "policy-owner-unchecked":
      return `Policy "${policy}" on ${key} does not tie written rows to their owner`;
    case "owner-not-compared":
      return `No policy on ${key} ties rows to the signed-in user`;
    case "view-bypasses-rls":
      return `View ${key} bypasses row level security`;
    case "unattributed":
      return `Access control of ${subjectKind} ${key} let an attack through`;
    case "untested":
      return `Access control of ${subjectKind} ${key} could not be fully tested`;
  }
}

function strategyFor(kind: RootCauseKind, key: string, policy: string | null, owner: string): string {
  switch (kind) {
    case "rls-disabled":
      return `Turn row level security on for ${key} and add policies that tie every command to the row's owner (${owner} = (select auth.uid())); revoke the anon role's privileges unless the table is meant to be public.`;
    case "policy-always-true":
      return `Drop or replace policy "${policy}" on ${key} with a condition that ties ${owner} to the caller (${owner} = (select auth.uid())), and revoke the anon privileges the application does not need.`;
    case "policy-owner-unchecked":
      return `Rewrite policy "${policy}" on ${key} so that both its USING and its WITH CHECK condition tie ${owner} to the caller (${owner} = (select auth.uid())).`;
    case "owner-not-compared":
      return `Add policies on ${key} that compare ${owner} with (select auth.uid()) for every command the application needs.`;
    case "view-bypasses-rls":
      return `Make the view run with the caller's rights (ALTER VIEW ${key} SET (security_invoker = true), PostgreSQL 15 or later) and revoke the anon role's privileges on it.`;
    case "unattributed":
    case "untested":
      return `Review the policies, privileges, rules and triggers of ${key}: the database let the proven attacks through but no static cause was identified.`;
  }
}

function intendedBehavior(table: Table | undefined, owner: string | null): string {
  if (table === undefined) return "A view over per-user rows should apply the caller's row level security (security_invoker), so each signed-in user sees only their own rows and the anonymous role sees none.";
  if (owner === null) return "The anonymous role should not read or write rows of this table unless it is deliberately public. The table has no owner column, so the tool cannot tell whose rows are whose.";
  return `A signed-in user should read and change only rows whose ${owner} is theirs, and the anonymous role (the public key) should have no access to rows of this table.`;
}

const sentence = (text: string): string => `${text.charAt(0).toUpperCase()}${text.slice(1)}`;

function conditionsFor(proofs: readonly Proof[]): Condition[] {
  const out: Condition[] = [];
  const claims = (actor: Proof["actor"]): string[] => unique(proofs.filter((p) => p.actor === actor).map((p) => p.claims));
  for (const c of claims("anon")) {
    out.push({ kind: "authentication_level", description: `No sign-in: the request carries the public anon key (database role anon). request.jwt.claims: ${c}` });
  }
  if (claims("anon").length > 0) out.push({ kind: "authorization_role", description: "Database role anon; no elevated role such as service_role is used." });
  for (const c of claims("user-a")) {
    out.push({ kind: "authentication_level", description: `Signed in as an ordinary user (synthetic user A, alice@example.test): database role authenticated. request.jwt.claims: ${c}` });
  }
  if (claims("user-a").length > 0) out.push({ kind: "authorization_role", description: "Database role authenticated; no elevated role such as service_role is used. The rows that are attacked belong to synthetic user B (bob@example.test)." });
  if (proofs.some((p) => p.targetRows !== null)) out.push({ kind: "data_state", description: "Rows exist to attack: the tool seeded one row for each synthetic user." });
  return out;
}

const resultOf = (p: Proof): string => `${p.id} as ${p.role}: ${p.title}: ${p.reason}${p.observation.status === "error" ? ` (SQLSTATE ${p.observation.sqlstate}: ${truncateCodePoints(p.observation.message, 300)})` : ""}`;

function instructionsFor(proofs: readonly Proof[]): string[] {
  const steps = [
    "Create a throwaway PostgreSQL database with the Supabase roles (anon, authenticated, service_role) and auth.uid() reading request.jwt.claims, apply the migrations as a non-superuser, and insert one row for each of two synthetic users, A (alice@example.test) and B (bob@example.test). `proof-audit rls <migrations> --out <dir>` does this and records every probe in proofs.jsonl.",
  ];
  for (const actor of ["anon", "user-a"] as const) {
    const numbers = proofs.flatMap((p, i) => (p.actor === actor ? [i + 1] : []));
    if (numbers.length === 0) continue;
    const who = actor === "anon" ? "the anonymous caller (role anon)" : "user A (role authenticated)";
    steps.push(`In a transaction that you roll back afterwards, SET LOCAL ROLE and SET LOCAL request.jwt.claims as ${who}, using the role and claims in the conditions, then run payload ${numbers.join(", ")}.`);
  }
  steps.push("Replay the recorded probes with `proof-audit verify <dir>/proofs.jsonl`: it regenerates these statements from the migrations and compares the database's answers by content hash.");
  return steps;
}

function resolveInput(file: string, line: number, inputs: ExportInput["inputs"]): { readonly path: string } | null {
  if (file === "" || line < 1) return null;
  const hit = inputs.find((i) => (i.path === file || i.path.endsWith(`/${file}`) || file.endsWith(`/${i.path}`)) && line <= i.lines);
  return hit === undefined ? null : { path: hit.path };
}

interface Subject {
  readonly name: QualifiedName;
  readonly table: Table | undefined;
  readonly view: View | undefined;
  readonly owner: string | null;
}

function confirmed(input: ExportInput, finding: Finding, subject: Subject, cause: RootCause | null, proofs: readonly Proof[], located: Located, exploitsRun: number): ConfirmedRecord {
  const { report } = input;
  const kind: RootCauseKind = cause?.kind ?? "unattributed";
  const policy = cause?.policy?.name ?? null;
  const key = finding.subject;
  const { schema, name } = subject.name;
  const kinds = proofs.map((p) => p.kind);
  const section = report.fix === null ? null : fixSectionFor(report.fix.sql, key);
  const verified = finding.fixStatus === "verified";
  const owner = subject.owner ?? "the owner column";
  const anchor = located.anchor;
  const evidence: EvidenceItem[] = [
    { file: anchor.file, line: anchor.line, description: cause?.text ?? `The ${finding.subjectKind} the proven attacks ran against; no policy or setting the static reader found explains them.` },
    ...proofs.map((p) => ({ file: anchor.file, line: anchor.line, description: `Probe ${p.id} (recorded in proofs.jsonl, content hash sha256:${p.hash}): ${p.reason}` })),
  ];
  return {
    verdict: "confirmed",
    fingerprint: rlsFingerprint(schema, name, kind, policy),
    title: titleFor(kind, key, finding.subjectKind, policy),
    description: `${attackerSentence(key, kinds)} Reproduced against a throwaway PostgreSQL database: ${proofs.length} of the ${exploitsRun} attacks run on ${key} were let through (${unique(kinds).join(", ")}).`,
    root_cause: cause?.text ?? "The database let these attacks through, but the static reader found no policy or setting that explains it (possible causes: grants, rules, triggers, functions or SQL the reader could not read).",
    intended_behavior: intendedBehavior(subject.table, subject.owner),
    trace: [...located.trace],
    evidence,
    conditions: conditionsFor(proofs),
    execution: {
      attacker_perspective: attackerSentence(key, kinds),
      payloads: unique(proofs.map((p) => p.sql)),
      instructions: instructionsFor(proofs),
      observed_result: `${proofs.length} probe(s) were PROVEN_VULNERABLE: the database let the statement through.\n${proofs.map(resultOf).join("\n")}`,
    },
    remediation: {
      strategy: `${strategyFor(kind, key, policy, owner)} ${finding.fixNote}${section === null ? "" : ` The generated ${FIX_FILE} section for ${key} is attached as a starting point; review it before use.`}`,
      ...(section === null ? {} : { code_changes: [{ file_name: FIX_FILE, fixed_code: section }] }),
    },
    severity: severityFor(kinds, subject.owner !== null || subject.view !== undefined, finding.subjectKind),
    confidence: verified
      ? { score: "high", reason: `Reproduced against a real database (${proofs.length} probe(s) PROVEN_VULNERABLE) and the before/after check passed: ${finding.fixNote}` }
      : { score: "medium", reason: `Reproduced against a real database (${proofs.length} probe(s) PROVEN_VULNERABLE), but the proposed fix is not verified (${finding.fixStatus}): ${finding.fixNote}` },
  };
}

function needsValidation(report: AnalysisReport, finding: Finding, subject: Subject, cause: RootCause | null, located: Located, quarantined: boolean): NeedsValidationRecord {
  const key = finding.subject;
  const { schema, name } = subject.name;
  const kind: RootCauseKind = cause?.kind ?? "untested";
  const policy = cause?.policy?.name ?? null;
  const reasons = finding.inconclusive.map((i) => `${i.id}: ${i.reason}`);
  const violations = quarantined ? report.integrity.violations.slice(0, 5).map((v) => `${v.kind}: ${v.detail}${v.file === null ? "" : ` (${v.file}:${v.line ?? 0})`}`) : [];
  const blockers = unique([...reasons, ...violations]);
  const probes = unique(finding.inconclusive.filter((i) => i.id.startsWith(`${key}/`)).map((i) => i.id.slice(key.length + 1)));
  const attacks = probes.length > 0 ? ` (${probes.join(", ")})` : "";
  const local = quarantined
    ? `Review the statements listed in the blockers: they touch the platform objects that every verdict depends on. Remove them from a copy of the migrations and run \`proof-audit rls\` on the copy; until then the access control of ${key} is unverified.`
    : `Create ${key} in a local PostgreSQL or Supabase instance from the same migrations, insert one row for each of two test users, and run the blocked attacks${attacks} as the anon role and as a signed-in user (SET LOCAL ROLE and request.jwt.claims). Treat the finding as confirmed only if a statement returns or changes rows it should not; \`proof-audit rls\` does this once the blocker, such as a table that cannot be seeded, is removed.`;
  return {
    verdict: "needs_validation",
    fingerprint: rlsFingerprint(schema, name, kind, policy),
    title: `${titleFor(kind, key, finding.subjectKind, policy)} (not proven)`,
    description: finding.attackerCan,
    claimed_root_cause: cause?.text ?? "No root cause is claimed: nothing the static reader found explains unauthorized access, and the attacks could not all be run, so the access control of this object is unverified.",
    trace: [...located.trace],
    evidence: [{ file: located.anchor.file, line: located.anchor.line, description: cause?.text ?? `The ${finding.subjectKind} that could not be fully tested.` }],
    blockers: blockers.length > 0 ? blockers : ["No exploit probe produced a clear answer for this object."],
    validation_plan: { local },
  };
}

function rejected(input: ExportInput, c: CorrelatedAuditFinding, parsed: ParsedAuditFinding | undefined, located: Located, subject: { table: string; policy: string | null }): RejectedRecord {
  const { report, audit, inputs } = input;
  const source = `${audit?.tool ?? c.rule}${audit?.version ? ` ${audit.version}` : ""}`;
  const flagged = resolveInput(c.file, c.line, inputs);
  const message = parsed !== undefined && hasVisible(parsed.message) ? parsed.message : null;
  const title = hasVisible(c.title) ? c.title : `Static finding ${c.rule} (no readable title)`;
  const detail = message === null ? "" : ` ${truncateCodePoints(message, 500)}`;
  const evidence: EvidenceItem[] = [
    { file: located.anchor.file, line: located.anchor.line, description: `The statement behind the static finding ${c.rule} (${c.severity}) reported at ${c.file === "" ? "an unknown file" : `${c.file}:${c.line}`}.` },
    ...(flagged === null || (flagged.path === located.anchor.file && c.line === located.anchor.line) ? [] : [{ file: flagged.path, line: c.line, description: `The position the static auditor flagged for ${c.rule}.` }]),
    ...c.proofIds.flatMap((id) => {
      const p = report.proofs.find((x) => x.id === id && x.phase === "before");
      return p === undefined ? [] : [{ file: located.anchor.file, line: located.anchor.line, description: `Probe ${p.id} (recorded in proofs.jsonl, content hash sha256:${p.hash}): ${p.reason}` }];
    }),
  ];
  return {
    verdict: "rejected",
    fingerprint: staticFingerprint(c.rule, c.file, subject.table, subject.policy),
    title,
    description: message ?? title,
    claimed_root_cause: `The static auditor (${source}, rule ${c.rule}) claimed: ${title}.${detail}`,
    trace: [...located.trace],
    evidence,
    reason: `${sentence(c.note)}. A refusal for two synthetic users and an anonymous caller refutes the attacks that were run; it does not show that the table is safe.`,
  };
}

/**
 * All the records of one run. A table or view whose declaration cannot be found in the migrations has no record
 * (it is listed in `omitted`): a record without a real line in the SQL would be worse than none.
 */
export function buildRecords(input: ExportInput): ExportResult {
  const { report, source } = input;
  const records: FindingRecord[] = [];
  const omitted: Omitted[] = [];
  const quarantined = report.integrity.status === "INTEGRITY_VIOLATION";

  for (const finding of report.findings) {
    if (finding.tier === "CLEAN") continue;
    const key = finding.subject;
    const table = report.model.tables.find((t) => qualifiedKey(t.name) === key);
    const view = table === undefined ? report.model.views.find((v) => qualifiedKey(v.name) === key) : undefined;
    if (table === undefined && view === undefined) {
      omitted.push({ subject: key, reason: "the schema model has no such table or view" });
      continue;
    }
    const causes = table !== undefined ? tableRootCauses(table) : viewRootCauses(view as View, report.model);
    const subject: Subject = { name: (table ?? (view as View)).name, table, view, owner: table === undefined ? null : (primaryOwnerColumn(table)?.column ?? null) };
    const locate = (cause: RootCause | null, untested: boolean): Located | null =>
      table !== undefined ? locateTableCause(source, table, cause, untested) : locateViewCause(source, view as View, report.model, cause, untested);

    if (finding.tier === "PROVEN") {
      const exploits = report.proofs.filter((p) => p.subject === key && p.phase === "before" && p.intent === "exploit");
      const proven = exploits.filter((p) => p.verdict === "PROVEN_VULNERABLE");
      for (const group of groupByRootCause(proven, causes)) {
        const located = locate(group.cause, false);
        if (located === null) omitted.push({ subject: key, reason: "no statement of the migrations declares it, so there is no line to point at" });
        else records.push(confirmed(input, finding, subject, group.cause, group.proofs, located, exploits.filter((p) => p.observation.status !== "not-run").length));
      }
      continue;
    }
    const wanted = quarantined ? [] : causes.filter((c) => c.suspicious);
    for (const cause of wanted.length === 0 ? [null] : wanted) {
      const located = locate(cause, cause === null);
      if (located === null) omitted.push({ subject: key, reason: "no statement of the migrations declares it, so there is no line to point at" });
      else records.push(needsValidation(report, finding, subject, cause, located, quarantined));
    }
  }

  const parsedBy = new Map((input.audit?.findings ?? []).map((f) => [`${f.rule}\u0000${f.file}\u0000${f.line}\u0000${f.title}`, f] as const));
  const seen = new Map<string, number>();
  for (const c of report.audit?.findings ?? []) {
    if (c.proofStatus !== "NOT_REPRODUCED") continue;
    const parsed = parsedBy.get(`${c.rule}\u0000${c.file}\u0000${c.line}\u0000${c.title}`);
    const named = parsed === undefined ? { table: c.table, policy: policyFromTitle(c.title) } : staticSubject(parsed);
    const label = `${c.rule} ${c.file}:${c.line}`;
    if (named.table === null) {
      omitted.push({ subject: label, reason: "the static finding does not name a table" });
      continue;
    }
    const located = locateStatic(source, named.table, named.policy, `The statement the static auditor flagged (${c.rule}).`);
    if (located === null) {
      omitted.push({ subject: label, reason: "no statement of the migrations declares its table, so there is no line to point at" });
      continue;
    }
    const record = rejected(input, c, parsed, located, { table: named.table, policy: named.policy });
    const n = (seen.get(record.fingerprint) ?? 0) + 1;
    seen.set(record.fingerprint, n);
    records.push(n === 1 ? record : { ...record, fingerprint: `${record.fingerprint}:@${n}` });
  }
  return { records, omitted };
}
