import { SEVERITY_RANK, type AuditCorrelation, type AuditProofStatus, type CorrelatedAuditFinding, type Finding, type Severity } from "../analysis/types.js";
import type { ProbeKind, Proof } from "../proof/types.js";
import { auditPriorityTables, isRlsRule, type ParsedAudit, type ParsedAuditFinding } from "./import.js";

export const STATIC_AUDITOR = "saas-audit";

export interface CorrelationInput {
  readonly findings: readonly Finding[];
  /** Probe results of the `before` phase. Other phases are ignored. */
  readonly proofs: readonly Proof[];
  /** Qualified names of every table and view that was analysed. */
  readonly subjects: readonly string[];
  /** True when the run's integrity is in doubt (the migrations touched the test environment): no probe result may then refute a static finding. */
  readonly untrusted?: boolean;
}

interface Outcome {
  readonly proofStatus: AuditProofStatus;
  readonly proofIds: readonly string[];
  readonly note: string;
}

// ---- which probes a static finding is about ------------------------------------------------------

/** `"all"`: every exploit probe of the table. A set: only those kinds. `null`: the finding does not say, use the table verdict. */
export type Relevance = "all" | ReadonlySet<ProbeKind> | null;

type Cmd = "select" | "insert" | "update" | "delete";

const KINDS_BY_COMMAND: Readonly<Record<Cmd, { readonly anon: readonly ProbeKind[]; readonly signedIn: readonly ProbeKind[] }>> = {
  select: { anon: ["anon-read", "view-read-anon"], signedIn: ["cross-read", "view-read-cross"] },
  insert: { anon: ["anon-insert"], signedIn: ["cross-insert", "null-owner-insert"] },
  update: { anon: ["anon-update"], signedIn: ["cross-update", "reassign-owner"] },
  delete: { anon: ["anon-delete"], signedIn: ["cross-delete"] },
};

const ALL_COMMANDS: readonly Cmd[] = ["select", "insert", "update", "delete"];

const TENANT_KINDS: readonly ProbeKind[] = ["cross-read", "cross-insert", "cross-update", "cross-delete", "reassign-owner"];

/** The verb the auditor prints in a policy title, as the commands it covers. */
const COMMANDS_BY_VERB: Readonly<Record<string, readonly Cmd[]>> = {
  read: ["select"],
  select: ["select"],
  insert: ["insert"],
  update: ["update"],
  delete: ["delete"],
  "read and write": ALL_COMMANDS,
  "write to": ALL_COMMANDS,
  write: ALL_COMMANDS,
  use: ALL_COMMANDS,
  all: ALL_COMMANDS,
};

const VERBS = "read and write|write to|read|select|insert|update|delete|write|use|all";
/** `Policy "<name>" lets <roles> <verb> every row of <table>` */
const LETS_SHAPE = new RegExp(`^Policy ".*" lets (.+?) (${VERBS}) every row of `, "s");
/** `Policy "<name>" allows the anon role to <verb> <table>` */
const ANON_SHAPE = new RegExp(`^Policy ".*" allows the anon role to (${VERBS}) `, "s");

function kindsFor(commands: readonly Cmd[], anon: boolean, signedIn: boolean): Set<ProbeKind> {
  const kinds = new Set<ProbeKind>();
  for (const cmd of commands) {
    if (anon) for (const k of KINDS_BY_COMMAND[cmd].anon) kinds.add(k);
    if (signedIn) for (const k of KINDS_BY_COMMAND[cmd].signedIn) kinds.add(k);
  }
  return kinds;
}

/**
 * The probes that can confirm or deny one static finding, read from its rule and the way the auditor
 * words its title. A policy that names the anon role is about the anonymous probes; one that does not is
 * about a signed-in user reaching other users' rows. Policies for both roles are about both.
 */
export function relevantProbes(rule: string, title: string): Relevance {
  if (rule === "supabase-rls-missing") return "all";
  if (rule === "supabase-tenant-unscoped") return new Set(TENANT_KINDS);
  if (rule !== "supabase-policy-permissive") return null;

  const lets = LETS_SHAPE.exec(title);
  if (lets?.[1] !== undefined && lets[2] !== undefined) {
    const roles = lets[1];
    const anon = /\b(?:anon|public)\b/.test(roles);
    const signedIn = !anon || /\bauthenticated\b/.test(roles);
    return kindsFor(COMMANDS_BY_VERB[lets[2]] ?? [], anon, signedIn);
  }
  const writes = ANON_SHAPE.exec(title);
  if (writes?.[1] !== undefined) return kindsFor(COMMANDS_BY_VERB[writes[1]] ?? [], true, false);
  return null;
}

// ---- outcomes -----------------------------------------------------------------------------------

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Sorted, de-duplicated. */
function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compare);
}

/** The probe kinds behind a list of proof ids, each named once, sorted. */
function probeKinds(ids: readonly string[], proofs: readonly Proof[]): string[] {
  const kindById = new Map<string, string>();
  for (const proof of proofs) if (!kindById.has(proof.id)) kindById.set(proof.id, proof.kind);
  return unique(ids.map((id) => kindById.get(id) ?? id.slice(id.lastIndexOf("/") + 1)));
}

/** What the table-level verdict says, for findings that do not name the attacks they are about. */
function tableOutcome(finding: Finding | undefined, proofs: readonly Proof[]): Outcome {
  if (finding === undefined) {
    return { proofStatus: "INCONCLUSIVE", proofIds: [], note: "could not be proven either way: no result was recorded for this table" };
  }
  switch (finding.tier) {
    case "PROVEN":
      return {
        proofStatus: "PROVEN",
        proofIds: unique(finding.provenBy),
        note: `reproduced against the throwaway database: ${probeKinds(finding.provenBy, proofs).join(", ")}`,
      };
    case "CLEAN":
      return {
        proofStatus: "NOT_REPRODUCED",
        proofIds: unique(finding.notReproduced),
        note: "the static pattern exists but the database denied every attack; likely a false positive or covered by grants/roles",
      };
    case "SUSPECTED":
    case "INCONCLUSIVE": {
      const first = finding.inconclusive[0];
      return {
        proofStatus: "INCONCLUSIVE",
        proofIds: unique(finding.inconclusive.map((i) => i.id)),
        note: `could not be proven either way: ${first?.reason ?? "no probe gave a clear answer"}`,
      };
    }
  }
}

/** The verdict of exactly the probes a finding is about; attacks on the same table that are not about it only get a mention. */
function scopedOutcome(relevance: "all" | ReadonlySet<ProbeKind>, tableProofs: readonly Proof[]): Outcome {
  const relevant = tableProofs.filter((p) => relevance === "all" || relevance.has(p.kind));
  const otherProven = tableProofs.filter((p) => !relevant.includes(p) && p.verdict === "PROVEN_VULNERABLE");
  const otherNote = otherProven.length > 0 ? `; other attacks on this table were proven: ${unique(otherProven.map((p) => p.kind)).join(", ")}` : "";

  const proven = relevant.filter((p) => p.verdict === "PROVEN_VULNERABLE");
  if (proven.length > 0) {
    return {
      proofStatus: "PROVEN",
      proofIds: unique(proven.map((p) => p.id)),
      note: `reproduced against the throwaway database: ${unique(proven.map((p) => p.kind)).join(", ")}`,
    };
  }
  if (relevant.length === 0) {
    return { proofStatus: "INCONCLUSIVE", proofIds: [], note: `could not be proven either way: no probe this finding is about was run${otherNote}` };
  }
  const unclear = relevant.filter((p) => p.verdict !== "NOT_REPRODUCED");
  const first = unclear[0];
  if (first !== undefined) {
    return { proofStatus: "INCONCLUSIVE", proofIds: unique(unclear.map((p) => p.id)), note: `could not be proven either way: ${first.reason}${otherNote}` };
  }
  return {
    proofStatus: "NOT_REPRODUCED",
    proofIds: unique(relevant.map((p) => p.id)),
    note: `the database denied every attack this finding describes (${unique(relevant.map((p) => p.kind)).join(", ")}); likely a false positive or covered by grants/roles${otherNote}`,
  };
}

interface Tables {
  readonly analysed: ReadonlySet<string>;
  readonly finding: ReadonlyMap<string, Finding>;
  /** Exploit probes of the `before` phase, in the order given. */
  readonly exploits: ReadonlyMap<string, readonly Proof[]>;
  readonly proofs: readonly Proof[];
  readonly untrusted: boolean;
}

function outcomeFor(f: ParsedAuditFinding, tables: Tables): Outcome {
  const table = f.table;
  if (table === null) {
    return { proofStatus: "STATIC_ONLY", proofIds: [], note: "the static finding does not name a table, so there was nothing to test" };
  }
  if (!tables.analysed.has(table)) {
    return { proofStatus: "STATIC_ONLY", proofIds: [], note: "table not found in the analysed migrations" };
  }
  if (tables.untrusted) {
    return { proofStatus: "INCONCLUSIVE", proofIds: [], note: "could not be proven either way: the migrations touched the test environment the results depend on, so no probe result of this run can be trusted" };
  }
  const relevance = relevantProbes(f.rule, f.title);
  const tableProofs = tables.exploits.get(table) ?? [];
  if (relevance === null || tableProofs.length === 0) return tableOutcome(tables.finding.get(table), tables.proofs);
  return scopedOutcome(relevance, tableProofs);
}

function severityRank(severity: string): number {
  return Object.hasOwn(SEVERITY_RANK, severity) ? SEVERITY_RANK[severity as Severity] : 0;
}

function order(a: CorrelatedAuditFinding, b: CorrelatedAuditFinding): number {
  return severityRank(b.severity) - severityRank(a.severity) || compare(a.file, b.file) || a.line - b.line || compare(a.rule, b.rule) || compare(a.title, b.title);
}

/**
 * Put every row level security finding of a static report next to what the database showed. A finding
 * is judged by the probes it is about (see `relevantProbes`): proven when one of them got through,
 * not reproduced when all were denied, undecided otherwise. Findings that do not say what they are
 * about take the verdict of the whole table. Findings of other families only add to `outOfScope`.
 */
export function correlateAudit(audit: ParsedAudit, results: CorrelationInput): AuditCorrelation {
  const finding = new Map<string, Finding>();
  for (const f of results.findings) if (!finding.has(f.subject)) finding.set(f.subject, f);

  const before = results.proofs.filter((p) => p.phase === "before");
  const exploits = new Map<string, Proof[]>();
  for (const proof of before) {
    if (proof.intent !== "exploit") continue;
    const list = exploits.get(proof.subject) ?? [];
    list.push(proof);
    exploits.set(proof.subject, list);
  }
  const tables: Tables = { analysed: new Set(results.subjects), finding, exploits, proofs: before, untrusted: results.untrusted === true };

  const inScope: ParsedAuditFinding[] = audit.findings.filter((f) => isRlsRule(f.rule));
  const correlated: CorrelatedAuditFinding[] = inScope.map((f) => ({
    rule: f.rule,
    severity: f.severity,
    file: f.file,
    line: f.line,
    title: f.title,
    table: f.table,
    ...outcomeFor(f, tables),
  }));
  correlated.sort(order);

  return {
    sourceTool: audit.tool,
    sourceVersion: audit.version,
    project: audit.project,
    findings: correlated,
    priorityTables: auditPriorityTables(audit),
    outOfScope: Math.max(0, audit.totalFindings - inScope.length),
    warnings: audit.tool === STATIC_AUDITOR ? [] : [`the report names its tool as a different auditor than ${STATIC_AUDITOR}; titles were read on a best-effort basis`],
  };
}
