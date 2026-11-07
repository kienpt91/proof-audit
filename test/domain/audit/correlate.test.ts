import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Finding, Tier } from "../../../src/domain/analysis/types.js";
import { correlateAudit, relevantProbes } from "../../../src/domain/audit/correlate.js";
import { parseAuditReport, type ParsedAudit, type ParsedAuditFinding } from "../../../src/domain/audit/import.js";
import { sealProof } from "../../../src/domain/proof/hash.js";
import type { ProbeKind, Proof, Verdict } from "../../../src/domain/proof/types.js";

function staticFinding(over: Partial<ParsedAuditFinding> = {}): ParsedAuditFinding {
  return { rule: "supabase-rls-missing", severity: "high", file: "m.sql", line: 1, title: "t", message: "", table: "public.notes", subject: null, ...over };
}

function audit(findings: readonly ParsedAuditFinding[], over: Partial<ParsedAudit> = {}): ParsedAudit {
  return { tool: "saas-audit", version: "0.1.0", project: "app", findings, totalFindings: findings.length, ...over };
}

function proof(subject: string, kind: ProbeKind): Proof {
  return sealProof({
    id: `${subject}/${kind}`,
    subject,
    subjectKind: "table",
    kind,
    intent: "exploit",
    command: "select",
    actor: "anon",
    role: "anon",
    claims: "{}",
    sql: "select 1",
    title: "t",
    targetRows: 1,
    observation: { status: "rows", rows: 1 },
    verdict: "PROVEN_VULNERABLE",
    reason: "r",
    phase: "before",
  });
}

function tableFinding(subject: string, tier: Tier, over: Partial<Finding> = {}): Finding {
  return {
    id: `rls:${subject}`,
    subject,
    subjectKind: "table",
    tier,
    severity: "high",
    title: "t",
    attackerCan: "a",
    causes: [],
    provenBy: [],
    notReproduced: [],
    inconclusive: [],
    fixStatus: "unverified",
    fixNote: "",
    ...over,
  };
}

describe("correlateAudit: status per static finding", () => {
  it("is PROVEN with the proving probes when the table finding is PROVEN", () => {
    const finding = tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read", "public.notes/cross-update"] });
    const result = correlateAudit(audit([staticFinding()]), {
      findings: [finding],
      proofs: [proof("public.notes", "anon-read"), proof("public.notes", "cross-update")],
      subjects: ["public.notes"],
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      table: "public.notes",
      proofStatus: "PROVEN",
      proofIds: ["public.notes/anon-read", "public.notes/cross-update"],
    });
    expect(result.findings[0]?.note).toContain("anon-read, cross-update");
  });

  it("names each probe kind once in the proven note", () => {
    const finding = tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read", "public.notes/anon-read"] });
    const result = correlateAudit(audit([staticFinding()]), { findings: [finding], proofs: [proof("public.notes", "anon-read")], subjects: ["public.notes"] });
    expect(result.findings[0]?.note.match(/anon-read/g)).toHaveLength(1);
  });

  it("takes the probe kind from the id when the proof is not among the given proofs", () => {
    const finding = tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-delete"] });
    const result = correlateAudit(audit([staticFinding()]), { findings: [finding], proofs: [], subjects: ["public.notes"] });
    expect(result.findings[0]?.note).toContain("anon-delete");
  });

  it("takes the verdict of the table for a policy finding whose title does not say what it is about", () => {
    const finding = tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/cross-read"] });
    const result = correlateAudit(audit([staticFinding({ rule: "supabase-policy-permissive" })]), {
      findings: [finding],
      proofs: [proof("public.notes", "cross-read")],
      subjects: ["public.notes"],
    });
    expect(result.findings[0]?.proofStatus).toBe("PROVEN");
  });

  it("is NOT_REPRODUCED with the denied probes when the table finding is CLEAN", () => {
    const finding = tableFinding("public.notes", "CLEAN", { notReproduced: ["public.notes/anon-read", "public.notes/anon-insert"] });
    const result = correlateAudit(audit([staticFinding()]), { findings: [finding], proofs: [], subjects: ["public.notes"] });
    expect(result.findings[0]).toMatchObject({ proofStatus: "NOT_REPRODUCED", proofIds: ["public.notes/anon-insert", "public.notes/anon-read"] });
    expect(result.findings[0]?.note).toBe(
      "the static pattern exists but the database denied every attack; likely a false positive or covered by grants/roles",
    );
  });

  it.each<Tier>(["SUSPECTED", "INCONCLUSIVE"])("is INCONCLUSIVE with the first reason when the table finding is %s", (tier) => {
    const finding = tableFinding("public.notes", tier, {
      inconclusive: [
        { id: "public.notes/anon-update", reason: "no seeded rows to target" },
        { id: "public.notes/cross-read", reason: "second reason" },
      ],
    });
    const result = correlateAudit(audit([staticFinding()]), { findings: [finding], proofs: [], subjects: ["public.notes"] });
    expect(result.findings[0]).toMatchObject({ proofStatus: "INCONCLUSIVE", proofIds: ["public.notes/anon-update", "public.notes/cross-read"] });
    expect(result.findings[0]?.note).toBe("could not be proven either way: no seeded rows to target");
  });

  it("is INCONCLUSIVE with a generic note when nothing was recorded as inconclusive", () => {
    const result = correlateAudit(audit([staticFinding()]), { findings: [tableFinding("public.notes", "SUSPECTED")], proofs: [], subjects: ["public.notes"] });
    expect(result.findings[0]).toMatchObject({ proofStatus: "INCONCLUSIVE", proofIds: [] });
    expect(result.findings[0]?.note).toContain("no probe gave a clear answer");
  });

  it("is INCONCLUSIVE when the table was analysed but has no finding", () => {
    const result = correlateAudit(audit([staticFinding()]), { findings: [], proofs: [], subjects: ["public.notes"] });
    expect(result.findings[0]?.proofStatus).toBe("INCONCLUSIVE");
  });

  it("is STATIC_ONLY when the table is not among the analysed subjects", () => {
    const result = correlateAudit(audit([staticFinding({ table: "public.ghost" })]), {
      findings: [tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read"] })],
      proofs: [],
      subjects: ["public.notes"],
    });
    expect(result.findings[0]).toMatchObject({ proofStatus: "STATIC_ONLY", proofIds: [], note: "table not found in the analysed migrations" });
  });

  it("does not treat a table of another schema as the same table", () => {
    const result = correlateAudit(audit([staticFinding({ table: "app.notes" })]), {
      findings: [tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read"] })],
      proofs: [],
      subjects: ["public.notes"],
    });
    expect(result.findings[0]?.proofStatus).toBe("STATIC_ONLY");
  });

  it("is STATIC_ONLY when the static finding names no table", () => {
    const result = correlateAudit(audit([staticFinding({ table: null, rule: "supabase-policy-permissive" })]), {
      findings: [tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read"] })],
      proofs: [],
      subjects: ["public.notes"],
    });
    expect(result.findings[0]).toMatchObject({ proofStatus: "STATIC_ONLY", table: null });
  });

  it("gives every static finding on one table the table's status", () => {
    const finding = tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read"] });
    const result = correlateAudit(
      audit([staticFinding(), staticFinding({ rule: "supabase-tenant-unscoped", line: 9 }), staticFinding({ rule: "supabase-policy-permissive", line: 12 })]),
      { findings: [finding], proofs: [], subjects: ["public.notes"] },
    );
    expect(result.findings.map((f) => f.proofStatus)).toEqual(["PROVEN", "PROVEN", "PROVEN"]);
  });
});

describe("correlateAudit: scope, metadata, ordering", () => {
  const empty = { findings: [], proofs: [], subjects: [] };

  it("counts findings that are not row level security only as out of scope", () => {
    const parsed = audit([staticFinding()], { totalFindings: 7 });
    const result = correlateAudit(parsed, empty);
    expect(result.findings).toHaveLength(1);
    expect(result.outOfScope).toBe(6);
  });

  it("drops a non-row-level-security finding that was handed in with the others", () => {
    const parsed = audit([staticFinding(), staticFinding({ rule: "secret-hardcoded", table: "public.notes" })]);
    const result = correlateAudit(parsed, empty);
    expect(result.findings.map((f) => f.rule)).toEqual(["supabase-rls-missing"]);
    expect(result.outOfScope).toBe(1);
  });

  it("reports source, version, project and the priority tables", () => {
    const parsed = audit([staticFinding({ table: "public.a", severity: "medium" }), staticFinding({ table: "public.b", severity: "critical" })], { project: "shop", version: "2.0.0" });
    const result = correlateAudit(parsed, empty);
    expect(result).toMatchObject({ sourceTool: "saas-audit", sourceVersion: "2.0.0", project: "shop", priorityTables: ["public.b", "public.a"], warnings: [] });
  });

  it("warns when the report came from another tool", () => {
    const result = correlateAudit(audit([], { tool: "other", version: null }), empty);
    expect(result.sourceTool).toBe("other");
    expect(result.sourceVersion).toBeNull();
    expect(result.warnings).toHaveLength(1);
  });

  it("orders by severity, then file, line, rule", () => {
    const parsed = audit([
      staticFinding({ severity: "medium", file: "a.sql", line: 1 }),
      staticFinding({ severity: "critical", file: "z.sql", line: 1 }),
      staticFinding({ severity: "high", file: "b.sql", line: 20, rule: "supabase-policy-missing" }),
      staticFinding({ severity: "high", file: "b.sql", line: 3, rule: "supabase-tenant-unscoped" }),
      staticFinding({ severity: "high", file: "b.sql", line: 3, rule: "supabase-policy-permissive" }),
      staticFinding({ severity: "high", file: "a.sql", line: 99 }),
    ]);
    const result = correlateAudit(parsed, empty);
    expect(result.findings.map((f) => [f.severity, f.file, f.line, f.rule])).toEqual([
      ["critical", "z.sql", 1, "supabase-rls-missing"],
      ["high", "a.sql", 99, "supabase-rls-missing"],
      ["high", "b.sql", 3, "supabase-policy-permissive"],
      ["high", "b.sql", 3, "supabase-tenant-unscoped"],
      ["high", "b.sql", 20, "supabase-policy-missing"],
      ["medium", "a.sql", 1, "supabase-rls-missing"],
    ]);
  });

  it("gives the same output for any input order", () => {
    const items = [
      staticFinding({ severity: "low", file: "c.sql", line: 2, table: "public.c" }),
      staticFinding({ severity: "high", file: "a.sql", line: 2, table: "public.a" }),
      staticFinding({ severity: "high", file: "a.sql", line: 2, table: "public.b", title: "other" }),
      staticFinding({ severity: "info", file: "a.sql", line: 1, table: null }),
    ];
    const results = { findings: [tableFinding("public.a", "CLEAN")], proofs: [], subjects: ["public.a", "public.b"] };
    const forward = correlateAudit(audit(items), results);
    const backward = correlateAudit(audit([...items].reverse()), results);
    expect(backward.findings).toEqual(forward.findings);
    expect(JSON.stringify(correlateAudit(audit(items), results))).toBe(JSON.stringify(forward));
  });

  it("does not modify its inputs", () => {
    const items = [staticFinding({ severity: "low" }), staticFinding({ severity: "critical" })];
    const parsed = audit(items);
    const before = JSON.stringify(parsed);
    correlateAudit(parsed, empty);
    expect(JSON.stringify(parsed)).toBe(before);
  });

  it("treats a severity outside the known set as the lowest rank", () => {
    const parsed = audit([staticFinding({ severity: "weird" as "high", line: 1 }), staticFinding({ severity: "low", line: 2 })]);
    const result = correlateAudit(parsed, empty);
    expect(result.findings.map((f) => f.line)).toEqual([2, 1]);
  });
});

describe("relevantProbes", () => {
  const kinds = (rule: string, title: string): string[] | "all" | null => {
    const r = relevantProbes(rule, title);
    return r === null || r === "all" ? r : [...r].sort();
  };

  it("covers every exploit probe for a table without row level security", () => {
    expect(kinds("supabase-rls-missing", "Table public.notes has no row level security")).toBe("all");
  });

  it("is about cross-user probes for an unscoped tenant column", () => {
    expect(kinds("supabase-tenant-unscoped", "No policy on notes ties user_id to the caller")).toEqual(["cross-delete", "cross-insert", "cross-read", "cross-update", "reassign-owner"]);
  });

  it.each([
    ['Policy "p" lets every role including anon read every row of notes', ["anon-read", "view-read-anon"]],
    ['Policy "p" lets anon read every row of notes', ["anon-read", "view-read-anon"]],
    ['Policy "p" lets authenticated read every row of notes', ["cross-read", "view-read-cross"]],
    ['Policy "p" lets authenticated insert every row of notes', ["cross-insert", "null-owner-insert"]],
    ['Policy "p" lets authenticated update every row of notes', ["cross-update", "reassign-owner"]],
    ['Policy "p" lets authenticated delete every row of notes', ["cross-delete"]],
    ['Policy "p" lets anon insert every row of notes', ["anon-insert"]],
    ['Policy "p" lets anon update every row of notes', ["anon-update"]],
    ['Policy "p" lets anon delete every row of notes', ["anon-delete"]],
    ['Policy "p" allows the anon role to insert notes', ["anon-insert"]],
    ['Policy "p" allows the anon role to update notes', ["anon-update"]],
    ['Policy "p" allows the anon role to delete notes', ["anon-delete"]],
    ['Policy "p" lets authenticated, anon update every row of notes', ["anon-update", "cross-update", "reassign-owner"]],
  ])("%s", (title, expected) => {
    expect(kinds("supabase-policy-permissive", title)).toEqual(expected);
  });

  it.each([
    'Policy "p" lets every role including anon read and write every row of notes',
    'Policy "p" lets anon use every row of notes',
    'Policy "p" allows the anon role to write to notes',
    'Policy "p" allows the anon role to all notes',
  ])("treats %s as every command", (title) => {
    const r = relevantProbes("supabase-policy-permissive", title);
    expect(r).not.toBeNull();
    expect(r === null || r === "all" ? [] : [...r]).toEqual(expect.arrayContaining(["anon-read", "anon-insert", "anon-update", "anon-delete"]));
  });

  it("does not add signed-in probes to an anon-only title", () => {
    const r = relevantProbes("supabase-policy-permissive", 'Policy "p" lets every role including anon read and write every row of notes');
    expect(r === null || r === "all" ? [] : [...r].filter((k) => k.startsWith("cross-") || k === "reassign-owner" || k === "null-owner-insert")).toEqual([]);
  });

  it("reads the table-side words after the last quote, not words inside the policy name", () => {
    expect(kinds("supabase-policy-permissive", 'Policy "lets anon read every row of x" lets authenticated update every row of notes')).toEqual(["cross-update", "reassign-owner"]);
  });

  it.each([
    ["supabase-policy-missing", "Table public.notes has row level security but no policies"],
    ["supabase-policy-permissive", 'Policy "p" is nested too deeply to analyse'],
    ["supabase-policy-permissive", ""],
    ["supabase-future-rule", 'Policy "p" lets anon read every row of notes'],
  ])("says nothing specific for %s / %j", (rule, title) => {
    expect(relevantProbes(rule, title)).toBeNull();
  });
});

describe("correlateAudit: judged by the probes a finding is about", () => {
  function p(subject: string, kind: ProbeKind, verdict: Verdict, over: Partial<Omit<Proof, "hash">> = {}): Proof {
    const { hash: _hash, ...base } = proof(subject, kind);
    return sealProof({
      ...base,
      verdict,
      observation: verdict === "PROVEN_VULNERABLE" ? { status: "rows", rows: 1 } : { status: "error", sqlstate: "42501", message: "denied" },
      reason: `${kind} was ${verdict}`,
      ...over,
    });
  }
  const T = "public.documents";
  const policy = (title: string, rule = "supabase-policy-permissive", over: Partial<ParsedAuditFinding> = {}): ParsedAuditFinding =>
    staticFinding({ table: T, rule, title, ...over });
  const run = (findings: readonly ParsedAuditFinding[], proofs: readonly Proof[], tier: Tier = "PROVEN") =>
    correlateAudit(audit(findings), { findings: [tableFinding(T, tier)], proofs, subjects: [T] }).findings;

  it("does not call an update policy proven because an insert got through", () => {
    const proofs = [p(T, "cross-insert", "PROVEN_VULNERABLE"), p(T, "cross-update", "NOT_REPRODUCED"), p(T, "reassign-owner", "NOT_REPRODUCED"), p(T, "cross-read", "NOT_REPRODUCED")];
    const [only] = run([policy('Policy "Owners can edit documents" lets authenticated update every row of documents')], proofs);
    expect(only).toMatchObject({ proofStatus: "NOT_REPRODUCED", proofIds: [`${T}/cross-update`, `${T}/reassign-owner`] });
    expect(only?.note).toContain("cross-update, reassign-owner");
    expect(only?.note).toContain("other attacks on this table were proven: cross-insert");
  });

  it("omits the other-attacks remark when nothing else was proven", () => {
    const proofs = [p(T, "cross-update", "NOT_REPRODUCED"), p(T, "reassign-owner", "NOT_REPRODUCED"), p(T, "cross-read", "NOT_REPRODUCED")];
    const [only] = run([policy('Policy "p" lets authenticated update every row of documents')], proofs, "CLEAN");
    expect(only?.proofStatus).toBe("NOT_REPRODUCED");
    expect(only?.note).not.toContain("other attacks");
  });

  it("names every other proven kind once, sorted", () => {
    const proofs = [p(T, "cross-update", "NOT_REPRODUCED"), p(T, "cross-read", "PROVEN_VULNERABLE"), p(T, "anon-read", "PROVEN_VULNERABLE"), p(T, "cross-insert", "PROVEN_VULNERABLE")];
    const [only] = run([policy('Policy "p" lets authenticated update every row of documents')], proofs);
    expect(only?.note).toContain("other attacks on this table were proven: anon-read, cross-insert, cross-read");
  });

  it("proves the finding with only the relevant probes as proof ids", () => {
    const proofs = [p(T, "cross-update", "PROVEN_VULNERABLE"), p(T, "reassign-owner", "NOT_REPRODUCED"), p(T, "cross-read", "PROVEN_VULNERABLE"), p(T, "anon-update", "PROVEN_VULNERABLE")];
    const [only] = run([policy('Policy "p" lets authenticated update every row of documents')], proofs);
    expect(only).toMatchObject({ proofStatus: "PROVEN", proofIds: [`${T}/cross-update`] });
    expect(only?.note).toBe("reproduced against the throwaway database: cross-update");
  });

  it("singles out the anonymous probes when the title names anon", () => {
    const title = 'Policy "p" lets every role including anon read every row of documents';
    expect(run([policy(title)], [p(T, "anon-read", "NOT_REPRODUCED"), p(T, "cross-read", "PROVEN_VULNERABLE")])[0]?.proofStatus).toBe("NOT_REPRODUCED");
    const proven = run([policy(title)], [p(T, "anon-read", "PROVEN_VULNERABLE"), p(T, "cross-read", "PROVEN_VULNERABLE")])[0];
    expect(proven).toMatchObject({ proofStatus: "PROVEN", proofIds: [`${T}/anon-read`] });
  });

  it("treats a read-and-write policy as every command and a write-to policy for anon as every anon command", () => {
    const proofs = [p(T, "anon-read", "NOT_REPRODUCED"), p(T, "anon-delete", "PROVEN_VULNERABLE")];
    expect(run([policy('Policy "p" lets every role including anon read and write every row of documents')], proofs)[0]).toMatchObject({ proofStatus: "PROVEN", proofIds: [`${T}/anon-delete`] });
    expect(run([policy('Policy "p" allows the anon role to write to documents', "supabase-policy-permissive")], proofs)[0]?.proofStatus).toBe("PROVEN");
  });

  it("does not let a signed-in insert prove an anon-only insert policy", () => {
    const proofs = [p(T, "anon-insert", "NOT_REPRODUCED"), p(T, "cross-insert", "PROVEN_VULNERABLE"), p(T, "null-owner-insert", "PROVEN_VULNERABLE")];
    const [only] = run([policy('Policy "p" allows the anon role to insert documents')], proofs);
    expect(only?.proofStatus).toBe("NOT_REPRODUCED");
    expect(only?.note).toContain("other attacks on this table were proven: cross-insert, null-owner-insert");
  });

  it("judges a tenant-unscoped finding by the cross-user probes only", () => {
    const finding = staticFinding({ table: T, rule: "supabase-tenant-unscoped", title: "No policy on documents ties owner_id to the caller" });
    expect(run([finding], [p(T, "anon-read", "PROVEN_VULNERABLE"), p(T, "cross-read", "NOT_REPRODUCED")])[0]?.proofStatus).toBe("NOT_REPRODUCED");
    expect(run([finding], [p(T, "anon-read", "NOT_REPRODUCED"), p(T, "reassign-owner", "PROVEN_VULNERABLE")])[0]).toMatchObject({ proofStatus: "PROVEN", proofIds: [`${T}/reassign-owner`] });
  });

  it("judges a missing-RLS finding by every exploit probe of the table", () => {
    const finding = staticFinding({ table: T, title: "Table public.documents has no row level security" });
    const proofs = [p(T, "anon-read", "NOT_REPRODUCED"), p(T, "cross-delete", "PROVEN_VULNERABLE")];
    expect(run([finding], proofs)[0]).toMatchObject({ proofStatus: "PROVEN", proofIds: [`${T}/cross-delete`] });
    expect(run([finding], [p(T, "anon-read", "NOT_REPRODUCED"), p(T, "cross-delete", "NOT_REPRODUCED")])[0]?.proofStatus).toBe("NOT_REPRODUCED");
  });

  it("is INCONCLUSIVE with the first unclear reason when nothing relevant was proven but a probe could not run", () => {
    const proofs = [
      p(T, "cross-update", "NOT_REPRODUCED"),
      p(T, "reassign-owner", "INCONCLUSIVE", { observation: { status: "not-run", reason: "no owner column" }, reason: "no owner column to reassign" }),
      p(T, "cross-insert", "PROVEN_VULNERABLE"),
    ];
    const [only] = run([policy('Policy "p" lets authenticated update every row of documents')], proofs);
    expect(only).toMatchObject({ proofStatus: "INCONCLUSIVE", proofIds: [`${T}/reassign-owner`] });
    expect(only?.note).toContain("could not be proven either way: no owner column to reassign");
  });

  it("stays PROVEN when one relevant probe is unclear and another got through", () => {
    const proofs = [p(T, "cross-update", "INCONCLUSIVE"), p(T, "reassign-owner", "PROVEN_VULNERABLE")];
    expect(run([policy('Policy "p" lets authenticated update every row of documents')], proofs)[0]?.proofStatus).toBe("PROVEN");
  });

  it("is INCONCLUSIVE when no probe of the relevant kinds was run for the table", () => {
    const [only] = run([policy('Policy "p" lets authenticated update every row of documents')], [p(T, "anon-read", "PROVEN_VULNERABLE")]);
    expect(only?.proofStatus).toBe("INCONCLUSIVE");
    expect(only?.proofIds).toEqual([]);
    expect(only?.note).toContain("no probe this finding is about was run");
    expect(only?.note).toContain("other attacks on this table were proven: anon-read");
  });

  it("falls back to the table verdict for missing-policy and unrecognised findings", () => {
    const proofs = [p(T, "cross-insert", "PROVEN_VULNERABLE")];
    const missing = policy("Table public.documents has row level security but no policies", "supabase-policy-missing");
    const nested = policy('Policy "p" is nested too deeply to analyse');
    const future = policy("Entirely new wording", "supabase-future-rule");
    const out = correlateAudit(audit([missing, nested, future]), { findings: [tableFinding(T, "PROVEN", { provenBy: [`${T}/cross-insert`] })], proofs, subjects: [T] }).findings;
    expect(out.map((f) => f.proofStatus)).toEqual(["PROVEN", "PROVEN", "PROVEN"]);
    expect(out.every((f) => f.proofIds.length === 1 && f.proofIds[0] === `${T}/cross-insert`)).toBe(true);
  });

  it("ignores legitimate probes and after-phase proofs", () => {
    const proofs = [
      p(T, "own-update", "PROVEN_VULNERABLE", { intent: "legitimate" }),
      p(T, "cross-update", "PROVEN_VULNERABLE", { phase: "after" }),
      p(T, "cross-update", "NOT_REPRODUCED"),
      p(T, "reassign-owner", "NOT_REPRODUCED"),
    ];
    const [only] = run([policy('Policy "p" lets authenticated update every row of documents')], proofs, "CLEAN");
    expect(only).toMatchObject({ proofStatus: "NOT_REPRODUCED", proofIds: [`${T}/cross-update`, `${T}/reassign-owner`] });
  });

  it("does not mix up the probes of two tables", () => {
    const other = "public.other";
    const proofs = [p(other, "cross-update", "PROVEN_VULNERABLE"), p(T, "cross-update", "NOT_REPRODUCED"), p(T, "reassign-owner", "NOT_REPRODUCED")];
    const out = correlateAudit(audit([policy('Policy "p" lets authenticated update every row of documents')]), {
      findings: [tableFinding(T, "CLEAN"), tableFinding(other, "PROVEN")],
      proofs,
      subjects: [T, other],
    }).findings;
    expect(out[0]?.proofStatus).toBe("NOT_REPRODUCED");
  });

  it("is the same whatever order the proofs and findings come in", () => {
    const findings = [
      policy('Policy "a" lets authenticated update every row of documents', "supabase-policy-permissive", { line: 3 }),
      policy("No policy on documents ties owner_id to the caller", "supabase-tenant-unscoped", { line: 5 }),
      policy("Table public.documents has no row level security", "supabase-rls-missing", { line: 1 }),
    ];
    const proofs = [p(T, "cross-insert", "PROVEN_VULNERABLE"), p(T, "cross-update", "NOT_REPRODUCED"), p(T, "reassign-owner", "NOT_REPRODUCED"), p(T, "cross-read", "NOT_REPRODUCED")];
    const forward = run(findings, proofs);
    const backward = run([...findings].reverse(), [...proofs].reverse());
    expect(backward).toEqual(forward);
  });

  it("reads the real report of the vulnerable example app against matching probe results", () => {
    const text = readFileSync(new URL("../../fixtures/audit/real-vulnerable-app.json", import.meta.url), "utf8");
    const parsed = parseAuditReport(text);
    if (!parsed.ok) throw new Error(parsed.error);
    const findings = [
      tableFinding("public.profiles", "PROVEN", { provenBy: ["public.profiles/anon-read"] }),
      tableFinding("public.tickets", "PROVEN", { provenBy: ["public.tickets/anon-read"] }),
      tableFinding("public.notes", "PROVEN", { provenBy: ["public.notes/anon-read"] }),
      tableFinding("public.documents", "PROVEN", { provenBy: ["public.documents/cross-insert"] }),
    ];
    const proofs = [
      p("public.profiles", "anon-read", "PROVEN_VULNERABLE"),
      p("public.tickets", "anon-read", "PROVEN_VULNERABLE"),
      p("public.tickets", "cross-read", "PROVEN_VULNERABLE"),
      p("public.notes", "anon-read", "PROVEN_VULNERABLE"),
      p("public.documents", "cross-insert", "PROVEN_VULNERABLE"),
      p("public.documents", "cross-update", "NOT_REPRODUCED"),
      p("public.documents", "reassign-owner", "NOT_REPRODUCED"),
    ];
    const result = correlateAudit(parsed.value, { findings, proofs, subjects: ["public.profiles", "public.tickets", "public.notes", "public.documents"] });
    const byTitle = new Map(result.findings.map((f) => [f.title, f]));
    expect(result.findings).toHaveLength(5);
    expect(byTitle.get('Policy "Owners can edit documents" lets authenticated update every row of documents')).toMatchObject({ proofStatus: "NOT_REPRODUCED", table: "public.documents" });
    expect(byTitle.get('Policy "Notes are viewable by everyone" lets every role including anon read every row of notes')?.proofStatus).toBe("PROVEN");
    expect(byTitle.get('Policy "Anyone can use tickets" lets every role including anon read and write every row of tickets')?.proofStatus).toBe("PROVEN");
    expect(byTitle.get("No policy on tickets ties user_id to the caller")).toMatchObject({ proofStatus: "PROVEN", proofIds: ["public.tickets/cross-read"] });
    expect(byTitle.get("Table public.profiles has no row level security")?.proofStatus).toBe("PROVEN");
  });
});
