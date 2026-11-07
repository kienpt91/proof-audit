import { describe, expect, it } from "vitest";
import { checkFindingsText } from "../../src/domain/interchange/conformance.js";
import type { ConfirmedRecord, FindingRecord, NeedsValidationRecord, RejectedRecord } from "../../src/domain/interchange/records.js";
import { parseMigrations } from "../../src/domain/sql/parser.js";
import { proof } from "../fixtures/reports.js";
import { analyseSql, auditFrom, exported, file, MIGRATION, recordsOf } from "../helpers/export.js";

const SQL = `-- notes app
create table public.notes (
  id uuid primary key,
  user_id uuid references auth.users (id),
  title text
);

alter table public.notes enable row level security;

create policy "Everyone reads" on public.notes
  for select using (true);

create table public.tickets (
  id uuid primary key,
  user_id uuid references auth.users (id),
  subject text
);

create table public.audit_log (id uuid primary key, line text);
alter table public.audit_log enable row level security;
`;

const FIX = `
drop policy "Everyone reads" on public.notes;
create policy notes_own on public.notes for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
revoke all on public.notes from anon;
alter table public.tickets enable row level security;
create policy tickets_own on public.tickets for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
revoke all on public.tickets from anon;
`;

const fixedModel = parseMigrations([{ path: MIGRATION, content: SQL + FIX }]).model;

const verdicts = (records: readonly FindingRecord[]): string[] => records.map((r) => `${r.verdict} ${r.fingerprint}`);
const confirmedOf = (records: readonly FindingRecord[], part: string): ConfirmedRecord => {
  const found = records.find((r): r is ConfirmedRecord => r.verdict === "confirmed" && r.fingerprint.includes(part));
  if (found === undefined) throw new Error(`no confirmed record for ${part}`);
  return found;
};

describe("findings.json from a proven run", () => {
  it("writes one conforming confirmed record per table and root cause, sorted by fingerprint", async () => {
    const run = await analyseSql(SQL, { fixed: fixedModel });
    const out = exported(run);
    expect(out.json).not.toBeNull();
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
    expect(verdicts(out.records)).toEqual([
      "confirmed proof-audit/rls/public.notes/policy-always-true/Everyone+20reads",
      "confirmed proof-audit/rls/public.tickets/rls-disabled",
    ]);
    // notes: two probes got through (anon-read and cross-read) but they share one root cause.
    expect(run.report.findings.find((f) => f.subject === "public.notes")?.provenBy.length).toBeGreaterThan(1);
  });

  it("points the trace and the evidence at real lines of the migration", async () => {
    const out = exported(await analyseSql(SQL, { fixed: fixedModel }));
    const notes = confirmedOf(out.records, "public.notes");
    expect(notes.trace.map((t) => [t.kind, t.file, t.line])).toEqual([
      ["entrypoint", MIGRATION, 10],
      ["propagation", MIGRATION, 8],
      ["sink", MIGRATION, 2],
    ]);
    expect(notes.evidence.every((e) => e.file === MIGRATION && e.line === 10)).toBe(true);
    const tickets = confirmedOf(out.records, "public.tickets");
    expect(tickets.trace.map((t) => [t.kind, t.line])).toEqual([["entrypoint", 13], ["sink", 13]]);
  });

  it("never emits a position that is not a statement of the input", async () => {
    const run = await analyseSql(SQL, { fixed: fixedModel });
    const lines = SQL.split("\n");
    const statementStart = /^(create|alter)\b/i;
    for (const record of exported(run).records) {
      for (const item of [...record.trace, ...record.evidence]) {
        expect(item.file).toBe(MIGRATION);
        expect(item.line).toBeGreaterThanOrEqual(2);
        expect(item.line).toBeLessThanOrEqual(lines.length);
        expect(lines[item.line - 1]).toMatch(statementStart);
      }
    }
  });

  it("records the exact SQL, the role and claims and what the database answered", async () => {
    const notes = confirmedOf(exported(await analyseSql(SQL, { fixed: fixedModel })).records, "public.notes");
    expect(notes.execution.payloads).toContain('SELECT * FROM "public"."notes"');
    expect(notes.execution.observed_result).toMatch(/public\.notes\/anon-read as anon: .*: the statement returned 2 rows/);
    expect(notes.conditions.map((c) => c.kind)).toEqual(expect.arrayContaining(["authentication_level", "authorization_role"]));
    expect(notes.conditions.some((c) => c.description.includes('"role":"anon"'))).toBe(true);
    expect(notes.execution.instructions.length).toBeGreaterThanOrEqual(2);
    expect(notes.root_cause).toContain('Policy "Everyone reads"');
  });

  it("takes the remediation from the proposed fix and raises confidence only when it was verified", async () => {
    const verified = confirmedOf(exported(await analyseSql(SQL, { fixed: fixedModel })).records, "public.notes");
    expect(verified.confidence.score).toBe("high");
    expect(verified.remediation.code_changes?.[0]?.file_name).toBe("fix.sql");
    expect(verified.remediation.code_changes?.[0]?.fixed_code).toMatch(/^-- public\.notes\n/);
    expect(verified.remediation.code_changes?.[0]?.fixed_code).not.toContain("public.tickets");
    expect(verified.remediation.strategy).toContain("Fix verified");

    const stillOpen = confirmedOf(exported(await analyseSql(SQL)).records, "public.notes");
    expect(stillOpen.confidence.score).toBe("medium");
    expect(stillOpen.confidence.reason).toContain("not verified");

    const noFix = confirmedOf(exported(await analyseSql(SQL, { proposeFix: false })).records, "public.notes");
    expect(noFix.confidence.score).toBe("medium");
    expect(noFix.remediation.code_changes).toBeUndefined();
  });

  it("takes the severity from the anchor table", async () => {
    const records = exported(await analyseSql(SQL, { fixed: fixedModel })).records;
    const notes = confirmedOf(records, "public.notes");
    expect(notes.severity.overall_severity).toBe("critical");
    expect(notes.severity.impact.score).toBe("critical");
    expect(notes.severity.likelihood.score).toBe("high");
    expect(confirmedOf(records, "public.tickets").severity.overall_severity).toBe("critical");
  });

  it("is the same text on every run and keeps the fingerprints when lines move", async () => {
    const first = exported(await analyseSql(SQL, { fixed: fixedModel }));
    const again = exported(await analyseSql(SQL, { fixed: fixedModel }));
    expect(again.json).toBe(first.json);

    // A cosmetic edit: a header, blank lines and a comment above everything moves every statement down.
    const moved = `-- reviewed 2026\n-- more notes\n\n\n${SQL.replace("create table public.tickets", "-- tickets\n\ncreate table public.tickets")}`;
    const after = exported(await analyseSql(moved, { fixed: parseMigrations([{ path: MIGRATION, content: moved + FIX }]).model }));
    expect(after.records.map((r) => r.fingerprint)).toEqual(first.records.map((r) => r.fingerprint));
    expect(after.records.map((r) => r.trace[0]?.line)).not.toEqual(first.records.map((r) => r.trace[0]?.line));
    expect(confirmedOf(after.records, "public.notes").trace.map((t) => t.line)).toEqual([14, 12, 6]);
  });

  it("changes a fingerprint only when a named object changes", async () => {
    const renamed = SQL.replace('"Everyone reads"', '"Public notes"');
    const records = exported(await analyseSql(renamed)).records;
    expect(verdicts(records)).toEqual([
      "confirmed proof-audit/rls/public.notes/policy-always-true/Public+20notes",
      "confirmed proof-audit/rls/public.tickets/rls-disabled",
    ]);
  });

  it("is an empty list when nothing is open", async () => {
    const run = await analyseSql("create table public.t (id uuid primary key, user_id uuid);\nalter table public.t enable row level security;\n");
    const out = exported(run);
    expect(out.json).toBe("[]\n");
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
  });
});

describe("findings.json for what could not be proven", () => {
  const failSeeding = (sandbox: { applyFirstSuccess: unknown; scalars: unknown }): void => {
    sandbox.applyFirstSuccess = async (groups: readonly unknown[]) => groups.map(() => ({ ok: false, attempt: null, sqlstate: "23514", message: "check violated" }));
    sandbox.scalars = async (queries: readonly unknown[]) => queries.map(() => ({ ok: true as const, value: 0 }));
  };
  /** No probe gets an answer, as if the run had run out of time. */
  const blockAll = (sandbox: { run: unknown }): void => {
    sandbox.run = async (probes: readonly unknown[]) => probes.map(() => ({ status: "not-run" as const, reason: "the run time budget was used up before this probe ran" }));
  };

  it("turns a suspected table into needs_validation with the reason no probe could confirm it", async () => {
    const run = await analyseSql(SQL, { tweak: blockAll });
    const out = exported(run);
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
    expect(verdicts(out.records)).toEqual([
      "needs_validation proof-audit/rls/public.audit_log/untested",
      "needs_validation proof-audit/rls/public.notes/owner-not-compared",
      "needs_validation proof-audit/rls/public.notes/policy-always-true/Everyone+20reads",
      "needs_validation proof-audit/rls/public.tickets/rls-disabled",
    ]);
    const tickets = out.records.find((r): r is NeedsValidationRecord => r.verdict === "needs_validation" && r.fingerprint.endsWith("public.tickets/rls-disabled"));
    expect(tickets?.blockers.join("\n")).toContain("run time budget");
    expect(tickets?.validation_plan.local).toContain("public.tickets");
    expect(tickets?.validation_plan.local).toContain("anon-read");
    expect(tickets?.title).toContain("(not proven)");
    expect(tickets?.trace.map((t) => [t.kind, t.line])).toEqual([["entrypoint", 13], ["sink", 13]]);
    expect(tickets && "severity" in tickets).toBe(false);
    expect(tickets && "execution" in tickets).toBe(false);
    expect(out.records.some((r) => r.verdict === "confirmed")).toBe(false);
  });

  it("records a seeding failure as the blocker", async () => {
    const out = exported(await analyseSql(SQL, { tweak: failSeeding }));
    const notes = out.records.filter((r) => r.fingerprint.includes("public.notes"));
    expect(notes.map((r) => r.verdict)).toEqual(["needs_validation", "needs_validation"]);
    const audit = out.records.find((r) => r.fingerprint.includes("public.audit_log"));
    expect(audit?.verdict).toBe("needs_validation");
    expect((audit as NeedsValidationRecord).blockers.join("\n")).toMatch(/seed/i);
    // the table that needed no seeded rows to be attacked is still confirmed
    expect(out.records.find((r) => r.fingerprint.includes("public.tickets"))?.verdict).toBe("confirmed");
  });

  it("keeps the fingerprint of a candidate that a later run proves", async () => {
    const candidate = exported(await analyseSql(SQL, { tweak: blockAll })).records.find((r) => r.fingerprint.includes("public.tickets"));
    const proven = exported(await analyseSql(SQL)).records.find((r) => r.fingerprint.includes("public.tickets"));
    expect(candidate?.verdict).toBe("needs_validation");
    expect(proven?.verdict).toBe("confirmed");
    expect(proven?.fingerprint).toBe(candidate?.fingerprint);
  });

  it("names an inconclusive table with nothing suspicious as untested", async () => {
    const good = "create table public.t (id uuid primary key, user_id uuid references auth.users (id));\nalter table public.t enable row level security;\ncreate policy own on public.t for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));\n";
    const out = exported(await analyseSql(good, { tweak: failSeeding }));
    expect(verdicts(out.records)).toEqual(["needs_validation proof-audit/rls/public.t/untested"]);
    expect((out.records[0] as NeedsValidationRecord).claimed_root_cause).toContain("No root cause is claimed");
  });

  it("lists the tampering as blockers when the migrations touched the test environment", async () => {
    const run = await analyseSql(SQL, { tamperedAfter: 2 });
    expect(run.report.integrity.status).toBe("INTEGRITY_VIOLATION");
    const out = exported(run);
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
    expect(out.records.every((r) => r.verdict === "needs_validation" && r.fingerprint.endsWith("/untested"))).toBe(true);
    expect((out.records[0] as NeedsValidationRecord).blockers.join("\n")).toContain("test environment");
  });
});

describe("findings.json with a static auditor report", () => {
  const DOCS = `create table public.docs (id uuid primary key, user_id uuid references auth.users (id), body text);
alter table public.docs enable row level security;

create policy "Owner write" on public.docs for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy "Owner read" on public.docs for select to authenticated using (user_id = (select auth.uid()));
`;
  const staticReport = (findings: readonly object[]): string => JSON.stringify({ tool: { name: "saas-audit", version: "0.1.0" }, project: "app", findings });
  const flagged = {
    rule: "supabase-policy-permissive",
    severity: "high",
    file: "supabase/migrations/001.sql",
    line: 4,
    title: 'Policy "Owner write" lets authenticated update every row of docs',
    message: "WITH CHECK (true) is always true.",
  };

  it("turns a static finding that the database refused into a rejected record with the static fingerprint", async () => {
    const run = await analyseSql(DOCS, { audit: auditFrom(staticReport([flagged])) });
    const out = exported(run);
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
    const record = out.records[0] as RejectedRecord;
    expect(out.records).toHaveLength(1);
    expect(record.verdict).toBe("rejected");
    expect(record.fingerprint).toBe("saas-audit/supabase-policy-permissive:supabase/migrations/001.sql:public.docs:Owner+20write");
    expect(record.reason).toContain("denied every attack");
    expect(record.claimed_root_cause).toContain("saas-audit 0.1.0");
    expect(record.trace.map((t) => [t.kind, t.line])).toEqual([["entrypoint", 4], ["sink", 1]]);
    expect(record.evidence.some((e) => e.description.includes("docs/cross-update"))).toBe(true);
  });

  it("prefers the subject array of the static report to the title, so a quote in a policy name is safe", async () => {
    const quoted = DOCS.replace('"Owner write"', '"Owner ""write"""');
    const finding = { ...flagged, title: 'Policy "Owner "write"" lets authenticated update every row of docs', subject: ["public.docs", 'Owner "write"'] };
    const out = exported(await analyseSql(quoted, { audit: auditFrom(staticReport([finding])) }));
    expect((out.records[0] as RejectedRecord).fingerprint).toBe("saas-audit/supabase-policy-permissive:supabase/migrations/001.sql:public.docs:Owner+20+22write+22");
  });

  it("writes nothing for static findings that were proven or not tested", async () => {
    const open = `${DOCS}create policy "Owner write 2" on public.docs for update to public using (true) with check (true);\n`;
    const out = exported(await analyseSql(open, { audit: auditFrom(staticReport([{ ...flagged, title: 'Policy "Owner write 2" lets everyone update every row of docs' }, { rule: "supabase-rls-missing", severity: "high", file: "x.sql", line: 1, title: "Table public.elsewhere has no row level security" }])) }));
    expect(out.records.some((r) => r.verdict === "rejected")).toBe(false);
  });

  it("numbers repeated static fingerprints instead of repeating them", async () => {
    const out = exported(await analyseSql(DOCS, { audit: auditFrom(staticReport([flagged, { ...flagged, line: 5 }])) }));
    expect(out.records.map((r) => r.fingerprint).sort()).toEqual([
      "saas-audit/supabase-policy-permissive:supabase/migrations/001.sql:public.docs:Owner+20write",
      "saas-audit/supabase-policy-permissive:supabase/migrations/001.sql:public.docs:Owner+20write:@2",
    ]);
  });
});

describe("findings.json when a line cannot be found", () => {
  it("finds the first statement that names a table the reader never saw declared", async () => {
    const sql = "-- ghost\ncomment on table public.ghost is 'x';\n";
    const ghost = parseMigrations([{ path: MIGRATION, content: "create table public.ghost (id uuid primary key, user_id uuid);" }]).model;
    const run = await analyseSql(sql, { catalog: ghost });
    const out = exported(run);
    expect(out.records).toHaveLength(1);
    expect(out.records[0]?.trace.map((t) => t.line)).toEqual([2, 2]);
  });

  it("leaves a table out, and says so, when no statement names it", async () => {
    const ghost = parseMigrations([{ path: MIGRATION, content: "create table public.ghost (id uuid primary key, user_id uuid);" }]).model;
    const run = await analyseSql("select 1;\n", { catalog: ghost });
    const out = exported(run);
    expect(out.records).toEqual([]);
    expect(out.notes.join("\n")).toContain("public.ghost");
    expect(recordsOf(run).omitted).toEqual([{ subject: "public.ghost", reason: expect.stringContaining("no line to point at") }]);
  });

  it("does not write the file when an input path is not a safe relative path", async () => {
    for (const path of ["/abs/001.sql", "../other/001.sql", "db:1/001.sql"]) {
      const out = exported(await analyseSql(SQL, { files: [file(SQL, path)] }));
      expect(out.json).toBeNull();
      expect(out.notes.join(" ")).toContain("findings.json was not written");
      expect(out.notes.join(" ")).toContain("project root");
    }
  });
});

describe("findings.json for views and for reports the analysis did not build", () => {
  const VIEW_SQL = `create table public.notes (id uuid primary key, user_id uuid references auth.users (id), title text);
alter table public.notes enable row level security;
create policy own on public.notes for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

create view public.note_titles as select id, user_id, title from public.notes;
`;

  it("confirms a view that runs with its owner's rights, from the view to the table it reads", async () => {
    const out = exported(await analyseSql(VIEW_SQL));
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
    expect(verdicts(out.records)).toEqual(["confirmed proof-audit/rls/public.note_titles/view-bypasses-rls"]);
    const view = out.records[0] as ConfirmedRecord;
    expect(view.trace.map((t) => [t.kind, t.line])).toEqual([["entrypoint", 5], ["sink", 1]]);
    expect(view.severity.overall_severity).toBe("critical");
    expect(view.intended_behavior).toContain("security_invoker");
    expect(view.remediation.strategy).toContain("security_invoker = true");
  });

  it("leaves out a table or view the schema model does not have", async () => {
    const run = await analyseSql(SQL);
    const result = recordsOf({ ...run, report: { ...run.report, model: { tables: [], views: [] } } });
    expect(result.records).toEqual([]);
    expect(result.omitted.map((o) => o.subject).sort()).toEqual(["public.notes", "public.tickets"]);
    expect(result.omitted[0]?.reason).toContain("no such table or view");
  });

  it("puts what no static cause explains into an unattributed record", async () => {
    const run = await analyseSql(SQL);
    const sql = "SELECT * FROM \"public\".\"audit_log\"";
    const forged = {
      ...run.report,
      findings: run.report.findings.map((f) => (f.subject === "public.audit_log" ? { ...f, tier: "PROVEN" as const, provenBy: ["public.audit_log/anon-read"] } : f)),
      proofs: [...run.report.proofs.filter((p) => p.subject !== "public.audit_log"), proof({ subject: "public.audit_log", kind: "anon-read", sql, observation: { status: "rows", rows: 2 }, verdict: "PROVEN_VULNERABLE", reason: "the statement returned 2 rows" })],
    };
    const record = recordsOf({ ...run, report: forged }).records.find((r) => r.fingerprint.includes("public.audit_log"));
    expect(record?.verdict).toBe("confirmed");
    expect(record?.fingerprint).toBe("proof-audit/rls/public.audit_log/unattributed");
    expect((record as ConfirmedRecord).root_cause).toContain("no policy or setting");
    expect((record as ConfirmedRecord).severity.overall_severity).toBe("medium");
    expect((record as ConfirmedRecord).execution.payloads).toEqual([sql]);
  });

  it("describes an error that counted as proof with its SQLSTATE", async () => {
    const run = await analyseSql(SQL);
    const forged = {
      ...run.report,
      proofs: run.report.proofs.map((p) =>
        p.id === "public.tickets/anon-insert" ? proof({ subject: p.subject, kind: p.kind, sql: p.sql, observation: { status: "error", sqlstate: "23502", message: "null value in column \"x\"" }, verdict: "PROVEN_VULNERABLE", reason: "the policy admitted the row and a constraint stopped it" }) : p,
      ),
    };
    const tickets = recordsOf({ ...run, report: forged }).records.find((r) => r.fingerprint.includes("public.tickets")) as ConfirmedRecord;
    expect(tickets.execution.observed_result).toContain("SQLSTATE 23502");
  });

  it("leaves out a static finding that names no table or whose table no statement declares", async () => {
    const DOCS = "create table public.docs (id uuid primary key, user_id uuid references auth.users (id));\nalter table public.docs enable row level security;\ncreate policy r on public.docs for select to authenticated using (user_id = (select auth.uid()));\n";
    const text = JSON.stringify({ tool: "saas-audit", findings: [{ rule: "supabase-policy-permissive", severity: "high", file: "m.sql", line: 3, title: 'Policy "r" lets authenticated read every row of docs', message: "" }] });
    const run = await analyseSql(DOCS, { audit: auditFrom(text) });
    const correlated = run.report.audit?.findings[0];
    if (correlated === undefined || run.report.audit === null) throw new Error("no audit");
    expect(correlated.proofStatus).toBe("NOT_REPRODUCED");

    const noTable = { ...run.report, audit: { ...run.report.audit, findings: [{ ...correlated, table: null }] } };
    const first = recordsOf({ ...run, audit: null, report: noTable });
    expect(first.records).toEqual([]);
    expect(first.omitted[0]?.reason).toContain("does not name a table");

    const ghost = { ...run.report, audit: { ...run.report.audit, findings: [{ ...correlated, table: "public.ghost", title: 'Policy "r" lets authenticated read every row of ghost' }] } };
    const second = recordsOf({ ...run, audit: null, report: ghost });
    expect(second.records).toEqual([]);
    expect(second.omitted[0]?.reason).toContain("no line to point at");
  });

  it("builds a rejected record from the report alone when the parsed static report is not at hand", async () => {
    const DOCS = "create table public.docs (id uuid primary key, user_id uuid references auth.users (id));\nalter table public.docs enable row level security;\ncreate policy r on public.docs for select to authenticated using (user_id = (select auth.uid()));\n";
    const text = JSON.stringify({ tool: "saas-audit", findings: [{ rule: "supabase-policy-permissive", severity: "high", file: "elsewhere/m.sql", line: 99, title: 'Policy "r" lets authenticated read every row of docs', message: "" }] });
    const run = await analyseSql(DOCS, { audit: auditFrom(text) });
    const [record] = recordsOf({ ...run, audit: null }).records;
    expect(record?.verdict).toBe("rejected");
    expect(record?.fingerprint).toBe("saas-audit/supabase-policy-permissive:elsewhere/m.sql:public.docs:r");
    expect((record as RejectedRecord).claimed_root_cause).toContain("supabase-policy-permissive");
    expect((record as RejectedRecord).description).toBe('Policy "r" lets authenticated read every row of docs');
    // the position the auditor reported is outside the file, so only the statement the reader found is cited
    expect(record?.evidence.every((e) => e.line <= 3)).toBe(true);
  });
});

describe("findings.json with static text that cannot be shown", () => {
  it("falls back to the title when the static message has no visible character", async () => {
    const DOCS = "create table public.docs (id uuid primary key, user_id uuid references auth.users (id));\nalter table public.docs enable row level security;\ncreate policy r on public.docs for select to authenticated using (user_id = (select auth.uid()));\n";
    const title = 'Policy "r" lets authenticated read every row of docs';
    const text = JSON.stringify({ tool: "saas-audit", findings: [{ rule: "supabase-policy-permissive", severity: "high", file: "supabase/migrations/001.sql", line: 3, title, message: "\u200b\u200b" }] });
    const out = exported(await analyseSql(DOCS, { audit: auditFrom(text) }));
    expect(checkFindingsText(out.json ?? "")).toEqual([]);
    const record = out.records[0] as RejectedRecord;
    expect(record.description).toBe(title);
    expect(record.claimed_root_cause).toBe(`The static auditor (saas-audit, rule supabase-policy-permissive) claimed: ${title}.`);
  });
});
