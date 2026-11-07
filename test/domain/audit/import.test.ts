import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { auditPriorityTables, parseAuditReport, policyFromTitle, qualifyTableName, staticSubject, tableFromTitle, type ParsedAudit } from "../../../src/domain/audit/import.js";
import { LIMITS } from "../../../src/domain/limits.js";

const fixture = (name: string): string => readFileSync(new URL(`../../fixtures/audit/${name}`, import.meta.url), "utf8");

function parsed(text: string): ParsedAudit {
  const result = parseAuditReport(text);
  if (!result.ok) throw new Error(`expected a parsed report: ${result.error}`);
  return result.value;
}

const finding = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  rule: "supabase-rls-missing",
  severity: "high",
  file: "m.sql",
  line: 3,
  title: "Table public.notes has no row level security",
  message: "m",
  ...over,
});
const report = (findings: unknown, extra: Record<string, unknown> = {}): string => JSON.stringify({ tool: { name: "saas-audit", version: "0.1.0" }, project: "p", findings, ...extra });

describe("parseAuditReport: fixtures", () => {
  it("reads the report of the example app and keeps only row level security findings", () => {
    const audit = parsed(fixture("vibe-app.json"));
    expect(audit.tool).toBe("saas-audit");
    expect(audit.version).toBe("0.1.0");
    expect(audit.project).toBe("vibe-app");
    expect(audit.totalFindings).toBe(9);
    expect(audit.findings.map((f) => f.rule)).toEqual([
      "supabase-rls-missing",
      "supabase-policy-permissive",
      "supabase-policy-permissive",
      "supabase-policy-permissive",
      "supabase-tenant-unscoped",
      "supabase-policy-missing",
    ]);
    expect(audit.findings.map((f) => f.table)).toEqual([
      "public.invoices",
      "public.feedback",
      "public.profiles",
      "public.projects",
      "public.projects",
      "public.notes",
    ]);
    const first = audit.findings[0];
    expect(first).toMatchObject({ severity: "critical", file: "supabase/migrations/0001_init.sql", line: 24 });
  });

  it("reads an older report with fewer top-level keys, other schemas and quoted names", () => {
    const audit = parsed(fixture("multi-schema.json"));
    expect(audit.version).toBe("0.0.9");
    expect(audit.project).toBe("multi-tenant-shop");
    expect(audit.totalFindings).toBe(8);
    expect(audit.findings.map((f) => f.table)).toEqual([
      "app.orders",
      "public.Audit Log",
      "public.comments",
      "public.tags",
      null,
      "public.countries",
      "public.comments",
    ]);
  });

  it("reads a newer report that has no row level security findings and ignores unknown keys and suppressed findings", () => {
    const audit = parsed(fixture("no-rls-findings.json"));
    expect(audit.version).toBe("1.2.0");
    expect(audit.project).toBeNull();
    expect(audit.findings).toEqual([]);
    expect(audit.totalFindings).toBe(2);
    expect(auditPriorityTables(audit)).toEqual([]);
  });
});

describe("parseAuditReport: tolerance", () => {
  it("accepts a report without tool and project", () => {
    const audit = parsed(JSON.stringify({ findings: [finding()] }));
    expect(audit).toMatchObject({ tool: "unknown", version: null, project: null, totalFindings: 1 });
  });

  it("accepts a tool without a version and a tool given as a plain string", () => {
    expect(parsed(JSON.stringify({ tool: { name: "saas-audit" }, findings: [] }))).toMatchObject({ tool: "saas-audit", version: null });
    expect(parsed(JSON.stringify({ tool: "saas-audit", findings: [] }))).toMatchObject({ tool: "saas-audit", version: null });
  });

  it("keeps the name and version of another tool", () => {
    const audit = parsed(JSON.stringify({ tool: { name: "other-scanner", version: "9.9.9-beta" }, findings: [finding()] }));
    expect(audit.tool).toBe("other-scanner");
    expect(audit.version).toBe("9.9.9-beta");
    expect(audit.findings).toHaveLength(1);
  });

  it("maps an unknown severity to info and is case-insensitive for known ones", () => {
    const audit = parsed(report([finding({ severity: "catastrophic" }), finding({ severity: "CRITICAL" }), finding({ severity: 7 }), finding({ severity: undefined })]));
    expect(audit.findings.map((f) => f.severity)).toEqual(["info", "critical", "info", "info"]);
  });

  it("does not take a prototype property name for a severity", () => {
    const audit = parsed(report([finding({ severity: "constructor" }), finding({ severity: "__proto__" })]));
    expect(audit.findings.map((f) => f.severity)).toEqual(["info", "info"]);
  });

  it("defaults a missing line to 0 and missing file and message to empty text", () => {
    const audit = parsed(report([{ rule: "supabase-rls-missing", title: "Table public.a has no row level security" }]));
    expect(audit.findings[0]).toMatchObject({ line: 0, file: "", message: "", table: "public.a" });
  });

  it("ignores unknown keys at every level", () => {
    const audit = parsed(report([finding({ evidence: "x", fix: "y", newField: { deep: [1, 2] } })], { extra: 1, tool2: {} }));
    expect(audit.findings).toHaveLength(1);
  });

  it("accepts an empty findings list", () => {
    expect(parsed(report([]))).toMatchObject({ findings: [], totalFindings: 0 });
  });

  it("counts findings of other families without keeping them", () => {
    const audit = parsed(report([finding(), finding({ rule: "secret-hardcoded", title: "Table public.x has no row level security" }), finding({ rule: "api-idor" })]));
    expect(audit.totalFindings).toBe(3);
    expect(audit.findings).toHaveLength(1);
  });
});

describe("parseAuditReport: rejection", () => {
  it.each([
    ["not JSON", "{oops"],
    ["a JSON array", "[]"],
    ["a JSON string", '"saas-audit"'],
    ["null", "null"],
    ["no findings key", JSON.stringify({ tool: { name: "saas-audit" } })],
    ["findings that are not an array", JSON.stringify({ findings: { a: 1 } })],
    ["findings null", JSON.stringify({ findings: null })],
    ["a finding that is not an object", report(["supabase-rls-missing"])],
    ["a finding without a rule", report([{ title: "t" }])],
    ["a finding without a title", report([{ rule: "supabase-rls-missing" }])],
    ["a non-integer line", report([finding({ line: 1.5 })])],
    ["a negative line", report([finding({ line: -1 })])],
    ["a string line", report([finding({ line: "3" })])],
    ["a tool of the wrong type", JSON.stringify({ tool: 5, findings: [] })],
    ["a project of the wrong type", JSON.stringify({ project: [], findings: [] })],
  ])("rejects %s", (_label, text) => {
    expect(parseAuditReport(text).ok).toBe(false);
  });

  it("rejects more than 20000 findings", () => {
    const many = Array.from({ length: 20_001 }, () => ({ rule: "a", title: "t" }));
    const result = parseAuditReport(JSON.stringify({ findings: many }));
    expect(result).toEqual({ ok: false, error: "audit report.findings: expected an array of at most 20000 items" });
  });

  it("accepts exactly 20000 findings", () => {
    const many = Array.from({ length: 20_000 }, () => ({ rule: "supabase-rls-missing", title: "Table public.a has no row level security" }));
    const audit = parsed(JSON.stringify({ findings: many }));
    expect(audit.totalFindings).toBe(20_000);
  });

  it("rejects input larger than the JSON cap without reading it", () => {
    const result = parseAuditReport(" ".repeat(LIMITS.maxJsonBytes + 1));
    expect(result).toEqual({ ok: false, error: `audit report: larger than ${LIMITS.maxJsonBytes} bytes` });
  });

  it("rejects over-long strings and never echoes them", () => {
    const hostile = "SECRET-PAYLOAD".repeat(1_000);
    const long = parseAuditReport(report([finding({ title: hostile })]));
    expect(long.ok).toBe(false);
    if (!long.ok) expect(long.error).not.toContain("SECRET");
    const longRule = parseAuditReport(report([finding({ rule: hostile })]));
    expect(longRule.ok).toBe(false);
    const longMessage = parseAuditReport(report([finding({ message: "x".repeat(20_001) })]));
    expect(longMessage.ok).toBe(false);
    const longProject = parseAuditReport(report([], { project: "p".repeat(201) }));
    expect(longProject.ok).toBe(false);
  });

  it("does not echo malformed JSON", () => {
    const result = parseAuditReport('{"findings": [SECRET-PAYLOAD');
    expect(result).toEqual({ ok: false, error: "audit report: not valid JSON" });
  });

  it("names the path of the failing finding", () => {
    const result = parseAuditReport(report([finding(), finding({ line: "x" })]));
    expect(result).toEqual({ ok: false, error: "audit report.findings[1].line: expected an integer" });
  });
});

describe("table extraction from titles", () => {
  it.each([
    ["Table public.notes has no row level security", "public.notes"],
    ["Table app.orders has no row level security", "app.orders"],
    ["Table notes has no row level security", "public.notes"],
    ['Table "public"."My Table" has no row level security', "public.My Table"],
    ['Table public."Order Items" has no row level security', "public.Order Items"],
    ['Table "weird""name" has no row level security', 'public.weird"name'],
    ["Table public.Audit Log has no row level security", "public.Audit Log"],
    ["Table public.notes has row level security but no policies", "public.notes"],
    ["Table billing.invoices has row level security but no policies", "billing.invoices"],
    ['Policy "x" lets anon read every row of notes', "public.notes"],
    ['Policy "x" lets every role including anon read every row of profiles', "public.profiles"],
    ['Policy "p" lets authenticated read and write every row of projects', "public.projects"],
    ['Policy "p" lets anon insert every row of app.feedback', "app.feedback"],
    ['Policy "p" allows the anon role to insert notes', "public.notes"],
    ['Policy "p" allows the anon role to write to comments', "public.comments"],
    ['Policy "p" allows the anon role to delete tags', "public.tags"],
    ['Policy "p" allows the anon role to update billing.plans', "billing.plans"],
    ["No policy on notes ties user_id / org_id to the caller", "public.notes"],
    ["No policy on app.orders ties tenant_id to the caller", "app.orders"],
  ])("%s", (title, expected) => {
    expect(tableFromTitle(title)).toBe(expected);
  });

  it("reads the table after the last fixed phrase when the policy name contains one", () => {
    expect(tableFromTitle('Policy "lets anon read every row of secrets" lets anon read every row of notes')).toBe("public.notes");
    expect(tableFromTitle('Policy "allows the anon role to insert logs" allows the anon role to insert notes')).toBe("public.notes");
    expect(tableFromTitle('Policy "has no row level security" lets anon read every row of notes')).toBe("public.notes");
  });

  it.each([
    'Policy "x" is nested too deeply to analyse',
    "Something else entirely",
    "",
    "Table  has no row level security",
    'Table "unclosed has no row level security',
    "Table . has no row level security",
    "Table public. has no row level security",
    "Table .notes has no row level security",
  ])("finds no table in %j", (title) => {
    expect(tableFromTitle(title)).toBeNull();
  });

  it("gives a null table to a row level security finding whose title is not recognised", () => {
    const audit = parsed(report([finding({ rule: "supabase-future-rule", title: "Entirely new wording" })]));
    expect(audit.findings[0]?.table).toBeNull();
  });

  it("qualifies identifiers", () => {
    expect(qualifyTableName("notes")).toBe("public.notes");
    expect(qualifyTableName('"Notes"')).toBe("public.Notes");
    expect(qualifyTableName('a."b.c"')).toBe("a.b.c");
    expect(qualifyTableName("a.b.c")).toBe("a.b.c");
    expect(qualifyTableName("  public.notes  ")).toBe("public.notes");
    expect(qualifyTableName("")).toBeNull();
    expect(qualifyTableName('""')).toBeNull();
  });
});

describe("auditPriorityTables", () => {
  const make = (items: readonly [string, string, string | null][]): ParsedAudit => ({
    tool: "saas-audit",
    version: null,
    project: null,
    totalFindings: items.length,
    findings: items.map(([rule, severity, table]) => ({ rule, severity: severity as "high", file: "f", line: 1, title: "t", message: "", table, subject: null })),
  });

  it("orders by the most severe finding, then alphabetically", () => {
    const audit = make([
      ["supabase-policy-missing", "medium", "public.b"],
      ["supabase-rls-missing", "critical", "public.z"],
      ["supabase-rls-missing", "high", "public.a"],
      ["supabase-policy-permissive", "high", "public.c"],
    ]);
    expect(auditPriorityTables(audit)).toEqual(["public.z", "public.a", "public.c", "public.b"]);
  });

  it("lists a table once, ranked by its worst finding", () => {
    const audit = make([
      ["supabase-policy-missing", "medium", "public.t"],
      ["supabase-rls-missing", "critical", "public.t"],
      ["supabase-rls-missing", "high", "public.u"],
    ]);
    expect(auditPriorityTables(audit)).toEqual(["public.t", "public.u"]);
  });

  it("skips findings without a table and findings of other families", () => {
    const audit = make([
      ["supabase-rls-missing", "high", null],
      ["api-idor", "critical", "public.x"],
    ]);
    expect(auditPriorityTables(audit)).toEqual([]);
  });

  it("ranks the example app: feedback and invoices (critical) before profiles and projects (high) before notes", () => {
    expect(auditPriorityTables(parsed(fixture("vibe-app.json")))).toEqual(["public.feedback", "public.invoices", "public.profiles", "public.projects", "public.notes"]);
  });
});

describe("the subject of a static finding", () => {
  const one = (over: Record<string, unknown>): ParsedAudit["findings"][number] => {
    const audit = parsed(JSON.stringify({ tool: { name: "saas-audit", version: "1" }, findings: [finding(over)] }));
    const first = audit.findings[0];
    if (first === undefined) throw new Error("no finding");
    return first;
  };

  it("reads the optional subject array and ignores anything else", () => {
    expect(one({ subject: ["public.docs", "Owner write"] }).subject).toEqual(["public.docs", "Owner write"]);
    expect(one({}).subject).toBeNull();
    expect(one({ subject: [] }).subject).toBeNull();
    expect(one({ subject: "public.docs" }).subject).toBeNull();
    expect(one({ subject: [1, 2] }).subject).toBeNull();
  });

  it("takes the policy name from the title when it has the shape the auditor prints", () => {
    expect(policyFromTitle('Policy "Anyone can use tickets" lets every role including anon read and write every row of tickets')).toBe("Anyone can use tickets");
    expect(policyFromTitle('Policy "x" allows the anon role to write to public.t')).toBe("x");
    expect(policyFromTitle('Policy "say "hi"" lets authenticated update every row of docs')).toBe('say "hi"');
    expect(policyFromTitle("Table public.profiles has no row level security")).toBeNull();
    expect(policyFromTitle("")).toBeNull();
  });

  it("prefers the subject array to the title", () => {
    const f = one({ rule: "supabase-policy-permissive", title: 'Policy "a" lets authenticated update every row of docs', subject: ["app.docs", 'a "b"'] });
    expect(staticSubject(f)).toEqual({ table: "app.docs", policy: 'a "b"' });
    expect(staticSubject(one({ subject: ["notes"] }))).toEqual({ table: "public.notes", policy: null });
  });

  it("falls back to the title for the table and the policy", () => {
    const f = one({ rule: "supabase-policy-permissive", title: 'Policy "Owner write" lets authenticated update every row of docs' });
    expect(staticSubject(f)).toEqual({ table: "public.docs", policy: "Owner write" });
    expect(staticSubject(one({}))).toEqual({ table: "public.notes", policy: null });
  });
});
