import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { renderJson } from "../../src/application/report/json.js";
import { renderMarkdown } from "../../src/application/report/markdown.js";
import { renderPlain } from "../../src/application/report/plain.js";
import { parseAuditReport } from "../../src/domain/audit/import.js";
import { analyze, exampleFiles, haveDatabase, sqlFile } from "./support.js";

describe.skipIf(!haveDatabase)("examples/vulnerable-app against real PostgreSQL", async () => {
  const report = await analyze(await exampleFiles("vulnerable-app"));
  const finding = (subject: string) => report.findings.find((f) => f.subject === subject);
  const provenKinds = (subject: string) => report.proofs.filter((p) => p.subject === subject && p.verdict === "PROVEN_VULNERABLE").map((p) => p.kind);

  it("runs against the pinned PostgreSQL 16 and completes", () => {
    expect(report.environment.postgresVersion).toMatch(/^16\./);
    expect(report.complete).toBe(true);
    expect(report.migrationErrors).toEqual([]);
  });

  it("proves six of the seven subjects and finds invoices clean", () => {
    expect(report.summary).toMatchObject({ subjects: 7, proven: 6, clean: 1, suspected: 0, inconclusive: 0 });
    expect(finding("public.invoices")?.tier).toBe("CLEAN");
  });

  it("proves the missing RLS on profiles for anonymous and signed-in callers", () => {
    expect(provenKinds("public.profiles")).toEqual(expect.arrayContaining(["anon-read", "anon-update", "anon-delete", "cross-read", "cross-update", "cross-delete"]));
    expect(finding("public.profiles")).toMatchObject({ severity: "critical" });
  });

  it("proves that the always-true select policy on notes leaks to anon and to other users but nothing else", () => {
    expect(provenKinds("public.notes")).toEqual(["anon-read", "cross-read"]);
  });

  it("proves the open ticket table in every direction", () => {
    expect(provenKinds("public.tickets")).toEqual(expect.arrayContaining(["anon-read", "anon-insert", "anon-update", "anon-delete", "cross-read", "cross-insert", "null-owner-insert", "cross-update", "cross-delete", "reassign-owner"]));
  });

  it("proves that documents can be created in another user's name", () => {
    expect(provenKinds("public.documents")).toEqual(["cross-insert"]);
    expect(finding("public.documents")).toMatchObject({ severity: "high" });
  });

  it("proves the wrong-column policy on projects: rows can be planted and handed over", () => {
    expect(provenKinds("public.projects")).toEqual(["cross-insert", "reassign-owner"]);
  });

  it("proves that the view bypasses row level security on invoices", () => {
    expect(provenKinds("public.invoice_summaries")).toEqual(["view-read-anon", "view-read-cross"]);
    expect(finding("public.invoice_summaries")?.causes.map((c) => c.code)).toEqual(["view-bypasses-rls"]);
  });

  it("verifies the proposed fix: every proven probe now fails and own access still works", () => {
    expect(report.verification?.status).toBe("VERIFIED");
    expect(report.verification?.subjects.map((s) => s.status)).toEqual(Array(6).fill("VERIFIED"));
    expect(report.findings.filter((f) => f.tier === "PROVEN").every((f) => f.fixStatus === "verified")).toBe(true);
    expect(report.verification?.applyErrors).toEqual([]);
  });

  it("records the exact SQL, the claims and a hash for each proof", () => {
    const p = report.proofs.find((x) => x.id === "public.notes/cross-read");
    expect(p?.sql).toContain('WHERE "user_id"::text = \'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\'');
    expect(JSON.parse(p?.claims ?? "{}").sub).toBe("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    expect(p?.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("seeds a row per user in every table, including the profile rows a trigger creates", () => {
    for (const s of report.seeding) expect(s).toMatchObject({ status: "ok", rowsUserA: 1, rowsUserB: 1 });
  });

  it("is deterministic: a second run gives identical bytes", async () => {
    const again = await analyze(await exampleFiles("vulnerable-app"));
    expect(renderJson(again)).toBe(renderJson(report));
  });

  it("renders plain-language and Markdown reports without raw control characters", () => {
    for (const text of [renderPlain(report), renderMarkdown(report)]) {
      expect(text).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/);
      expect(text).toContain("public.documents");
    }
  });

  it("cross-checks the real static auditor report against the proofs", async () => {
    const audit = parseAuditReport(readFileSync("examples/vulnerable-app/saas-audit.json", "utf8"));
    if (!audit.ok) throw new Error(audit.error);
    const withAudit = await analyze(await exampleFiles("vulnerable-app"), { audit: audit.value });
    const byRule = (needle: string) => withAudit.audit?.findings.find((f) => f.title.includes(needle));
    expect(byRule("Anyone can use tickets")?.proofStatus).toBe("PROVEN");
    expect(byRule("Notes are viewable by everyone")?.proofStatus).toBe("PROVEN");
    expect(byRule("public.profiles has no row level security")?.proofStatus).toBe("PROVEN");
    expect(byRule("Owners can edit documents")?.proofStatus).toBe("NOT_REPRODUCED");
    expect(withAudit.audit?.priorityTables[0]).toBe("public.profiles");
  });
});

describe.skipIf(!haveDatabase)("examples/fixed-app against real PostgreSQL", async () => {
  const report = await analyze(await exampleFiles("fixed-app"));

  it("finds every table and the view clean and proposes nothing", () => {
    expect(report.summary).toMatchObject({ subjects: 7, proven: 0, clean: 7 });
    expect(report.fix).toBeNull();
    expect(report.verification).toBeNull();
  });

  it("shows that every exploit probe was refused and own access works", () => {
    expect(report.proofs.filter((p) => p.intent === "exploit" && p.verdict !== "NOT_REPRODUCED").map((p) => p.id)).toEqual([]);
    expect(report.proofs.filter((p) => p.intent === "legitimate" && p.verdict !== "ACCESS_OK").map((p) => `${p.id}: ${p.reason}`)).toEqual([]);
  });
});

describe.skipIf(!haveDatabase)("other schemas against real PostgreSQL", () => {
  it("fixes a tenant-owned table through a membership table", async () => {
    const report = await analyze([
      sqlFile(
        "m/001.sql",
        `create table public.members (user_id uuid not null references auth.users (id), org_id uuid not null, primary key (user_id, org_id));
create table public.org_docs (id uuid primary key default gen_random_uuid(), org_id uuid not null, title text not null);`,
      ),
    ]);
    expect(report.summary.proven).toBe(2);
    expect(report.fix?.needsDecision).toEqual([]);
    expect(report.fix?.statements.join("\n")).toContain('"org_id" IN (SELECT m."org_id" FROM "public"."members" m');
    expect(report.verification?.status).toBe("VERIFIED");
  });

  it("leaves a table without an owner column for a human decision and never calls it verified", async () => {
    const report = await analyze([sqlFile("m/001.sql", "create table public.plans (id uuid primary key default gen_random_uuid(), name text not null);")]);
    expect(report.findings[0]).toMatchObject({ tier: "PROVEN", severity: "critical", fixStatus: "needs-decision" });
    expect(report.verification?.status).toBe("NOT_VERIFIED");
  });

  it("records an honest INCONCLUSIVE when a row cannot be seeded", async () => {
    const report = await analyze([
      sqlFile("m/001.sql", "create table public.codes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), code text not null check (code ~ '^[A-Z]{3}[0-9]{3}$'));"),
    ]);
    expect(report.seeding[0]).toMatchObject({ table: "public.codes", status: "failed", rowsUserA: 0, rowsUserB: 0 });
    expect(report.seeding[0]?.reason).toContain("23514");
    expect(report.proofs.find((p) => p.id === "public.codes/anon-read")).toMatchObject({ verdict: "INCONCLUSIVE" });
    expect(report.findings[0]?.tier).not.toBe("CLEAN");
  });

  it("records rejected statements, keeps going and flags a table that could not be created", async () => {
    const report = await analyze([
      sqlFile("m/001.sql", "create table public.ok1 (id uuid primary key, user_id uuid references auth.users (id));\ncreate table public.broken (id uuid primary key, user_id uuid references public.missing (id));\nalter table public.ok1 enable row level security;\n"),
    ]);
    expect(report.migrationErrors).toEqual([expect.objectContaining({ file: "m/001.sql", line: 2, sqlstate: "42P01" })]);
    expect(report.warnings.some((w) => w.includes("public.broken") && w.includes("does not have it"))).toBe(true);
    expect(report.findings.some((f) => f.subject === "public.ok1")).toBe(true);
  });

  it("stops a statement that runs too long and carries on", async () => {
    const started = Date.now();
    const report = await analyze([sqlFile("m/001.sql", "select pg_sleep(30);\ncreate table public.t1 (id uuid primary key, user_id uuid references auth.users (id));")], {}, 1000);
    expect(Date.now() - started).toBeLessThan(20_000);
    expect(report.migrationErrors).toEqual([expect.objectContaining({ sqlstate: "57014" })]);
    expect(report.findings.some((f) => f.subject === "public.t1")).toBe(true);
  });

  it("copes with hostile identifiers and never emits a raw escape sequence", async () => {
    const report = await analyze([
      sqlFile(
        "m/001.sql",
        `create table public."we""ird; drop table x; --" (id uuid primary key, user_id uuid references auth.users (id), "co l\`umn" text);
create table public.U&"esc\\001b[31mred" (id uuid primary key, user_id uuid references auth.users (id));
create policy "pol|icy <b>x</b> \`\`\`" on public."we""ird; drop table x; --" for select using (true);
alter table public."we""ird; drop table x; --" enable row level security;`,
      ),
    ]);
    for (const text of [renderPlain(report), renderMarkdown(report)]) {
      expect(text).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/);
    }
    expect(report.findings.length).toBeGreaterThanOrEqual(2);
    expect(report.fix?.statements.some((s) => /[\u0000-\u001f\u007f]/.test(s))).toBe(false);
    expect(report.fix?.sql).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
    // the generated fix, with hostile identifiers quoted, applies cleanly and does what it says
    expect(report.verification?.applyErrors).toEqual([]);
    expect(report.verification?.subjects.every((v) => v.status === "VERIFIED")).toBe(true);
  });

  it("does not let a migration that rewrites the roles fool the later probes", async () => {
    const report = await analyze([
      sqlFile("m/001.sql", "create table public.t2 (id uuid primary key, user_id uuid references auth.users (id));\nalter table public.t2 enable row level security;\nset role anon;\nselect 1;\nreset role;\n"),
    ]);
    expect(report.findings.find((f) => f.subject === "public.t2")?.tier).toBe("CLEAN");
  });
});
