import { describe, expect, it } from "vitest";
import { analyzeRls, type AnalyzeRequest } from "../../src/application/analyze.js";
import type { Clock, CreatedSandbox, Sandbox, SandboxProvider } from "../../src/application/ports.js";
import { SandboxError } from "../../src/application/ports.js";
import { parseAuditReport } from "../../src/domain/audit/import.js";
import { renderJson } from "../../src/application/report/json.js";
import { ALL, col, model, notes, OWN, pk, policy, tbl, userFk } from "../helpers/model.js";
import { ModelSandbox } from "../helpers/model-sandbox.js";
import { readFileSync } from "node:fs";

const clock: Clock = { now: () => 0 };
const tool = { name: "proof-audit", version: "0.0.0-test" };

const open = notes({ rlsEnabled: false, policies: [], privileges: { anon: ALL, authenticated: ALL } });
const good = notes();
const docs = tbl("docs", [pk(), userFk(), col("body", "text")], { policies: [policy("own", "all", ["authenticated"], OWN, OWN)], privileges: { anon: [], authenticated: ALL } });

function providerFor(sandbox: Sandbox): SandboxProvider & { created: number } {
  const p = {
    created: 0,
    async create(): Promise<CreatedSandbox> {
      p.created += 1;
      return { sandbox, environment: { mode: "url", image: "loopback" } };
    },
  };
  return p;
}

const request = (over: Partial<AnalyzeRequest> = {}): AnalyzeRequest => ({
  files: [{ path: "supabase/migrations/001.sql", content: "create table public.notes (id uuid primary key, user_id uuid, title text);\nalter table public.notes enable row level security;\n", bytes: 100 }],
  loadWarnings: [],
  inputsComplete: true,
  audit: null,
  proposeFix: true,
  tool,
  ...over,
});

async function run(options: ConstructorParameters<typeof ModelSandbox>[0], over: Partial<AnalyzeRequest> = {}, c: Clock = clock) {
  const sandbox = new ModelSandbox(options);
  const provider = providerFor(sandbox);
  const report = await analyzeRls(request(over), { provider, clock: c });
  return { report, sandbox, provider };
}

describe("analyzeRls on a vulnerable schema", () => {
  const options = { model: model([open, docs]), fixed: model([good, docs]) };

  it("proves the open table and calls the protected one clean", async () => {
    const { report } = await run(options);
    const byTier = Object.fromEntries(report.findings.map((f) => [f.subject, f.tier]));
    expect(byTier).toEqual({ "public.notes": "PROVEN", "public.docs": "CLEAN" });
    expect(report.summary).toMatchObject({ subjects: 2, proven: 1, clean: 1 });
  });

  it("records one hashed proof per probe with the exact SQL", async () => {
    const { report } = await run(options);
    const anon = report.proofs.find((p) => p.id === "public.notes/anon-read");
    expect(anon).toMatchObject({ verdict: "PROVEN_VULNERABLE", sql: 'SELECT * FROM "public"."notes"', phase: "before" });
    expect(anon?.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifies the proposed fix on a fresh copy and says so", async () => {
    const { report, sandbox } = await run(options);
    expect(report.verification?.status).toBe("VERIFIED");
    expect(report.findings[0]).toMatchObject({ fixStatus: "verified" });
    expect(report.fix?.statements[0]).toBe('ALTER TABLE "public"."notes" ENABLE ROW LEVEL SECURITY');
    expect(sandbox.forks).toBe(1);
    expect(report.verification?.after.every((p) => p.phase === "after")).toBe(true);
  });

  it("applies the shim, then the migrations, then the users", async () => {
    const { sandbox } = await run(options);
    expect(sandbox.applied[0]).toContain("CREATE ROLE anon");
    expect(sandbox.applied.some((s) => s.startsWith("create table public.notes"))).toBe(true);
    expect(sandbox.applied.some((s) => s.startsWith("INSERT INTO auth.users"))).toBe(true);
  });

  it("destroys the sandbox and is deterministic", async () => {
    const a = await run(options);
    const b = await run(options);
    expect(a.sandbox.disposed).toBe(true);
    expect(renderJson(a.report)).toBe(renderJson(b.report));
  });

  it("does not propose a fix when asked not to", async () => {
    const { report, sandbox } = await run(options, { proposeFix: false });
    expect(report.fix).toBeNull();
    expect(report.verification).toBeNull();
    expect(sandbox.forks).toBe(0);
    expect(report.findings[0]?.fixStatus).toBe("not-proposed");
  });
});

describe("analyzeRls fix outcomes", () => {
  const lockedOut = notes({ policies: [policy("nobody", "all", ["authenticated"], "false", "false")], privileges: { anon: [], authenticated: ALL } });
  const stillOpen = notes({ rlsEnabled: true, policies: [policy("everyone", "all", ["public"], "true", "true")] });

  it("refuses to call a fix verified when it locks out the legitimate user", async () => {
    const { report } = await run({ model: model([open]), fixed: model([lockedOut]) });
    expect(report.verification?.status).toBe("BREAKS_ACCESS");
    expect(report.findings[0]?.fixStatus).toBe("breaks-access");
    expect(report.verification?.subjects[0]?.broken.length).toBeGreaterThan(0);
  });

  it("refuses to call a fix verified when the hole is still open", async () => {
    const { report } = await run({ model: model([open]), fixed: model([stillOpen]) });
    expect(report.verification?.status).toBe("NOT_VERIFIED");
    expect(report.findings[0]?.fixStatus).toBe("still-vulnerable");
  });

  it("reports a fix whose statements the database rejected", async () => {
    const { report } = await run({ model: model([open]), fixed: model([good]), rejectStatement: /ENABLE ROW LEVEL SECURITY/ }, { files: [{ path: "m.sql", content: "select 1;", bytes: 9 }] });
    expect(report.verification?.status).toBe("FIX_FAILED");
    expect(report.verification?.applyErrors[0]?.sqlstate).toBe("42P01");
  });

  it("leaves a table without an owner column for a human decision", async () => {
    const plans = tbl("plans", [pk(), col("name", "text")], { rlsEnabled: false, privileges: { anon: ALL, authenticated: ALL } });
    const { report } = await run({ model: model([plans]), fixed: model([plans]) });
    expect(report.fix?.needsDecision[0]?.subject).toBe("public.plans");
    expect(report.findings[0]?.fixStatus).toBe("needs-decision");
    expect(report.verification?.status).toBe("NOT_VERIFIED");
  });
});

describe("analyzeRls on a clean schema", () => {
  it("reports everything clean and proposes nothing", async () => {
    const { report, sandbox } = await run({ model: model([good, docs]) });
    expect(report.summary).toMatchObject({ proven: 0, clean: 2 });
    expect(report.fix).toBeNull();
    expect(report.verification).toBeNull();
    expect(sandbox.forks).toBe(0);
    expect(report.complete).toBe(true);
  });

  it("lists what was not checked", async () => {
    const { report } = await run({ model: model([good]) });
    expect(report.notChecked.join(" ")).toContain("not a penetration test");
  });
});

describe("analyzeRls robustness", () => {
  it("records rejected migration statements with file and line", async () => {
    const { report } = await run({ model: model([good]), rejectStatement: /alter table/i });
    expect(report.migrationErrors).toEqual([expect.objectContaining({ file: "supabase/migrations/001.sql", line: 2, sqlstate: "42P01" })]);
    expect(report.warnings.join("\n")).not.toContain("undefined");
  });

  it("flags a table the migrations declare but the database lacks", async () => {
    const { report } = await run({ model: model([docs]), rejectStatement: /create table public\.notes/i });
    expect(report.warnings.some((w) => w.includes("public.notes") && w.includes("does not have it"))).toBe(true);
    const f = report.findings.find((x) => x.subject === "public.notes");
    expect(f?.tier).toBe("INCONCLUSIVE");
    expect(f?.inconclusive[0]?.reason).toContain("could not be created");
  });

  it("marks the report incomplete when the clock passes the budget and records unrun probes", async () => {
    let t = 0;
    const ticking: Clock = { now: () => (t += 400_000) };
    const { report } = await run({ model: model([open]), fixed: model([good]) }, {}, ticking);
    expect(report.complete).toBe(false);
    expect(report.verification?.after.some((p) => p.observation.status === "not-run" && p.reason.includes("budget"))).toBe(true);
    expect(report.verification?.status).not.toBe("VERIFIED");
  });

  it("marks the report incomplete when input was capped", async () => {
    const { report } = await run({ model: model([good]) }, { inputsComplete: false });
    expect(report.complete).toBe(false);
    expect(report.warnings.some((w) => w.includes("cap"))).toBe(true);
  });

  it("destroys the sandbox when a step throws", async () => {
    const sandbox = new ModelSandbox({ model: model([good]) });
    sandbox.catalog = async () => {
      throw new Error("boom");
    };
    await expect(analyzeRls(request(), { provider: providerFor(sandbox), clock })).rejects.toThrow("boom");
    expect(sandbox.disposed).toBe(true);
  });

  it("fails clearly when the compatibility layer cannot be set up", async () => {
    const sandbox = new ModelSandbox({ model: model([good]), rejectStatement: /CREATE ROLE/ });
    await expect(analyzeRls(request(), { provider: providerFor(sandbox), clock })).rejects.toBeInstanceOf(SandboxError);
    expect(sandbox.disposed).toBe(true);
  });

  it("rejects a catalog it cannot read", async () => {
    const sandbox = new ModelSandbox({ model: model([good]) });
    sandbox.catalog = async () => ({ nonsense: true });
    await expect(analyzeRls(request(), { provider: providerFor(sandbox), clock })).rejects.toThrow(/catalog/);
  });

  it("records seeding problems per table", async () => {
    const sandbox = new ModelSandbox({ model: model([good]) });
    sandbox.applyFirstSuccess = async (groups) => groups.map(() => ({ ok: false, attempt: null, sqlstate: "23514", message: "check violated" }));
    sandbox.scalars = async (qs) => qs.map(() => ({ ok: true as const, value: 0 }));
    const report = await analyzeRls(request(), { provider: providerFor(sandbox), clock });
    expect(report.seeding[0]).toMatchObject({ table: "public.notes", status: "failed" });
    expect(report.seeding[0]?.reason).toContain("23514");
    const anon = report.proofs.find((p) => p.id === "public.notes/anon-read");
    expect(anon?.verdict).toBe("INCONCLUSIVE");
    expect(report.notChecked.join(" ")).toContain("public.notes");
  });
});

describe("analyzeRls with a static audit report", () => {
  it("attaches proof status to each static finding and orders probes by priority", async () => {
    const audit = parseAuditReport(readFileSync(new URL("../fixtures/audit/vibe-app.json", import.meta.url), "utf8"));
    if (!audit.ok) throw new Error(audit.error);
    const t1 = tbl("notes", [pk(), userFk()], { rlsEnabled: false, policies: [] });
    const { report } = await run({ model: model([t1]) }, { audit: audit.value });
    expect(report.audit?.findings.length).toBeGreaterThan(0);
    expect(report.audit?.findings.some((f) => f.proofStatus === "PROVEN")).toBe(true);
    expect(report.audit?.findings.some((f) => f.proofStatus === "STATIC_ONLY")).toBe(true);
    expect(report.audit?.outOfScope).toBeGreaterThan(0);
  });
});
