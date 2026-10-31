import { buildFindings } from "../domain/analysis/findings.js";
import type { AnalysisReport, Finding, InputFileRecord, SeedTableResult } from "../domain/analysis/types.js";
import { correlateAudit } from "../domain/audit/correlate.js";
import { auditPriorityTables, type ParsedAudit } from "../domain/audit/import.js";
import { generateFix } from "../domain/fix/generate.js";
import { applyFixOutcome } from "../domain/fix/outcome.js";
import { verifyFix } from "../domain/fix/verify.js";
import { sha256Hex } from "../domain/hash/sha256.js";
import { LIMITS } from "../domain/limits.js";
import { planProbes } from "../domain/proof/plan.js";
import { qualifiedKey, type SchemaModel, type Table } from "../domain/schema/model.js";
import { parseMigrations } from "../domain/sql/parser.js";
import { NOT_CHECKED } from "./not-checked.js";
import { checkPlatform, prepareSandbox } from "./prepare.js";
import { assessIntegrity } from "../domain/integrity/assess.js";
import type { IntegrityViolation } from "../domain/analysis/types.js";
import { runProbes } from "./probes.js";
import type { Clock, LoadedFile, SandboxProvider } from "./ports.js";

export interface AnalyzeRequest {
  readonly files: readonly LoadedFile[];
  /** Warnings from reading the files (skipped, too large, ...). */
  readonly loadWarnings: readonly string[];
  /** False when reading the files dropped some input. */
  readonly inputsComplete: boolean;
  readonly audit: ParsedAudit | null;
  /** Propose a fix and verify it. */
  readonly proposeFix: boolean;
  readonly tool: { readonly name: string; readonly version: string };
}

export interface AnalyzeDeps {
  readonly provider: SandboxProvider;
  readonly clock: Clock;
}

export function inputRecords(files: readonly LoadedFile[]): InputFileRecord[] {
  return files.map((f) => ({ path: f.path, sha256: sha256Hex(f.content), bytes: f.bytes }));
}

/** Tables the migrations declare that the database does not have: their CREATE TABLE failed or was skipped. */
function missingFromDatabase(statics: SchemaModel, live: SchemaModel): readonly Table[] {
  const have = new Set(live.tables.map((t) => qualifiedKey(t.name)));
  return statics.tables.filter((t) => !have.has(qualifiedKey(t.name)));
}

/**
 * The whole analysis: read the migrations, build the throwaway database, seed it, run the probes, classify,
 * propose a fix and re-run the same probes against a fresh copy. The sandbox is always destroyed.
 */
export async function analyzeRls(request: AnalyzeRequest, deps: AnalyzeDeps): Promise<AnalysisReport> {
  const parsed = parseMigrations(request.files.map((f) => ({ path: f.path, content: f.content })));
  const warnings: string[] = [...request.loadWarnings, ...parsed.warnings.map((w) => (w.line > 0 ? `${w.file}:${w.line}: ${w.message}` : `${w.file}: ${w.message}`))];
  const budget = { clock: deps.clock, deadline: deps.clock.now() + LIMITS.runTimeoutMs };
  const priority = request.audit ? auditPriorityTables(request.audit) : [];

  const created = await deps.provider.create();
  try {
    const prepared = await prepareSandbox(created.sandbox, parsed.statements);
    warnings.push(...prepared.warnings);

    const probes = planProbes({ model: prepared.model, seed: prepared.seedCounts, views: prepared.viewCounts, priority });
    const before = await runProbes(created.sandbox, probes, "before", budget);

    const missing = missingFromDatabase(parsed.model, prepared.model);
    const findingModel: SchemaModel = { tables: [...prepared.model.tables, ...missing], views: prepared.model.views };
    const changes: IntegrityViolation[] = [...prepared.platformChanges, ...(await checkPlatform(created.sandbox, prepared.baseline, "after the probes"))];
    let integrity = assessIntegrity(prepared.attempts, prepared.outcomes, changes);
    const quarantineReason = "the migrations touched the test environment the results depend on (see the integrity section)";
    const judge = (): readonly Finding[] =>
      buildFindings(findingModel, before.proofs, priority, integrity.status === "INTACT" ? null : quarantineReason).map((f) => {
        if (!missing.some((t) => qualifiedKey(t.name) === f.subject)) return f;
        const reason = "the table could not be created in the test database (see the rejected migration statements), so nothing could be probed";
        return { ...f, inconclusive: [{ id: f.subject, reason }] };
      });
    let findings: readonly Finding[] = judge();
    for (const t of missing) warnings.push(`The migrations declare ${qualifiedKey(t.name)} but the test database does not have it.`);

    let fix: AnalysisReport["fix"] = null;
    let verification: AnalysisReport["verification"] = null;
    let timedOut = before.timedOut;
    if (request.proposeFix && integrity.status === "INTACT" && findings.some((f) => f.tier === "PROVEN")) {
      fix = generateFix(prepared.model, findings);
      const copy = await created.sandbox.fork();
      try {
        const applied = fix.statements.length > 0 ? await copy.apply(fix.statements) : [];
        const applyErrors = applied.flatMap((o, i) => (o.ok ? [] : [{ statement: fix?.statements[i] ?? "", sqlstate: o.sqlstate ?? "?????", message: o.message ?? "" }]));
        const after = await runProbes(copy, probes, "after", budget);
        timedOut = timedOut || after.timedOut;
        changes.push(...(await checkPlatform(copy, prepared.baseline, "after the fix probes")));
        verification = verifyFix(before.proofs, after.proofs, fix, applyErrors);
      } finally {
        await copy.dispose();
      }
      integrity = assessIntegrity(prepared.attempts, prepared.outcomes, changes);
      if (integrity.status === "INTACT") findings = applyFixOutcome(findings, fix, verification);
      else {
        findings = judge();
        fix = null;
        verification = null;
      }
    }

    const seeding: SeedTableResult[] = [...prepared.seeding].sort((a, b) => (a.table < b.table ? -1 : 1));
    const notChecked = [...NOT_CHECKED];
    const unseeded = seeding.filter((s) => s.status !== "ok");
    if (unseeded.length > 0) notChecked.push(`Probes that need seeded rows could not run for: ${unseeded.map((s) => s.table).join(", ")} (see the test-data section).`);
    if (prepared.migrationErrors.length > 0) notChecked.push(`${prepared.migrationErrors.length} migration statement(s) were rejected by the test database, so the schema it holds may differ from yours.`);
    if (timedOut) warnings.push("The run time budget was used up; some probes were not run.");
    if (!request.inputsComplete || !parsed.complete) warnings.push("Some input was not read because of a size or count cap; results may be partial.");

    const proven = findings.filter((f) => f.tier === "PROVEN").length;
    return {
      tool: request.tool,
      inputs: inputRecords(request.files),
      environment: { ...created.environment, postgresVersion: prepared.serverVersion },
      complete: request.inputsComplete && parsed.complete && !prepared.truncated && !timedOut,
      integrity,
      summary: {
        subjects: findings.length,
        proven,
        suspected: findings.filter((f) => f.tier === "SUSPECTED").length,
        clean: findings.filter((f) => f.tier === "CLEAN").length,
        inconclusive: findings.filter((f) => f.tier === "INCONCLUSIVE").length,
        probesRun: before.proofs.filter((p) => p.observation.status !== "not-run").length,
        probesProven: before.proofs.filter((p) => p.verdict === "PROVEN_VULNERABLE").length,
      },
      findings,
      proofs: before.proofs,
      seeding,
      fix,
      verification,
      audit: request.audit ? correlateAudit(request.audit, { findings, proofs: before.proofs, subjects: findingModel.tables.map((t) => qualifiedKey(t.name)) }) : null,
      migrationErrors: prepared.migrationErrors,
      warnings,
      notChecked,
    };
  } finally {
    await created.sandbox.dispose();
  }
}
