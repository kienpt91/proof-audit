import { buildFindings } from "../domain/analysis/findings.js";
import type { FixPlan } from "../domain/analysis/types.js";
import { decodeProofsJsonl } from "../domain/evidence/proofs.js";
import { generateFix } from "../domain/fix/generate.js";
import { verifyFix } from "../domain/fix/verify.js";
import { sha256Hex } from "../domain/hash/sha256.js";
import { assessIntegrity } from "../domain/integrity/assess.js";
import { LIMITS } from "../domain/limits.js";
import { planProbes } from "../domain/proof/plan.js";
import type { Probe, Proof } from "../domain/proof/types.js";
import { parseMigrations } from "../domain/sql/parser.js";
import { checkPlatform, prepareSandbox, type Prepared } from "./prepare.js";
import { runProbes } from "./probes.js";
import type { Clock, CreatedSandbox, LoadedFile, SandboxProvider } from "./ports.js";

export interface VerifyRequest {
  readonly proofsText: string;
  /** Read one input recorded in the evidence file; null when it is missing or not allowed. */
  readonly readInput: (path: string) => Promise<LoadedFile | null>;
  /** Migrations to test instead of the recorded ones: "has the fix been applied to my migrations?" */
  readonly against: readonly LoadedFile[] | null;
}

export interface VerifyDeps {
  readonly provider: SandboxProvider;
  readonly clock: Clock;
}

/**
 * - `ok`: every recorded expectation holds.
 * - `mismatch`: the database behaved differently from the record, or the fix did not close the holes.
 * - `stale`: the inputs changed since the evidence was written, so a replay would prove nothing about them.
 * - `invalid`: the evidence file is damaged, is not evidence of anything, or asks for SQL this tool would not have written.
 * - `integrity`: the migrations touched the test environment, so no result can be trusted.
 */
export interface VerifyResult {
  readonly status: "ok" | "mismatch" | "stale" | "invalid" | "integrity";
  readonly messages: readonly string[];
  readonly probesChecked: number;
}

const refuse = (messages: string[]): VerifyResult => ({ status: "invalid", messages, probesChecked: 0 });

interface Fresh {
  readonly created: CreatedSandbox;
  readonly prepared: Prepared;
  readonly probes: readonly Probe[];
  readonly attempted: ReturnType<typeof assessIntegrity>;
}

async function prepare(provider: SandboxProvider, files: readonly LoadedFile[]): Promise<Fresh> {
  const created = await provider.create();
  try {
    const parsed = parseMigrations(files.map((f) => ({ path: f.path, content: f.content })));
    const prepared = await prepareSandbox(created.sandbox, parsed.statements);
    const probes = planProbes({ model: prepared.model, seed: prepared.seedCounts, views: prepared.viewCounts });
    return { created, prepared, probes, attempted: assessIntegrity(prepared.attempts, prepared.outcomes, prepared.platformChanges) };
  } catch (e) {
    await created.sandbox.dispose();
    throw e;
  }
}

function differences(recorded: readonly Proof[], replayed: readonly Proof[], label: string): string[] {
  const now = new Map(replayed.map((p) => [p.id, p]));
  const out: string[] = [];
  for (const r of recorded) {
    const n = now.get(r.id);
    if (!n) out.push(`${label} ${r.id}: not replayed`);
    else if (n.hash !== r.hash) out.push(`${label} ${r.id}: recorded ${r.verdict}, replay gave ${n.verdict} (${n.reason})`);
  }
  return out;
}

/** What this tool would send for a recorded proof, or why the record asks for something else. */
function foreignProbe(recorded: Proof, planned: ReadonlyMap<string, Probe>): string | null {
  const p = planned.get(recorded.id);
  if (!p) return `${recorded.id}: this tool would not run that probe against these migrations`;
  const same =
    p.subject === recorded.subject && p.kind === recorded.kind && p.role === recorded.role && p.claims === recorded.claims && p.command === recorded.command && p.actor === recorded.actor && p.intent === recorded.intent &&
    p.targetRows === recorded.targetRows && (p.blockedReason === null) === (recorded.observation.status !== "not-run") && (p.blockedReason !== null || p.sql === recorded.sql);
  return same ? null : `${recorded.id}: the recorded SQL or claims differ from what this tool generates`;
}

/**
 * Replay recorded evidence. The file is not trusted beyond its hashes: nothing in it is executed. The probes and the fix
 * are generated again from the migrations by this tool's own planner, the record must match them statement for statement,
 * and the database decides every verdict.
 */
export async function verifyEvidence(request: VerifyRequest, deps: VerifyDeps): Promise<VerifyResult> {
  const decoded = decodeProofsJsonl(request.proofsText);
  if (!decoded.ok) return refuse([decoded.error]);
  const { meta, proofs } = decoded.value;
  const recordedBefore = proofs.filter((p) => p.phase === "before");
  const recordedAfter = proofs.filter((p) => p.phase === "after");
  if (recordedBefore.length === 0) return refuse(["the evidence contains no proofs, so there is nothing to check"]);
  const budget = { clock: deps.clock, deadline: deps.clock.now() + LIMITS.runTimeoutMs };

  if (request.against) {
    if (!recordedBefore.some((p) => p.intent === "exploit" && p.verdict === "PROVEN_VULNERABLE")) {
      return refuse(["the evidence has no proven attack, so there is nothing a fix could have closed"]);
    }
    const fresh = await prepare(deps.provider, request.against);
    try {
      const replay = await runProbes(fresh.created.sandbox, fresh.probes, "after", budget);
      const platform = [...fresh.prepared.platformChanges, ...(await checkPlatform(fresh.created.sandbox, fresh.prepared.baseline, "after the probes"))];
      const integrity = assessIntegrity(fresh.prepared.attempts, fresh.prepared.outcomes, platform);
      if (integrity.status !== "INTACT") return { status: "integrity", messages: integrity.violations.map((v) => `${v.kind}: ${v.detail}`), probesChecked: replay.proofs.length };
      const subjects = [...new Set(recordedBefore.filter((p) => p.verdict === "PROVEN_VULNERABLE").map((p) => p.subject))];
      const plan: FixPlan = { statements: [], sql: "", covered: subjects, needsDecision: [] };
      const v = verifyFix(recordedBefore, replay.proofs, plan, []);
      const ok = v.status === "VERIFIED";
      const messages = ok ? [`${subjects.length === 1 ? "the previously proven subject is" : `all ${subjects.length} previously proven subjects are`} now closed and legitimate access still works`] : v.subjects.filter((s) => s.status !== "VERIFIED").map((s) => `${s.subject}: ${s.status} (${s.reason})`);
      return { status: ok ? "ok" : "mismatch", messages, probesChecked: replay.proofs.length };
    } finally {
      await fresh.created.sandbox.dispose();
    }
  }

  const loaded: LoadedFile[] = [];
  const stale: string[] = [];
  for (const input of meta.inputs) {
    const file = await request.readInput(input.path);
    if (!file) stale.push(`${input.path}: input file not found (or outside --root)`);
    else if (sha256Hex(file.content) !== input.sha256) stale.push(`${input.path}: input changed since the evidence was recorded`);
    else loaded.push({ ...file, path: input.path });
  }
  if (stale.length > 0) return { status: "stale", messages: stale, probesChecked: 0 };

  const fresh = await prepare(deps.provider, loaded);
  try {
    const planned = new Map(fresh.probes.map((p) => [p.id, p]));
    const foreign = [...recordedBefore, ...recordedAfter].map((r) => foreignProbe(r, planned)).filter((m): m is string => m !== null);
    if (foreign.length > 0) return refuse(["the evidence asks for SQL this tool would not have generated, so nothing was run", ...foreign.slice(0, 10)]);

    const messages: string[] = [];
    if (fresh.created.environment.image !== meta.image) messages.push(`note: the evidence was recorded on ${meta.image}, this run uses ${fresh.created.environment.image}`);
    const wanted = new Set(recordedBefore.map((p) => p.id));
    const replay = await runProbes(fresh.created.sandbox, fresh.probes.filter((p) => wanted.has(p.id)), "before", budget);
    messages.push(...differences(recordedBefore, replay.proofs, "before"));
    let checked = replay.proofs.length;
    if (messages.some((m) => !m.startsWith("note:"))) return { status: "mismatch", messages, probesChecked: checked };
    const changes = [...fresh.prepared.platformChanges, ...(await checkPlatform(fresh.created.sandbox, fresh.prepared.baseline, "after the probes"))];

    const expectedFix = generateFix(fresh.prepared.model, buildFindings(fresh.prepared.model, replay.proofs)).statements;
    if (JSON.stringify(expectedFix) !== JSON.stringify(meta.fixStatements)) {
      return refuse(["the recorded fix is not the fix this tool generates for these migrations, so it was not applied"]);
    }
    if (meta.fixStatements.length > 0) {
      const copy = await fresh.created.sandbox.fork();
      try {
        const applied = await copy.apply(meta.fixStatements);
        applied.forEach((o, i) => {
          if (!o.ok) messages.push(`fix statement ${i + 1} did not apply (${o.sqlstate ?? "?????"})`);
        });
        const afterWanted = new Set(recordedAfter.map((p) => p.id));
        const after = await runProbes(copy, fresh.probes.filter((p) => afterWanted.has(p.id)), "after", budget);
        messages.push(...differences(recordedAfter, after.proofs, "after"));
        checked += after.proofs.length;
        changes.push(...(await checkPlatform(copy, fresh.prepared.baseline, "after the fix probes")));
      } finally {
        await copy.dispose();
      }
    }
    const integrity = assessIntegrity(fresh.prepared.attempts, fresh.prepared.outcomes, changes);
    if (integrity.status !== "INTACT") return { status: "integrity", messages: integrity.violations.map((v) => `${v.kind}: ${v.detail}`), probesChecked: checked };
    const failures = messages.filter((m) => !m.startsWith("note:"));
    return { status: failures.length === 0 ? "ok" : "mismatch", messages: failures.length === 0 ? [`all ${checked} recorded probes replayed with identical results`, ...messages] : messages, probesChecked: checked };
  } finally {
    await fresh.created.sandbox.dispose();
  }
}
