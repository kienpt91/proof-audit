import type { FixPlan } from "../domain/analysis/types.js";
import { decodeProofsJsonl } from "../domain/evidence/proofs.js";
import { verifyFix } from "../domain/fix/verify.js";
import { sha256Hex } from "../domain/hash/sha256.js";
import type { Probe, Proof } from "../domain/proof/types.js";
import { parseMigrations } from "../domain/sql/parser.js";
import { prepareSandbox } from "./prepare.js";
import { runProbes } from "./probes.js";
import type { Clock, LoadedFile, Sandbox, SandboxProvider } from "./ports.js";
import { LIMITS } from "../domain/limits.js";

export interface VerifyRequest {
  readonly proofsText: string;
  /** Read one input recorded in the evidence file; null when it is missing. */
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
 * - `invalid`: the evidence file is damaged or not evidence at all.
 */
export interface VerifyResult {
  readonly status: "ok" | "mismatch" | "stale" | "invalid";
  readonly messages: readonly string[];
  readonly probesChecked: number;
}

function probeOf(p: Proof): Probe {
  return {
    id: p.id,
    subject: p.subject,
    subjectKind: p.subjectKind,
    kind: p.kind,
    intent: p.intent,
    command: p.command,
    actor: p.actor,
    role: p.role,
    claims: p.claims,
    sql: p.sql,
    title: p.title,
    targetRows: p.targetRows,
    blockedReason: p.observation.status === "not-run" ? p.observation.reason : null,
  };
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

async function freshSandbox(provider: SandboxProvider, files: readonly LoadedFile[]): Promise<{ sandbox: Sandbox; image: string; errors: number; dispose: () => Promise<void> }> {
  const created = await provider.create();
  try {
    const parsed = parseMigrations(files.map((f) => ({ path: f.path, content: f.content })));
    const prepared = await prepareSandbox(created.sandbox, parsed.statements);
    return { sandbox: created.sandbox, image: created.environment.image, errors: prepared.migrationErrors.length, dispose: () => created.sandbox.dispose() };
  } catch (e) {
    await created.sandbox.dispose();
    throw e;
  }
}

/** Replay recorded evidence. Nothing here trusts the file beyond its hashes: the database decides every verdict. */
export async function verifyEvidence(request: VerifyRequest, deps: VerifyDeps): Promise<VerifyResult> {
  const decoded = decodeProofsJsonl(request.proofsText);
  if (!decoded.ok) return { status: "invalid", messages: [decoded.error], probesChecked: 0 };
  const { meta, proofs } = decoded.value;
  const budget = { clock: deps.clock, deadline: deps.clock.now() + LIMITS.runTimeoutMs };
  const recordedBefore = proofs.filter((p) => p.phase === "before");
  const recordedAfter = proofs.filter((p) => p.phase === "after");

  if (request.against) {
    const env = await freshSandbox(deps.provider, request.against);
    try {
      const replay = await runProbes(env.sandbox, recordedBefore.map(probeOf), "after", budget);
      const subjects = [...new Set(recordedBefore.filter((p) => p.verdict === "PROVEN_VULNERABLE").map((p) => p.subject))];
      const plan: FixPlan = { statements: [], sql: "", covered: subjects, needsDecision: [] };
      const v = verifyFix(recordedBefore, replay.proofs, plan, []);
      const bad = v.subjects.filter((s) => s.status !== "VERIFIED").map((s) => `${s.subject}: ${s.status} (${s.reason})`);
      const messages = v.status === "VERIFIED" || v.status === "NOT_APPLICABLE" ? [`${subjects.length === 1 ? "the previously proven subject is" : `all ${subjects.length} previously proven subjects are`} now closed and legitimate access still works`] : bad;
      return { status: v.status === "VERIFIED" || v.status === "NOT_APPLICABLE" ? "ok" : "mismatch", messages, probesChecked: replay.proofs.length };
    } finally {
      await env.dispose();
    }
  }

  const loaded: LoadedFile[] = [];
  const stale: string[] = [];
  for (const input of meta.inputs) {
    const file = await request.readInput(input.path);
    if (!file) stale.push(`${input.path}: input file not found`);
    else if (sha256Hex(file.content) !== input.sha256) stale.push(`${input.path}: input changed since the evidence was recorded`);
    else loaded.push({ ...file, path: input.path });
  }
  if (stale.length > 0) return { status: "stale", messages: stale, probesChecked: 0 };

  const env = await freshSandbox(deps.provider, loaded);
  try {
    const messages: string[] = [];
    if (env.image !== meta.image) messages.push(`note: the evidence was recorded on ${meta.image}, this run uses ${env.image}`);
    const replay = await runProbes(env.sandbox, recordedBefore.map(probeOf), "before", budget);
    messages.push(...differences(recordedBefore, replay.proofs, "before"));
    let checked = replay.proofs.length;
    if (meta.fixStatements.length > 0) {
      const copy = await env.sandbox.fork();
      try {
        const applied = await copy.apply(meta.fixStatements);
        applied.forEach((o, i) => {
          if (!o.ok) messages.push(`fix statement ${i + 1} did not apply (${o.sqlstate ?? "?????"})`);
        });
        const after = await runProbes(copy, recordedAfter.map(probeOf), "after", budget);
        messages.push(...differences(recordedAfter, after.proofs, "after"));
        checked += after.proofs.length;
      } finally {
        await copy.dispose();
      }
    }
    const failures = messages.filter((m) => !m.startsWith("note:"));
    return { status: failures.length === 0 ? "ok" : "mismatch", messages: failures.length === 0 ? [`all ${checked} recorded probes replayed with identical results`, ...messages] : messages, probesChecked: checked };
  } finally {
    await env.dispose();
  }
}
