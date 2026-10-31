import type { Phase, Probe, ProbeObservation, Proof } from "../domain/proof/types.js";
import { recordProof } from "../domain/proof/verdict.js";
import type { Clock, Sandbox } from "./ports.js";

const BATCH = 20;

export interface Budget {
  readonly clock: Clock;
  /** Clock value after which no new batch starts. */
  readonly deadline: number;
}

export interface ProbeRunResult {
  readonly proofs: readonly Proof[];
  /** True when the time budget ran out and some probes were recorded as not run. */
  readonly timedOut: boolean;
}

/** Run every runnable probe in small batches and record a proof for each probe, in probe order. */
export async function runProbes(sandbox: Sandbox, probes: readonly Probe[], phase: Phase, budget: Budget): Promise<ProbeRunResult> {
  const observed = new Map<string, ProbeObservation>();
  const runnable = probes.filter((p) => p.blockedReason === null);
  let timedOut = false;
  for (let i = 0; i < runnable.length; i += BATCH) {
    const batch = runnable.slice(i, i + BATCH);
    if (budget.clock.now() > budget.deadline) {
      timedOut = true;
      for (const p of batch) observed.set(p.id, { status: "not-run", reason: "the run time budget was used up before this probe ran" });
      continue;
    }
    const results = await sandbox.run(batch.map((p) => ({ role: p.role, claims: p.claims, sql: p.sql })));
    batch.forEach((p, j) => {
      observed.set(p.id, results[j] ?? { status: "not-run", reason: "the sandbox returned no result for this probe" });
    });
  }
  const proofs = probes.map((p) => recordProof(p, observed.get(p.id) ?? { status: "not-run", reason: "not run" }, phase));
  return { proofs, timedOut };
}
