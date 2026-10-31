import type { IntegrityReport, IntegrityViolation } from "../analysis/types.js";
import type { TamperAttempt } from "./attempts.js";

/**
 * Combine what the migration text tried with what the database did. An attempt whose statement the database
 * refused is `blocked`, one it accepted is `succeeded`; without an outcome it stays `unknown`. Fingerprint
 * differences arrive already as violations.
 */
export function assessIntegrity(
  attempts: readonly TamperAttempt[],
  outcomes: ReadonlyMap<string, boolean>,
  changes: readonly IntegrityViolation[],
): IntegrityReport {
  const fromAttempts: IntegrityViolation[] = attempts.map((a) => {
    const ok = outcomes.get(`${a.file}:${a.line}`);
    return { kind: a.kind, detail: a.detail, file: a.file, line: a.line, outcome: ok === undefined ? "unknown" : ok ? "succeeded" : "blocked" };
  });
  const violations = [...fromAttempts, ...changes];
  return { status: violations.length === 0 ? "INTACT" : "INTEGRITY_VIOLATION", violations };
}

export const INTACT: IntegrityReport = { status: "INTACT", violations: [] };
