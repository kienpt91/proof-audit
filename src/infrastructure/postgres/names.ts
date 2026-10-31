import { randomBytes } from "node:crypto";
import type { SandboxNaming } from "./sandbox.js";

/** Fresh database names. The only randomness in the tool, and it never reaches a report. */
export function randomNaming(maintenanceDatabase: string, statementTimeoutMs?: number): SandboxNaming {
  return { nextName: () => `proof_audit_${randomBytes(6).toString("hex")}`, maintenanceDatabase, ...(statementTimeoutMs === undefined ? {} : { statementTimeoutMs }) };
}
