import { array, object, string, type Validator } from "../validate.js";
import type { IntegrityViolation } from "../analysis/types.js";
import type { Result } from "../result.js";

/**
 * What the platform part of the sandbox looks like: the `auth.*` shim functions (owner, definer flag, settings,
 * hash of the body), the roles and their attributes, role memberships, per-database and per-role settings and
 * event triggers. Read by the database owner before the migrations, after them and after the probes. Nothing
 * the migrations can legitimately do changes it.
 */
export interface FingerprintEntry {
  readonly key: string;
  readonly value: string;
}

export type Fingerprint = readonly FingerprintEntry[];

const entry: Validator<FingerprintEntry> = object({ key: string({ max: 500, min: 1 }), value: string({ max: 2000 }) });
const fingerprint: Validator<{ entries: FingerprintEntry[] }> = object({ entries: array(entry, { max: 2000 }) });

export function parseFingerprint(value: unknown): Result<Fingerprint, string> {
  const r = fingerprint(value, "fingerprint");
  return r.ok ? { ok: true, value: [...r.value.entries].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)) } : r;
}

/** Everything that differs between two fingerprints, as violations. Equal fingerprints give an empty list. */
export function compareFingerprints(before: Fingerprint, after: Fingerprint, when: string): IntegrityViolation[] {
  const a = new Map(before.map((e) => [e.key, e.value]));
  const b = new Map(after.map((e) => [e.key, e.value]));
  const out: IntegrityViolation[] = [];
  const push = (detail: string): void => void out.push({ kind: "platform-changed", detail: `${detail} (${when})`, file: null, line: null, outcome: "state-changed" });
  for (const [key, value] of a) {
    if (!b.has(key)) push(`${key} was removed`);
    else if (b.get(key) !== value) push(`${key} changed`);
  }
  for (const key of b.keys()) if (!a.has(key)) push(`${key} appeared`);
  return out.sort((x, y) => (x.detail < y.detail ? -1 : x.detail > y.detail ? 1 : 0));
}
