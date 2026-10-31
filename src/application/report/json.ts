import type { AnalysisReport } from "../../domain/analysis/types.js";

/** Documented top-level layout, in the order the keys appear in the output. */
const TOP_LEVEL_ORDER = [
  "tool",
  "inputs",
  "environment",
  "complete",
  "integrity",
  "summary",
  "findings",
  "proofs",
  "seeding",
  "fix",
  "verification",
  "audit",
  "migrationErrors",
  "warnings",
  "notChecked",
] as const;

/** Objects get alphabetically sorted keys at every level; arrays keep their order. */
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => [k, sortKeys(v)] as const);
    // fromEntries defines own properties, so a key named `__proto__` stays plain data.
    return Object.fromEntries(entries);
  }
  return value;
}

/**
 * Machine-readable report: top-level keys in the documented order, nested keys sorted, two-space
 * indent, trailing newline. Text from the audited repository is kept as is; JSON escapes control
 * characters. The report carries no timestamps.
 */
export function renderJson(report: AnalysisReport): string {
  const ordered = TOP_LEVEL_ORDER.map((key) => [key, sortKeys(report[key])] as const);
  return `${JSON.stringify(Object.fromEntries(ordered), null, 2)}\n`;
}
