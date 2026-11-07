/**
 * A small conformance check for `findings.json`, written for this project against the published description
 * of the format (the three verdicts, their required and forbidden fields, patterns, uniqueness, ordering and
 * the limits on size). It checks the encoded document, so it sees exactly what a reader would read. It is used
 * before the file is written (a file that fails is not written) and by the tests; it does not need a network
 * and shares no code with any other validator.
 */

export const MAX_RECORDS = 1000;
export const MAX_BYTES = 5 * 1024 * 1024;

const FINGERPRINT = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;
const SCORES = ["informational", "low", "medium", "high", "critical"] as const;
const CONFIDENCE = ["low", "medium", "high"] as const;
const TRACE_KINDS = ["entrypoint", "propagation", "sink"] as const;
const CONDITION_KINDS = [
  "authentication_level",
  "authorization_role",
  "user_interaction",
  "system_configuration",
  "network_routing",
  "environmental_dependency",
  "data_state",
  "timing_dependency",
  "third_party_dependency",
] as const;

const COMMON = ["verdict", "fingerprint", "title", "description", "trace", "evidence"];
const FIELDS: Readonly<Record<string, readonly string[]>> = {
  confirmed: [...COMMON, "root_cause", "intended_behavior", "conditions", "execution", "remediation", "severity", "confidence"],
  needs_validation: [...COMMON, "claimed_root_cause", "blockers", "validation_plan"],
  rejected: [...COMMON, "claimed_root_cause", "reason"],
};

const VISIBLE = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const PATH_BAD_CHAR = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
const WINDOWS_DEVICE = /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\.|$)/i;

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

function wellFormed(s: string): boolean {
  return !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);
}

/** A string a person can read: well-formed Unicode with at least one visible character. */
export function hasVisible(s: string): boolean {
  return wellFormed(s) && VISIBLE.test(s);
}

/** A path that stays inside the repository it is read against and means the same thing on every platform. */
export function isSafeRelativePath(p: string): boolean {
  if (p.length === 0 || !wellFormed(p) || p.trim() !== p || PATH_BAD_CHAR.test(p)) return false;
  if (p.includes("\\") || p.includes(":") || p.startsWith("/") || p.startsWith("~")) return false;
  return p.split("/").every((part) => part !== "" && part !== "." && part !== ".." && !/[ .]$/.test(part) && !WINDOWS_DEVICE.test(part));
}

/** Key-order independent text of a value, to find duplicates in lists that must be unique. */
function identity(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(identity).join(",")}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${identity(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

class Errors {
  readonly list: string[] = [];
  add(path: string, message: string): void {
    if (this.list.length < 100) this.list.push(`${path}: ${message}`);
  }
}

function exactKeys(e: Errors, path: string, o: Obj, allowed: readonly string[], required: readonly string[]): void {
  for (const k of required) if (!(k in o)) e.add(path, `missing required field "${k}"`);
  for (const k of Object.keys(o)) if (!allowed.includes(k)) e.add(path, `unexpected field "${k}"`);
}

// A field that is absent is reported once, by `exactKeys`; the helpers below only judge values that are there.

function text(e: Errors, path: string, v: unknown): string | null {
  if (v === undefined) return null;
  if (typeof v !== "string") {
    e.add(path, "expected a string");
    return null;
  }
  if (!hasVisible(v)) {
    e.add(path, "must contain a visible character");
    return null;
  }
  return v;
}

function oneOf<T extends string>(e: Errors, path: string, v: unknown, allowed: readonly T[]): T | null {
  if (v === undefined) return null;
  if (typeof v === "string" && (allowed as readonly string[]).includes(v)) return v as T;
  e.add(path, `must be one of ${allowed.join(", ")}`);
  return null;
}

function list(e: Errors, path: string, v: unknown, min: number): readonly unknown[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) {
    e.add(path, "expected an array");
    return [];
  }
  if (v.length < min) e.add(path, `needs at least ${min} item(s)`);
  return v;
}

function unique(e: Errors, path: string, items: readonly unknown[]): void {
  const seen = new Set<string>();
  items.forEach((item, i) => {
    const key = identity(item);
    if (seen.has(key)) e.add(`${path}[${i}]`, "duplicate of an earlier item");
    seen.add(key);
  });
}

function position(e: Errors, path: string, o: Obj): void {
  if (typeof o.file !== "string" || !isSafeRelativePath(o.file)) e.add(`${path}.file`, "must be a safe repository-relative path");
  if (!Number.isInteger(o.line) || (o.line as number) < 1) e.add(`${path}.line`, "must be an integer of at least 1");
}

function checkTrace(e: Errors, path: string, v: unknown): void {
  const items = list(e, path, v, 1);
  unique(e, path, items);
  const kinds: (string | null)[] = [];
  items.forEach((item, i) => {
    const p = `${path}[${i}]`;
    if (!isObj(item)) return void e.add(p, "expected an object");
    exactKeys(e, p, item, ["kind", "file", "line", "scope", "description"], ["kind", "file", "line", "scope", "description"]);
    kinds.push(oneOf(e, `${p}.kind`, item.kind, TRACE_KINDS));
    position(e, p, item);
    text(e, `${p}.scope`, item.scope);
    text(e, `${p}.description`, item.description);
  });
  if (kinds.length === 1 && kinds[0] === "propagation") e.add(`${path}[0].kind`, "a trace of one step must be an entrypoint or a sink");
  if (kinds.length > 1) {
    kinds.forEach((k, i) => {
      const want = i === 0 ? "entrypoint" : i === kinds.length - 1 ? "sink" : "propagation";
      if (k !== null && k !== want) e.add(`${path}[${i}].kind`, `must be ${want} at this position`);
    });
  }
}

function checkEvidence(e: Errors, path: string, v: unknown): void {
  const items = list(e, path, v, 1);
  unique(e, path, items);
  items.forEach((item, i) => {
    const p = `${path}[${i}]`;
    if (!isObj(item)) return void e.add(p, "expected an object");
    exactKeys(e, p, item, ["file", "line", "description"], ["file", "line", "description"]);
    position(e, p, item);
    text(e, `${p}.description`, item.description);
  });
}

function checkScore(e: Errors, path: string, v: unknown): Score | null {
  if (!isObj(v)) {
    e.add(path, "expected an object");
    return null;
  }
  exactKeys(e, path, v, ["score", "reason"], ["score", "reason"]);
  text(e, `${path}.reason`, v.reason);
  return oneOf(e, `${path}.score`, v.score, SCORES);
}

type Score = (typeof SCORES)[number];

function checkConfirmed(e: Errors, p: string, r: Obj): void {
  for (const k of ["root_cause", "intended_behavior"]) text(e, `${p}.${k}`, r[k]);
  const conditions = list(e, `${p}.conditions`, r.conditions, 0);
  unique(e, `${p}.conditions`, conditions);
  conditions.forEach((c, i) => {
    const q = `${p}.conditions[${i}]`;
    if (!isObj(c)) return void e.add(q, "expected an object");
    exactKeys(e, q, c, ["kind", "description"], ["kind", "description"]);
    oneOf(e, `${q}.kind`, c.kind, CONDITION_KINDS);
    text(e, `${q}.description`, c.description);
  });

  const x = r.execution;
  if (!isObj(x)) e.add(`${p}.execution`, "expected an object");
  else {
    exactKeys(e, `${p}.execution`, x, ["attacker_perspective", "payloads", "instructions", "observed_result"], ["attacker_perspective", "payloads", "instructions", "observed_result"]);
    text(e, `${p}.execution.attacker_perspective`, x.attacker_perspective);
    text(e, `${p}.execution.observed_result`, x.observed_result);
    const payloads = list(e, `${p}.execution.payloads`, x.payloads, 1);
    unique(e, `${p}.execution.payloads`, payloads);
    payloads.forEach((s, i) => typeof s !== "string" && e.add(`${p}.execution.payloads[${i}]`, "expected a string"));
    list(e, `${p}.execution.instructions`, x.instructions, 1).forEach((s, i) => text(e, `${p}.execution.instructions[${i}]`, s));
  }

  const m = r.remediation;
  if (!isObj(m)) e.add(`${p}.remediation`, "expected an object");
  else {
    exactKeys(e, `${p}.remediation`, m, ["strategy", "code_changes"], ["strategy"]);
    text(e, `${p}.remediation.strategy`, m.strategy);
    if ("code_changes" in m) {
      list(e, `${p}.remediation.code_changes`, m.code_changes, 0).forEach((c, i) => {
        const q = `${p}.remediation.code_changes[${i}]`;
        if (!isObj(c)) return void e.add(q, "expected an object");
        exactKeys(e, q, c, ["file_name", "fixed_code"], ["file_name", "fixed_code"]);
        if (typeof c.file_name !== "string" || !isSafeRelativePath(c.file_name)) e.add(`${q}.file_name`, "must be a safe repository-relative path");
        if (typeof c.fixed_code !== "string") e.add(`${q}.fixed_code`, "expected a string");
      });
    }
  }

  const s = r.severity;
  if (!isObj(s)) e.add(`${p}.severity`, "expected an object");
  else {
    exactKeys(e, `${p}.severity`, s, ["likelihood", "impact", "overall_severity"], ["likelihood", "impact", "overall_severity"]);
    checkScore(e, `${p}.severity.likelihood`, s.likelihood);
    const impact = checkScore(e, `${p}.severity.impact`, s.impact);
    const overall = oneOf(e, `${p}.severity.overall_severity`, s.overall_severity, SCORES);
    if (impact !== null && overall !== null && SCORES.indexOf(overall) > SCORES.indexOf(impact)) e.add(`${p}.severity.overall_severity`, "cannot be higher than the impact");
  }

  const c = r.confidence;
  if (!isObj(c)) e.add(`${p}.confidence`, "expected an object");
  else {
    exactKeys(e, `${p}.confidence`, c, ["score", "reason"], ["score", "reason"]);
    oneOf(e, `${p}.confidence.score`, c.score, CONFIDENCE);
    text(e, `${p}.confidence.reason`, c.reason);
  }
}

function checkNeedsValidation(e: Errors, p: string, r: Obj): void {
  text(e, `${p}.claimed_root_cause`, r.claimed_root_cause);
  const blockers = list(e, `${p}.blockers`, r.blockers, 1);
  unique(e, `${p}.blockers`, blockers);
  blockers.forEach((b, i) => text(e, `${p}.blockers[${i}]`, b));
  const plan = r.validation_plan;
  if (!isObj(plan)) return void e.add(`${p}.validation_plan`, "expected an object");
  exactKeys(e, `${p}.validation_plan`, plan, ["local", "deployment"], []);
  let visible = 0;
  for (const k of ["local", "deployment"]) {
    if (k in plan && text(e, `${p}.validation_plan.${k}`, plan[k]) !== null) visible += 1;
  }
  if (visible === 0) e.add(`${p}.validation_plan`, "needs a local or a deployment plan");
}

/** Every way `document` (parsed JSON of a findings.json) departs from the format; empty when it conforms. `bytes` is the size of the encoded text. */
export function checkFindings(document: unknown, bytes: number): string[] {
  const e = new Errors();
  if (bytes > MAX_BYTES) e.add("$", `larger than ${MAX_BYTES} bytes`);
  if (!Array.isArray(document)) {
    e.add("$", "expected an array of records");
    return e.list;
  }
  if (document.length > MAX_RECORDS) e.add("$", `more than ${MAX_RECORDS} records`);
  const seen = new Map<string, number>();
  let previous: string | null = null;
  document.forEach((r, i) => {
    const p = `$[${i}]`;
    if (!isObj(r)) return void e.add(p, "expected an object");
    const verdict = typeof r.verdict === "string" ? FIELDS[r.verdict] : undefined;
    if (verdict === undefined) return void e.add(`${p}.verdict`, "must be confirmed, needs_validation or rejected");
    exactKeys(e, p, r, verdict, verdict);
    if (typeof r.fingerprint !== "string" || !FINGERPRINT.test(r.fingerprint)) e.add(`${p}.fingerprint`, "must match the fingerprint pattern");
    else {
      const first = seen.get(r.fingerprint);
      if (first !== undefined) e.add(`${p}.fingerprint`, `duplicates $[${first}]`);
      seen.set(r.fingerprint, i);
      if (previous !== null && previous > r.fingerprint) e.add(`${p}.fingerprint`, "records must be sorted by fingerprint");
      previous = r.fingerprint;
    }
    text(e, `${p}.title`, r.title);
    text(e, `${p}.description`, r.description);
    checkTrace(e, `${p}.trace`, r.trace);
    checkEvidence(e, `${p}.evidence`, r.evidence);
    if (r.verdict === "confirmed") checkConfirmed(e, p, r);
    else if (r.verdict === "needs_validation") checkNeedsValidation(e, p, r);
    else {
      text(e, `${p}.claimed_root_cause`, r.claimed_root_cause);
      text(e, `${p}.reason`, r.reason);
    }
  });
  return e.list;
}

/** Parses encoded text and checks it; a text that is not JSON is one error. */
export function checkFindingsText(encoded: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(encoded);
  } catch {
    return ["$: not valid JSON"];
  }
  return checkFindings(parsed, new TextEncoder().encode(encoded).length);
}
