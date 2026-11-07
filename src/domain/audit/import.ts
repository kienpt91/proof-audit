import { SEVERITY_RANK, type Severity } from "../analysis/types.js";
import { LIMITS } from "../limits.js";
import { err, ok, type Result } from "../result.js";
import { array, integer, parseJson, string, type Validator } from "../validate.js";

/** One finding of a static auditor report, reduced to what this tool uses. */
export interface ParsedAuditFinding {
  readonly rule: string;
  readonly severity: Severity;
  readonly file: string;
  readonly line: number;
  readonly title: string;
  readonly message: string;
  /** Qualified table (`schema.name`, `public.` when the title gave no schema); null when none could be read. */
  readonly table: string | null;
  /** The `subject` array newer reports carry (`[table]` or `[table, policy name]`); null when absent or not a list of strings. */
  readonly subject: readonly string[] | null;
}

export interface ParsedAudit {
  /** Tool name as found in the report, `unknown` when the report names none. */
  readonly tool: string;
  readonly version: string | null;
  readonly project: string | null;
  /** Findings that are in scope: row level security family, in report order. */
  readonly findings: readonly ParsedAuditFinding[];
  /** Every finding in the file, including those this tool does not test. */
  readonly totalFindings: number;
}

export const MAX_AUDIT_FINDINGS = 20_000;
const RLS_RULE_PREFIX = "supabase-";

const ruleText = string({ min: 1, max: 200 });
const fileText = string({ max: 4_096 });
const titleText = string({ max: 2_000 });
const messageText = string({ max: 20_000 });
const nameText = string({ max: 200 });
const lineNumber = integer({ max: 100_000_000 });

export function isRlsRule(rule: string): boolean {
  return rule.startsWith(RLS_RULE_PREFIX);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A key that may be absent or null; present values must satisfy `inner`. */
function optionalField<T>(record: Record<string, unknown>, key: string, inner: Validator<T>, path: string): Result<T | undefined, string> {
  const value = record[key];
  if (value === undefined || value === null) return ok(undefined);
  return inner(value, `${path}.${key}`);
}

// ---- table extraction ---------------------------------------------------------------------------

/**
 * Read an identifier written either the way the auditor prints it (`public.notes`, `notes`, and
 * `public.My Table` for quoted names, whose quotes it drops) or as SQL (`"public"."My Table"`).
 * Returns `schema.name`, defaulting the schema to `public`; null when nothing usable is there.
 */
export function qualifyTableName(token: string): string | null {
  const parts: string[] = [];
  let i = 0;
  const text = token.trim();
  if (text.length === 0) return null;
  for (;;) {
    let part = "";
    if (text.charAt(i) === '"') {
      i++;
      for (;;) {
        const close = text.indexOf('"', i);
        if (close === -1) return fallbackQualify(text);
        part += text.slice(i, close);
        if (text.charAt(close + 1) === '"') {
          part += '"';
          i = close + 2;
        } else {
          i = close + 1;
          break;
        }
      }
    } else {
      let end = i;
      while (end < text.length && text.charAt(end) !== "." && text.charAt(end) !== '"') end++;
      part = text.slice(i, end);
      i = end;
    }
    if (part.length === 0) return fallbackQualify(text);
    parts.push(part);
    if (i >= text.length) break;
    if (text.charAt(i) !== ".") return fallbackQualify(text);
    i++;
  }
  if (parts.length === 1) return `public.${parts[0]}`;
  return `${parts[0]}.${parts.slice(1).join(".")}`;
}

/** Last resort for text with stray quotes: split at the first dot. */
function fallbackQualify(text: string): string | null {
  if (text.includes('"')) return null;
  const dot = text.indexOf(".");
  if (dot === -1) return `public.${text}`;
  const schema = text.slice(0, dot);
  const name = text.slice(dot + 1);
  return schema.length > 0 && name.length > 0 ? `${schema}.${name}` : null;
}

const TITLE_SHAPES: readonly RegExp[] = [
  /^Table (.+) has no row level security$/s,
  /^Table (.+) has row level security but no policies$/s,
  // The policy name sits between double quotes and may itself contain anything, so the greedy name
  // makes the table the text after the last occurrence of the fixed words.
  /^Policy ".*" lets .+ every row of (.+)$/s,
  /^Policy ".*" allows the anon role to (?:write to|all|select|insert|update|delete) (.+)$/s,
  /^No policy on (.+?) ties .+ to the caller$/s,
];

/** The qualified table a row level security finding is about, from the way the auditor words its title. */
export function tableFromTitle(title: string): string | null {
  for (const shape of TITLE_SHAPES) {
    const match = shape.exec(title);
    if (match?.[1] !== undefined) return qualifyTableName(match[1]);
  }
  return null;
}

// ---- parsing ------------------------------------------------------------------------------------

function severityOf(value: unknown): Severity {
  if (typeof value !== "string") return "info";
  const lowered = value.toLowerCase();
  return Object.hasOwn(SEVERITY_RANK, lowered) ? (lowered as Severity) : "info";
}

const subjectNames = array(string({ max: 4_000 }), { max: 8 });

const findingValidator: Validator<ParsedAuditFinding> = (value, path) => {
  if (!isRecord(value)) return err(`${path}: expected an object`);
  const rule = ruleText(value.rule, `${path}.rule`);
  if (!rule.ok) return rule;
  const title = titleText(value.title, `${path}.title`);
  if (!title.ok) return title;
  const file = optionalField(value, "file", fileText, path);
  if (!file.ok) return file;
  const message = optionalField(value, "message", messageText, path);
  if (!message.ok) return message;
  const line = optionalField(value, "line", lineNumber, path);
  if (!line.ok) return line;
  const subject = subjectNames(value.subject, `${path}.subject`);
  return ok({
    rule: rule.value,
    severity: severityOf(value.severity),
    file: file.value ?? "",
    line: line.value ?? 0,
    title: title.value,
    message: message.value ?? "",
    table: isRlsRule(rule.value) ? tableFromTitle(title.value) : null,
    subject: subject.ok && subject.value.length > 0 ? subject.value : null,
  });
};

interface AuditDocument {
  readonly tool: string;
  readonly version: string | null;
  readonly project: string | null;
  readonly all: readonly ParsedAuditFinding[];
}

const documentValidator: Validator<AuditDocument> = (value, path) => {
  if (!isRecord(value)) return err(`${path}: expected an object`);
  let tool = "unknown";
  let version: string | null = null;
  const toolField = value.tool;
  if (typeof toolField === "string") {
    const name = nameText(toolField, `${path}.tool`);
    if (!name.ok) return name;
    tool = name.value;
  } else if (isRecord(toolField)) {
    const name = optionalField(toolField, "name", nameText, `${path}.tool`);
    if (!name.ok) return name;
    const ver = optionalField(toolField, "version", nameText, `${path}.tool`);
    if (!ver.ok) return ver;
    tool = name.value ?? "unknown";
    version = ver.value ?? null;
  } else if (toolField !== undefined && toolField !== null) {
    return err(`${path}.tool: expected an object or a string`);
  }
  const project = optionalField(value, "project", nameText, path);
  if (!project.ok) return project;
  const findings = array(findingValidator, { max: MAX_AUDIT_FINDINGS })(value.findings, `${path}.findings`);
  if (!findings.ok) return findings;
  return ok({ tool, version, project: project.value ?? null, all: findings.value });
};

/**
 * Read a static auditor JSON report. Unknown keys are ignored so newer report versions still load;
 * a finding needs a rule and a title, everything else has a default. Errors name the path that failed
 * and never repeat the report's content.
 */
export function parseAuditReport(text: string): Result<ParsedAudit, string> {
  const parsed = parseJson(text, documentValidator, { maxBytes: LIMITS.maxJsonBytes, label: "audit report" });
  if (!parsed.ok) return parsed;
  const doc = parsed.value;
  return ok({
    tool: doc.tool,
    version: doc.version,
    project: doc.project,
    findings: doc.all.filter((f) => isRlsRule(f.rule)),
    totalFindings: doc.all.length,
  });
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Distinct tables named by row level security findings: most severe finding first, then alphabetical. */
export function auditPriorityTables(audit: ParsedAudit): string[] {
  const worst = new Map<string, number>();
  for (const finding of audit.findings) {
    if (!isRlsRule(finding.rule) || finding.table === null) continue;
    const rank = SEVERITY_RANK[finding.severity];
    if (rank > (worst.get(finding.table) ?? -1)) worst.set(finding.table, rank);
  }
  return [...worst.entries()].sort(([ta, ra], [tb, rb]) => rb - ra || compare(ta, tb)).map(([table]) => table);
}

/** `Policy "<name>" lets ...` and `Policy "<name>" allows the anon role to ...`: the name may itself contain quotes, so it is the greedy part. */
const POLICY_TITLE = /^Policy "(.*)" (?:lets .+ every row of |allows the anon role to )/s;

/** The policy a row level security finding is about, from its title; null for findings about a table. */
export function policyFromTitle(title: string): string | null {
  return POLICY_TITLE.exec(title)?.[1] ?? null;
}

/**
 * The table and policy a static finding is about. A `subject` array in the report wins over the title, because a
 * policy name containing quotes makes the title ambiguous.
 */
export function staticSubject(finding: ParsedAuditFinding): { readonly table: string | null; readonly policy: string | null } {
  const [first, second] = finding.subject ?? [];
  if (first === undefined) return { table: finding.table, policy: policyFromTitle(finding.title) };
  return { table: qualifyTableName(first), policy: second ?? null };
}
