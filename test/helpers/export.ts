import { analyzeRls } from "../../src/application/analyze.js";
import type { Clock, CreatedSandbox, LoadedFile } from "../../src/application/ports.js";
import { renderFindings } from "../../src/application/report/findings.js";
import type { AnalysisReport } from "../../src/domain/analysis/types.js";
import { parseAuditReport, type ParsedAudit } from "../../src/domain/audit/import.js";
import { buildRecords, type ExportResult } from "../../src/domain/interchange/build.js";
import type { FindingRecord } from "../../src/domain/interchange/records.js";
import type { SchemaModel } from "../../src/domain/schema/model.js";
import { parseMigrations } from "../../src/domain/sql/parser.js";
import { ModelSandbox } from "./model-sandbox.js";

const clock: Clock = { now: () => 0 };

export const MIGRATION = "supabase/migrations/001.sql";

export function file(content: string, path = MIGRATION): LoadedFile {
  return { path, content, bytes: content.length };
}

export interface Analysed {
  readonly report: AnalysisReport;
  readonly files: readonly LoadedFile[];
  readonly audit: ParsedAudit | null;
}

export interface AnalyseOptions {
  /** What the database looks like after the proposed fix; defaults to the schema as migrated. */
  readonly fixed?: SchemaModel;
  /** The schema the fake database holds; defaults to what the SQL reader makes of the migrations. */
  readonly catalog?: SchemaModel;
  /** Makes the platform fingerprint differ from this call (1-based) on. */
  readonly tamperedAfter?: number;
  /** Changes the fake database before the run, e.g. to make seeding fail. */
  readonly tweak?: (sandbox: ModelSandbox) => void;
  readonly audit?: ParsedAudit | null;
  readonly files?: readonly LoadedFile[];
  readonly proposeFix?: boolean;
}

/** Runs the whole analysis on migrations the SQL reader understands, against a fake database that answers from the parsed policies. */
export async function analyseSql(sql: string, options: AnalyseOptions = {}): Promise<Analysed> {
  const files = options.files ?? [file(sql)];
  const parsed = parseMigrations(files.map((f) => ({ path: f.path, content: f.content })));
  const sandbox = new ModelSandbox({
    model: options.catalog ?? parsed.model,
    ...(options.fixed === undefined ? {} : { fixed: options.fixed }),
    ...(options.tamperedAfter === undefined ? {} : { tamperedAfter: options.tamperedAfter }),
  });
  options.tweak?.(sandbox);
  const provider = {
    async create(): Promise<CreatedSandbox> {
      return { sandbox, environment: { mode: "url", image: "loopback" } };
    },
  };
  const audit = options.audit ?? null;
  const report = await analyzeRls(
    { files, loadWarnings: [], inputsComplete: true, audit, proposeFix: options.proposeFix ?? true, tool: { name: "proof-audit", version: "0.0.0-test" } },
    { provider, clock },
  );
  return { report, files, audit };
}

export function recordsOf(run: Analysed): ExportResult {
  const parsed = parseMigrations(run.files.map((f) => ({ path: f.path, content: f.content })));
  return buildRecords({
    report: run.report,
    source: { statements: parsed.statements, sources: parsed.sources },
    audit: run.audit,
    inputs: run.files.map((f) => ({ path: f.path, lines: f.content.split("\n").length })),
  });
}

/** The text `findings.json` would have, the records in it and the notes the person running the tool would see. */
export function exported(run: Analysed): { readonly json: string | null; readonly notes: readonly string[]; readonly records: readonly FindingRecord[] } {
  const out = renderFindings(run.report, run.files, run.audit);
  return { json: out.json, notes: out.notes, records: out.json === null ? [] : (JSON.parse(out.json) as FindingRecord[]) };
}

export function auditFrom(text: string): ParsedAudit {
  const parsed = parseAuditReport(text);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}
