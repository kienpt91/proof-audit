import type { AnalysisReport } from "../../domain/analysis/types.js";
import type { ParsedAudit } from "../../domain/audit/import.js";
import { buildRecords } from "../../domain/interchange/build.js";
import { checkFindingsText } from "../../domain/interchange/conformance.js";
import { encodeFindings } from "../../domain/interchange/records.js";
import { parseMigrations } from "../../domain/sql/parser.js";
import type { LoadedFile } from "../ports.js";

export interface FindingsExport {
  /** The text of `findings.json`; null when it must not be written (see `notes`). */
  readonly json: string | null;
  /** What the person running the tool should know: records left out and why, or why nothing was written. */
  readonly notes: readonly string[];
}

const MAX_NOTES = 10;

const lineCount = (text: string): number => text.split("\n").length;

/**
 * `findings.json`: the run's results as records of the findings.json format. The file is derived from the report and
 * the migrations, nothing in it is read back by `proof-audit verify`, and a file that does not conform to the format is
 * never produced: the check runs on the exact text that would be written.
 */
export function renderFindings(report: AnalysisReport, files: readonly LoadedFile[], audit: ParsedAudit | null): FindingsExport {
  const parsed = parseMigrations(files.map((f) => ({ path: f.path, content: f.content })));
  const { records, omitted } = buildRecords({
    report,
    source: { statements: parsed.statements, sources: parsed.sources },
    audit,
    inputs: files.map((f) => ({ path: f.path, lines: lineCount(f.content) })),
  });
  const encoded = encodeFindings(records);
  const errors = checkFindingsText(encoded);
  if (errors.length > 0) {
    const pathProblem = errors.some((e) => e.includes(".file:")) ? " Run proof-audit from the project root so that the input paths are relative and contain no ':' or '..'." : "";
    return { json: null, notes: [`findings.json was not written: it would not conform to the format (${errors.slice(0, 3).join("; ")}).${pathProblem}`] };
  }
  const notes = omitted.map((o) => `findings.json has no record for ${o.subject}: ${o.reason}`);
  return { json: encoded, notes: notes.length > MAX_NOTES ? [...notes.slice(0, MAX_NOTES), `findings.json: ${notes.length - MAX_NOTES} more records left out`] : notes };
}
