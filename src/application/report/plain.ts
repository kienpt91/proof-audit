import type { AnalysisReport, Finding, SubjectVerification } from "../../domain/analysis/types.js";
import { terminalText } from "../../domain/text/sanitize.js";
import {
  LIMITS,
  type Part,
  attemptParts,
  TIER_ORDER,
  auditStatusWords,
  checkHeadline,
  databaseParts,
  fixIsConfirmed,
  fixLine,
  headlineCounts,
  narrateProof,
  nonClean,
  plural,
  probeTitle,
  renderParts,
  resultParagraph,
  seedingProblems,
  sqlLines,
  subjectCheckWords,
  tierCaveat,
  tierHeadline,
} from "./shared.js";

const text = (s: string): string => terminalText(s, LIMITS.text);
const code = (s: string): string => terminalText(s, LIMITS.code);
const fmt = (parts: readonly Part[]): string => renderParts(parts, { text, code });

function indentSql(out: string[], sql: string, maxLines: number, indent: string): void {
  const { lines, omitted } = sqlLines(sql, maxLines);
  for (const line of lines) out.push(`${indent}${terminalText(line)}`);
  if (omitted > 0) out.push(`${indent}... (${omitted} more lines not shown)`);
}

function heading(out: string[], title: string): void {
  out.push("", title.toUpperCase(), "-".repeat(title.length));
}

function renderFinding(out: string[], report: AnalysisReport, f: Finding, n: number): void {
  out.push("", `[${n}] ${tierHeadline(f.tier)}`);
  out.push(`    Severity: ${f.severity.toUpperCase()}`);
  out.push(`    What: ${text(f.title)}`);
  out.push(`    Where: ${fmt([{ input: f.subject }, ` (${f.subjectKind})`])}`);
  const caveat = tierCaveat(f.tier);
  if (caveat !== null) out.push(`    NOTE: ${caveat}`);
  out.push(`    An attacker could: ${text(f.attackerCan)}`);
  if (f.causes.length > 0) {
    out.push("    Why:");
    for (const c of f.causes) out.push(`      - ${text(c.text)}`);
  }
  if (f.provenBy.length > 0) {
    out.push("    How we proved it:");
    f.provenBy.forEach((id, i) => {
      const proof = report.proofs.find((p) => p.id === id);
      if (proof === undefined) {
        out.push(`      ${i + 1}. The evidence record ${code(id)} is missing from this report.`);
        return;
      }
      const story = narrateProof(proof);
      out.push(`      ${i + 1}. ${story.lead}`);
      indentSql(out, story.sql, LIMITS.proofSqlLines, "           ");
      out.push(`         Result: ${fmt(story.outcome)}.`);
      out.push(`         ${story.meaning}${story.reason.length > 0 ? ` ${fmt(story.reason)}` : ""}`);
      out.push(`         Evidence: ${story.evidence}`);
    });
  }
  if (f.notReproduced.length > 0) {
    out.push("    Attempts the database blocked:");
    for (const id of f.notReproduced) out.push(`      - ${fmt(attemptParts(report, id))}`);
  }
  if (f.inconclusive.length > 0) {
    out.push("    Could not be tested (no clear answer):");
    for (const item of f.inconclusive) out.push(`      - ${text(probeTitle(report, item.id))}: ${text(item.reason)}`);
  }
}

function renderSubjectCheck(out: string[], report: AnalysisReport, s: SubjectVerification): void {
  out.push("", `  ${code(s.subject)}: ${subjectCheckWords(s.status)}`);
  out.push(`    Because: ${text(s.reason)}`);
  const rows: [string, readonly string[]][] = [
    ["worked before, now blocked", s.closed],
    ["worked before, STILL works", s.stillProven],
    ["normal use that worked before, now BROKEN", s.broken],
    ["no clear answer after the fix", s.unresolved],
  ];
  for (const [label, ids] of rows) {
    for (const id of ids) out.push(`    - ${text(probeTitle(report, id))}: ${label}`);
  }
}

export function renderPlain(report: AnalysisReport): string {
  const out: string[] = [];
  const s = report.summary;

  out.push("SECURITY REPORT (plain language)", "================================");
  out.push(`Tool: ${text(report.tool.name)} ${text(report.tool.version)}`);
  out.push(`Checked: ${plural(s.subjects, "table or view", "tables or views")}`);
  out.push(`Input files read: ${report.inputs.length}`);
  out.push(`Database used: ${fmt(databaseParts(report))}`);
  out.push(`Run complete: ${report.complete ? "yes" : "NO, results may be partial"}`);
  out.push(`Tests run: ${s.probesRun} (${s.probesProven} showed a real problem)`);

  out.push(`RESULT: ${headlineCounts(report)}.`);
  out.push(resultParagraph(report));

  heading(out, "What we found");
  const problems = nonClean(report.findings);
  if (problems.length === 0) out.push("", "Nothing to report: no table or view showed a problem.");
  const ordered = TIER_ORDER.flatMap((tier) => problems.filter((f) => f.tier === tier));
  ordered.forEach((f, i) => renderFinding(out, report, f, i + 1));

  const clean = report.findings.filter((f) => f.tier === "CLEAN");
  heading(out, "Looked fine");
  if (clean.length === 0) out.push("None.");
  for (const f of clean) out.push(`- ${fmt([{ input: f.subject }])}: ${text(f.title)}`);

  heading(out, "How to fix");
  const fixable = problems.filter((f) => f.fixStatus !== "not-needed");
  if (fixable.length === 0) out.push("Nothing to fix.");
  for (const f of fixable) {
    const note = f.fixNote.length > 0 ? text(f.fixNote) : "";
    out.push(`- ${code(f.subject)}: ${fixLine(f.fixStatus, fixIsConfirmed(report, f.subject), note)}`);
  }
  if (report.fix !== null && report.fix.sql.trim().length > 0) {
    out.push("", "Proposed SQL (starting point, review before use):");
    indentSql(out, report.fix.sql, LIMITS.fixSqlLines, "    ");
  }
  if (report.fix !== null && report.fix.needsDecision.length > 0) {
    out.push("", "These need a decision only you can make:");
    for (const d of report.fix.needsDecision) out.push(`- ${code(d.subject)}: ${text(d.reason)}`);
  }

  heading(out, "Fix check");
  const v = report.verification;
  if (v === null) {
    out.push("No fix check was run, so no fix is confirmed.");
  } else {
    out.push(checkHeadline(v.status));
    if (v.applyErrors.length > 0) {
      out.push("", `Fix statements the database rejected: ${v.applyErrors.length}`);
      for (const e of v.applyErrors) out.push(`  - ${text(e.statement)} [${text(e.sqlstate)}] ${text(e.message)}`);
    }
    if (v.subjects.length > 0) out.push("", "Per table, before the fix versus after the fix:");
    for (const subject of v.subjects) renderSubjectCheck(out, report, subject);
  }

  if (report.audit !== null) {
    const a = report.audit;
    heading(out, "Static auditor cross-check");
    const version = a.sourceVersion === null ? "" : ` ${text(a.sourceVersion)}`;
    out.push(`Findings from ${text(a.sourceTool)}${version}${a.project === null ? "" : ` (project ${text(a.project)})`}, checked against our tests:`);
    if (a.findings.length === 0) out.push("  (none about row level security)");
    for (const f of a.findings) {
      const table = f.table === null ? "" : ` [table ${code(f.table)}]`;
      out.push(`- ${auditStatusWords(f.proofStatus)}: ${text(f.title)}${table}`);
      out.push(`    ${text(f.rule)} (${text(f.severity)}) at ${code(f.file)}:${f.line}`);
      if (f.note.length > 0) out.push(`    ${text(f.note)}`);
    }
    out.push(`${plural(a.outOfScope, "static finding", "static findings")} out of scope (not about row level security, not tested here).`);
    for (const w of a.warnings.slice(0, LIMITS.warnings)) out.push(`  warning: ${text(w)}`);
  }

  if (report.migrationErrors.length > 0) {
    heading(out, "Migration statements the database rejected");
    out.push(`${report.migrationErrors.length} in total. Anything after them may not have been tested as written.`);
    for (const e of report.migrationErrors.slice(0, LIMITS.migrationErrors)) {
      out.push(`- ${code(e.file)}:${e.line} [${text(e.sqlstate)}] ${text(e.message)}`);
      out.push(`    ${text(e.statement)}`);
    }
    const rest = report.migrationErrors.length - LIMITS.migrationErrors;
    if (rest > 0) out.push(`... and ${rest} more.`);
  }

  const seeding = seedingProblems(report);
  if (seeding.length > 0) {
    heading(out, "Test data problems");
    for (const t of seeding) {
      out.push(`- ${code(t.table)}: ${t.status}${t.reason === null ? "" : ` (${text(t.reason)})`}`);
    }
  }

  if (report.warnings.length > 0) {
    heading(out, "Warnings");
    for (const w of report.warnings.slice(0, LIMITS.warnings)) out.push(`- ${text(w)}`);
    const rest = report.warnings.length - LIMITS.warnings;
    if (rest > 0) out.push(`... and ${rest} more.`);
  }

  heading(out, "What was not checked");
  if (report.notChecked.length === 0) out.push("Nothing was left out.");
  for (const n of report.notChecked) out.push(`- ${text(n)}`);

  return `${out.join("\n")}\n`;
}
