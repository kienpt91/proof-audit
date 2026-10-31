import type { AnalysisReport, Finding } from "../../domain/analysis/types.js";
import { escapeMarkdown, markdownCode, markdownFence } from "../../domain/text/sanitize.js";
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

/**
 * Static strings in this file contain no markdown specials except the structure they intend; everything
 * that comes from the input goes through `esc`, `code` or `fenced`.
 */
const esc = (s: string): string => escapeMarkdown(s, LIMITS.text);
const codeSpan = (s: string): string => markdownCode(s, LIMITS.code);
const prose = (parts: readonly Part[]): string => renderParts(parts, { text: esc, code: codeSpan });
/** Table cells never hold code spans: a pipe inside one would end the cell. */
const cell = (parts: readonly Part[]): string => renderParts(parts, { text: esc, code: (s) => escapeMarkdown(s, LIMITS.code) });

function fenced(out: string[], sql: string, maxLines: number): void {
  const { lines, omitted } = sqlLines(sql, maxLines);
  out.push(markdownFence(lines.join("\n"), "sql"));
  if (omitted > 0) out.push("", `_${omitted} more lines are not shown._`);
}

function renderFinding(out: string[], report: AnalysisReport, f: Finding, n: number): void {
  out.push("", `### ${n}. ${tierHeadline(f.tier).split(":")[0]} · ${f.severity} · ${codeSpan(f.subject)}`, "");
  out.push(`**${esc(f.title)}**`, "");
  const caveat = tierCaveat(f.tier);
  if (caveat !== null) out.push(`> **NOT proven.** ${caveat}`, "");
  out.push(`**An attacker could:** ${esc(f.attackerCan)}`);
  out.push("", `Kind: ${f.subjectKind}. ${tierHeadline(f.tier)}.`);
  if (f.causes.length > 0) {
    out.push("", "#### Why", "");
    for (const c of f.causes) out.push(`- ${esc(c.text)}`);
  }
  if (f.provenBy.length > 0) {
    out.push("", "#### How we proved it");
    f.provenBy.forEach((id, i) => {
      const proof = report.proofs.find((p) => p.id === id);
      out.push("");
      if (proof === undefined) {
        out.push(`${i + 1}\\. The evidence record ${codeSpan(id)} is missing from this report.`);
        return;
      }
      const story = narrateProof(proof);
      out.push(`**Check ${i + 1}.** ${story.lead}`, "");
      fenced(out, story.sql, LIMITS.proofSqlLines);
      out.push("", `Result: ${prose(story.outcome)}. ${story.meaning}${story.reason.length > 0 ? ` ${prose(story.reason)}` : ""}`);
      out.push("", `Evidence: ${codeSpan(story.evidence)}`);
    });
  }
  if (f.notReproduced.length > 0) {
    out.push("", "#### Attempts the database blocked", "");
    for (const id of f.notReproduced) out.push(`- ${prose(attemptParts(report, id))}`);
  }
  if (f.inconclusive.length > 0) {
    out.push("", "#### Could not be tested (no clear answer)", "");
    for (const item of f.inconclusive) out.push(`- ${esc(probeTitle(report, item.id))}: ${esc(item.reason)}`);
  }
}

function auditSection(out: string[], report: AnalysisReport): void {
  const a = report.audit;
  if (a === null) return;
  out.push("", "## Static auditor cross-check", "");
  const version = a.sourceVersion === null ? [] : [" ", { input: a.sourceVersion }];
  const project = a.project === null ? [] : [" (project ", { input: a.project }, ")"];
  out.push(`Findings from ${prose([{ input: a.sourceTool }, ...version, ...project])}, checked against our tests:`);
  if (a.findings.length > 0) {
    out.push("", "| Result | Finding | Rule | Severity | Location | Table | Note |", "|---|---|---|---|---|---|---|");
    for (const f of a.findings) {
      const location = [{ input: `${f.file}:${f.line}` }];
      const table = f.table === null ? ["none"] : [{ input: f.table }];
      out.push(
        `| ${cell([auditStatusWords(f.proofStatus)])} | ${cell([{ input: f.title }])} | ${cell([{ input: f.rule }])} | ${cell([{ input: f.severity }])} | ${cell(location)} | ${cell(table)} | ${cell([{ input: f.note }])} |`,
      );
    }
  }
  out.push("", `${plural(a.outOfScope, "static finding", "static findings")} out of scope (not about row level security, not tested here).`);
  if (a.warnings.length > 0) {
    out.push("");
    for (const w of a.warnings.slice(0, LIMITS.warnings)) out.push(`- ${esc(w)}`);
  }
}

function checkSection(out: string[], report: AnalysisReport): void {
  out.push("", "## Fix check", "");
  const v = report.verification;
  if (v === null) {
    out.push("No fix check was run, so no fix is confirmed.");
    return;
  }
  out.push(`**${checkHeadline(v.status).replace(":", "**:")}`);
  if (v.applyErrors.length > 0) {
    out.push("", `Fix statements the database rejected: ${v.applyErrors.length}`, "");
    for (const e of v.applyErrors) out.push(`- ${codeSpan(e.statement)} ${esc(e.sqlstate)} ${esc(e.message)}`);
  }
  if (v.subjects.length === 0) return;
  out.push("", "| Table | Result | Closed | Still works | Normal use broken | No clear answer | Because |", "|---|---|---|---|---|---|---|");
  const titles = (ids: readonly string[]): string => (ids.length === 0 ? "none" : ids.map((id) => esc(probeTitle(report, id))).join("; "));
  for (const s of v.subjects) {
    out.push(
      `| ${cell([{ input: s.subject }])} | ${subjectCheckWords(s.status)} | ${titles(s.closed)} | ${titles(s.stillProven)} | ${titles(s.broken)} | ${titles(s.unresolved)} | ${cell([{ input: s.reason }])} |`,
    );
  }
}

export function renderMarkdown(report: AnalysisReport): string {
  const out: string[] = [];
  const s = report.summary;

  out.push("# Row level security report", "");
  out.push("| Item | Value |", "|---|---|");
  out.push(`| Tool | ${cell([{ input: `${report.tool.name} ${report.tool.version}` }])} |`);
  out.push(`| Checked | ${plural(s.subjects, "table or view", "tables or views")} |`);
  out.push(`| Input files read | ${report.inputs.length} |`);
  out.push(`| Database used | ${cell(databaseParts(report))} |`);
  out.push(`| Run complete | ${report.complete ? "yes" : "**NO**, results may be partial"} |`);
  out.push(`| Tests run | ${s.probesRun} (${s.probesProven} showed a real problem) |`);
  out.push(`| PROVEN | ${s.proven} |`, `| SUSPECTED | ${s.suspected} |`, `| INCONCLUSIVE | ${s.inconclusive} |`, `| CLEAN | ${s.clean} |`);

  out.push("", "## Result", "");
  out.push(`**${headlineCounts(report)}**`, "", resultParagraph(report));

  out.push("", "## What we found");
  const problems = nonClean(report.findings);
  if (problems.length === 0) out.push("", "Nothing to report: no table or view showed a problem.");
  const ordered = TIER_ORDER.flatMap((tier) => problems.filter((f) => f.tier === tier));
  ordered.forEach((f, i) => renderFinding(out, report, f, i + 1));

  out.push("", "## Looked fine", "");
  const clean = report.findings.filter((f) => f.tier === "CLEAN");
  if (clean.length === 0) out.push("None.");
  for (const f of clean) out.push(`- ${codeSpan(f.subject)}: ${esc(f.title)}`);

  out.push("", "## How to fix", "");
  const fixable = problems.filter((f) => f.fixStatus !== "not-needed");
  if (fixable.length === 0) out.push("Nothing to fix.");
  for (const f of fixable) {
    const note = f.fixNote.length > 0 ? esc(f.fixNote) : "";
    out.push(`- ${codeSpan(f.subject)}: ${fixLine(f.fixStatus, fixIsConfirmed(report, f.subject), note)}`);
  }
  if (report.fix !== null && report.fix.sql.trim().length > 0) {
    out.push("", "### Proposed SQL (starting point, review before use)", "");
    fenced(out, report.fix.sql, LIMITS.fixSqlLines);
  }
  if (report.fix !== null && report.fix.needsDecision.length > 0) {
    out.push("", "### These need a decision only you can make", "");
    for (const d of report.fix.needsDecision) out.push(`- ${codeSpan(d.subject)}: ${esc(d.reason)}`);
  }

  checkSection(out, report);
  auditSection(out, report);

  if (report.migrationErrors.length > 0) {
    out.push("", "## Migration statements the database rejected", "");
    out.push(`${report.migrationErrors.length} in total. Anything after them may not have been tested as written.`, "");
    for (const e of report.migrationErrors.slice(0, LIMITS.migrationErrors)) {
      out.push(`- ${codeSpan(`${e.file}:${e.line}`)} ${esc(e.sqlstate)} ${esc(e.message)}: ${codeSpan(e.statement)}`);
    }
    const rest = report.migrationErrors.length - LIMITS.migrationErrors;
    if (rest > 0) out.push("", `... and ${rest} more.`);
  }

  const seeding = seedingProblems(report);
  if (seeding.length > 0) {
    out.push("", "## Test data problems", "");
    for (const t of seeding) out.push(`- ${codeSpan(t.table)}: ${t.status}${t.reason === null ? "" : ` (${esc(t.reason)})`}`);
  }

  if (report.warnings.length > 0) {
    out.push("", "## Warnings", "");
    for (const w of report.warnings.slice(0, LIMITS.warnings)) out.push(`- ${esc(w)}`);
    const rest = report.warnings.length - LIMITS.warnings;
    if (rest > 0) out.push("", `... and ${rest} more.`);
  }

  out.push("", "## What was not checked", "");
  if (report.notChecked.length === 0) out.push("Nothing was left out.");
  for (const n of report.notChecked) out.push(`- ${esc(n)}`);

  out.push("", "## Inputs", "", "| File | Bytes | sha256 |", "|---|---|---|");
  for (const f of report.inputs) out.push(`| ${cell([{ input: f.path }])} | ${f.bytes} | ${cell([{ input: f.sha256 }])} |`);

  return `${out.join("\n")}\n`;
}
