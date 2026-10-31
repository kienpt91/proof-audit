import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { AnalysisReport } from "../../../src/domain/analysis/types.js";
import { proofIsIntact } from "../../../src/domain/proof/hash.js";
import { renderJson } from "../../../src/application/report/json.js";
import { renderMarkdown } from "../../../src/application/report/markdown.js";
import { renderPlain } from "../../../src/application/report/plain.js";
import {
  breaksAccessReport,
  fixedReport,
  proof,
  hostileReport,
  integrityReport,
  hostileTwin,
  verifiedReport,
  vulnerableReport,
} from "../../fixtures/reports.js";

const GOLDEN_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "golden");

/** Compares with a golden file; rewrites it only when UPDATE_GOLDEN=1. */
function expectGolden(name: string, actual: string): void {
  const path = join(GOLDEN_DIR, name);
  if (process.env.UPDATE_GOLDEN === "1") {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, actual);
  }
  expect(existsSync(path), `missing golden ${name}; run with UPDATE_GOLDEN=1`).toBe(true);
  expect(actual).toBe(readFileSync(path, "utf8"));
}

const FIXTURES: readonly (readonly [string, () => AnalysisReport])[] = [
  ["vulnerable", vulnerableReport],
  ["fixed", fixedReport],
  ["verified", verifiedReport],
  ["breaks-access", breaksAccessReport],
  ["hostile", hostileReport],
  ["integrity", integrityReport],
];

const FORBIDDEN_PLAIN = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFFE\uFFFF\u{E0000}-\u{E007F}]|[\uD800-\uDFFF]/u;
/** Markdown fences keep real tabs; newlines are the line separator. */
const FORBIDDEN_MARKDOWN = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFFE\uFFFF\u{E0000}-\u{E007F}]|[\uD800-\uDFFF]/u;

describe("report fixtures", () => {
  it("carry proofs whose hashes are valid", () => {
    for (const [, build] of FIXTURES) {
      const report = build();
      for (const p of [...report.proofs, ...(report.verification?.after ?? [])]) expect(proofIsIntact(p)).toBe(true);
    }
  });
});

describe.each(FIXTURES)("golden output for the %s report", (name, build) => {
  it("plain text matches the golden file", () => {
    expectGolden(`${name}.plain.txt`, renderPlain(build()));
  });

  it("markdown matches the golden file", () => {
    expectGolden(`${name}.md`, renderMarkdown(build()));
  });

  it("json matches the golden file", () => {
    expectGolden(`${name}.json`, renderJson(build()));
  });

  it("renders to identical bytes every time", () => {
    expect(renderPlain(build())).toBe(renderPlain(build()));
    expect(renderMarkdown(build())).toBe(renderMarkdown(build()));
    expect(renderJson(build())).toBe(renderJson(build()));
  });
});

describe("plain report content", () => {
  const plain = renderPlain(vulnerableReport());

  it("opens with tool, scope, database and completeness", () => {
    expect(plain).toContain("Tool: proof-audit 0.1.0");
    expect(plain).toContain("Checked: 7 tables or views");
    expect(plain).toContain("version 16.3");
    expect(plain).toContain("postgres:16.3@sha256:0123456789abcdef");
    expect(plain).toContain("Run complete: yes");
  });

  it("states the result by tier", () => {
    expect(plain).toContain("RESULT: 3 PROVEN, 1 SUSPECTED, 1 INCONCLUSIVE, 2 CLEAN.");
  });

  it("lists PROVEN findings before SUSPECTED and INCONCLUSIVE ones", () => {
    const proven = plain.indexOf("PROVEN: reproduced against a real database");
    const suspected = plain.indexOf("SUSPECTED: NOT proven, low confidence");
    const inconclusive = plain.indexOf("INCONCLUSIVE: NOT proven");
    expect(proven).toBeGreaterThan(-1);
    expect(suspected).toBeGreaterThan(proven);
    expect(inconclusive).toBeGreaterThan(suspected);
  });

  it("labels SUSPECTED and INCONCLUSIVE items as not proven", () => {
    expect(plain).toContain("NOTE: Reading the SQL suggests a problem, but the database did not confirm it.");
    expect(plain).toContain("NOTE: The test could not be completed");
  });

  it("explains in plain words what was done and what came back", () => {
    expect(plain).toContain("We acted as an anonymous visitor (no login, only the public key) and ran:");
    expect(plain).toContain("select * from public.notes");
    expect(plain).toContain("Result: the database returned 3 rows (3 rows seeded for this test).");
    expect(plain).toContain("Access was ALLOWED. That is the problem.");
    expect(plain).toContain("Evidence: sha256 ");
  });

  it("explains a denied attack with the database error", () => {
    expect(plain).toContain("- Anonymous visitor reads rows: the database refused it (error 42501: permission denied for table profiles)");
    expect(plain).toContain("Attempts the database blocked:");
    expect(plain).toContain("Signed-in user deletes another user's rows");
  });

  it("lists attempts that gave no clear answer with their reason", () => {
    expect(plain).toContain("Could not be tested (no clear answer):");
    expect(plain).toContain("Anonymous visitor reads rows: the table could not be seeded");
  });

  it("lists clean subjects one per line", () => {
    expect(plain).toContain("LOOKED FINE");
    expect(plain).toContain("- public.orders: Row level security on, owner checked");
    expect(plain).toContain("- public.settings: Row level security on, no public access");
  });

  it("offers the SQL as a starting point and lists the decisions only the owner can take", () => {
    expect(plain).toContain("Proposed SQL (starting point, review before use):");
    expect(plain).toContain('create policy "notes_owner" on public.notes');
    expect(plain).toContain("These need a decision only you can make:");
    expect(plain).toContain("Only you know whether receivers may read messages.");
  });

  it("describes a partial fix check subject by subject", () => {
    expect(plain).toContain("PARTIAL: only some tables are fixed and confirmed.");
    expect(plain).toContain("public.notes: VERIFIED (attacks closed, normal use works)");
    expect(plain).toContain("public.profiles: STILL VULNERABLE");
    expect(plain).toContain("Signed-in user reads another user's rows: worked before, STILL works");
    expect(plain).not.toContain("every attack that worked before now fails");
  });

  it("cross-checks the static auditor with a proof status per finding", () => {
    expect(plain).toContain("STATIC AUDITOR CROSS-CHECK");
    expect(plain).toContain("- PROVEN by our test: Table without row level security [table public.notes]");
    expect(plain).toContain("- could not be reproduced: Policy that allows everything");
    expect(plain).toContain("- static finding only, not tested: Possible gap in a dynamic policy");
    expect(plain).toContain("2 static findings out of scope");
  });

  it("lists rejected migration statements with file, line and sqlstate", () => {
    expect(plain).toContain("2 in total.");
    expect(plain).toContain("- supabase/migrations/002_profiles.sql:18 [0A000] extension \"pg_cron\" is not available");
  });

  it("lists warnings, test data problems and what was not checked", () => {
    expect(plain).toContain("WARNINGS");
    expect(plain).toContain("- storage.objects policies were not read");
    expect(plain).toContain("- public.audit_log: failed (column details has no default and is not null)");
    expect(plain).toContain("WHAT WAS NOT CHECKED");
    expect(plain).toContain("- Storage bucket policies");
  });

  it("emits no ANSI escape sequences of its own", () => {
    for (const [, build] of FIXTURES.slice(0, 4)) expect(renderPlain(build())).not.toContain("\u001b");
  });
});

describe("plain report for a clean app", () => {
  const plain = renderPlain(fixedReport());

  it("reports nothing to fix and no proof blocks", () => {
    expect(plain).toContain("RESULT: 0 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 3 CLEAN.");
    expect(plain).toContain("No problem could be reproduced.");
    expect(plain).toContain("Nothing to report: no table or view showed a problem.");
    expect(plain).toContain("Nothing to fix.");
    expect(plain).not.toContain("How we proved it");
    expect(plain).not.toContain("Proposed SQL");
  });

  it("says no fix check was run, not that a fix is confirmed", () => {
    expect(plain).toContain("No fix check was run, so no fix is confirmed.");
    expect(plain).not.toMatch(/verified/i);
  });
});

describe("the word verified", () => {
  it("is used for a VERIFIED fix check and explains what it means", () => {
    const plain = renderPlain(verifiedReport());
    expect(plain).toContain(
      "VERIFIED: every attack that worked before now fails, and a normal signed-in user can still read and write their own rows.",
    );
    expect(plain).toContain("- public.todos: Fix VERIFIED: Switch on row level security and restrict todos to their owner.");
  });

  it("is never used when the fix breaks legitimate access", () => {
    for (const out of [renderPlain(breaksAccessReport()), renderMarkdown(breaksAccessReport())]) {
      expect(out).not.toMatch(/verified/i);
      expect(out).toContain("BREAKS ACCESS");
      expect(out).toContain("Do not ship this fix as it is.");
    }
    const plain = renderPlain(breaksAccessReport());
    expect(plain).toContain("normal use that worked before, now BROKEN");
    expect(plain).toContain("Signed-in user reads own rows: normal use that worked before, now BROKEN");
  });

  it("is not claimed for a finding marked verified when the fix check never confirmed it", () => {
    const base = verifiedReport();
    const first = base.findings[0];
    if (first === undefined) throw new Error("fixture has no finding");
    const forged: AnalysisReport = { ...base, verification: null, findings: [{ ...first, fixStatus: "verified" }] };
    for (const out of [renderPlain(forged), renderMarkdown(forged)]) {
      expect(out).not.toMatch(/verified/i);
      expect(out).toContain("A fix was proposed but is not yet confirmed.");
    }
  });

  it("is not claimed for a subject that the fix check left unconfirmed", () => {
    const base = verifiedReport();
    const verification = base.verification;
    const first = base.findings[0];
    if (verification === null || first === undefined) throw new Error("fixture incomplete");
    const forged: AnalysisReport = {
      ...base,
      findings: [{ ...first, fixStatus: "verified" }],
      verification: {
        ...verification,
        status: "PARTIAL",
        subjects: verification.subjects.map((s) => ({ ...s, status: "UNVERIFIED" as const })),
      },
    };
    expect(renderPlain(forged)).not.toMatch(/verified/i);
    expect(renderPlain(forged)).toContain("NOT CONFIRMED");
  });

  it("is not used for a failed fix", () => {
    const base = breaksAccessReport();
    const verification = base.verification;
    if (verification === null) throw new Error("fixture incomplete");
    const failed: AnalysisReport = {
      ...base,
      verification: {
        ...verification,
        status: "FIX_FAILED",
        applyErrors: [{ statement: "create policy p on nowhere", sqlstate: "42P01", message: 'relation "nowhere" does not exist' }],
      },
    };
    const plain = renderPlain(failed);
    expect(plain).toContain("FIX FAILED: the database rejected part of the fix");
    expect(plain).toContain('- create policy p on nowhere [42P01] relation "nowhere" does not exist');
    expect(plain).not.toMatch(/verified/i);
  });
});

describe("markdown report content", () => {
  const md = renderMarkdown(vulnerableReport());

  it("has an H1 title and a summary table", () => {
    expect(md.startsWith("# Row level security report\n")).toBe(true);
    expect(md).toContain("| Item | Value |");
    expect(md).toContain("| Tests run | 8 (4 showed a real problem) |");
  });

  it("has an H2 per section and an H3 per finding", () => {
    for (const heading of ["## Result", "## What we found", "## Looked fine", "## How to fix", "## Fix check", "## Static auditor cross-check", "## Migration statements the database rejected", "## What was not checked"]) {
      expect(md).toContain(`\n${heading}\n`);
    }
    expect(md.match(/^### \d+\. /gm)).toHaveLength(5);
  });

  it("puts SQL in fenced blocks and identifiers in code spans", () => {
    expect(md).toContain("```sql\nselect * from public.notes\n```");
    expect(md).toContain("### 1. PROVEN · critical · `public.notes`");
    expect(md).toContain("```sql\n-- public.notes: only the owner may touch a note\nalter table public.notes enable row level security;");
  });

  it("marks suspected findings as not proven", () => {
    expect(md).toContain("> **NOT proven.** Reading the SQL suggests a problem");
  });

  it("renders the fix check as a table with probe titles", () => {
    expect(md).toContain("| Table | Result | Closed | Still works | Normal use broken | No clear answer | Because |");
    expect(md).toMatch(/\| public\\\.profiles \| STILL VULNERABLE \| none \| Signed\\-in user reads another user's rows \|/);
  });

  it("lists the proof status of every static finding", () => {
    expect(md).toContain("| PROVEN by our test | Table without row level security |");
    expect(md).toContain("| static finding only, not tested |");
  });

  it("escapes the dot in a file location inside table cells", () => {
    expect(md).toContain("supabase/migrations/001\\_init\\.sql\\:12");
  });

  it("lists input files with their hashes", () => {
    expect(md).toContain("## Inputs");
    expect(md).toContain(`| supabase/migrations/001\\_init\\.sql | 1204 | ${"a".repeat(64)} |`);
  });
});

describe("json report", () => {
  const report = vulnerableReport();
  const json = renderJson(report);

  it("is two-space indented and ends with one newline", () => {
    expect(json.startsWith('{\n  "tool": {')).toBe(true);
    expect(json.endsWith("}\n")).toBe(true);
    expect(json.endsWith("\n\n")).toBe(false);
  });

  it("round-trips to the same data", () => {
    expect(JSON.parse(json)).toEqual(JSON.parse(JSON.stringify(report)));
  });

  it("orders the top-level keys as documented", () => {
    expect(Object.keys(JSON.parse(json) as object)).toEqual([
      "tool", "inputs", "environment", "complete", "integrity", "summary", "findings", "proofs", "seeding", "fix", "verification", "audit", "migrationErrors", "warnings", "notChecked",
    ]);
  });

  it("sorts nested keys alphabetically", () => {
    const parsed: { findings: Record<string, unknown>[] } = JSON.parse(json);
    const first = parsed.findings[0];
    const keys = Object.keys(first ?? {});
    expect(keys).toEqual([...keys].sort());
  });

  it("does not depend on the key order of the input", () => {
    const shuffled = Object.fromEntries(Object.entries(report).reverse()) as unknown as AnalysisReport;
    const reversedTool = { ...shuffled, tool: { version: report.tool.version, name: report.tool.name } };
    expect(renderJson(reversedTool)).toBe(json);
  });

  it("contains no timestamps or absolute paths", () => {
    expect(json).not.toMatch(/\b20\d\d-\d\d-\d\dT/);
    expect(json).not.toMatch(/"(?:\/Users|\/home|[A-Z]:\\\\)/);
  });

  it("keeps hostile text as data and escapes control characters", () => {
    const hostile = hostileReport();
    const out = renderJson(hostile);
    expect(out).not.toMatch(/[\u0000-\u0009\u000B-\u001F\u007F]/);
    expect(JSON.parse(out)).toEqual(JSON.parse(JSON.stringify(hostile)));
    expect(out).toContain("\\u001b[31mred");
  });
});

describe("hostile content in plain output", () => {
  const plain = renderPlain(hostileReport());

  it("contains no raw control, ANSI, bidi, zero-width or surrogate characters", () => {
    expect(plain).not.toMatch(FORBIDDEN_PLAIN);
  });

  it("shows the neutralised sequences as visible text", () => {
    expect(plain).toContain("\\x1B[31mred");
    expect(plain).toContain("\\u{202E}");
    expect(plain).toContain("\\u{D800}");
  });

  it("cannot forge a line of its own", () => {
    for (const line of plain.split("\n")) expect(line.trim().startsWith("FORGED")).toBe(false);
  });

  it("truncates very long strings", () => {
    expect(plain).not.toContain("A".repeat(401));
    expect(plain).toContain("…");
  });

  it("has the same section structure as the benign twin", () => {
    const sections = (s: string): number => s.split("\n").filter((l) => /^-{3,}$/.test(l)).length;
    expect(sections(plain)).toBe(sections(renderPlain(hostileTwin())));
  });
});

type LineKind = string;

/** Classifies markdown lines the way a renderer would, so structure can be compared between two reports. */
function skeleton(md: string): LineKind[] {
  const kinds: LineKind[] = [];
  let fence = 0;
  for (const line of md.split("\n")) {
    if (fence > 0) {
      const close = /^ {0,3}(`+)\s*$/.exec(line)?.[1];
      if (close !== undefined && close.length >= fence) {
        fence = 0;
        kinds.push("fence-close");
      } else if (kinds[kinds.length - 1] !== "code") kinds.push("code");
      continue;
    }
    const open = /^ {0,3}(`{3,})([^`]*)$/.exec(line);
    if (open !== null) {
      fence = open[1]?.length ?? 0;
      kinds.push("fence-open");
      continue;
    }
    const heading = /^ {0,3}(#{1,6})(\s|$)/.exec(line);
    if (heading !== null) kinds.push(`h${heading[1]?.length}`);
    else if (line.trim() === "") kinds.push("blank");
    else if (/^\s*\|/.test(line)) kinds.push(`row:${unescapedPipes(line)}`);
    else if (/^\s{0,3}([-+*]|\d+[.)])\s/.test(line)) kinds.push("li");
    else if (/^\s{0,3}>/.test(line)) kinds.push("quote");
    else if (/^\s{0,3}([-*_=])(\s*\1){2,}\s*$/.test(line) || /^\s{0,3}=+\s*$/.test(line)) kinds.push("rule");
    else kinds.push("p");
  }
  return kinds;
}

function unescapedPipes(line: string): number {
  let count = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "\\") i += 1;
    else if (ch === "|") count += 1;
  }
  return count;
}

/** Removes fenced blocks and inline code spans, leaving only what a renderer would interpret. */
function proseOnly(md: string): string[] {
  const out: string[] = [];
  let fence = 0;
  for (const line of md.split("\n")) {
    if (fence > 0) {
      const close = /^ {0,3}(`+)\s*$/.exec(line)?.[1];
      if (close !== undefined && close.length >= fence) fence = 0;
      continue;
    }
    const open = /^ {0,3}(`{3,})([^`]*)$/.exec(line);
    if (open !== null) {
      fence = open[1]?.length ?? 0;
      continue;
    }
    out.push(stripCodeSpans(line));
  }
  return out;
}

function stripCodeSpans(line: string): string {
  let out = "";
  let i = 0;
  while (i < line.length) {
    if (line[i] === "\\") {
      out += line.slice(i, i + 2);
      i += 2;
    } else if (line[i] === "`") {
      const run = /^`+/.exec(line.slice(i))?.[0] ?? "`";
      let j = i + run.length;
      let end = -1;
      while (j < line.length) {
        if (line[j] === "`") {
          const r = /^`+/.exec(line.slice(j))?.[0] ?? "`";
          if (r.length === run.length) {
            end = j + r.length;
            break;
          }
          j += r.length;
        } else j += 1;
      }
      if (end === -1) {
        out += run;
        i += run.length;
      } else {
        out += "CODE";
        i = end;
      }
    } else {
      out += line[i];
      i += 1;
    }
  }
  return out;
}

describe("hostile content in markdown output", () => {
  const hostile = renderMarkdown(hostileReport());
  const twin = renderMarkdown(hostileTwin());

  it("contains no raw control, ANSI, bidi, zero-width or surrogate characters", () => {
    expect(hostile).not.toMatch(FORBIDDEN_MARKDOWN);
  });

  it("has exactly the structure of the benign twin: headings, tables, lists, fences", () => {
    expect(skeleton(hostile)).toEqual(skeleton(twin));
  });

  it("makes the fence around hostile SQL longer than any backtick run inside it", () => {
    expect(hostile).toMatch(/^`{5,}sql$/m);
  });

  it("never lets a forged heading, quote or list item out of a fence or code span", () => {
    for (const line of proseOnly(hostile)) {
      expect(line).not.toMatch(/^\s*(#|>|[-+*]\s|\d+\.\s)\s*FORGED/);
    }
  });

  it("produces no raw HTML, link, image, autolink or mention outside code", () => {
    for (const line of proseOnly(hostile)) {
      expect(line).not.toMatch(/[<]/);
      expect(line).not.toMatch(/[^\\]:\/\//);
      expect(line).not.toMatch(/www\./);
      expect(line).not.toMatch(/(^|[^\\])@/);
      expect(line).not.toMatch(/(^|[^\\])[[\]]/);
      expect(line).not.toMatch(/(^|[^\\])!\\?\[/);
    }
  });

  it("keeps hostile pipes from adding cells", () => {
    const rows = hostile.split("\n").filter((l) => l.startsWith("|"));
    const twinRows = twin.split("\n").filter((l) => l.startsWith("|"));
    expect(rows.map(unescapedPipes)).toEqual(twinRows.map(unescapedPipes));
  });

  it("truncates very long strings", () => {
    expect(hostile).not.toContain("A".repeat(401));
  });
});

describe("caps and gaps", () => {
  const many: AnalysisReport = {
    ...fixedReport(),
    complete: false,
    migrationErrors: Array.from({ length: 15 }, (_, i) => ({
      file: `m/${i + 1}.sql`,
      line: i + 1,
      statement: `select ${i + 1}`,
      sqlstate: "42601",
      message: `syntax error number ${i + 1}`,
    })),
    warnings: Array.from({ length: 25 }, (_, i) => `warning number ${i + 1}`),
  };

  it("lists the first 10 migration errors and counts the rest", () => {
    for (const out of [renderPlain(many), renderMarkdown(many)]) {
      expect(out).toContain("15 in total.");
      expect(out).toContain("syntax error number 10");
      expect(out).not.toContain("syntax error number 11");
      expect(out).toContain("... and 5 more.");
    }
  });

  it("lists the first 20 warnings and counts the rest", () => {
    for (const out of [renderPlain(many), renderMarkdown(many)]) {
      expect(out).toContain("warning number 20");
      expect(out).not.toContain("warning number 21");
      expect(out).toContain("... and 5 more.");
    }
  });

  it("says plainly when the run is incomplete", () => {
    expect(renderPlain(many)).toContain("Run complete: NO, results may be partial");
    expect(renderPlain(many)).toContain("The run is incomplete, so results may be partial.");
    expect(renderMarkdown(many)).toContain("| Run complete | **NO**, results may be partial |");
  });

  it("reports an evidence record that is missing instead of failing", () => {
    const base = vulnerableReport();
    const missing: AnalysisReport = { ...base, proofs: [] };
    expect(renderPlain(missing)).toContain("The evidence record public.notes/anon-read is missing from this report.");
    expect(renderMarkdown(missing)).toContain("is missing from this report.");
  });

  it("caps very long SQL to a readable number of lines", () => {
    const base = verifiedReport();
    const sql = Array.from({ length: 300 }, (_, i) => `-- line ${i + 1}`).join("\n");
    const long: AnalysisReport = base.fix === null ? base : { ...base, fix: { ...base.fix, sql } };
    expect(renderPlain(long)).toContain("-- line 200");
    expect(renderPlain(long)).not.toContain("-- line 201");
    expect(renderPlain(long)).toContain("(100 more lines not shown)");
    expect(renderMarkdown(long)).toContain("_100 more lines are not shown._");
  });
});

describe("wording of proof results and fix lines", () => {
  const constraintProof = proof({
    subject: "public.profiles",
    kind: "anon-insert",
    sql: "insert into public.profiles (id) values (1)",
    observation: { status: "error", sqlstate: "23505", message: 'duplicate key value violates unique constraint "profiles_pkey"' },
    verdict: "PROVEN_VULNERABLE",
    reason: "the access policy let the row through; only a table constraint (SQLSTATE 23505) stopped the insert",
  });

  function withProofs(...proofs: ReturnType<typeof proof>[]): AnalysisReport {
    const base = vulnerableReport();
    const first = base.findings[0];
    if (first === undefined) throw new Error("fixture has no finding");
    return { ...base, proofs: [...proofs], findings: [{ ...first, provenBy: proofs.map((p) => p.id), notReproduced: [], inconclusive: [] }] };
  }

  it("says the policy let a constraint-stopped insert through instead of 'refused'", () => {
    for (const out of [renderPlain(withProofs(constraintProof)), renderMarkdown(withProofs(constraintProof))]) {
      expect(out).toContain("the access policy let the row through; only a table constraint stopped it (error 23505");
      expect(out).not.toContain("refused it");
      expect(out).toContain("Access was ALLOWED. That is the problem.");
      expect(out).not.toContain("SQLSTATE 23505) stopped");
    }
  });

  it("keeps 'refused' for a denied attack", () => {
    const denied = proof({
      subject: "public.profiles",
      kind: "anon-insert",
      sql: "insert into public.profiles (id) values (1)",
      observation: { status: "error", sqlstate: "42501", message: "denied" },
      verdict: "NOT_REPRODUCED",
      reason: "the database refused the insert",
    });
    expect(renderPlain(withProofs(denied))).toContain("the database refused it (error 42501: denied)");
  });

  it("drops a reason that only repeats the row count and writes other reasons as a sentence", () => {
    const repeat = proof({
      subject: "public.notes",
      kind: "anon-read",
      sql: "select 1",
      observation: { status: "rows", rows: 2 },
      verdict: "PROVEN_VULNERABLE",
      reason: "the statement returned 2 rows",
    });
    const other = proof({
      subject: "public.notes",
      kind: "anon-delete",
      sql: "delete from t",
      observation: { status: "rows", rows: 2 },
      verdict: "PROVEN_VULNERABLE",
      reason: "every seeded row was removed",
    });
    const plain = renderPlain(withProofs(repeat, other));
    expect(plain).toContain("Access was ALLOWED. That is the problem.\n");
    expect(plain).not.toContain("the statement returned 2 rows\n");
    expect(plain).toContain("Access was ALLOWED. That is the problem. Every seeded row was removed.");
  });

  it("shows the fix status once and uses the finding's note as the detail", () => {
    const base = verifiedReport();
    const first = base.findings[0];
    if (first === undefined) throw new Error("fixture has no finding");
    const note = "Fix verified: 2 attack(s) now fail and 1 legitimate action(s) still work.";
    const report: AnalysisReport = { ...base, findings: [{ ...first, fixNote: note }] };
    for (const out of [renderPlain(report), renderMarkdown(report)]) {
      const line = (out.split("\n").find((l) => l.includes("Fix VERIFIED")) ?? "").replaceAll("\\", "");
      expect(line).toContain("Fix VERIFIED: 2 attack(s) now fail");
      expect(line.match(/verified/gi)).toHaveLength(1);
    }
  });

  it("pluralises the counts it generates", () => {
    const one = proof({
      subject: "public.notes",
      kind: "anon-read",
      sql: "select 1",
      observation: { status: "rows", rows: 1 },
      targetRows: 1,
      verdict: "PROVEN_VULNERABLE",
      reason: "x",
    });
    expect(renderPlain(withProofs(one))).toContain("returned 1 row (1 row seeded for this test)");
  });
});

describe("integrity violation in the reports", () => {
  const plain = renderPlain(integrityReport());
  const markdown = renderMarkdown(integrityReport());

  it("says so in the first screen, in plain language, and lists every violation with whether the database allowed it", () => {
    expect(plain).toContain("INTEGRITY_VIOLATION: DO NOT TRUST THESE RESULTS");
    expect(plain).toContain("CREATE FUNCTION auth.uid (redefines-platform-object; the database refused it) at supabase/migrations/001_init.sql:4");
    expect(plain).toContain("function auth.uid() changed (after the probes) (platform-changed; the environment changed)");
    expect(markdown).toContain("## INTEGRITY\\_VIOLATION\\: do not trust these results");
  });

  it("shows every table as could not be judged and never proven or clean", () => {
    expect(plain).toContain("0 PROVEN, 0 SUSPECTED, 3 INCONCLUSIVE, 0 CLEAN");
    expect(plain).not.toContain("refused every attack");
    expect(plain).toContain("No fix check was run");
  });

  it("is absent from a report whose environment is intact", () => {
    for (const out of [renderPlain(fixedReport()), renderMarkdown(fixedReport())]) expect(out).not.toContain("INTEGRITY");
  });

  it("escapes hostile text in the detail and the file", () => {
    const base = integrityReport();
    const hostile = { ...base, integrity: { status: "INTEGRITY_VIOLATION" as const, violations: [{ kind: "event-trigger" as const, detail: "\u001b[31m\u202eevil|`x`", file: "a\nb<script>.sql", line: 1, outcome: "unknown" as const }] } };
    expect(renderPlain(hostile)).not.toMatch(FORBIDDEN_PLAIN);
    expect(renderMarkdown(hostile)).not.toMatch(FORBIDDEN_MARKDOWN);
    expect(JSON.parse(renderJson(hostile)).integrity.status).toBe("INTEGRITY_VIOLATION");
  });
});
