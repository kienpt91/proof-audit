import { describe, expect, it } from "vitest";
import { checkFindings, checkFindingsText, isSafeRelativePath, MAX_RECORDS } from "../../../src/domain/interchange/conformance.js";
import { encodeFindings, type ConfirmedRecord, type FindingRecord, type NeedsValidationRecord, type RejectedRecord } from "../../../src/domain/interchange/records.js";

const step = (kind: "entrypoint" | "propagation" | "sink", line: number) => ({ kind, file: "db/001.sql", line, scope: "table public.t", description: `step ${line}` });
const base = (fingerprint: string) => ({
  fingerprint,
  title: "A title",
  description: "A description",
  trace: [step("entrypoint", 3), step("sink", 1)],
  evidence: [{ file: "db/001.sql", line: 3, description: "evidence" }],
});

const confirmed = (fingerprint = "proof-audit/rls/public.t/rls-disabled"): ConfirmedRecord => ({
  verdict: "confirmed",
  ...base(fingerprint),
  root_cause: "root cause",
  intended_behavior: "intended",
  conditions: [{ kind: "authentication_level", description: "anon" }],
  execution: { attacker_perspective: "anyone", payloads: ["SELECT 1"], instructions: ["run it"], observed_result: "1 row" },
  remediation: { strategy: "fix it", code_changes: [{ file_name: "fix.sql", fixed_code: "-- fix" }] },
  severity: { likelihood: { score: "high", reason: "easy" }, impact: { score: "high", reason: "bad" }, overall_severity: "high" },
  confidence: { score: "high", reason: "proven" },
});

const needs = (fingerprint = "proof-audit/rls/public.u/untested"): NeedsValidationRecord => ({
  verdict: "needs_validation",
  ...base(fingerprint),
  claimed_root_cause: "claim",
  blockers: ["no probe ran"],
  validation_plan: { local: "run it locally" },
});

const rejected = (fingerprint = "saas-audit/r:f.sql:public.t"): RejectedRecord => ({ verdict: "rejected", ...base(fingerprint), claimed_root_cause: "claim", reason: "refused" });

const errorsOf = (records: readonly unknown[]): string[] => checkFindings(JSON.parse(JSON.stringify(records)), 1000);
/** Test data is edited in place to break one rule at a time; its shape is exactly what the encoder wrote. */
type Loose = any;
const mutate = (record: object, change: (r: Loose) => void): unknown => {
  const copy: Loose = JSON.parse(JSON.stringify(record));
  change(copy);
  return copy;
};

describe("a conforming document", () => {
  it("accepts one record of each verdict, sorted by fingerprint, and the empty list", () => {
    const records: FindingRecord[] = [confirmed("a/1"), needs("b/2"), rejected("c/3")];
    expect(checkFindingsText(encodeFindings(records))).toEqual([]);
    expect(checkFindingsText("[]\n")).toEqual([]);
  });

  it("is sorted by the encoder whatever the order of the records", () => {
    const text = encodeFindings([rejected("z/1"), confirmed("a/1"), needs("m/1")]);
    expect((JSON.parse(text) as FindingRecord[]).map((r) => r.fingerprint)).toEqual(["a/1", "m/1", "z/1"]);
    expect(text.endsWith("]\n")).toBe(true);
  });

  it("allows a one-step trace of kind entrypoint or sink and a deployment-only validation plan", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [step("sink", 1)]))])).toEqual([]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [step("entrypoint", 1)]))])).toEqual([]);
    expect(errorsOf([mutate(needs(), (r) => (r.validation_plan = { deployment: "check in staging" }))])).toEqual([]);
  });
});

describe("what is refused", () => {
  it("something that is not an array of records", () => {
    expect(checkFindingsText("{}")).toEqual(["$: expected an array of records"]);
    expect(checkFindingsText("nope")).toEqual(["$: not valid JSON"]);
    expect(errorsOf([42])).toEqual(["$[0]: expected an object"]);
    expect(errorsOf([{ verdict: "maybe" }])[0]).toContain("must be confirmed, needs_validation or rejected");
  });

  it("missing and extra properties on every verdict", () => {
    expect(errorsOf([mutate(confirmed(), (r) => delete r.root_cause)])).toEqual(['$[0]: missing required field "root_cause"']);
    expect(errorsOf([mutate(confirmed(), (r) => (r.extra = 1))])).toEqual(['$[0]: unexpected field "extra"']);
    expect(errorsOf([mutate(needs(), (r) => (r.severity = {}))])).toEqual(['$[0]: unexpected field "severity"']);
    expect(errorsOf([mutate(needs(), (r) => (r.execution = {}))])).toEqual(['$[0]: unexpected field "execution"']);
    expect(errorsOf([mutate(rejected(), (r) => (r.blockers = ["x"]))])).toEqual(['$[0]: unexpected field "blockers"']);
    expect(errorsOf([mutate(rejected(), (r) => delete r.reason)])).toEqual(['$[0]: missing required field "reason"']);
    expect(errorsOf([mutate(confirmed(), (r) => (r.claimed_root_cause = "x"))])).toEqual(['$[0]: unexpected field "claimed_root_cause"']);
  });

  it("a fingerprint outside the pattern, a duplicate and an unsorted list", () => {
    for (const bad of ["", "-x", "a b", "a\n", "é", "a#b", "/a"]) expect(errorsOf([confirmed(bad)])).toEqual(["$[0].fingerprint: must match the fingerprint pattern"]);
    expect(errorsOf([confirmed("a"), needs("a")])).toEqual(["$[1].fingerprint: duplicates $[0]"]);
    expect(errorsOf([confirmed("b"), needs("a")])).toEqual(["$[1].fingerprint: records must be sorted by fingerprint"]);
  });

  it("text without a visible character", () => {
    for (const blank of ["", "   ", "\u200b", "\u0007", "\u202e\u2060", "\ud800"]) {
      expect(errorsOf([mutate(confirmed(), (r) => (r.title = blank))])).toEqual(["$[0].title: must contain a visible character"]);
    }
    expect(errorsOf([mutate(needs(), (r) => (r.blockers = ["\u200b"]))])).toEqual(["$[0].blockers[0]: must contain a visible character"]);
    expect(errorsOf([mutate(needs(), (r) => (r.validation_plan = { local: " " }))])).toContain("$[0].validation_plan.local: must contain a visible character");
    expect(errorsOf([mutate(needs(), (r) => (r.validation_plan = {}))])).toEqual(["$[0].validation_plan: needs a local or a deployment plan"]);
  });

  it("an empty trace, empty evidence, empty blockers, empty payloads and instructions", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = []))])).toEqual(["$[0].trace: needs at least 1 item(s)"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.evidence = []))])).toEqual(["$[0].evidence: needs at least 1 item(s)"]);
    expect(errorsOf([mutate(needs(), (r) => (r.blockers = []))])).toEqual(["$[0].blockers: needs at least 1 item(s)"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = []))])).toEqual(["$[0].execution.payloads: needs at least 1 item(s)"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.instructions = []))])).toEqual(["$[0].execution.instructions: needs at least 1 item(s)"]);
  });

  it("duplicates in lists that must be unique", () => {
    const dup = step("propagation", 2);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [step("entrypoint", 3), dup, { ...dup }, step("sink", 1)]))])).toEqual(["$[0].trace[2]: duplicate of an earlier item"]);
    const e = { file: "db/001.sql", line: 3, description: "same" };
    expect(errorsOf([mutate(rejected(), (r) => (r.evidence = [e, { description: "same", line: 3, file: "db/001.sql" }]))])).toEqual(["$[0].evidence[1]: duplicate of an earlier item"]);
    expect(errorsOf([mutate(needs(), (r) => (r.blockers = ["a", "a"]))])).toEqual(["$[0].blockers[1]: duplicate of an earlier item"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = ["x", "x"]))])).toEqual(["$[0].execution.payloads[1]: duplicate of an earlier item"]);
  });

  it("positions that are not a real line of a safe relative path", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace[0].line = 0))])).toEqual(["$[0].trace[0].line: must be an integer of at least 1"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace[0].line = 1.5))])).toEqual(["$[0].trace[0].line: must be an integer of at least 1"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.evidence[0].line = "3"))])).toEqual(["$[0].evidence[0].line: must be an integer of at least 1"]);
    for (const file of ["/etc/passwd", "../x.sql", "a/../b.sql", "C:\\x.sql", "a\\b.sql", "a b ", "a/./b", "a//b", "con.sql", "x/aux", "dir./f.sql", "~/f.sql", "f\u0000.sql", "f\u202e.sql", "db:1.sql", ""]) {
      expect(errorsOf([mutate(confirmed(), (r) => (r.trace[0].file = file))])).toEqual(["$[0].trace[0].file: must be a safe repository-relative path"]);
    }
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation.code_changes[0]!.file_name = "../fix.sql"))])).toEqual(["$[0].remediation.code_changes[0].file_name: must be a safe repository-relative path"]);
  });

  it("a trace whose kinds are out of order", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [step("propagation", 1)]))])).toEqual(["$[0].trace[0].kind: a trace of one step must be an entrypoint or a sink"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [step("sink", 1), step("entrypoint", 2)]))])).toEqual(["$[0].trace[0].kind: must be entrypoint at this position", "$[0].trace[1].kind: must be sink at this position"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [step("entrypoint", 1), step("entrypoint", 2), step("sink", 3)]))])).toEqual(["$[0].trace[1].kind: must be propagation at this position"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace[0].kind = "source"))])).toEqual(["$[0].trace[0].kind: must be one of entrypoint, propagation, sink"]);
  });

  it("scores, kinds and an overall severity above the impact", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity.overall_severity = "critical"))])).toEqual(["$[0].severity.overall_severity: cannot be higher than the impact"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity.overall_severity = "info"))])).toEqual(["$[0].severity.overall_severity: must be one of informational, low, medium, high, critical"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity.impact.score = "severe"))])[0]).toContain("severity.impact.score: must be one of");
    expect(errorsOf([mutate(confirmed(), (r) => (r.confidence.score = "certain"))])).toEqual(["$[0].confidence.score: must be one of low, medium, high"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.conditions[0].kind = "moon_phase"))])[0]).toContain("conditions[0].kind: must be one of");
  });

  it("an overall severity below the impact is fine", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity.overall_severity = "medium"))])).toEqual([]);
  });

  it("nested objects with extra or missing properties", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.extra = 1))])).toEqual(['$[0].execution: unexpected field "extra"']);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace[0].extra = 1))])).toEqual(['$[0].trace[0]: unexpected field "extra"']);
    expect(errorsOf([mutate(confirmed(), (r) => delete r.remediation.strategy)])).toContain('$[0].remediation: missing required field "strategy"');
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity.likelihood = { score: "low" }))])).toContain('$[0].severity.likelihood: missing required field "reason"');
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation.code_changes = [{ file_name: "fix.sql" }]))])).toContain('$[0].remediation.code_changes[0]: missing required field "fixed_code"');
  });

  it("a document with too many records or too many bytes", () => {
    const many = Array.from({ length: MAX_RECORDS + 1 }, (_, i) => rejected(`s/${String(i).padStart(5, "0")}`));
    expect(checkFindings(JSON.parse(JSON.stringify(many)), 10)[0]).toBe(`$: more than ${MAX_RECORDS} records`);
    expect(checkFindings([], 6 * 1024 * 1024)[0]).toContain("larger than");
  });

  it("stops listing after a hundred errors", () => {
    expect(errorsOf(Array.from({ length: 300 }, () => 1))).toHaveLength(100);
  });
});

describe("isSafeRelativePath", () => {
  it("accepts ordinary repository paths", () => {
    for (const p of ["a.sql", "supabase/migrations/20260105090000_init.sql", "dir/.hidden/file", "a-b_c.d/e", "com10.sql", "com0", "console.sql", "cloc.sql"]) expect(isSafeRelativePath(p)).toBe(true);
  });

  it("refuses whatever could leave the repository or mean something else on another platform", () => {
    for (const p of ["", " a", "a ", "/a", "~a", "a\\b", "a:b", "..", "a/..", "./a", "a/", "a//b", "nul", "COM1.txt", "lpt9", "a/Clock$", "a.", "a /b", "\u0000", "a\u200bb", "a\u2028b"]) expect(isSafeRelativePath(p)).toBe(false);
  });

  it("refuses the device names the reference validator refuses: superscript digits and Unicode case folding", () => {
    for (const p of ["com\u00b9.sql", "COM\u00b2", "a/lpt\u00b3.x", "LPT\u00b9", "cloc\u212a$", "a/cloc\u212a$.sql", "conin$", "conout$.txt", "NUL.sql", "Aux", "prn.d/x"]) expect(isSafeRelativePath(p), p).toBe(false);
  });
});

describe("the size limits of the uniqueness check", () => {
  const KEY_LIMIT = 1024 * 1024;
  // the canonical text of a string is `string:"` + the string + `"`: nine bytes more
  const payload = (bytes: number, lead = "x"): string => lead + "x".repeat(bytes - 1);

  it("accepts a list item whose canonical key is exactly 1 MiB and refuses one byte more", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [payload(KEY_LIMIT - 9)]))])).toEqual([]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [payload(KEY_LIMIT - 8)]))])).toEqual(["$[0].execution.payloads[0]: canonical key exceeds 1048576 byte limit"]);
  });

  it("counts UTF-8 bytes, not characters: 2, 3 and 4 bytes per character and a lone surrogate as 3", () => {
    const message = "$[0].execution.payloads[0]: canonical key exceeds 1048576 byte limit";
    // [character, the most that fit next to the 9 bytes of `string:"` and `"`]
    const rows: [string, number][] = [["\u00e9", 524_283], ["\u20ac", 349_522], ["\ud83d\ude00", 262_141]];
    for (const [ch, fits] of rows) {
      expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [ch.repeat(fits)]))])).toEqual([]);
      expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [ch.repeat(fits + 1)]))])).toEqual([message]);
    }
    // a lone surrogate is another error of its own, and still counts three bytes
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = ["\ud800".repeat(349_523)]))])).toContain(message);
  });

  it("compares numbers, booleans and null by their canonical text", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [1, 1]))])).toContain("$[0].execution.payloads[1]: duplicate of an earlier item");
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [-0, 0]))])).toContain("$[0].execution.payloads[1]: duplicate of an earlier item");
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [null, null, true, true]))])).toEqual(expect.arrayContaining(["$[0].execution.payloads[1]: duplicate of an earlier item", "$[0].execution.payloads[3]: duplicate of an earlier item"]));
  });

  it("refuses a list whose canonical keys together pass 5 MiB", () => {
    const six = Array.from({ length: 6 }, (_, i) => payload(KEY_LIMIT - 9, String.fromCharCode(97 + i)));
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = six))])).toEqual(["$[0].execution.payloads: canonical uniqueness set exceeds 5242880 byte limit"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = six.slice(0, 5)))])).toEqual([]);
  });

  it("sizes nested objects by their canonical text too", () => {
    const big = { file: "db/001.sql", line: 3, description: "x".repeat(KEY_LIMIT) };
    expect(errorsOf([mutate(confirmed(), (r) => (r.evidence = [big]))])).toEqual(["$[0].evidence[0]: canonical key exceeds 1048576 byte limit"]);
  });
});

describe("values of the wrong type", () => {
  it("are reported where they are, not as a crash", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = "x"))])).toEqual(["$[0].trace: expected an array"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.trace = [5]))])).toEqual(["$[0].trace[0]: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.evidence = [null]))])).toEqual(["$[0].evidence[0]: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.conditions = [3]))])).toEqual(["$[0].conditions[0]: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution = 5))])).toEqual(["$[0].execution: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation = []))])).toEqual(["$[0].remediation: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity = "high"))])).toEqual(["$[0].severity: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.confidence = null))])).toEqual(["$[0].confidence: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.severity.likelihood = 1))])).toEqual(["$[0].severity.likelihood: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation.code_changes = [7]))])).toEqual(["$[0].remediation.code_changes[0]: expected an object"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation.code_changes = "x"))])).toEqual(["$[0].remediation.code_changes: expected an array"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation.code_changes[0].fixed_code = 1))])).toEqual(["$[0].remediation.code_changes[0].fixed_code: expected a string"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [5]))])).toEqual(["$[0].execution.payloads[0]: expected a string"]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.instructions = [""]))])).toEqual(["$[0].execution.instructions[0]: must contain a visible character"]);
    expect(errorsOf([mutate(needs(), (r) => (r.validation_plan = "run"))])).toEqual(["$[0].validation_plan: expected an object"]);
    expect(errorsOf([mutate(needs(), (r) => (r.blockers = 1))])).toEqual(["$[0].blockers: expected an array"]);
    expect(errorsOf([mutate(needs(), (r) => (r.validation_plan = { local: 4 }))])).toContain("$[0].validation_plan.local: expected a string");
    expect(errorsOf([mutate(rejected(), (r) => (r.reason = 5))])).toEqual(["$[0].reason: expected a string"]);
  });

  it("treats a payload with any text, even blank, as valid because the format does not ask for visible payloads", () => {
    expect(errorsOf([mutate(confirmed(), (r) => (r.execution.payloads = [" "]))])).toEqual([]);
    expect(errorsOf([mutate(confirmed(), (r) => (r.remediation.code_changes[0].fixed_code = ""))])).toEqual([]);
  });
});
