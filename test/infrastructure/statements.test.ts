import { describe, expect, it } from "vitest";
import { tokenize } from "../../src/domain/sql/tokenizer.js";
import * as sql from "../../src/infrastructure/postgres/statements.js";
import type { Step } from "../../src/infrastructure/postgres/transport.js";

const HOSTILE = "select $pa$ x $pa$, $pa1$ y $pa1$; drop table users; -- \\ \u0000".replace("\u0000", "");

/** The PL/pgSQL text inside the DO step, with every dollar-quoted string (the SQL under test) removed. */
function ourCode(steps: readonly Step[]): ReturnType<typeof tokenize> {
  const block = steps[0]?.sql ?? "";
  const m = /^DO (\$[a-z0-9_]*\$)([\s\S]*)\1$/.exec(block);
  if (!m) throw new Error("not a DO block with a dollar-quoted body");
  return tokenize(m[2] ?? "").filter((t) => t.kind !== "dollar-string");
}

function unqualifiedCalls(steps: readonly Step[]): string[] {
  const tokens = ourCode(steps);
  const bad: string[] = [];
  tokens.forEach((t, i) => {
    if (t.kind !== "word" || tokens[i + 1]?.value !== "(") return;
    const qualified = tokens[i - 1]?.value === "." && tokens[i - 2]?.value.toLowerCase() === "pg_catalog";
    if (!qualified && t.value !== "coalesce") bad.push(t.value);
  });
  return bad;
}

function operators(steps: readonly Step[]): string[] {
  return ourCode(steps).filter((t) => t.kind === "operator" && ![":=", "::", "=", ":"].includes(t.value)).map((t) => t.value);
}

const all = (): Step[][] => [
  sql.tryExec(HOSTILE),
  sql.tryFirst([HOSTILE, "select 2"]),
  sql.scalar(HOSTILE),
  sql.probe("anon", '{"role":"anon"}', HOSTILE),
  sql.probe("authenticated", `{"sub":"it's"}`, HOSTILE),
];

describe("statement builders", () => {
  it("send a DO block that runs nothing stored, then one SELECT that reads the reply", () => {
    for (const steps of all()) {
      expect(steps).toHaveLength(2);
      expect(steps[0]).toMatchObject({ fetch: false });
      expect(steps[0]?.sql.startsWith("DO $")).toBe(true);
      expect(steps[1]).toEqual({ sql: "SELECT pg_catalog.current_setting('proof_audit.reply', true)", fetch: true });
    }
  });

  it("call only pg_catalog-qualified functions, so nothing a migration defines can be reached", () => {
    for (const steps of all()) expect(unqualifiedCalls(steps)).toEqual([]);
  });

  it("use no operator of their own, so no operator a migration defines can be reached", () => {
    for (const steps of all()) expect(operators(steps)).toEqual([]);
  });

  it("carry the SQL under test as a dollar-quoted string that it cannot terminate early", () => {
    for (const steps of all()) {
      const block = steps[0]?.sql ?? "";
      const outer = /^DO (\$[a-z0-9_]*\$)/.exec(block)?.[1] ?? "";
      const body = block.slice(3 + outer.length, block.length - outer.length);
      expect(body.includes(outer)).toBe(false);
      expect(block.endsWith(outer)).toBe(true);
    }
  });

  it("tryExec reports success or the SQLSTATE and message, including for a cancelled query", () => {
    const code = sql.tryExec("select 1")[0]?.sql ?? "";
    expect(code).toContain("WHEN query_canceled THEN");
    expect(code).toContain("WHEN OTHERS THEN");
    expect(code).toContain("'sqlstate', SQLSTATE");
    expect(code).toContain("pg_catalog.left(SQLERRM, 500)");
  });

  it("tryFirst unrolls the alternatives in order and stops at the first success", () => {
    const code = sql.tryFirst(["select 1", "select 2", "select 3"])[0]?.sql ?? "";
    expect(code.match(/EXECUTE/g)).toHaveLength(3);
    expect(code.match(/IF r IS NULL THEN/g)).toHaveLength(4);
    expect(code).toContain('"attempt": 2');
  });

  it("tryFirst with no alternatives replies with a failure", () => {
    expect(sql.tryFirst([])[0]?.sql).toContain("no statement given");
  });

  it("probe sets the claims, switches role, reads ROW_COUNT and always rolls back with its own error code", () => {
    const code = sql.probe("authenticated", `{"sub":"it's"}`, "select 1")[0]?.sql ?? "";
    expect(code).toContain(`pg_catalog.set_config('request.jwt.claims', '{"sub":"it''s"}', true)`);
    expect(code).toContain("SET LOCAL ROLE authenticated;");
    expect(code).toContain("GET DIAGNOSTICS n = ROW_COUNT");
    expect(code).toContain("RAISE EXCEPTION USING ERRCODE = 'PA000'");
    expect(code).toContain("WHEN SQLSTATE 'PA000' THEN NULL");
  });

  it("probe publishes the reply only after its sub-transaction has ended, so the SQL under test cannot set it", () => {
    const code = sql.probe("anon", "{}", "select 1")[0]?.sql ?? "";
    expect(code.indexOf("END;")).toBeLessThan(code.indexOf("PERFORM pg_catalog.set_config('proof_audit.reply'"));
  });

  it("probe only accepts the two client roles", () => {
    for (const role of ["service_role", "postgres", "anon; drop table x", "ANON", ""]) expect(() => sql.probe(role, "{}", "select 1")).toThrow("only run as anon or authenticated");
  });
});
