import { describe, expect, it } from "vitest";
import { splitStatements } from "../../../src/domain/sql/splitter.js";

const split = (content: string, options?: { maxStatementBytes?: number; maxStatements?: number }) =>
  splitStatements({ path: "a.sql", content }, options);

const texts = (content: string): string[] => split(content).statements.map((s) => s.text);

describe("splitStatements basics", () => {
  it("splits on semicolons and drops them from the text", () => {
    expect(texts("select 1; select 2;")).toEqual(["select 1", "select 2"]);
  });

  it("returns a final statement that has no semicolon", () => {
    expect(texts("select 1; select 2")).toEqual(["select 1", "select 2"]);
  });

  it("ignores empty statements", () => {
    expect(texts(";; select 1 ;;\n;")).toEqual(["select 1"]);
  });

  it("returns nothing for blank or comment-only input", () => {
    expect(split("").statements).toEqual([]);
    expect(split("  -- nothing\n/* here */").statements).toEqual([]);
  });

  it("records file path and the line of the first token", () => {
    const { statements } = split("\n\n-- note\nselect 1;\n\ncreate table t (a int);");
    expect(statements.map((s) => [s.file, s.line])).toEqual([["a.sql", 4], ["a.sql", 6]]);
  });

  it("drops leading comments but keeps inner comments", () => {
    expect(texts("-- lead\n/* x */ select 1 /* mid */ + 2;")).toEqual(["select 1 /* mid */ + 2"]);
  });

  it("does not keep a comment that sits between the last token and the semicolon", () => {
    expect(texts("select 1 -- trailing\n;")).toEqual(["select 1"]);
  });

  it("does not split on semicolons inside strings, quoted identifiers or comments", () => {
    expect(texts(`select ';', ";", 'a''b;c' /* ; */ -- ;\n; select 2`)).toEqual([
      `select ';', ";", 'a''b;c'`,
      "select 2",
    ]);
  });

  it("does not split inside dollar-quoted function bodies", () => {
    const sql = "create function f() returns int as $body$ begin select 1; return 2; end; $body$ language plpgsql; select 3;";
    const out = texts(sql);
    expect(out).toHaveLength(2);
    expect(out[0]).toContain("return 2;");
    expect(out[1]).toBe("select 3");
  });

  it("treats an unterminated dollar quote as one statement to the end", () => {
    expect(texts("select 1; do $$ begin; select 2;")).toEqual(["select 1", "do $$ begin; select 2;"]);
  });

  it("counts a statement after a multi-line string on the right line", () => {
    const { statements } = split("select 'a\nb\nc';\nselect 2;");
    expect(statements.map((s) => s.line)).toEqual([1, 4]);
  });
});

describe("splitStatements BEGIN ATOMIC", () => {
  it("keeps the body of a SQL-standard function together", () => {
    const sql = "create function f() returns int language sql begin atomic select 1; select 2; end; select 3;";
    const out = texts(sql);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatch(/begin atomic select 1; select 2; end$/);
    expect(out[1]).toBe("select 3");
  });

  it("counts CASE ... END so the inner END does not close the body", () => {
    const sql = "create function f() returns int begin atomic select case when true then 1 else 2 end; select 5; end; select 3;";
    const out = texts(sql);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatch(/select 5; end$/);
  });

  it("does not count a column named like END after a dot", () => {
    const sql = "create function f() returns int begin atomic select t.\"end\"; select x.end; end; select 3;";
    expect(texts(sql)).toHaveLength(2);
  });

  it("swallows the rest of the file when the body never ends, as one statement", () => {
    const out = texts("create procedure p() begin atomic select 1; select 2;");
    expect(out).toEqual(["create procedure p() begin atomic select 1; select 2;"]);
  });

  it("classifies BEGIN ATOMIC as sql, not as a transaction", () => {
    const { statements } = split("begin atomic select 1; end;");
    expect(statements).toHaveLength(1);
    expect(statements[0]?.kind).toBe("sql");
  });
});

describe("splitStatements kinds", () => {
  it.each([
    "begin",
    "BEGIN TRANSACTION",
    "begin work",
    "begin isolation level serializable",
    "start transaction",
    "commit",
    "COMMIT AND CHAIN",
    "end",
    "rollback",
    "rollback to savepoint x",
  ])("classifies %s as transaction control", (text) => {
    expect(split(`${text};`).statements[0]?.kind).toBe("transaction-control");
  });

  it("does not classify START or other statements that merely begin with a keyword", () => {
    expect(split("start replication;").statements[0]?.kind).toBe("sql");
    expect(split("beginner();").statements[0]?.kind).toBe("sql");
  });

  it("returns psql meta lines as their own statements with a warning", () => {
    const { statements, warnings } = split("select 1;\n\\connect db\nselect 2;");
    expect(statements.map((s) => [s.kind, s.text])).toEqual([["sql", "select 1"], ["psql-meta", "\\connect db"], ["sql", "select 2"]]);
    expect(warnings).toEqual([{ file: "a.sql", line: 2, message: "psql meta-command skipped" }]);
  });

  it("flushes an unterminated statement before a meta line", () => {
    const { statements } = split("select 1\n\\q\nselect 2;");
    expect(statements.map((s) => s.text)).toEqual(["select 1", "\\q", "select 2"]);
  });
});

describe("splitStatements caps", () => {
  it("drops a statement longer than the byte cap with a warning", () => {
    const result = split(`select 1; select '${"x".repeat(100)}'; select 3;`, { maxStatementBytes: 50 });
    expect(result.statements.map((s) => s.text)).toEqual(["select 1", "select 3"]);
    expect(result.complete).toBe(false);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]?.line).toBe(1);
  });

  it("measures the cap in UTF-8 bytes, not characters", () => {
    const body = "é".repeat(30); // 30 characters, 60 bytes
    expect(split(`select '${body}'`, { maxStatementBytes: 50 }).complete).toBe(false);
    expect(split(`select '${body}'`, { maxStatementBytes: 80 }).complete).toBe(true);
  });

  it("keeps a statement exactly at the cap", () => {
    const result = split("select 1", { maxStatementBytes: 8 });
    expect(result.statements).toHaveLength(1);
    expect(result.complete).toBe(true);
  });

  it("stops at the statement count cap with a warning", () => {
    const result = split("select 1; select 2; select 3; select 4;", { maxStatements: 2 });
    expect(result.statements.map((s) => s.text)).toEqual(["select 1", "select 2"]);
    expect(result.complete).toBe(false);
    expect(result.warnings.at(-1)?.message).toContain("limit");
  });

  it("is complete when the count equals the cap exactly", () => {
    const result = split("select 1; select 2;", { maxStatements: 2 });
    expect(result.statements).toHaveLength(2);
    expect(result.complete).toBe(true);
  });

  it("counts meta lines against the statement cap", () => {
    const result = split("\\a\n\\b\n\\c\n", { maxStatements: 2 });
    expect(result.statements).toHaveLength(2);
    expect(result.complete).toBe(false);
  });

  it("does not echo the dropped statement text in warnings", () => {
    const result = split(`select '${"secret".repeat(40)}';`, { maxStatementBytes: 20 });
    expect(result.warnings[0]?.message).not.toContain("secret");
  });
});
