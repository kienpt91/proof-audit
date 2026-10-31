import { describe, expect, it } from "vitest";
import { dollarQuote, quoteIdent, quoteLiteral, quoteQualified } from "../../src/domain/sql/quote.js";

describe("quoting", () => {
  it("doubles embedded double quotes in identifiers", () => {
    expect(quoteIdent('we"ird')).toBe('"we""ird"');
  });

  it("quotes a qualified name part by part", () => {
    expect(quoteQualified("public", "My Table")).toBe('"public"."My Table"');
  });

  it("doubles single quotes in literals and leaves backslashes alone", () => {
    expect(quoteLiteral("it's \\ fine")).toBe("'it''s \\ fine'");
  });

  it("writes identifiers with unsafe characters as Unicode escapes so the SQL is safe to print", () => {
    expect(quoteIdent("a\u001b[31mb")).toBe('U&"a\\001b[31mb"');
    expect(quoteIdent("x\ny")).toBe('U&"x\\000ay"');
    expect(quoteIdent("\u202ereversed")).toBe('U&"\\202ereversed"');
    expect(quoteIdent('q"\u0007')).toBe('U&"q""\\0007"');
  });

  it("doubles a backslash only inside Unicode-escape identifiers, where it is an escape character", () => {
    expect(quoteIdent("a\\b")).toBe('"a\\b"');
    expect(quoteIdent("a\\b\u0001")).toBe('U&"a\\\\b\\0001"');
  });

  it("writes literals with unsafe characters as Unicode escapes too", () => {
    expect(quoteLiteral("it's\u001b")).toBe("U&'it''s\\001b'");
    expect(quoteLiteral("plain")).toBe("'plain'");
  });

  it("leaves ordinary non-ASCII text alone", () => {
    expect(quoteIdent("naïve_表")).toBe('"naïve_表"');
    expect(quoteLiteral("emoji 🙂")).toBe("'emoji 🙂'");
  });

  it("rejects NUL bytes everywhere", () => {
    expect(() => quoteIdent("a\u0000b")).toThrow();
    expect(() => quoteLiteral("a\u0000b")).toThrow();
    expect(() => dollarQuote("a\u0000b")).toThrow();
  });

  it("dollar-quotes with a tag that is absent from the text", () => {
    expect(dollarQuote("select 1")).toBe("$pa$select 1$pa$");
    const hostile = "select $pa$ x $pa$ ; $pa1$";
    const q = dollarQuote(hostile);
    const tag = /^\$(pa\d*)\$/.exec(q)?.[1] ?? "";
    expect(q).toBe(`$${tag}$${hostile}$${tag}$`);
    expect(hostile.includes(`$${tag}$`)).toBe(false);
  });

  it("does not let the text end in a way that merges with the closing tag", () => {
    const q = dollarQuote("x$pa");
    expect(q.endsWith("$pa$") && q.startsWith("$pa$")).toBe(false);
  });
});
