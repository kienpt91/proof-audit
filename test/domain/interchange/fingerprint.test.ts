import { describe, expect, it } from "vitest";
import { encodePath, encodeSegment, rlsFingerprint, staticFingerprint, staticNames } from "../../../src/domain/interchange/fingerprint.js";

const PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;

describe("encodeSegment", () => {
  it("keeps letters, digits, dot, underscore and hyphen", () => {
    expect(encodeSegment("public.My_table-2")).toBe("public.My_table-2");
  });

  it("writes every other byte as + and two lowercase hex digits", () => {
    expect(encodeSegment("Anyone can use tickets")).toBe("Anyone+20can+20use+20tickets");
    expect(encodeSegment("a+b")).toBe("a+2bb");
    expect(encodeSegment("a:b/c")).toBe("a+3ab+2fc");
    expect(encodeSegment('say "hi"')).toBe("say+20+22hi+22");
  });

  it("encodes multi-byte characters byte by byte", () => {
    expect(encodeSegment("é")).toBe("+c3+a9");
    expect(encodeSegment("日")).toBe("+e6+97+a5");
    expect(encodeSegment("😀")).toBe("+f0+9f+98+80");
  });

  it("never produces a separator, so segments can be joined with : and /", () => {
    for (const name of ["a:b", "a/b", "::", "//", "a\nb", "a b:c/d@e"]) expect(encodeSegment(name)).not.toMatch(/[:/@\s]/);
  });

  it("is injective on a spread of awkward names", () => {
    const names = ["", "a", "A", "a b", "a+20b", "a+b", "a%20b", "a:b", "a+3ab", "é", "e", "+", "++", "+2b", "a.b", "a_b", "a-b", "\u0000", "\u0001", "x\u202ey", "x\u200by"];
    const seen = new Map<string, string>();
    for (const n of names) {
      const e = encodeSegment(n);
      expect(seen.get(e) ?? n).toBe(n);
      seen.set(e, n);
    }
  });

  it("only ever yields characters the fingerprint pattern allows", () => {
    for (let cp = 1; cp < 0x3000; cp += 7) expect(`x${encodeSegment(String.fromCodePoint(cp))}`).toMatch(PATTERN);
  });
});

describe("encodePath", () => {
  it("keeps the separators and encodes the parts", () => {
    expect(encodePath("supabase/migrations/2026 01.sql")).toBe("supabase/migrations/2026+2001.sql");
    expect(encodePath("a:b/c")).toBe("a+3ab/c");
    expect(encodePath("")).toBe("");
  });
});

describe("rlsFingerprint", () => {
  it("is built from the schema-qualified name, the kind and the policy only", () => {
    expect(rlsFingerprint("public", "tickets", "rls-disabled", null)).toBe("proof-audit/rls/public.tickets/rls-disabled");
    expect(rlsFingerprint("public", "tickets", "policy-always-true", "Anyone can use tickets")).toBe("proof-audit/rls/public.tickets/policy-always-true/Anyone+20can+20use+20tickets");
  });

  it("separates a table from a schema and a table named with dots", () => {
    expect(rlsFingerprint("a", "b.c", "untested", null)).not.toBe(rlsFingerprint("a.b", "c", "untested", null));
  });

  it("matches the fingerprint pattern for hostile names", () => {
    for (const name of ["", "x y", "é", 'a"b', "a\nb", "\u202e", "😀", "a/b:c@d"]) {
      expect(rlsFingerprint(name, name, "policy-always-true", name)).toMatch(PATTERN);
    }
  });
});

describe("staticFingerprint", () => {
  it("follows the scheme of the static auditor: rule, path, then every name of the subject", () => {
    expect(staticFingerprint("supabase-policy-permissive", "supabase/migrations/20260105090000_init.sql", ["public.tickets", "Anyone can use tickets"])).toBe(
      "saas-audit/supabase-policy-permissive:supabase/migrations/20260105090000_init.sql:public.tickets:Anyone+20can+20use+20tickets",
    );
    expect(staticFingerprint("supabase-rls-missing", "m.sql", ["public.profiles"])).toBe("saas-audit/supabase-rls-missing:m.sql:public.profiles");
  });

  it("does not depend on a line number", () => {
    expect(staticFingerprint("r", "f.sql", ["public.t"])).toBe(staticFingerprint("r", "f.sql", ["public.t"]));
  });

  it("matches the pattern when the file, rule or names are odd", () => {
    expect(staticFingerprint("odd rule", "a b/\u00e9.sql", ["s.t", "p:q"])).toMatch(PATTERN);
    expect(staticFingerprint("", "", ["s.t"])).toMatch(PATTERN);
  });
});

describe("staticNames", () => {
  it("takes the non-empty names of the subject array, else the whole title", () => {
    expect(staticNames(["public.t", "", "p"], "a title")).toEqual(["public.t", "p"]);
    expect(staticNames(null, "Table public.t has no row level security")).toEqual(["Table public.t has no row level security"]);
    expect(staticNames([], "t")).toEqual(["t"]);
    expect(staticNames([""], "t")).toEqual(["t"]);
  });

  it("builds the title-based identity that saas-audit gives a report without subject", () => {
    expect(staticFingerprint("supabase-rls-missing", "m.sql", staticNames(null, "Table public.profiles has no RLS"))).toBe("saas-audit/supabase-rls-missing:m.sql:Table+20public.profiles+20has+20no+20RLS");
  });
});
