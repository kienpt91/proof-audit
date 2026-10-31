import { describe, expect, it } from "vitest";
import { checkHints } from "../../../src/domain/seed/hints.js";

describe("checkHints", () => {
  it("finds the enumerated strings in an ANY(ARRAY[...]) constraint", () => {
    const h = checkHints("status", ["CHECK ((status = ANY (ARRAY['draft'::text, 'live'::text])))"]);
    expect(h.literals).toEqual(["draft", "live"]);
  });

  it("finds literals in an IN-style constraint written by hand", () => {
    expect(checkHints("kind", ["CHECK (kind IN ('a','b'))"]).literals).toEqual(["a", "b"]);
  });

  it("ignores constraints about other columns", () => {
    expect(checkHints("status", ["CHECK ((kind = 'x'))"])).toEqual({ literals: [], min: null, max: null, minLength: null });
  });

  it("does not match a longer column name that contains the name", () => {
    expect(checkHints("id", ["CHECK ((user_id > 5))"]).min).toBeNull();
  });

  it("reads inclusive and exclusive lower bounds", () => {
    expect(checkHints("age", ["CHECK ((age >= 18))"]).min).toBe(18);
    expect(checkHints("qty", ["CHECK ((qty > 0))"]).min).toBe(1);
  });

  it("reads inclusive and exclusive upper bounds", () => {
    expect(checkHints("rating", ["CHECK ((rating <= 5))"]).max).toBe(5);
    expect(checkHints("rating", ["CHECK ((rating < 5))"]).max).toBe(4);
  });

  it("reads BETWEEN", () => {
    const h = checkHints("score", ["CHECK (((score >= 1) AND (score <= 10)))", "CHECK (score BETWEEN 2 AND 8)"]);
    expect(h.min).toBe(2);
    expect(h.max).toBe(8);
  });

  it("reads a minimum length", () => {
    expect(checkHints("title", ["CHECK ((char_length(title) > 2))"]).minLength).toBe(3);
    expect(checkHints("title", ["CHECK ((length(title) >= 5))"]).minLength).toBe(5);
  });

  it("handles quoted column names and casts", () => {
    expect(checkHints("Status", [`CHECK (("Status" = 'ok'::text))`]).literals).toEqual(["ok"]);
  });

  it("unescapes doubled quotes and skips empty literals", () => {
    expect(checkHints("name", ["CHECK (name <> '' AND name <> 'it''s')"]).literals).toEqual(["it's"]);
  });

  it("returns empty hints for no checks", () => {
    expect(checkHints("x", [])).toEqual({ literals: [], min: null, max: null, minLength: null });
  });
});
