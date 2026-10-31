import { describe, expect, it } from "vitest";
import { array, boolean, integer, literal, nullable, object, parseJson, string } from "../../src/domain/validate.js";

describe("validators", () => {
  it("accepts and rejects strings with a length cap", () => {
    expect(string({ max: 3 })("abc", "x").ok).toBe(true);
    expect(string({ max: 3 })("abcd", "x")).toEqual({ ok: false, error: "x: expected a string of at most 3 characters" });
    expect(string()(5, "x").ok).toBe(false);
  });

  it("checks string patterns and minimum length", () => {
    expect(string({ pattern: /^a+$/ })("aab", "p").ok).toBe(false);
    expect(string({ min: 2 })("a", "p").ok).toBe(false);
  });

  it("bounds integers", () => {
    expect(integer({ min: 1, max: 3 })(2, "n").ok).toBe(true);
    expect(integer({ min: 1, max: 3 })(4, "n").ok).toBe(false);
    expect(integer()(1.5, "n").ok).toBe(false);
    expect(integer()("1", "n").ok).toBe(false);
  });

  it("accepts only listed literals", () => {
    const v = literal("a", "b");
    expect(v("a", "l").ok).toBe(true);
    expect(v("c", "l")).toEqual({ ok: false, error: "l: expected one of a, b" });
  });

  it("validates booleans and nullables", () => {
    expect(boolean(true, "b").ok).toBe(true);
    expect(boolean("true", "b").ok).toBe(false);
    expect(nullable(string())(null, "s")).toEqual({ ok: true, value: null });
    expect(nullable(string())(1, "s").ok).toBe(false);
  });

  it("names the failing array index", () => {
    const r = array(integer())([1, "x"], "list");
    expect(r).toEqual({ ok: false, error: "list[1]: expected an integer" });
    expect(array(integer(), { max: 1 })([1, 2], "list").ok).toBe(false);
  });

  it("rejects unknown keys by default and allows them on request", () => {
    const shape = { a: string() };
    expect(object(shape)({ a: "x", b: 1 }, "o")).toEqual({ ok: false, error: 'o: unexpected key "b"' });
    expect(object(shape, { allowUnknown: true })({ a: "x", b: 1 }, "o")).toEqual({ ok: true, value: { a: "x" } });
  });

  it("reports a missing key and accepts optional ones", () => {
    expect(object({ a: string() })({}, "o")).toEqual({ ok: false, error: "o.a: missing" });
    expect(object({ a: string() }, { optional: ["a"] })({}, "o")).toEqual({ ok: true, value: {} });
  });

  it("rejects arrays and null where an object is expected", () => {
    expect(object({})([], "o").ok).toBe(false);
    expect(object({})(null, "o").ok).toBe(false);
  });

  it("does not treat inherited keys as present", () => {
    expect(object({ toString: string() })({}, "o").ok).toBe(false);
  });

  it("does not echo a hostile key in full", () => {
    const r = object({ a: string() })({ ["x".repeat(500)]: 1 }, "o");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.length).toBeLessThan(80);
  });
});

describe("parseJson", () => {
  const v = object({ n: integer() });
  it("parses and validates", () => {
    expect(parseJson('{"n":1}', v, { maxBytes: 100, label: "doc" })).toEqual({ ok: true, value: { n: 1 } });
  });

  it("refuses oversized text before parsing", () => {
    expect(parseJson('{"n":1}', v, { maxBytes: 3, label: "doc" })).toEqual({ ok: false, error: "doc: larger than 3 bytes" });
  });

  it("does not echo invalid JSON", () => {
    expect(parseJson("{secret", v, { maxBytes: 100, label: "doc" })).toEqual({ ok: false, error: "doc: not valid JSON" });
  });
});
