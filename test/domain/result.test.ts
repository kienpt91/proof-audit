import { describe, expect, it } from "vitest";
import { err, mapResult, ok } from "../../src/domain/result.js";

describe("Result", () => {
  it("wraps a value", () => {
    expect(ok(3)).toEqual({ ok: true, value: 3 });
  });

  it("wraps an error", () => {
    expect(err("nope")).toEqual({ ok: false, error: "nope" });
  });

  it("maps only successful results", () => {
    expect(mapResult(ok(2), (n) => n * 2)).toEqual(ok(4));
    expect(mapResult(err("x"), (n: number) => n * 2)).toEqual(err("x"));
  });
});
