import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../../src/domain/hash/canonical-json.js";
import { sha256Hex, sha256HexBytes } from "../../../src/domain/hash/sha256.js";

describe("sha256Hex", () => {
  it("matches the FIPS 180-4 vector for the empty string", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("matches the vector for 'abc'", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("matches the two-block vector", () => {
    expect(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("matches the one-million-'a' vector", () => {
    expect(sha256Hex("a".repeat(1_000_000))).toBe("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  });

  it("hashes the UTF-8 bytes of non-ASCII text", () => {
    expect(sha256Hex("é")).toBe(sha256HexBytes(new Uint8Array([0xc3, 0xa9])));
  });

  it("handles lengths around the padding boundary", () => {
    const digests = new Set([55, 56, 63, 64, 65].map((n) => sha256Hex("x".repeat(n))));
    expect(digests.size).toBe(5);
  });
});

describe("canonicalJson", () => {
  it("sorts keys at every level", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } })).toBe('{"a":{"c":[3,{"y":2,"z":1}],"d":2},"b":1}');
  });

  it("is independent of insertion order", () => {
    expect(canonicalJson({ x: 1, y: 2 })).toBe(canonicalJson({ y: 2, x: 1 }));
  });

  it("drops undefined properties and keeps null", () => {
    expect(canonicalJson({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("escapes strings like JSON", () => {
    expect(canonicalJson({ s: 'a"b\n' })).toBe('{"s":"a\\"b\\n"}');
  });

  it("rejects values without a JSON form", () => {
    expect(() => canonicalJson(() => 1)).toThrow(TypeError);
  });
});
