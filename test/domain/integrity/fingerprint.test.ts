import { describe, expect, it } from "vitest";
import { assessIntegrity, INTACT } from "../../../src/domain/integrity/assess.js";
import { compareFingerprints, parseFingerprint } from "../../../src/domain/integrity/fingerprint.js";

const fp = (pairs: [string, string][]) => {
  const r = parseFingerprint({ entries: pairs.map(([key, value]) => ({ key, value })) });
  if (!r.ok) throw new Error(r.error);
  return r.value;
};

describe("parseFingerprint", () => {
  it("sorts entries by key so the order the database returns does not matter", () => {
    expect(fp([["b", "1"], ["a", "2"]]).map((e) => e.key)).toEqual(["a", "b"]);
  });

  it("rejects unknown keys, wrong shapes and oversized lists", () => {
    expect(parseFingerprint({ entries: [], extra: 1 }).ok).toBe(false);
    expect(parseFingerprint({ entries: [{ key: "", value: "x" }] }).ok).toBe(false);
    expect(parseFingerprint("x").ok).toBe(false);
    expect(parseFingerprint({ entries: Array.from({ length: 2001 }, (_, i) => ({ key: `k${i}`, value: "v" })) }).ok).toBe(false);
  });
});

describe("compareFingerprints", () => {
  it("finds nothing when they are equal", () => {
    expect(compareFingerprints(fp([["a", "1"]]), fp([["a", "1"]]), "after the migrations")).toEqual([]);
  });

  it("reports changed, removed and added entries with when it was noticed", () => {
    const out = compareFingerprints(fp([["function auth.uid()", "sha=1"], ["role anon", "x"]]), fp([["function auth.uid()", "sha=2"], ["event trigger t", "y"]]), "after the probes");
    expect(out.map((v) => v.detail)).toEqual(["event trigger t appeared (after the probes)", "function auth.uid() changed (after the probes)", "role anon was removed (after the probes)"]);
    expect(out.every((v) => v.kind === "platform-changed" && v.outcome === "state-changed")).toBe(true);
  });

  it("never echoes values, only keys", () => {
    const out = compareFingerprints(fp([["k", "secret-value"]]), fp([["k", "other"]]), "x");
    expect(JSON.stringify(out)).not.toContain("secret-value");
  });
});

describe("assessIntegrity", () => {
  const attempt = { kind: "event-trigger" as const, detail: "CREATE EVENT TRIGGER", file: "m.sql", line: 3 };

  it("is intact with nothing to report", () => {
    expect(assessIntegrity([], new Map(), [])).toEqual(INTACT);
  });

  it("marks an attempt the database refused as blocked and one it accepted as succeeded", () => {
    expect(assessIntegrity([attempt], new Map([["m.sql:3", false]]), []).violations[0]?.outcome).toBe("blocked");
    expect(assessIntegrity([attempt], new Map([["m.sql:3", true]]), []).violations[0]?.outcome).toBe("succeeded");
    expect(assessIntegrity([attempt], new Map(), []).violations[0]?.outcome).toBe("unknown");
  });

  it("is a violation even when every attempt was blocked, and keeps fingerprint changes", () => {
    const r = assessIntegrity([attempt], new Map([["m.sql:3", false]]), compareFingerprints(fp([["a", "1"]]), fp([["a", "2"]]), "x"));
    expect(r.status).toBe("INTEGRITY_VIOLATION");
    expect(r.violations).toHaveLength(2);
  });
});
