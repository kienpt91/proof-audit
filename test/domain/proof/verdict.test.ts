import { describe, expect, it } from "vitest";
import { proofIsIntact } from "../../../src/domain/proof/hash.js";
import type { Probe, ProbeObservation } from "../../../src/domain/proof/types.js";
import { judge, recordProof } from "../../../src/domain/proof/verdict.js";

function probe(overrides: Partial<Probe> = {}): Probe {
  return {
    id: "public.notes/cross-read",
    subject: "public.notes",
    subjectKind: "table",
    kind: "cross-read",
    intent: "exploit",
    command: "select",
    actor: "user-a",
    role: "authenticated",
    claims: "{}",
    sql: "SELECT * FROM public.notes",
    title: "t",
    targetRows: 1,
    blockedReason: null,
    ...overrides,
  };
}

const rows = (n: number): ProbeObservation => ({ status: "rows", rows: n });
const error = (sqlstate: string): ProbeObservation => ({ status: "error", sqlstate, message: "m" });

describe("judge: exploit probes", () => {
  it("proves a read that returned rows", () => {
    expect(judge(probe(), rows(2))).toEqual({ verdict: "PROVEN_VULNERABLE", reason: "the statement returned 2 rows" });
  });

  it("proves a write that changed one row", () => {
    expect(judge(probe({ command: "update" }), rows(1)).reason).toBe("the statement changed 1 row");
  });

  it("proves an insert that went through", () => {
    expect(judge(probe({ command: "insert", targetRows: null }), rows(1)).verdict).toBe("PROVEN_VULNERABLE");
  });

  it("does not reproduce when no rows come back although rows existed", () => {
    const r = judge(probe({ targetRows: 3 }), rows(0));
    expect(r.verdict).toBe("NOT_REPRODUCED");
    expect(r.reason).toContain("although 3 rows existed");
  });

  it("is inconclusive when zero rows came back and nothing existed to hit", () => {
    expect(judge(probe({ targetRows: 0 }), rows(0)).verdict).toBe("INCONCLUSIVE");
    expect(judge(probe({ targetRows: null }), rows(0)).verdict).toBe("INCONCLUSIVE");
  });

  it("treats permission denied and RLS violations (42501) as a refusal", () => {
    expect(judge(probe(), error("42501")).verdict).toBe("NOT_REPRODUCED");
    expect(judge(probe({ command: "insert" }), error("42501")).verdict).toBe("NOT_REPRODUCED");
  });

  it("is inconclusive for any other error and names the SQLSTATE", () => {
    const r = judge(probe({ command: "insert" }), error("22P02"));
    expect(r.verdict).toBe("INCONCLUSIVE");
    expect(r.reason).toContain("22P02");
  });

  it("proves an insert the policy admitted and only a constraint stopped, since policies are checked first", () => {
    const r = judge(probe({ command: "insert", targetRows: null }), error("23505"));
    expect(r.verdict).toBe("PROVEN_VULNERABLE");
    expect(r.reason).toContain("only a table constraint");
  });

  it("does not apply the constraint rule to reads or to legitimate inserts", () => {
    expect(judge(probe({ command: "update" }), error("23505")).verdict).toBe("INCONCLUSIVE");
    expect(judge(probe({ kind: "own-insert", intent: "legitimate", command: "insert", targetRows: null }), error("23502")).verdict).toBe("INCONCLUSIVE");
  });

  it("treats a timeout as inconclusive", () => {
    expect(judge(probe(), error("57014")).verdict).toBe("INCONCLUSIVE");
  });

  it("is inconclusive when an insert reports neither rows nor an error", () => {
    expect(judge(probe({ command: "insert" }), rows(0)).verdict).toBe("INCONCLUSIVE");
  });

  it("is inconclusive for a probe that could not be built", () => {
    expect(judge(probe({ blockedReason: "nothing was seeded" }), rows(5))).toEqual({ verdict: "INCONCLUSIVE", reason: "nothing was seeded" });
  });

  it("passes a not-run reason through", () => {
    expect(judge(probe(), { status: "not-run", reason: "timed out" })).toEqual({ verdict: "INCONCLUSIVE", reason: "timed out" });
  });
});

describe("judge: legitimate probes", () => {
  const own = (o: Partial<Probe> = {}) => probe({ kind: "own-read", intent: "legitimate", ...o });

  it("accepts access that worked", () => {
    expect(judge(own(), rows(1)).verdict).toBe("ACCESS_OK");
  });

  it("flags access that was refused or returned nothing", () => {
    expect(judge(own(), error("42501")).verdict).toBe("ACCESS_BROKEN");
    expect(judge(own(), rows(0)).verdict).toBe("ACCESS_BROKEN");
  });

  it("is inconclusive when nothing was there to read", () => {
    expect(judge(own({ targetRows: 0 }), rows(0)).verdict).toBe("INCONCLUSIVE");
  });

  it("accepts an own insert and flags a refused one", () => {
    expect(judge(own({ command: "insert", targetRows: null }), rows(1)).verdict).toBe("ACCESS_OK");
    expect(judge(own({ command: "insert", targetRows: null }), error("42501")).verdict).toBe("ACCESS_BROKEN");
  });

  it("does not call a constraint error broken access", () => {
    expect(judge(own({ command: "insert", targetRows: null }), error("23502")).verdict).toBe("INCONCLUSIVE");
  });
});

describe("recordProof", () => {
  it("seals the proof with an intact hash", () => {
    const p = recordProof(probe(), rows(1), "before");
    expect(p.phase).toBe("before");
    expect(p.verdict).toBe("PROVEN_VULNERABLE");
    expect(proofIsIntact(p)).toBe(true);
  });

  it("records a blocked probe as not run whatever was observed", () => {
    const p = recordProof(probe({ blockedReason: "no rows" }), rows(4), "before");
    expect(p.observation).toEqual({ status: "not-run", reason: "no rows" });
    expect(p.verdict).toBe("INCONCLUSIVE");
  });

  it("gives equal evidence an equal hash and different evidence a different one", () => {
    const a = recordProof(probe(), rows(1), "before");
    expect(recordProof(probe(), rows(1), "before").hash).toBe(a.hash);
    expect(recordProof(probe(), rows(2), "before").hash).not.toBe(a.hash);
    expect(recordProof(probe(), rows(1), "after").hash).not.toBe(a.hash);
  });
});
