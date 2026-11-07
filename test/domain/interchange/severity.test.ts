import { describe, expect, it } from "vitest";
import { severityOf, type SeverityAnchorId, severityAnchor } from "../../../src/domain/analysis/findings.js";
import { IMPACT_ANCHORS, severityFor, toScore } from "../../../src/domain/interchange/severity.js";
import type { ProbeKind } from "../../../src/domain/proof/types.js";

const EXPLOITS: readonly ProbeKind[] = ["anon-read", "anon-insert", "anon-update", "anon-delete", "cross-read", "cross-insert", "null-owner-insert", "cross-update", "cross-delete", "reassign-owner", "view-read-anon", "view-read-cross"];

/** The rows of the severity anchor table in the docs, written out once more: what was proven, whether the owner is known, the result. */
const TABLE: readonly (readonly [string, readonly ProbeKind[], boolean, "table" | "view", SeverityAnchorId, string])[] = [
  ["anonymous write", ["anon-insert"], true, "table", "anon-write", "critical"],
  ["anonymous write, no owner column", ["anon-update"], false, "table", "anon-write", "critical"],
  ["anonymous delete with cross reads", ["anon-delete", "cross-read"], true, "table", "anon-write", "critical"],
  ["anonymous read of owned rows", ["anon-read"], true, "table", "anon-read-owned", "critical"],
  ["anonymous read through a view", ["view-read-anon"], false, "view", "anon-read-owned", "critical"],
  ["anonymous read, table without owner", ["anon-read"], false, "table", "anon-read-unowned", "medium"],
  ["cross-user read", ["cross-read"], true, "table", "cross-user", "high"],
  ["cross-user insert", ["cross-insert"], true, "table", "cross-user", "high"],
  ["cross-user update", ["cross-update"], true, "table", "cross-user", "high"],
  ["cross-user delete", ["cross-delete"], true, "table", "cross-user", "high"],
  ["handing a row over", ["reassign-owner"], true, "table", "cross-user", "high"],
  ["cross-user read through a view", ["view-read-cross"], true, "view", "cross-user", "high"],
  ["a row without an owner", ["null-owner-insert"], true, "table", "other", "medium"],
];

describe("severity anchors", () => {
  it.each(TABLE)("%s", (_name, kinds, owner, subject, id, severity) => {
    expect(severityAnchor(kinds, owner, subject)).toEqual({ id, severity });
    const block = severityFor(kinds, owner, subject);
    expect(block.overall_severity).toBe(severity);
    expect(block.impact.score).toBe(severity);
    expect(block.impact.reason).toBe(IMPACT_ANCHORS[id].reason);
  });

  it("agrees with the severity that report.json gives, for every combination of attacks", () => {
    for (let mask = 1; mask < 1 << EXPLOITS.length; mask++) {
      const kinds = EXPLOITS.filter((_, i) => (mask >> i) & 1);
      for (const owner of [true, false]) {
        for (const subject of ["table", "view"] as const) {
          expect(severityFor(kinds, owner, subject).overall_severity).toBe(toScore(severityOf(kinds, owner, subject)));
        }
      }
    }
  });

  it("keeps the table in step with the function: every anchor has the impact the function gives it", () => {
    for (const [, kinds, owner, subject, id] of TABLE) expect(IMPACT_ANCHORS[id].impact).toBe(toScore(severityOf(kinds, owner, subject)));
    expect(Object.keys(IMPACT_ANCHORS).sort()).toEqual(["anon-read-owned", "anon-read-unowned", "anon-write", "cross-user", "other"]);
  });

  it("never lets the overall severity exceed the impact", () => {
    const order = ["informational", "low", "medium", "high", "critical"];
    for (const [, kinds, owner, subject] of TABLE) {
      const block = severityFor(kinds, owner, subject);
      expect(order.indexOf(block.overall_severity)).toBeLessThanOrEqual(order.indexOf(block.impact.score));
    }
  });

  it("scores the likelihood by what the attacker needs: the public key alone is high, a signed-in account is medium", () => {
    expect(severityFor(["anon-read"], true, "table").likelihood.score).toBe("high");
    expect(severityFor(["view-read-anon"], true, "view").likelihood.score).toBe("high");
    expect(severityFor(["cross-read", "anon-delete"], true, "table").likelihood.score).toBe("high");
    expect(severityFor(["cross-update", "reassign-owner"], true, "table").likelihood.score).toBe("medium");
  });

  it("is deterministic: the same attacks give the same block", () => {
    expect(severityFor(["cross-read"], true, "table")).toEqual(severityFor(["cross-read"], true, "table"));
  });

  it("maps the report scale to the interchange scale", () => {
    expect(toScore("info")).toBe("informational");
    expect(["low", "medium", "high", "critical"].map((s) => toScore(s as "low"))).toEqual(["low", "medium", "high", "critical"]);
  });
});
