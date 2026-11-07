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

  it("follows the written rules, for every combination of attacks (an oracle that shares no code with the implementation)", () => {
    const anonWrites = ["anon-insert", "anon-update", "anon-delete"];
    const crossUser = ["cross-read", "cross-insert", "cross-update", "cross-delete", "reassign-owner", "view-read-cross"];
    const oracle = (kinds: readonly string[], owner: boolean, subject: string): string => {
      if (kinds.some((k) => anonWrites.includes(k))) return "critical";
      if (kinds.includes("anon-read") || kinds.includes("view-read-anon")) return owner || subject === "view" ? "critical" : "medium";
      return kinds.some((k) => crossUser.includes(k)) ? "high" : "medium";
    };
    for (let mask = 1; mask < 1 << EXPLOITS.length; mask++) {
      const kinds = EXPLOITS.filter((_, i) => (mask >> i) & 1);
      for (const owner of [true, false]) {
        for (const subject of ["table", "view"] as const) {
          const want = oracle(kinds, owner, subject);
          expect(severityFor(kinds, owner, subject).overall_severity, `${kinds.join()} ${owner} ${subject}`).toBe(want);
          expect(severityOf(kinds, owner, subject), `${kinds.join()} ${owner} ${subject}`).toBe(want);
        }
      }
    }
  });

  it("gives each anchor the impact the docs table lists, literally", () => {
    expect(Object.fromEntries(Object.entries(IMPACT_ANCHORS).map(([id, a]) => [id, a.impact]))).toEqual({
      "anon-write": "critical",
      "anon-read-owned": "critical",
      "anon-read-unowned": "medium",
      "cross-user": "high",
      other: "medium",
    });
  });

  it("can give one record of a table a lower severity than the table as a whole", () => {
    // report.json rates the table by every attack proven on it; a record is rated by the attacks of its own root cause
    expect(severityOf(["anon-read", "cross-update"], true, "table")).toBe("critical");
    expect(severityFor(["cross-update"], true, "table").overall_severity).toBe("high");
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
