import { describe, expect, it } from "vitest";
import { groupByRootCause, tableRootCauses, viewRootCauses, type ProofGroup } from "../../../src/domain/interchange/rootcause.js";
import type { ProbeKind, Proof } from "../../../src/domain/proof/types.js";
import { ALL, col, model, notes, OWN, pk, policy, tbl, userFk, view } from "../../helpers/model.js";
import { proof } from "../../fixtures/reports.js";

const proven = (subject: string, kind: ProbeKind): Proof =>
  proof({ subject, kind, sql: `-- ${kind}`, observation: { status: "rows", rows: 1 }, verdict: "PROVEN_VULNERABLE", reason: "the statement changed 1 row", subjectKind: subject.includes("view") ? "view" : "table" });

const kindsOf = (groups: readonly ProofGroup[]): [string, string[]][] =>
  groups.map((g) => [`${g.cause?.kind ?? "unattributed"}${g.cause?.policy ? `:${g.cause.policy.name}` : ""}`, g.proofs.map((p) => p.kind)]);

describe("tableRootCauses", () => {
  it("is empty for a table with a correct owner policy", () => {
    expect(tableRootCauses(notes()).filter((c) => c.suspicious)).toEqual([]);
  });

  it("names row level security that is off, once, for every probe", () => {
    const open = notes({ rlsEnabled: false, policies: [], privileges: { anon: ALL, authenticated: ALL } });
    const causes = tableRootCauses(open);
    expect(causes.map((c) => c.kind)).toEqual(["rls-disabled"]);
    expect(causes[0]?.suspicious).toBe(true);
    const groups = groupByRootCause([proven("public.notes", "anon-read"), proven("public.notes", "cross-update"), proven("public.notes", "anon-delete")], causes);
    expect(kindsOf(groups)).toEqual([["rls-disabled", ["anon-read", "cross-update", "anon-delete"]]]);
  });

  it("gives each always-true policy its own group, by the commands and roles it reaches", () => {
    const t = tbl("things", [pk(), userFk()], {
      policies: [
        policy("Anyone reads", "select", ["public"], "true", null),
        policy("Anon writes", "insert", ["anon"], null, "true"),
        policy("Signed-in updates", "update", ["authenticated"], "true", "true"),
      ],
    });
    const groups = groupByRootCause(
      [proven("public.things", "anon-read"), proven("public.things", "cross-read"), proven("public.things", "anon-insert"), proven("public.things", "cross-update"), proven("public.things", "reassign-owner")],
      tableRootCauses(t),
    );
    expect(kindsOf(groups)).toEqual([
      ["policy-always-true:Anon writes", ["anon-insert"]],
      ["policy-always-true:Anyone reads", ["anon-read", "cross-read"]],
      ["policy-always-true:Signed-in updates", ["cross-update", "reassign-owner"]],
    ]);
  });

  it("attributes a probe to the first cause in the documented order and each probe once", () => {
    const t = tbl("both", [pk(), userFk()], {
      policies: [policy("Everyone", "all", ["public"], "true", "true"), policy("Weak insert", "insert", ["authenticated"], null, "title is not null")],
    });
    const causes = tableRootCauses(t);
    expect(causes.map((c) => c.kind)).toEqual(["policy-always-true", "policy-owner-unchecked", "owner-not-compared"]);
    const groups = groupByRootCause([proven("public.both", "cross-insert"), proven("public.both", "null-owner-insert")], causes);
    expect(kindsOf(groups)).toEqual([["policy-always-true:Everyone", ["cross-insert", "null-owner-insert"]]]);
  });

  it("separates a policy that does not tie the written row to its owner", () => {
    const t = tbl("posts", [pk(), userFk(), col("title", "text")], {
      policies: [policy("Read own", "select", ["authenticated"], OWN, null), policy("Add posts", "insert", ["authenticated"], null, "title is not null")],
    });
    const causes = tableRootCauses(t);
    expect(causes.map((c) => c.kind)).toEqual(["policy-owner-unchecked"]);
    expect(causes[0]?.policy?.name).toBe("Add posts");
    const groups = groupByRootCause([proven("public.posts", "cross-insert"), proven("public.posts", "cross-read")], causes);
    expect(kindsOf(groups)).toEqual([["policy-owner-unchecked:Add posts", ["cross-insert"]], ["unattributed", ["cross-read"]]]);
  });

  it("names a table where no policy compares the owner with the caller", () => {
    const t = tbl("loose", [pk(), userFk()], { policies: [policy("Signed-in", "all", ["authenticated"], "auth.role() = 'authenticated'", "auth.role() = 'authenticated'")] });
    const causes = tableRootCauses(t);
    expect(causes.map((c) => c.kind)).toContain("owner-not-compared");
    const groups = groupByRootCause([proven("public.loose", "cross-read"), proven("public.loose", "anon-read")], causes);
    expect(kindsOf(groups).find(([key]) => key === "owner-not-compared")?.[1]).toEqual(["cross-read"]);
    expect(kindsOf(groups).find(([key]) => key === "unattributed")?.[1]).toEqual(["anon-read"]);
  });

  it("puts probes no static cause explains into the unattributed group, last", () => {
    const groups = groupByRootCause([proven("public.notes", "anon-read")], tableRootCauses(notes()));
    expect(kindsOf(groups)).toEqual([["unattributed", ["anon-read"]]]);
    expect(groups[0]?.cause).toBeNull();
  });

  it("orders policy causes by policy name so the output does not depend on catalog order", () => {
    const a = tbl("t", [pk(), userFk()], { policies: [policy("b", "all", ["public"], "true", "true"), policy("a", "all", ["public"], "true", "true")] });
    expect(tableRootCauses(a).flatMap((c) => (c.policy === null ? [] : [c.policy.name]))).toEqual(["a", "b"]);
  });

  it("does not treat a restrictive or client-less policy as a cause", () => {
    const t = tbl("r", [pk(), userFk()], { policies: [policy("srv", "all", ["service_role"], "true", "true"), policy("own", "all", ["authenticated"], OWN, OWN)] });
    expect(tableRootCauses(t)).toEqual([]);
  });
});

describe("viewRootCauses", () => {
  const base = notes();

  it("names a view that runs with its owner's rights over a table with row level security", () => {
    const causes = viewRootCauses(view("summary"), model([base], [view("summary")]));
    expect(causes.map((c) => c.kind)).toEqual(["view-bypasses-rls"]);
    const groups = groupByRootCause([proven("public.summary", "view-read-anon"), proven("public.summary", "view-read-cross")], causes);
    expect(kindsOf(groups)).toEqual([["view-bypasses-rls", ["view-read-anon", "view-read-cross"]]]);
  });

  it("names nothing for a security_invoker view or a view over unprotected tables", () => {
    const invoker = view("summary", { securityInvoker: true });
    expect(viewRootCauses(invoker, model([base], [invoker]))).toEqual([]);
    const open = notes({ rlsEnabled: false });
    expect(viewRootCauses(view("summary"), model([open], [view("summary")]))).toEqual([]);
  });
});
