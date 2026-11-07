import { explainTableDetailed, policyCovers, policyReachesAnon, SUSPICIOUS } from "../analysis/causes.js";
import { baseTables } from "../proof/plan.js";
import type { Proof } from "../proof/types.js";
import type { Policy, SchemaModel, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import type { RootCauseKind } from "./fingerprint.js";

/** One root cause of a table or view: the kind, the policy it is about (if any) and the static reason in words. */
export interface RootCause {
  readonly kind: RootCauseKind;
  readonly policy: Policy | null;
  readonly text: string;
  /** Does this cause account for the database letting `proof` through? */
  readonly explains: (proof: Proof) => boolean;
  /** Is the cause worth a look on its own, without a proof? (The same list the report uses for SUSPECTED.) */
  readonly suspicious: boolean;
}

const CROSS_USER: readonly Proof["kind"][] = ["cross-read", "cross-insert", "null-owner-insert", "cross-update", "cross-delete", "reassign-owner"];
const VIEW_READS: readonly Proof["kind"][] = ["view-read-anon", "view-read-cross"];

/** Can a policy created for `policy.roles` apply to a statement run as `role`? */
function policyReaches(policy: Policy, role: Proof["role"]): boolean {
  return role === "anon" ? policyReachesAnon(policy) : policy.roles.includes("authenticated") || policy.roles.includes("public");
}

const byPolicyName = (a: RootCause, b: RootCause): number => ((a.policy?.name ?? "") < (b.policy?.name ?? "") ? -1 : (a.policy?.name ?? "") > (b.policy?.name ?? "") ? 1 : 0);

/**
 * The root causes of a table, most direct first. A proof is attributed to the first cause that explains it, in
 * this order: row level security off; a policy whose condition is always true; a policy that does not tie the
 * written row to its owner; no policy comparing the owner with the caller. Probes none of them explains belong
 * to the `unattributed` record, added by the caller.
 */
export function tableRootCauses(table: Table): readonly RootCause[] {
  const details = explainTableDetailed(table);
  const disabled: RootCause[] = [];
  const alwaysTrue: RootCause[] = [];
  const unchecked: RootCause[] = [];
  const notCompared: RootCause[] = [];
  for (const d of details) {
    const suspicious = SUSPICIOUS[d.code];
    if (d.code === "rls-disabled") disabled.push({ kind: "rls-disabled", policy: null, text: d.text, explains: () => true, suspicious });
    else if ((d.code === "policy-anon-write" || d.code === "policy-always-true") && d.policy !== null) {
      const p = d.policy;
      alwaysTrue.push({ kind: "policy-always-true", policy: p, text: d.text, explains: (proof) => policyCovers(p, proof.command) && policyReaches(p, proof.role), suspicious });
    } else if (d.code === "owner-not-checked" && d.policy !== null) {
      const p = d.policy;
      unchecked.push({ kind: "policy-owner-unchecked", policy: p, text: d.text, explains: (proof) => d.gaps.includes(proof.command) && policyReaches(p, proof.role), suspicious });
    } else if (d.code === "owner-not-compared") {
      notCompared.push({ kind: "owner-not-compared", policy: null, text: d.text, explains: (proof) => CROSS_USER.includes(proof.kind), suspicious });
    }
  }
  return [...disabled, ...alwaysTrue.sort(byPolicyName), ...unchecked.sort(byPolicyName), ...notCompared];
}

/** The root causes of a view: it runs with its owner's rights, so row level security of the tables it reads is skipped. */
export function viewRootCauses(view: View, model: SchemaModel): readonly RootCause[] {
  const protectedBases = baseTables(view, model).filter((t) => t.rlsEnabled);
  if (view.securityInvoker || protectedBases.length === 0) return [];
  const names = protectedBases.map((t) => qualifiedKey(t.name)).join(", ");
  const text = `The view runs with its owner's rights (it is not security_invoker), so the row level security on ${names} is skipped when the view is read.`;
  return [{ kind: "view-bypasses-rls", policy: null, text, explains: (proof) => VIEW_READS.includes(proof.kind), suspicious: SUSPICIOUS["view-bypasses-rls"] }];
}

export interface ProofGroup {
  /** The cause every proof in the group is attributed to; null for the group no static cause explains. */
  readonly cause: RootCause | null;
  readonly proofs: readonly Proof[];
}

/** Splits proven proofs into one group per root cause (each proof in exactly one group), the unexplained rest last. */
export function groupByRootCause(proven: readonly Proof[], causes: readonly RootCause[]): readonly ProofGroup[] {
  const groups = new Map<RootCause, Proof[]>();
  const rest: Proof[] = [];
  for (const proof of proven) {
    const cause = causes.find((c) => c.explains(proof));
    if (cause === undefined) rest.push(proof);
    else groups.set(cause, [...(groups.get(cause) ?? []), proof]);
  }
  const out: ProofGroup[] = causes.flatMap((cause) => {
    const proofs = groups.get(cause);
    return proofs === undefined ? [] : [{ cause, proofs }];
  });
  return rest.length === 0 ? out : [...out, { cause: null, proofs: rest }];
}
