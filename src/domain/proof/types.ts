import type { ClientRole, Command } from "../schema/model.js";

/**
 * What a probe does. Exploit probes try something an attacker would try; legitimate probes try what the
 * application itself must still be able to do, so a "fix" that locks everyone out is caught.
 */
export type ProbeKind =
  | "anon-read"
  | "anon-insert"
  | "anon-update"
  | "anon-delete"
  | "cross-read"
  | "cross-insert"
  | "null-owner-insert"
  | "cross-update"
  | "cross-delete"
  | "reassign-owner"
  | "view-read-anon"
  | "view-read-cross"
  | "own-read"
  | "own-insert"
  | "own-update"
  | "own-delete";

export type ProbeIntent = "exploit" | "legitimate";

/** Who runs the probe. `user-a` is the signed-in attacker (or legitimate user); `user-b` owns the victim rows. */
export type ProbeActor = "anon" | "user-a";

export interface Probe {
  /** Stable id, `<schema.table>/<kind>`. */
  readonly id: string;
  /** Qualified table or view name, e.g. `public.notes`. */
  readonly subject: string;
  readonly subjectKind: "table" | "view";
  readonly kind: ProbeKind;
  readonly intent: ProbeIntent;
  readonly command: Command;
  readonly actor: ProbeActor;
  readonly role: ClientRole;
  /** JSON text of the `request.jwt.claims` the run sets. */
  readonly claims: string;
  /** The exact statement run as that role, rolled back afterwards. */
  readonly sql: string;
  /** Plain-language one-liner, e.g. "Anonymous visitor reads rows". */
  readonly title: string;
  /** Seeded rows the statement aims at; null when it does not target existing rows (inserts). */
  readonly targetRows: number | null;
  /** When set the probe cannot run and is recorded INCONCLUSIVE with this reason. */
  readonly blockedReason: string | null;
}

export type ProbeObservation =
  | { readonly status: "rows"; readonly rows: number }
  | { readonly status: "error"; readonly sqlstate: string; readonly message: string }
  | { readonly status: "not-run"; readonly reason: string };

export type Verdict = "PROVEN_VULNERABLE" | "NOT_REPRODUCED" | "INCONCLUSIVE" | "ACCESS_OK" | "ACCESS_BROKEN";

export type Phase = "before" | "after";

export interface Proof {
  readonly id: string;
  readonly subject: string;
  readonly subjectKind: "table" | "view";
  readonly kind: ProbeKind;
  readonly intent: ProbeIntent;
  readonly command: Command;
  readonly actor: ProbeActor;
  readonly role: ClientRole;
  readonly claims: string;
  readonly sql: string;
  readonly title: string;
  readonly targetRows: number | null;
  readonly observation: ProbeObservation;
  readonly verdict: Verdict;
  /** Why the verdict is what it is, in one sentence. */
  readonly reason: string;
  readonly phase: Phase;
  /** sha256 over the canonical JSON of every other field. */
  readonly hash: string;
}
