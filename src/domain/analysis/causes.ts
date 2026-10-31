import { primaryOwnerColumn } from "../schema/owner.js";
import { analyzeExpression } from "../schema/expression.js";
import type { Command, Policy, SchemaModel, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import { baseTables } from "../proof/plan.js";
import type { Cause } from "./types.js";

const WRITES: readonly Command[] = ["insert", "update", "delete"];

export function policyReachesAnon(policy: Policy): boolean {
  return policy.roles.includes("anon") || policy.roles.includes("public");
}

export function policyReachesClients(policy: Policy): boolean {
  return policyReachesAnon(policy) || policy.roles.includes("authenticated");
}

export function policyCovers(policy: Policy, command: Command): boolean {
  return policy.command === "all" || policy.command === command;
}

/** Does the expression tie one of the owner columns to the caller (auth.uid(), a JWT claim, a membership lookup)? */
export function bindsOwner(expression: string | null, ownerColumns: readonly string[]): boolean {
  return analyzeExpression(expression, ownerColumns).callerBoundColumns.length > 0;
}

/**
 * Is this policy a correct owner rule for `command`? The expression that decides the command has to tie an
 * owner column to the caller. For UPDATE both the old row (USING) and, when given, the new row (WITH CHECK)
 * must be tied, otherwise an owner could hand a row to someone else.
 */
export function policySoundFor(policy: Policy, command: Command, ownerColumns: readonly string[]): boolean {
  if (!policy.permissive || !policyCovers(policy, command)) return false;
  switch (command) {
    case "select":
    case "delete":
      return bindsOwner(policy.using, ownerColumns);
    case "insert":
      return bindsOwner(policy.withCheck ?? (policy.command === "all" ? policy.using : null), ownerColumns);
    case "update":
      return bindsOwner(policy.using, ownerColumns) && (policy.withCheck === null || bindsOwner(policy.withCheck, ownerColumns));
  }
}

function roleList(policy: Policy): string {
  return policy.roles.includes("public") ? "everyone" : policy.roles.join(", ");
}

function clientsCanTouch(table: Table): boolean {
  return [...table.privileges.anon, ...table.privileges.authenticated].length > 0;
}

/** Static reasons why a table may let people in. They explain a proof; on their own they are only suspicions. */
export function explainTable(table: Table): readonly Cause[] {
  const out: Cause[] = [];
  const owner = primaryOwnerColumn(table);
  const ownerColumns = owner ? [owner.column] : [];
  const clientPolicies = table.policies.filter((p) => p.permissive && policyReachesClients(p));

  if (!table.rlsEnabled && clientsCanTouch(table)) {
    out.push({ code: "rls-disabled", text: "Row level security is switched off on this table, so the database applies no row filter at all." });
  }
  if (table.rlsEnabled && table.policies.length === 0) {
    out.push({ code: "rls-no-policies", text: "Row level security is on but there are no policies, so every client request is refused (fine for tables only the server touches)." });
  }
  if (table.rlsEnabled) {
    for (const p of clientPolicies) {
      const always = analyzeExpression(p.using, []).alwaysTrue || analyzeExpression(p.withCheck, []).alwaysTrue;
      const writes = WRITES.some((c) => policyCovers(p, c));
      if (always && policyReachesAnon(p) && writes) {
        out.push({ code: "policy-anon-write", text: `Policy "${p.name}" lets ${roleList(p)} write (${p.command}) with a condition that is always true.` });
      } else if (always) {
        out.push({ code: "policy-always-true", text: `Policy "${p.name}" has a condition that is always true, so it admits every row for ${roleList(p)} (${p.command}).` });
      }
    }
  }
  if (owner && table.privileges.anon.some((c) => WRITES.includes(c))) {
    out.push({ code: "anon-grant", text: `The anon role (your public key) holds ${table.privileges.anon.filter((c) => WRITES.includes(c)).join(", ")} privileges on this table.` });
  }
  if (owner && table.rlsEnabled) {
    for (const p of clientPolicies) {
      const gaps = (["insert", "update"] as const).filter((c) => policyCovers(p, c) && !policySoundFor(p, c, ownerColumns));
      const always = analyzeExpression(p.using, []).alwaysTrue || analyzeExpression(p.withCheck, []).alwaysTrue;
      if (gaps.length > 0 && !always) {
        out.push({ code: "owner-not-checked", text: `Policy "${p.name}" does not check that ${owner.column} is the caller when a row is written (${gaps.join(", ")}).` });
      }
    }
    const anyBinding = table.policies.some((p) => bindsOwner(p.using, ownerColumns) || bindsOwner(p.withCheck, ownerColumns));
    if (table.policies.length > 0 && !anyBinding) {
      out.push({ code: "owner-not-compared", text: `No policy compares ${owner.column} with the signed-in user, so nothing separates one user's rows from another's.` });
    }
  }
  if (!owner) {
    out.push({ code: "no-owner-column", text: "The table has no column that says who owns a row (user_id, owner_id, org_id, ...), so the tool cannot tell whose rows are whose." });
  }
  return out;
}

export function explainView(view: View, model: SchemaModel): readonly Cause[] {
  const protectedBases = baseTables(view, model).filter((t) => t.rlsEnabled);
  if (view.securityInvoker || protectedBases.length === 0) return [];
  const names = protectedBases.map((t) => qualifiedKey(t.name)).join(", ");
  return [{ code: "view-bypasses-rls", text: `The view runs with its owner's rights (it is not security_invoker), so the row level security on ${names} is skipped when the view is read.` }];
}

/** Causes that on their own make a table worth a second look even when no probe could run. */
export const SUSPICIOUS: Readonly<Record<Cause["code"], boolean>> = {
  "rls-disabled": true,
  "rls-no-policies": false,
  "policy-always-true": true,
  "policy-anon-write": true,
  "anon-grant": false,
  "owner-not-checked": true,
  "owner-not-compared": true,
  "view-bypasses-rls": true,
  "no-owner-column": false,
};
