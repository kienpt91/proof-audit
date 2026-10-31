import { canonicalJson } from "../hash/canonical-json.js";

/** A synthetic person. Nothing here is, or is derived from, real data. */
export interface Identity {
  readonly label: "user-a" | "user-b";
  /** `sub` claim and `auth.users.id`. */
  readonly id: string;
  readonly email: string;
  /** One tenant per user, used for tenant-style columns (org_id, tenant_id, ...). */
  readonly tenantId: string;
  /** Small integer for owner columns that are not uuids. */
  readonly ordinal: number;
}

export const USER_A: Identity = {
  label: "user-a",
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  email: "alice@example.test",
  tenantId: "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1",
  ordinal: 1,
};

export const USER_B: Identity = {
  label: "user-b",
  id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  email: "bob@example.test",
  tenantId: "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2",
  ordinal: 2,
};

export const IDENTITIES: readonly Identity[] = [USER_A, USER_B];

/** What the anon key carries: a role and nothing else. */
export const ANON_CLAIMS: string = canonicalJson({ role: "anon" });

/** The JWT claims Supabase would put in a signed-in user's token, plus tenant claims that tenant-style policies read. */
export function authenticatedClaims(identity: Identity): string {
  return canonicalJson({
    aud: "authenticated",
    role: "authenticated",
    sub: identity.id,
    email: identity.email,
    tenant_id: identity.tenantId,
    org_id: identity.tenantId,
    app_metadata: { provider: "email", tenant_id: identity.tenantId, org_id: identity.tenantId },
    user_metadata: {},
  });
}
