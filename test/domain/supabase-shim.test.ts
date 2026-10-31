import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../src/domain/hash/canonical-json.js";
import { ANON_CLAIMS, authenticatedClaims, IDENTITIES, USER_A, USER_B } from "../../src/domain/supabase/identities.js";
import { identitySeedStatements, SHIM_STATEMENTS } from "../../src/domain/supabase/shim.js";

describe("synthetic identities", () => {
  it("are two distinct, well-formed uuids with example.test addresses", () => {
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    expect(IDENTITIES).toHaveLength(2);
    for (const u of IDENTITIES) {
      expect(u.id).toMatch(uuid);
      expect(u.tenantId).toMatch(uuid);
      expect(u.email.endsWith("@example.test")).toBe(true);
    }
    expect(USER_A.id).not.toBe(USER_B.id);
    expect(USER_A.tenantId).not.toBe(USER_B.tenantId);
  });

  it("produce claims that parse and carry the caller's subject and role", () => {
    const claims = JSON.parse(authenticatedClaims(USER_A)) as Record<string, unknown>;
    expect(claims.sub).toBe(USER_A.id);
    expect(claims.role).toBe("authenticated");
    expect(claims.aud).toBe("authenticated");
    expect((claims.app_metadata as Record<string, unknown>).tenant_id).toBe(USER_A.tenantId);
  });

  it("give the anon key a role and no subject", () => {
    expect(JSON.parse(ANON_CLAIMS)).toEqual({ role: "anon" });
  });

  it("render claims canonically so proofs hash the same every run", () => {
    expect(authenticatedClaims(USER_B)).toBe(canonicalJson(JSON.parse(authenticatedClaims(USER_B))));
  });
});

describe("Supabase shim", () => {
  it("creates the three roles with the right RLS bypass attributes", () => {
    const all = SHIM_STATEMENTS.join("\n");
    expect(all).toMatch(/ALTER ROLE anon [^\n]*NOBYPASSRLS/);
    expect(all).toMatch(/ALTER ROLE authenticated [^\n]*NOBYPASSRLS/);
    expect(all).toMatch(/ALTER ROLE service_role [^\n]* BYPASSRLS/);
  });

  it("defines the auth helpers over request.jwt.claims", () => {
    const all = SHIM_STATEMENTS.join("\n");
    for (const fn of ["auth.jwt()", "auth.uid()", "auth.role()", "auth.email()"]) expect(all).toContain(`FUNCTION ${fn}`);
    expect(all).toContain("request.jwt.claims");
  });

  it("grants the Supabase default privileges on public", () => {
    expect(SHIM_STATEMENTS).toContain("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role");
  });

  it("holds single statements only, none of them transaction control", () => {
    for (const s of SHIM_STATEMENTS) expect(s).not.toMatch(/^\s*(BEGIN|COMMIT|ROLLBACK)\b/i);
  });

  it("seeds both users into auth.users idempotently with quoted literals", () => {
    const statements = identitySeedStatements();
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain(`'${USER_A.id}'`);
    for (const s of statements) expect(s).toContain("ON CONFLICT (id) DO NOTHING");
  });
});
