import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../src/domain/hash/canonical-json.js";
import { ANON_CLAIMS, authenticatedClaims, IDENTITIES, USER_A, USER_B } from "../../src/domain/supabase/identities.js";
import { identitySeedStatements, platformStatements, roleStatements } from "../../src/domain/supabase/shim.js";

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

const NAMES = { admin: "supabase_admin", migrator: "postgres", prober: "proof_audit_prober" };

describe("sandbox roles", () => {
  const roles = roleStatements(NAMES, { migrator: null, prober: null }).join("\n");

  it("creates the three client roles with the right RLS bypass attributes", () => {
    expect(roles).toMatch(/ALTER ROLE anon [^\n]*NOBYPASSRLS/);
    expect(roles).toMatch(/ALTER ROLE authenticated [^\n]*NOBYPASSRLS/);
    expect(roles).toMatch(/ALTER ROLE service_role [^\n]* BYPASSRLS/);
  });

  it("makes the migrator a non-superuser like Supabase's postgres role", () => {
    expect(roles).toContain('CREATE ROLE "postgres" LOGIN NOSUPERUSER CREATEDB CREATEROLE BYPASSRLS NOREPLICATION');
    expect(roles).not.toMatch(/"postgres"[^\n]* SUPERUSER[^\n]*$/m);
  });

  it("makes the prober a plain role that can only switch to the client roles", () => {
    expect(roles).toContain('CREATE ROLE "proof_audit_prober" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION NOINHERIT');
    expect(roles).toContain('GRANT anon, authenticated TO "proof_audit_prober"');
  });

  it("sets passwords only when asked, quoting them", () => {
    const withPw = roleStatements(NAMES, { migrator: "it's", prober: "p2" }).join("\n");
    expect(withPw).toContain("PASSWORD 'it''s'");
    expect(withPw).toContain("PASSWORD 'p2'");
    expect(roles).not.toContain("PASSWORD");
  });

  it("quotes hostile role names", () => {
    const hostile = roleStatements({ ...NAMES, migrator: 'a"; DROP ROLE x; --' }, { migrator: null, prober: null }).join("\n");
    expect(hostile).toContain('CREATE ROLE "a""; DROP ROLE x; --" LOGIN');
  });
});

describe("platform provisioning", () => {
  const all = platformStatements(NAMES).join("\n");

  it("defines the auth helpers over request.jwt.claims and pins their search_path", () => {
    for (const fn of ["auth.jwt()", "auth.uid()", "auth.role()", "auth.email()"]) expect(all).toContain(`FUNCTION ${fn}`);
    expect(all).toContain("request.jwt.claims");
    expect(all.match(/SET search_path = pg_catalog AS/g)).toHaveLength(4);
  });

  it("gives the migrator what a Supabase postgres role has, and no ownership of the platform", () => {
    expect(all).toContain('GRANT SELECT, INSERT, REFERENCES, TRIGGER ON auth.users TO "postgres"');
    expect(all).toContain('GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role, "postgres"');
    expect(all).not.toMatch(/GRANT [^\n]*CREATE ON SCHEMA auth/);
    expect(all).not.toMatch(/OWNER TO/);
  });

  it("grants the Supabase default privileges for what the migrator creates in public", () => {
    expect(platformStatements(NAMES)).toContain('ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role');
  });

  it("holds single statements only, none of them transaction control", () => {
    for (const s of platformStatements(NAMES)) expect(s).not.toMatch(/^\s*(BEGIN|COMMIT|ROLLBACK)\b/i);
  });

  it("seeds both users into auth.users idempotently with quoted literals", () => {
    const statements = identitySeedStatements();
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain(`'${USER_A.id}'`);
    for (const s of statements) expect(s).toContain("ON CONFLICT (id) DO NOTHING");
  });
});
