import { IDENTITIES } from "./identities.js";
import { quoteIdent, quoteLiteral } from "../sql/quote.js";

/**
 * The parts of a Supabase project that row level security depends on, rebuilt in the throwaway database, and the
 * three database roles of the sandbox:
 *
 * - `admin` (a superuser, like `supabase_admin`): provisions the platform and reads the catalog. It only ever
 *   runs statements written by this tool and never runs code from the migrations.
 * - `migrator` (not a superuser, like Supabase's `postgres` role: CREATEDB, CREATEROLE, BYPASSRLS): applies the
 *   migrations, the seed rows and the proposed fix. It cannot create event triggers or untrusted-language
 *   functions, cannot use COPY ... PROGRAM or server-side files, cannot ALTER SYSTEM or the database, and does not
 *   own the `auth` schema or its functions, exactly as on the platform.
 * - `prober` (not a superuser): runs the probes, switching to `anon` or `authenticated` for each one.
 *
 * What it reproduces: the roles `anon`, `authenticated` (no RLS bypass) and `service_role` (bypass), the `auth`
 * schema with `auth.users`, `auth.uid()`, `auth.role()`, `auth.jwt()` and `auth.email()` reading
 * `request.jwt.claims`, the `extensions` schema with `uuid-ossp` and `pgcrypto`, and Supabase's default
 * privileges (everything the migrator creates in `public` is granted to the three roles). What it does not
 * reproduce: GoTrue, PostgREST, `storage`, `realtime`, `vault`, any other extension, or hosted-platform event triggers.
 */
export interface PlatformNames {
  readonly admin: string;
  readonly migrator: string;
  readonly prober: string;
}

export interface RolePasswords {
  readonly migrator: string | null;
  readonly prober: string | null;
}

const pw = (p: string | null): string => (p === null ? "" : ` PASSWORD ${quoteLiteral(p)}`);

/** Cluster-level statements, run by the admin before the sandbox database exists. */
export function roleStatements(names: PlatformNames, passwords: RolePasswords): readonly string[] {
  const m = quoteIdent(names.migrator);
  const p = quoteIdent(names.prober);
  return [
    `DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; END IF;
END
$$`,
    "ALTER ROLE anon NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
    "ALTER ROLE authenticated NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
    "ALTER ROLE service_role NOLOGIN NOINHERIT NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE",
    `CREATE ROLE ${m} LOGIN NOSUPERUSER CREATEDB CREATEROLE BYPASSRLS NOREPLICATION${pw(passwords.migrator)}`,
    `CREATE ROLE ${p} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION NOINHERIT${pw(passwords.prober)}`,
    `GRANT anon, authenticated, service_role TO ${m}`,
    `GRANT anon, authenticated TO ${p}`,
  ];
}

/** Statements run inside the sandbox database by the admin, before anything from the migrations. */
export function platformStatements(names: PlatformNames): readonly string[] {
  const m = quoteIdent(names.migrator);
  return [
    "CREATE SCHEMA IF NOT EXISTS extensions",
    `GRANT USAGE ON SCHEMA extensions TO anon, authenticated, service_role`,
    `GRANT USAGE, CREATE ON SCHEMA extensions TO ${m}`,
    'CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions',
    "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions",
    "CREATE SCHEMA IF NOT EXISTS auth",
    `GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role, ${m}`,
    `CREATE TABLE IF NOT EXISTS auth.users (
  id uuid PRIMARY KEY,
  email text,
  aud text DEFAULT 'authenticated',
  role text DEFAULT 'authenticated',
  raw_app_meta_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  raw_user_meta_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
)`,
    `GRANT SELECT, INSERT, REFERENCES, TRIGGER ON auth.users TO ${m}`,
    `CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$`,
    `CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT nullif(auth.jwt() ->> 'sub', '')::uuid
$$`,
    `CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT nullif(auth.jwt() ->> 'role', '')
$$`,
    `CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT nullif(auth.jwt() ->> 'email', '')
$$`,
    "GRANT EXECUTE ON FUNCTION auth.jwt(), auth.uid(), auth.role(), auth.email() TO anon, authenticated, service_role",
    "GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role",
    `GRANT ALL ON SCHEMA public TO ${m}`,
    `DO $$
BEGIN
  EXECUTE format('GRANT CREATE, TEMPORARY ON DATABASE %I TO %I', current_database(), ${quoteLiteral(names.migrator)});
  EXECUTE format('ALTER DATABASE %I SET search_path TO "$user", public, extensions', current_database());
END
$$`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${m} IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${m} IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${m} IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role`,
  ];
}

/** Rows for the two synthetic users in `auth.users`. Applied by the migrator after the migrations, so triggers on that table fire as they would in production. */
export function identitySeedStatements(): readonly string[] {
  return IDENTITIES.map(
    (u) =>
      `INSERT INTO auth.users (id, email) VALUES (${quoteLiteral(u.id)}, ${quoteLiteral(u.email)}) ON CONFLICT (id) DO NOTHING`,
  );
}
