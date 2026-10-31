import { IDENTITIES } from "./identities.js";
import { quoteLiteral } from "../sql/quote.js";

/**
 * Approximation of the parts of a Supabase project that row level security depends on, applied to the
 * throwaway database before the user's migrations. Each entry is one statement.
 *
 * What it reproduces: the roles `anon`, `authenticated` (no RLS bypass) and `service_role` (bypass), the
 * `auth` schema with `auth.users`, `auth.uid()`, `auth.role()`, `auth.jwt()` and `auth.email()` reading
 * `request.jwt.claims`, the `extensions` schema with `uuid-ossp` and `pgcrypto`, and Supabase's default
 * privileges (everything in `public` is granted to the three roles). What it does not reproduce: GoTrue,
 * PostgREST, `storage`, `realtime`, `vault`, any other extension, or hosted-platform event triggers.
 */
export const SHIM_STATEMENTS: readonly string[] = [
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
  "CREATE SCHEMA IF NOT EXISTS extensions",
  "GRANT USAGE ON SCHEMA extensions TO anon, authenticated, service_role",
  'CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions',
  "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions",
  "CREATE SCHEMA IF NOT EXISTS auth",
  "GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role",
  `CREATE TABLE IF NOT EXISTS auth.users (
  id uuid PRIMARY KEY,
  email text,
  aud text DEFAULT 'authenticated',
  role text DEFAULT 'authenticated',
  raw_app_meta_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  raw_user_meta_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
)`,
  `CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$`,
  `CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT nullif(auth.jwt() ->> 'sub', '')::uuid
$$`,
  `CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$
  SELECT nullif(auth.jwt() ->> 'role', '')
$$`,
  `CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS $$
  SELECT nullif(auth.jwt() ->> 'email', '')
$$`,
  "GRANT EXECUTE ON FUNCTION auth.jwt(), auth.uid(), auth.role(), auth.email() TO anon, authenticated, service_role",
  "GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role",
  "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role",
  "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role",
  "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role",
  `DO $$
BEGIN
  EXECUTE format('ALTER DATABASE %I SET search_path TO "$user", public, extensions', current_database());
END
$$`,
];

/** Rows for the two synthetic users in `auth.users`. Applied after the migrations so triggers on that table fire as they would in production. */
export function identitySeedStatements(): readonly string[] {
  return IDENTITIES.map(
    (u) =>
      `INSERT INTO auth.users (id, email) VALUES (${quoteLiteral(u.id)}, ${quoteLiteral(u.email)}) ON CONFLICT (id) DO NOTHING`,
  );
}
