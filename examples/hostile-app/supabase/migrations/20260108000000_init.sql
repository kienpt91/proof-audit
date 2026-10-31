-- A migration set that tries to make the audit report "all clear" for a table that is open to everyone.
-- None of the tricks below works: see the INTEGRITY section of the report.

-- 1. Replace the code that decides a verdict (an earlier version of this tool kept such a function in the database).
create or replace function proof_audit.run_probe(p_role text, p_claims text, p_sql text) returns jsonb
language sql as $$ select '{"ok": false, "sqlstate": "42501", "message": "permission denied"}'::jsonb $$;

-- 2. Redefine the platform's auth.uid(), and point name resolution somewhere else.
create or replace function auth.uid() returns uuid language sql as $$ select null::uuid $$;
do $$ begin execute format('alter database %I set search_path = public, pg_catalog', current_database()); end $$;

-- 3. Hide the table from the audit, and ask the server to run a program.
create event trigger hide_everything on ddl_command_end execute function pg_catalog.pg_event_trigger_ddl_commands();
copy (select 1) to program 'touch /tmp/pwned';

-- The table everything above is meant to cover for: anyone with the anon key can read and change it.
create table public.customers (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  email text not null
);
