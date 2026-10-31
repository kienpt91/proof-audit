# 0011. The project's SQL must not share a trust domain with the verdicts

Status: accepted (supersedes the "harness in the database" design of 0004 and 0005)

## Context

A security review (finding PA-VERDICT-HARNESS-TAMPER, reproduced before the fix) showed that the first design let a hostile migration forge a verdict. Migrations ran as the PostgreSQL superuser in the same database that held the tool's helper functions (`proof_audit.run_probe`, `try_exec`, `catalog`). A well-formed `CREATE OR REPLACE FUNCTION proof_audit.run_probe(p_role text, p_claims text, p_sql text) ... SELECT '{"ok":false,"sqlstate":"42501"}'` made every attack look denied while the schema was wide open: the report said CLEAN and the exit code was 0. Repointing `search_path` so the helpers' unqualified calls (`set_config`, `jsonb_build_object`, `left`) resolved to attacker functions had the same effect, and a superuser can also `UPDATE pg_catalog.pg_proc` directly. The same review found that `ALTER EXTENSION ... ADD TABLE` hid a table from a catalog filter, and that loopback mode ran hostile SQL as a superuser on whatever server answered.

## Options

- **(a) Probe from the client side.** The tool sends the transaction itself and parses the raw result, so no replaceable server-side function sits in the verdict path.
- **(b) Run migrations as a role that cannot touch anything the verdicts depend on**, like Supabase's own `postgres` role, and read the catalog in a session migrations cannot influence.
- **(c) Detect tampering** with fingerprints and report it as an explicit INTEGRITY_VIOLATION.

## Decision

All three, in this order of strength.

1. **Three database roles** (`src/domain/supabase/shim.ts`). The **admin** is a superuser (`supabase_admin` in the container) and only ever runs statements written by this tool: provisioning, `CREATE`/`DROP DATABASE`, the catalog read, the fingerprint. The **migrator** is what Supabase calls `postgres`: not a superuser, with `CREATEDB`, `CREATEROLE` and `BYPASSRLS`. It applies the migrations, the seed rows, the counts and the proposed fix, so triggers and functions from the project never run with superuser rights. It does not own the platform: it cannot replace `auth.uid()`, create event triggers or untrusted-language functions, use `COPY ... PROGRAM` or server-side files, `ALTER SYSTEM`, `ALTER DATABASE`, change the platform roles, or write the system catalogs. The **prober** is a plain role that can only switch to `anon` and `authenticated`.
2. **No stored helper.** Every operation is an anonymous `DO` block built by the tool (`src/infrastructure/postgres/statements.ts`), carrying the SQL under test as a dollar-quoted string, followed by one `SELECT` that reads the reply from a custom setting that the block sets after its sub-transaction has ended. The blocks call only `pg_catalog`-qualified functions and use no operator of their own (a test tokenises the generated blocks and fails on an unqualified call). There is nothing in the database for a migration to replace.
3. **Pinned sessions.** Each connection fixes `search_path`, timeouts and `row_security` in the connection itself (`PGOPTIONS` for `psql`, the `options` startup parameter for `pg`), which overrides `ALTER DATABASE/ROLE ... SET`. The catalog and fingerprint reads use `search_path = pg_catalog` and qualified names.
4. **Fingerprint and attempts.** The platform (the `auth.*` functions with owner and a hash of their body, `auth.users`, the roles and their attributes and memberships, per-database and per-role settings, event triggers, the owner and ACL of the platform schemas) is fingerprinted before the migrations, after them, after the probes and after the probes on the fix copy. Any difference, and any statement in the migrations that touches protected objects (found by tokenising the text, including SQL inside `DO` blocks and `EXECUTE` strings), is an integrity violation, whether the database refused the statement or not. A violation makes the run INTEGRITY_VIOLATION (exit code 4): every finding becomes INCONCLUSIVE, no fix is proposed, the proofs keep what the database answered, and the report lists each violation with whether the database allowed it.
5. **No blanket catalog filters.** Only the database's own schemas and the shim's `auth.users` are skipped; extension membership no longer hides a table.

## What this guarantees, and what it does not

Given an intact PostgreSQL and a container or server that holds, a migration cannot make the tool report a probe result the database did not produce: every reply is the server's own answer to a tool-authored statement, in a session whose settings the migration cannot change, and the platform objects the SQL could depend on are checked three times.

It does **not** guarantee: that a table, view, policy, trigger or function from the project behaves the same for the synthetic users as for real ones (a function can look at `request.jwt.claims` or `current_user` and answer differently for `aaaaaaaa-...`; the verdict is then correct for the synthetic identity); protection against a PostgreSQL privilege-escalation vulnerability or a container escape; that `statement_timeout` cannot be reset by a migration in its own session (the 120 s wall-clock limit, the server-side session termination and the container's limits bound it); that `SECURITY DEFINER` functions the migrator creates run without `BYPASSRLS` (they run as the migrator, as `postgres` on the platform, so a view or function owned by it bypasses row level security by design, and that is exactly what the view probes show). A fingerprint cannot see what it does not list.

## Consequences

- Migrations that redefine platform objects are reported and make the run inconclusive; the platform provides those objects.
- In the container the migrator is literally named `postgres`. In loopback mode the roles are created per run with random names and passwords and dropped afterwards, so migrations that name the role `postgres` (`ALTER ... OWNER TO postgres`) behave differently there.
- Tests: offline logic (`test/domain/integrity`, `test/infrastructure/statements.test.ts`, `test/application`), hostile migrations built at run time against the pinned PostgreSQL (`test/integration/hostile.integration.test.ts`), and the same in the real container through the relay (`test/smoke`).
