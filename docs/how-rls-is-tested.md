# How row level security is tested

One page on what `proof-audit` does to your policies, so you can judge the evidence it produces. A full example of the output is in [sample-report.md](sample-report.md).

## The idea

A policy is only a claim. The only way to know what it allows is to run statements as the roles an attacker would have and watch what the database answers. So the tool does not read your policies and judge them: it builds a real PostgreSQL 16 database from your migrations and attacks it.

## The commands

```sh
# 1. audit: build the database from the migrations, attack it, propose a fix, check the fix
scripts/run-contained.sh rls supabase/migrations --out out/audit

# 2. replay the recorded evidence in a fresh database (exit 0: it reproduces identically)
scripts/run-contained.sh verify out/audit/proofs.jsonl

# 3. after you changed the migrations: do the recorded attacks still work?
scripts/run-contained.sh verify out/audit/proofs.jsonl --against supabase/migrations
```

The analysis runs in containers with no route to the network (the first run also installs the locked dependencies, in a container); your machine needs Docker and nothing else. Exit code 0 means nothing was proven, 1 means a hole was proven (see the README for the others).

## 1. Roles and identities

Supabase's API connects as one of two roles: `anon` (anyone holding the public key) or `authenticated` (a signed-in user). The tool recreates those roles, the `auth.users` table and the helper functions `auth.uid()`, `auth.role()`, `auth.jwt()` and `auth.email()`, which read the `request.jwt.claims` setting the way PostgREST populates it. Your migrations are applied as a non-superuser, like Supabase's `postgres` role.

There are two synthetic users, Alice (user A) and Bob (user B), and an anonymous caller. Each table gets one seeded row per user, built from the column types and `CHECK` constraints. No real data is read.

## 2. JWT claims simulation

Each probe is run the way the API would run it. This is the statement pattern the tool uses, by hand:

```sql
BEGIN;
-- what PostgREST sets for a request carrying Alice's token
SELECT set_config('request.jwt.claims',
  '{"role":"authenticated","aud":"authenticated","sub":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}', true);
SET LOCAL ROLE authenticated;
-- the attack
SELECT * FROM public.notes WHERE user_id::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
ROLLBACK;
```

The claims the tool sets for Alice also carry `email`, `tenant_id`, `org_id`, `app_metadata` and `user_metadata`, so policies that read those claims have something to read. The anonymous caller carries only `role: anon`. Every probe runs in a sub-transaction that is always rolled back, so one probe never changes what the next one sees. The exact SQL, role and claims of every probe are written to `proofs.jsonl`.

## 3. Negative cases: attacks that must fail

For every table, as `anon`: read, insert, update and delete. For every table with an owner column (`user_id`, `owner_id`, `tenant_id`, a reference to `auth.users`, ...), as Alice:

- read Bob's rows;
- insert a row owned by Bob;
- insert a row with no owner (when the column is nullable);
- update and delete Bob's rows;
- update one of her own rows so that it belongs to Bob.

An attack is **PROVEN** when the database let it through (rows returned or changed, or an insert accepted). An insert that only a table constraint stopped counts as proven, because PostgreSQL checks the row level security rule first. If the database refused every attack, the table is **CLEAN**. If a probe could not run (nothing could be seeded, say), it is **INCONCLUSIVE** and says why; it is never counted as clean.

## 4. Positive cases: normal use must keep working

Alice also reads, inserts, updates and deletes her own rows. These probes are what make a fix honest: a fix that closes every hole by locking everybody out fails them and is reported as `BREAKS_ACCESS`, not as verified.

## 5. Views, `SECURITY DEFINER` and storage

- **Views.** A view over a table with row level security enabled that is not `security_invoker` runs with its owner's rights and skips that security. The tool probes every such view: it reads it as `anon` and as Alice, asking for Bob's rows through the view, and checks that Alice can still read her own rows through it. (Example: `invoice_summaries` in the sample report.)
- **`SECURITY DEFINER` functions.** They are created when your migrations are applied, but they are **not attacked**: functions that clients can call over RPC are not probed. Review them by hand: a fixed `search_path`, no `EXECUTE` for `public` or `anon` unless it is intended, and no trust in arguments that name a user.
- **Storage.** Storage buckets and the policies on `storage.objects` are **not modelled or tested**. The sandbox has no `storage` schema.

## 6. The fix check

The proposed fix (enable RLS, owner-scoped policies written with `(select auth.uid())`, revoke `anon` privileges, `security_invoker` views) is applied to a fresh copy of the database, and **the same probes are run again**. `VERIFIED` requires both: every attack that worked now fails, and every normal-use probe that worked before still works. `verify --against` repeats the comparison against migrations you changed yourself.

## What this cannot prove

- Only row level security is covered. Not application code (route handlers, server actions, edge functions), not secrets or leaked service-role keys, not storage, realtime or auth settings.
- The users are synthetic and each table has one row per user. Policies that depend on other claims, on many rows, on roles other than `anon` and `authenticated`, or on data the tool does not create are not exercised.
- It is PostgreSQL 16 with a Supabase-shaped platform, not your Supabase project. Differences in version, extensions and exposed schemas are not modelled.
- Table-level privileges only: column privileges, materialized views and RPC functions are not probed.
- CLEAN means the listed attacks were refused. It is not a penetration test and not a guarantee.

The full list is in the README ("What it proves, and what it does not" and "Limitations").
