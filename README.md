# proof-audit

`proof-audit` turns an access-control suspicion into a **reproducible proof** against a throwaway local database, proposes a fix, and re-runs the same proof to show that the fix works and that normal use still works. The first vertical is Supabase-style Postgres **row level security (RLS)**.

```
$ scripts/run-contained.sh rls examples/vulnerable-app/supabase/migrations
RESULT: 6 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 1 CLEAN.
6 of 7 checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves.
...
FIX CHECK
VERIFIED: every attack that worked before now fails, and a normal signed-in user can still read and write their own rows.
```

It is honest, local-only, defensive tooling: it reads plain SQL migrations, builds a Supabase-shaped database in a container that has no network (or in a loopback database you started), attacks it as an anonymous caller and as one signed-in user against another user's rows, and writes down exactly what the database answered.

## The problem, and why a proof

Apps built quickly with coding assistants ("vibe-coded" apps) ship with broken access control more often than anything else. *Understanding the (In)Security of Vibe-Coded Applications* ([arXiv:2606.23130](https://arxiv.org/abs/2606.23130), 2026-06-22) audited 200 publicly deployed vibe-coded applications and found that **91.0% contain at least one vulnerability**, 65.77% of the 1,186 vulnerabilities rated Critical or High, **concentrated in broken access control**, injection and authentication failures.

On Supabase, broken access control usually means row level security: a table without RLS, a policy that says `using (true)`, a policy that compares the wrong column. Static scanners flag patterns, but a pattern is not a problem: findings are noisy, nobody trusts them, and nobody proves that a fix works. `proof-audit` answers the two questions that matter: *can someone really read or change data they should not?* and *does this fix really close it without breaking my app?*

## What it proves, and what it does not

Proves: for the SQL you give it, against two synthetic users (A and B) and an anonymous caller, in a real PostgreSQL 16, whether each table and view lets someone

- read, add, change or delete rows as `anon` (anyone holding the public key);
- read, add, change or delete **another user's** rows as a signed-in user, add a row with no owner, or hand a row to someone else;
- read other users' rows through a view that bypasses RLS (a view that is not `security_invoker`);

and whether a proposed fix closes each of those **and** leaves the signed-in user able to read, add, change and delete their own rows.

Does **not** prove: anything outside RLS logic. Not authorization written in application code (route handlers, server actions, edge functions), not frontends, not secrets exposure (keys in `.env`, service-role keys in the browser), not storage buckets, realtime or auth settings, not other databases. It is **not a penetration test**: CLEAN means the listed attacks were refused for the synthetic users, not that a table is safe. Tables without an owner column get anonymous probes only, and their fix is left to you.

## Evidence tiers

| Tier | Meaning |
| --- | --- |
| **PROVEN** | A probe reproduced the access against the database. Each proof records the exact SQL, the role and JWT claims, the observed row count or error, a verdict and a content hash. |
| **SUSPECTED** | A static pattern exists but no probe could confirm it. Low confidence, labelled as such. |
| **CLEAN** | Every attack was refused. This wins over a static pattern: if the scanner says "risky" and the database says no, the result is CLEAN. |
| **INCONCLUSIVE** | Some probes could not run (for example a table that could not be seeded) and nothing points to a problem. Never silently treated as clean. |

## Run it safely

Everything runs in throwaway containers. Nothing needs to be installed on your machine except Docker.

```sh
# Option A: no Node and no database on your machine. Node 22 and PostgreSQL 16.14 (both pinned by digest)
# run in containers; the database is on an internal docker network with no route out, and the tool runs
# in a container that shares its network namespace, so the database is at 127.0.0.1.
scripts/run-contained.sh rls supabase/migrations --out out/audit
scripts/run-contained.sh verify out/audit/proofs.jsonl

# Option B: with Node >= 22.12 on the host, the tool starts its own throwaway container
# (no network, no published port, read-only root, no capabilities, memory/CPU/process limits).
docker pull postgres@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b
npm ci --ignore-scripts && npm run build
node dist/bin.js rls supabase/migrations --out out/audit
```

```
proof-audit rls <migrations-dir | file.sql...> [options]
  --json | --markdown       print JSON or Markdown instead of the plain-language report
  --out <dir>               also write report.md, report.json, proofs.jsonl,
                            verification-contract.json and fix.sql into <dir>
  --from-audit <file>       report of the saas-audit static auditor (see below)
  --no-fix                  do not propose or verify a fix
  --fail-on <proven|none>   exit 1 when something was proven (default) or never
  --database-url <url>      a Postgres server you started on this machine (loopback only)

proof-audit verify <proofs.jsonl> [--against <migrations...>] [--root <dir>] [--database-url <url>]
```

Exit codes: `0` nothing proven / evidence reproduces, `1` holes proven / evidence not reproduced, `2` usage or invalid input, `3` the sandbox could not run, the run was incomplete (a cap was hit), or the inputs changed since the evidence was recorded.

**Safety boundary.** The tool connects only to a database it creates itself in a container with no network, or to a PostgreSQL server on this machine's loopback interface (`--database-url`, also `PROOF_AUDIT_DATABASE_URL`). Any other host is refused in the domain layer before a socket exists. It makes no network call during analysis, reads no secrets or `.env` files, and uses synthetic seed data only. The migrations are treated as hostile input; see [SECURITY.md](SECURITY.md).

## A real run

`examples/vulnerable-app` is a Supabase-style schema with six realistic mistakes; `examples/fixed-app` is the same schema corrected. The output below is real, produced by `scripts/run-contained.sh` on PostgreSQL 16.14 and committed in `examples/vulnerable-app/sample-output/`. Running it twice gives identical bytes.

| Table | Mistake | What the database let through |
| --- | --- | --- |
| `profiles` | RLS never enabled | everything, to anyone with the anon key |
| `notes` | a `for select using (true)` policy left over from debugging | anon and every signed-in user read every note |
| `tickets` | `for all using (true) with check (true)` plus `grant all ... to anon` | read, add, change, delete and re-assign, as anon and as any user |
| `documents` | insert policy only checks `auth.role() = 'authenticated'` | any user creates documents in someone else's name |
| `projects` | policy compares `customer_id`, not the owner column `owner_id` | rows can be planted in another owner's name and handed over |
| `invoice_summaries` | a view over a protected table, not `security_invoker` | anon and any user read every customer's invoices |

`invoices` itself is correct and comes out CLEAN. The static auditor never mentions the `projects` policy, the `documents` insert policy or the view; the proofs find all three.

<details>
<summary>The plain-language report, in full (examples/vulnerable-app/sample-output/report.txt)</summary>

```text
SECURITY REPORT (plain language)
================================
Tool: proof-audit 0.1.0
Checked: 7 tables or views
Input files read: 2
Database used: a throwaway PostgreSQL database (version 16.14 (Debian 16.14-1.pgdg13+1), local connection loopback)
Run complete: yes
Tests run: 81 (25 showed a real problem)
RESULT: 6 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 1 CLEAN.
6 of 7 checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves.

WHAT WE FOUND
-------------

[1] PROVEN: reproduced against a real database
    Severity: CRITICAL
    What: Table public.profiles can be accessed by people who should not see or change its rows
    Where: public.profiles (table)
    An attacker could: Anyone with your public anon key can read rows of public.profiles, add rows to public.profiles, change rows in public.profiles and delete rows from public.profiles, and any signed-in user can read other users' rows, create rows in other users' names, change other users' rows and delete other users' rows.
    Why:
      - Row level security is switched off on this table, so the database applies no row filter at all.
      - The anon role (your public key) holds insert, update, delete privileges on this table.
    How we proved it:
      1. We acted as an anonymous visitor (no login, only the public key) and ran:
           SELECT * FROM "public"."profiles"
         Result: the database returned 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 1005e1751317
      2. We acted as an anonymous visitor (no login, only the public key) and ran:
           INSERT INTO "public"."profiles" ("id", "display_name", "avatar_url") VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Bob', 'https://example.test/9b9fbf')
         Result: the access policy let the row through; only a table constraint stopped it (error 23505: duplicate key value violates unique constraint "profiles_pkey").
         Access was ALLOWED. That is the problem.
         Evidence: sha256 243035d4a204
      3. We acted as an anonymous visitor (no login, only the public key) and ran:
           UPDATE "public"."profiles" SET "display_name" = "display_name"
         Result: the database accepted it and changed 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 2b6dcdc88d45
      4. We acted as an anonymous visitor (no login, only the public key) and ran:
           DELETE FROM "public"."profiles"
         Result: the database accepted it and changed 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 aefc1cea706c
      5. We acted as a signed-in user trying to reach someone else's data and ran:
           SELECT * FROM "public"."profiles" WHERE "id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database returned 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 7ecd238b7f33
      6. We acted as a signed-in user trying to reach someone else's data and ran:
           INSERT INTO "public"."profiles" ("id", "display_name", "avatar_url") VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Bob', 'https://example.test/16ff09')
         Result: the access policy let the row through; only a table constraint stopped it (error 23505: duplicate key value violates unique constraint "profiles_pkey").
         Access was ALLOWED. That is the problem.
         Evidence: sha256 364cf1c0dcb1
      7. We acted as a signed-in user trying to reach someone else's data and ran:
           UPDATE "public"."profiles" SET "display_name" = "display_name" WHERE "id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database accepted it and changed 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 95173f5b2dc4
      8. We acted as a signed-in user trying to reach someone else's data and ran:
           DELETE FROM "public"."profiles" WHERE "id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database accepted it and changed 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 478d2c3b142c
    Could not be tested (no clear answer):
      - Signed-in user A hands one of their rows to user B: the statement failed with SQLSTATE 23505 before access could be judged

[2] PROVEN: reproduced against a real database
    Severity: CRITICAL
    What: Table public.tickets can be accessed by people who should not see or change its rows
    Where: public.tickets (table)
    An attacker could: Anyone with your public anon key can read rows of public.tickets, add rows to public.tickets, change rows in public.tickets and delete rows from public.tickets, and any signed-in user can read other users' rows, create rows in other users' names, create rows that belong to nobody, change other users' rows, delete other users' rows and give their own rows to another user.
    Why:
      - Policy "Anyone can use tickets" lets everyone write (all) with a condition that is always true.
      - The anon role (your public key) holds insert, update, delete privileges on this table.
      - No policy compares user_id with the signed-in user, so nothing separates one user's rows from another's.
    How we proved it:
      1. We acted as an anonymous visitor (no login, only the public key) and ran:
           SELECT * FROM "public"."tickets"
         Result: the database returned 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 90562acfca47
      2. We acted as an anonymous visitor (no login, only the public key) and ran:
           INSERT INTO "public"."tickets" ("id", "user_id", "subject") VALUES ('36384538-dd35-4a35-a38e-c8a664532d19', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic subject (Bob)')
         Result: the database accepted it and changed 1 row.
         Access was ALLOWED. That is the problem.
         Evidence: sha256 55ca3553570a
      3. We acted as an anonymous visitor (no login, only the public key) and ran:
           UPDATE "public"."tickets" SET "subject" = "subject"
         Result: the database accepted it and changed 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 03e56b5db03a
      4. We acted as an anonymous visitor (no login, only the public key) and ran:
           DELETE FROM "public"."tickets"
         Result: the database accepted it and changed 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 abeac5841442
      5. We acted as a signed-in user trying to reach someone else's data and ran:
           SELECT * FROM "public"."tickets" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database returned 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 58752f7fc91f
      6. We acted as a signed-in user trying to reach someone else's data and ran:
           INSERT INTO "public"."tickets" ("id", "user_id", "subject") VALUES ('ac193d51-5819-4ef0-951d-9e45259b89c3', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic subject (Bob)')
         Result: the database accepted it and changed 1 row.
         Access was ALLOWED. That is the problem.
         Evidence: sha256 3f9e937a71e1
      7. We acted as a signed-in user trying to reach someone else's data and ran:
           INSERT INTO "public"."tickets" ("id", "user_id", "subject") VALUES ('e781bca1-85b3-4e1a-95b4-dd9eebe43807', NULL, 'Synthetic subject (Bob)')
         Result: the database accepted it and changed 1 row.
         Access was ALLOWED. That is the problem.
         Evidence: sha256 be6c381bab9d
      8. We acted as a signed-in user trying to reach someone else's data and ran:
           UPDATE "public"."tickets" SET "subject" = "subject" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database accepted it and changed 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 91079424847d
      9. We acted as a signed-in user trying to reach someone else's data and ran:
           DELETE FROM "public"."tickets" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database accepted it and changed 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 83f93acf454e
      10. We acted as a signed-in user trying to reach someone else's data and ran:
           UPDATE "public"."tickets" SET "user_id" = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' WHERE "user_id"::text = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
         Result: the database accepted it and changed 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 b8aac0e872d1

[3] PROVEN: reproduced against a real database
    Severity: CRITICAL
    What: Table public.notes can be accessed by people who should not see or change its rows
    Where: public.notes (table)
    An attacker could: Anyone with your public anon key can read rows of public.notes, and any signed-in user can read other users' rows.
    Why:
      - Policy "Notes are viewable by everyone" has a condition that is always true, so it admits every row for everyone (select).
      - The anon role (your public key) holds insert, update, delete privileges on this table.
    How we proved it:
      1. We acted as an anonymous visitor (no login, only the public key) and ran:
           SELECT * FROM "public"."notes"
         Result: the database returned 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 3002c2a3c176
      2. We acted as a signed-in user trying to reach someone else's data and ran:
           SELECT * FROM "public"."notes" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database returned 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 0f6cc8e547ef
    Attempts the database blocked:
      - Anonymous visitor adds a row: the database refused it (error 42501: new row violates row-level security policy for table "notes")
      - Anonymous visitor changes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
      - Anonymous visitor deletes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
      - Signed-in user A adds a row owned by user B: the database refused it (error 42501: new row violates row-level security policy for table "notes")
      - Signed-in user A changes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
      - Signed-in user A deletes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
      - Signed-in user A hands one of their rows to user B: the database refused it (error 42501: new row violates row-level security policy for table "notes")

[4] PROVEN: reproduced against a real database
    Severity: CRITICAL
    What: View public.invoice_summaries can be accessed by people who should not see or change its rows
    Where: public.invoice_summaries (view)
    An attacker could: Anyone with your public anon key can read the rows behind public.invoice_summaries, and any signed-in user can read other users' rows through the view.
    Why:
      - The view runs with its owner's rights (it is not security_invoker), so the row level security on public.invoices is skipped when the view is read.
    How we proved it:
      1. We acted as an anonymous visitor (no login, only the public key) and ran:
           SELECT * FROM "public"."invoice_summaries"
         Result: the database returned 2 rows (2 rows seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 84ca98065feb
      2. We acted as a signed-in user trying to reach someone else's data and ran:
           SELECT * FROM "public"."invoice_summaries" WHERE "owner_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
         Result: the database returned 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 db4e5ef0c5b1

[5] PROVEN: reproduced against a real database
    Severity: HIGH
    What: Table public.documents can be accessed by people who should not see or change its rows
    Where: public.documents (table)
    An attacker could: Any signed-in user can create rows in other users' names in public.documents.
    Why:
      - Policy "Owners can edit documents" has a condition that is always true, so it admits every row for authenticated (update).
      - The anon role (your public key) holds insert, update, delete privileges on this table.
      - Policy "Signed-in users can add documents" does not check that owner_id is the caller when a row is written (insert).
    How we proved it:
      1. We acted as a signed-in user trying to reach someone else's data and ran:
           INSERT INTO "public"."documents" ("id", "owner_id", "title", "body") VALUES ('2511056d-6edd-4291-94ab-1c262ec4bf33', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic title (Bob)', 'Synthetic body from Bob')
         Result: the database accepted it and changed 1 row.
         Access was ALLOWED. That is the problem.
         Evidence: sha256 f27281fd2ea7
    Attempts the database blocked:
      - Anonymous visitor reads rows: the database returned 0 rows (2 rows seeded for this test)
      - Anonymous visitor adds a row: the database refused it (error 42501: new row violates row-level security policy for table "documents")
      - Anonymous visitor changes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
      - Anonymous visitor deletes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
      - Signed-in user A reads user B's rows: the database returned 0 rows (1 row seeded for this test)
      - Signed-in user A changes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
      - Signed-in user A deletes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
      - Signed-in user A hands one of their rows to user B: the database refused it (error 42501: new row violates row-level security policy for table "documents")

[6] PROVEN: reproduced against a real database
    Severity: HIGH
    What: Table public.projects can be accessed by people who should not see or change its rows
    Where: public.projects (table)
    An attacker could: Any signed-in user can create rows in other users' names and give their own rows to another user in public.projects.
    Why:
      - The anon role (your public key) holds insert, update, delete privileges on this table.
      - Policy "Projects follow the customer" does not check that owner_id is the caller when a row is written (insert, update).
      - No policy compares owner_id with the signed-in user, so nothing separates one user's rows from another's.
    How we proved it:
      1. We acted as a signed-in user trying to reach someone else's data and ran:
           INSERT INTO "public"."projects" ("id", "owner_id", "customer_id", "name") VALUES ('52061537-e5e0-479c-9964-19942efbc6d4', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Bob')
         Result: the database accepted it and changed 1 row.
         Access was ALLOWED. That is the problem.
         Evidence: sha256 18643611b3a1
      2. We acted as a signed-in user trying to reach someone else's data and ran:
           UPDATE "public"."projects" SET "owner_id" = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' WHERE "owner_id"::text = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
         Result: the database accepted it and changed 1 row (1 row seeded for this test).
         Access was ALLOWED. That is the problem.
         Evidence: sha256 5e1f67c651bf
    Attempts the database blocked:
      - Anonymous visitor reads rows: the database returned 0 rows (2 rows seeded for this test)
      - Anonymous visitor adds a row: the database refused it (error 42501: new row violates row-level security policy for table "projects")
      - Anonymous visitor changes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
      - Anonymous visitor deletes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
      - Signed-in user A reads user B's rows: the database returned 0 rows (1 row seeded for this test)
      - Signed-in user A changes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
      - Signed-in user A deletes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)

LOOKED FINE
-----------
- public.invoices: Table public.invoices refused every attack we tried

HOW TO FIX
----------
- public.profiles: Fix VERIFIED: 8 attacks now fail and 3 legitimate actions still work.
- public.tickets: Fix VERIFIED: 10 attacks now fail and 4 legitimate actions still work.
- public.notes: Fix VERIFIED: 2 attacks now fail and 4 legitimate actions still work.
- public.invoice_summaries: Fix VERIFIED: 2 attacks now fail and 1 legitimate action still works.
- public.documents: Fix VERIFIED: 1 attack now fails and 4 legitimate actions still work.
- public.projects: Fix VERIFIED: 2 attacks now fail and 4 legitimate actions still work.

Proposed SQL (starting point, review before use):
    -- proof-audit proposed fix: a STARTING POINT, not a finished migration.
    -- Review every statement. It was derived from the schema model and checked against synthetic users only.
    
    -- public.documents
    -- Drop policy "Owners can edit documents": it does not tie every command to the row's owner.
    -- Drop policy "Signed-in users can add documents": it does not tie every command to the row's owner.
    -- Allow signed-in users to insert, update only rows whose owner_id is theirs.
    -- Take every privilege away from the anon role (the public key).
    DROP POLICY IF EXISTS "Owners can edit documents" ON "public"."documents";
    DROP POLICY IF EXISTS "Signed-in users can add documents" ON "public"."documents";
    CREATE POLICY "documents_insert_own" ON "public"."documents" FOR INSERT TO authenticated WITH CHECK ("owner_id" = (select auth.uid()));
    CREATE POLICY "documents_update_own" ON "public"."documents" FOR UPDATE TO authenticated USING ("owner_id" = (select auth.uid())) WITH CHECK ("owner_id" = (select auth.uid()));
    REVOKE ALL ON TABLE "public"."documents" FROM anon;
    
    -- public.invoice_summaries
    -- Make the view run with the caller's rights so row level security applies to it.
    -- Take every privilege away from the anon role.
    ALTER VIEW "public"."invoice_summaries" SET (security_invoker = true);
    REVOKE ALL ON TABLE "public"."invoice_summaries" FROM anon;
    
    -- public.notes
    -- Drop policy "Notes are viewable by everyone": it does not tie every command to the row's owner.
    -- Take every privilege away from the anon role (the public key).
    DROP POLICY IF EXISTS "Notes are viewable by everyone" ON "public"."notes";
    REVOKE ALL ON TABLE "public"."notes" FROM anon;
    
    -- public.profiles
    -- Turn row level security on.
    -- Allow signed-in users to select, insert, update, delete only rows whose id is theirs.
    -- Take every privilege away from the anon role (the public key).
    ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
    CREATE POLICY "profiles_select_own" ON "public"."profiles" FOR SELECT TO authenticated USING ("id" = (select auth.uid()));
    CREATE POLICY "profiles_insert_own" ON "public"."profiles" FOR INSERT TO authenticated WITH CHECK ("id" = (select auth.uid()));
    CREATE POLICY "profiles_update_own" ON "public"."profiles" FOR UPDATE TO authenticated USING ("id" = (select auth.uid())) WITH CHECK ("id" = (select auth.uid()));
    CREATE POLICY "profiles_delete_own" ON "public"."profiles" FOR DELETE TO authenticated USING ("id" = (select auth.uid()));
    REVOKE ALL ON TABLE "public"."profiles" FROM anon;
    
    -- public.projects
    -- Drop policy "Projects follow the customer": it does not tie every command to the row's owner.
    -- Allow signed-in users to select, insert, update, delete only rows whose owner_id is theirs.
    -- Take every privilege away from the anon role (the public key).
    DROP POLICY IF EXISTS "Projects follow the customer" ON "public"."projects";
    CREATE POLICY "projects_select_own" ON "public"."projects" FOR SELECT TO authenticated USING ("owner_id" = (select auth.uid()));
    CREATE POLICY "projects_insert_own" ON "public"."projects" FOR INSERT TO authenticated WITH CHECK ("owner_id" = (select auth.uid()));
    CREATE POLICY "projects_update_own" ON "public"."projects" FOR UPDATE TO authenticated USING ("owner_id" = (select auth.uid())) WITH CHECK ("owner_id" = (select auth.uid()));
    CREATE POLICY "projects_delete_own" ON "public"."projects" FOR DELETE TO authenticated USING ("owner_id" = (select auth.uid()));
    REVOKE ALL ON TABLE "public"."projects" FROM anon;
    
    -- public.tickets
    -- Drop policy "Anyone can use tickets": it does not tie every command to the row's owner.
    -- Allow signed-in users to select, insert, update, delete only rows whose user_id is theirs.
    -- Take every privilege away from the anon role (the public key).
    DROP POLICY IF EXISTS "Anyone can use tickets" ON "public"."tickets";
    CREATE POLICY "tickets_select_own" ON "public"."tickets" FOR SELECT TO authenticated USING ("user_id" = (select auth.uid()));
    CREATE POLICY "tickets_insert_own" ON "public"."tickets" FOR INSERT TO authenticated WITH CHECK ("user_id" = (select auth.uid()));
    CREATE POLICY "tickets_update_own" ON "public"."tickets" FOR UPDATE TO authenticated USING ("user_id" = (select auth.uid())) WITH CHECK ("user_id" = (select auth.uid()));
    CREATE POLICY "tickets_delete_own" ON "public"."tickets" FOR DELETE TO authenticated USING ("user_id" = (select auth.uid()));
    REVOKE ALL ON TABLE "public"."tickets" FROM anon;
    

FIX CHECK
---------
VERIFIED: every attack that worked before now fails, and a normal signed-in user can still read and write their own rows.

Per table, before the fix versus after the fix:

  public.documents: VERIFIED (attacks closed, normal use works)
    Because: 1 attack now fails and 4 legitimate actions still work
    - Signed-in user A adds a row owned by user B: worked before, now blocked

  public.invoice_summaries: VERIFIED (attacks closed, normal use works)
    Because: 2 attacks now fail and 1 legitimate action still works
    - Anonymous visitor reads the view: worked before, now blocked
    - Signed-in user A reads user B's rows through the view: worked before, now blocked

  public.notes: VERIFIED (attacks closed, normal use works)
    Because: 2 attacks now fail and 4 legitimate actions still work
    - Anonymous visitor reads rows: worked before, now blocked
    - Signed-in user A reads user B's rows: worked before, now blocked

  public.profiles: VERIFIED (attacks closed, normal use works)
    Because: 8 attacks now fail and 3 legitimate actions still work
    - Anonymous visitor reads rows: worked before, now blocked
    - Anonymous visitor adds a row: worked before, now blocked
    - Anonymous visitor changes rows: worked before, now blocked
    - Anonymous visitor deletes rows: worked before, now blocked
    - Signed-in user A reads user B's rows: worked before, now blocked
    - Signed-in user A adds a row owned by user B: worked before, now blocked
    - Signed-in user A changes user B's rows: worked before, now blocked
    - Signed-in user A deletes user B's rows: worked before, now blocked

  public.projects: VERIFIED (attacks closed, normal use works)
    Because: 2 attacks now fail and 4 legitimate actions still work
    - Signed-in user A adds a row owned by user B: worked before, now blocked
    - Signed-in user A hands one of their rows to user B: worked before, now blocked

  public.tickets: VERIFIED (attacks closed, normal use works)
    Because: 10 attacks now fail and 4 legitimate actions still work
    - Anonymous visitor reads rows: worked before, now blocked
    - Anonymous visitor adds a row: worked before, now blocked
    - Anonymous visitor changes rows: worked before, now blocked
    - Anonymous visitor deletes rows: worked before, now blocked
    - Signed-in user A reads user B's rows: worked before, now blocked
    - Signed-in user A adds a row owned by user B: worked before, now blocked
    - Signed-in user A adds a row with no owner: worked before, now blocked
    - Signed-in user A changes user B's rows: worked before, now blocked
    - Signed-in user A deletes user B's rows: worked before, now blocked
    - Signed-in user A hands one of their rows to user B: worked before, now blocked

STATIC AUDITOR CROSS-CHECK
--------------------------
Findings from saas-audit 0.1.0 (project audit), checked against our tests:
- PROVEN by our test: Table public.profiles has no row level security [table public.profiles]
    supabase-rls-missing (critical) at supabase/migrations/20260105090000_init.sql:10
    reproduced against the throwaway database: anon-delete, anon-insert, anon-read, anon-update, cross-delete, cross-insert, cross-read, cross-update
- PROVEN by our test: Policy "Anyone can use tickets" lets every role including anon read and write every row of tickets [table public.tickets]
    supabase-policy-permissive (critical) at supabase/migrations/20260105090000_init.sql:44
    reproduced against the throwaway database: anon-delete, anon-insert, anon-read, anon-update
- PROVEN by our test: Policy "Notes are viewable by everyone" lets every role including anon read every row of notes [table public.notes]
    supabase-policy-permissive (high) at supabase/migrations/20260105090000_init.sql:27
    reproduced against the throwaway database: anon-read
- PROVEN by our test: No policy on tickets ties user_id to the caller [table public.tickets]
    supabase-tenant-unscoped (high) at supabase/migrations/20260105090000_init.sql:36
    reproduced against the throwaway database: cross-delete, cross-insert, cross-read, cross-update, reassign-owner
- could not be reproduced: Policy "Owners can edit documents" lets authenticated update every row of documents [table public.documents]
    supabase-policy-permissive (high) at supabase/migrations/20260105090000_init.sql:62
    the database denied every attack this finding describes (cross-update, reassign-owner); likely a false positive or covered by grants/roles; other attacks on this table were proven: cross-insert
0 static findings out of scope (not about row level security, not tested here).

WHAT WAS NOT CHECKED
--------------------
- Authorization written in application code: route handlers, server actions, edge functions and anything else that runs before the database.
- Frontend code, and anything the browser does with the data it receives.
- Exposure of secrets: keys, tokens, .env files and service-role keys that ship to the client.
- Supabase features outside Postgres row level security: storage buckets and their policies, realtime, GraphQL, auth settings.
- Policies that depend on data this tool does not create: custom JWT claims other than sub, role, tenant_id and org_id, extensions other than uuid-ossp and pgcrypto.
- Materialized views, functions callable as RPC, column-level privileges, and tables that the migrations do not create.
- A CLEAN result means the listed attacks were refused for two synthetic users and an anonymous caller. It is not a penetration test and does not show the table is safe.
```

</details>

### The proof records

`proofs.jsonl` has one metadata line and one line per probe (163 lines: the metadata, then 162 proofs: the 81 probes before the fix and the same 81 after it). Here is the metadata line and the proof of the `documents` problem. Every field is plain data; the `sql` is exactly what ran, as `authenticated` with those claims, inside a transaction that was rolled back.

```json
{
  "fixSha256": "afb6bc8c637fac5e0bcfe2054d13e108a59565bc87aa71f01d29a4cb5cc3b1cf",
  "fixStatements": [
    "... 27 statements, see fix.sql ..."
  ],
  "image": "loopback",
  "inputs": [
    {
      "bytes": 4606,
      "path": "examples/vulnerable-app/supabase/migrations/20260105090000_init.sql",
      "sha256": "85a898596387da1659e7ab24d7b4ee6db383d4ade14b901b0a68cd0dfcc96775"
    },
    {
      "bytes": 452,
      "path": "examples/vulnerable-app/supabase/migrations/20260106120000_profile_trigger.sql",
      "sha256": "d5c23be51364246d03603388dbfc8346b219321e33f23b12132d81160a73b7ef"
    }
  ],
  "schema": "proof-audit/proofs@1",
  "seed": "deterministic-v1",
  "tool": {
    "name": "proof-audit",
    "version": "0.1.0"
  },
  "type": "meta"
}
{
  "actor": "user-a",
  "claims": "{\"app_metadata\":{\"org_id\":\"a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1\",\"provider\":\"email\",\"tenant_id\":\"a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1\"},\"aud\":\"authenticated\",\"email\":\"alice@example.test\",\"org_id\":\"a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1\",\"role\":\"authenticated\",\"sub\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"tenant_id\":\"a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1\",\"user_metadata\":{}}",
  "command": "insert",
  "hash": "f27281fd2ea7edb174d34698c80b9b86876d28f3fb15f4d996382db0b3a96ad3",
  "id": "public.documents/cross-insert",
  "intent": "exploit",
  "kind": "cross-insert",
  "observation": {
    "rows": 1,
    "status": "rows"
  },
  "phase": "before",
  "reason": "the statement changed 1 row",
  "role": "authenticated",
  "sql": "INSERT INTO \"public\".\"documents\" (\"id\", \"owner_id\", \"title\", \"body\") VALUES ('2511056d-6edd-4291-94ab-1c262ec4bf33', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic title (Bob)', 'Synthetic body from Bob')",
  "subject": "public.documents",
  "subjectKind": "table",
  "targetRows": null,
  "title": "Signed-in user A adds a row owned by user B",
  "type": "proof",
  "verdict": "PROVEN_VULNERABLE"
}
```

### The proposed fix

`fix.sql` is derived from the model and marked as a starting point. It enables RLS, writes owner policies with `(select auth.uid())`, revokes anon privileges and turns the view into a `security_invoker` view. It was applied to a fresh copy of the database, and the same 81 probes were re-run.

```sql
-- proof-audit proposed fix: a STARTING POINT, not a finished migration.
-- Review every statement. It was derived from the schema model and checked against synthetic users only.

-- public.documents
-- Drop policy "Owners can edit documents": it does not tie every command to the row's owner.
-- Drop policy "Signed-in users can add documents": it does not tie every command to the row's owner.
-- Allow signed-in users to insert, update only rows whose owner_id is theirs.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Owners can edit documents" ON "public"."documents";
DROP POLICY IF EXISTS "Signed-in users can add documents" ON "public"."documents";
CREATE POLICY "documents_insert_own" ON "public"."documents" FOR INSERT TO authenticated WITH CHECK ("owner_id" = (select auth.uid()));
CREATE POLICY "documents_update_own" ON "public"."documents" FOR UPDATE TO authenticated USING ("owner_id" = (select auth.uid())) WITH CHECK ("owner_id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."documents" FROM anon;

-- public.invoice_summaries
-- Make the view run with the caller's rights so row level security applies to it.
-- Take every privilege away from the anon role.
ALTER VIEW "public"."invoice_summaries" SET (security_invoker = true);
REVOKE ALL ON TABLE "public"."invoice_summaries" FROM anon;

-- public.notes
-- Drop policy "Notes are viewable by everyone": it does not tie every command to the row's owner.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Notes are viewable by everyone" ON "public"."notes";
REVOKE ALL ON TABLE "public"."notes" FROM anon;

-- public.profiles
-- Turn row level security on.
-- Allow signed-in users to select, insert, update, delete only rows whose id is theirs.
-- Take every privilege away from the anon role (the public key).
ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "profiles_select_own" ON "public"."profiles" FOR SELECT TO authenticated USING ("id" = (select auth.uid()));
CREATE POLICY "profiles_insert_own" ON "public"."profiles" FOR INSERT TO authenticated WITH CHECK ("id" = (select auth.uid()));
CREATE POLICY "profiles_update_own" ON "public"."profiles" FOR UPDATE TO authenticated USING ("id" = (select auth.uid())) WITH CHECK ("id" = (select auth.uid()));
CREATE POLICY "profiles_delete_own" ON "public"."profiles" FOR DELETE TO authenticated USING ("id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."profiles" FROM anon;

-- public.projects
-- Drop policy "Projects follow the customer": it does not tie every command to the row's owner.
-- Allow signed-in users to select, insert, update, delete only rows whose owner_id is theirs.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Projects follow the customer" ON "public"."projects";
CREATE POLICY "projects_select_own" ON "public"."projects" FOR SELECT TO authenticated USING ("owner_id" = (select auth.uid()));
CREATE POLICY "projects_insert_own" ON "public"."projects" FOR INSERT TO authenticated WITH CHECK ("owner_id" = (select auth.uid()));
CREATE POLICY "projects_update_own" ON "public"."projects" FOR UPDATE TO authenticated USING ("owner_id" = (select auth.uid())) WITH CHECK ("owner_id" = (select auth.uid()));
CREATE POLICY "projects_delete_own" ON "public"."projects" FOR DELETE TO authenticated USING ("owner_id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."projects" FROM anon;

-- public.tickets
-- Drop policy "Anyone can use tickets": it does not tie every command to the row's owner.
-- Allow signed-in users to select, insert, update, delete only rows whose user_id is theirs.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Anyone can use tickets" ON "public"."tickets";
CREATE POLICY "tickets_select_own" ON "public"."tickets" FOR SELECT TO authenticated USING ("user_id" = (select auth.uid()));
CREATE POLICY "tickets_insert_own" ON "public"."tickets" FOR INSERT TO authenticated WITH CHECK ("user_id" = (select auth.uid()));
CREATE POLICY "tickets_update_own" ON "public"."tickets" FOR UPDATE TO authenticated USING ("user_id" = (select auth.uid())) WITH CHECK ("user_id" = (select auth.uid()));
CREATE POLICY "tickets_delete_own" ON "public"."tickets" FOR DELETE TO authenticated USING ("user_id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."tickets" FROM anon;
```

### Re-verification

The fix check in the report above says VERIFIED because, for each of the six tables, every probe that was proven now fails **and** the legitimate probes (user A reads, adds, changes and deletes their own rows) still work. A fix that closes the hole by locking everyone out is reported as `BREAKS_ACCESS`, never as verified (tested offline and against PostgreSQL).

The same evidence can be replayed at any time, and against your own migrations:

```console
$ scripts/run-contained.sh verify examples/vulnerable-app/sample-output/proofs.jsonl
OK: 162 probes replayed
  all 162 recorded probes replayed with identical results
exit code: 0

$ scripts/run-contained.sh verify examples/vulnerable-app/sample-output/proofs.jsonl --against examples/fixed-app/supabase/migrations
OK: 81 probes replayed
  all 6 previously proven subjects are now closed and legitimate access still works
exit code: 0

$ scripts/run-contained.sh verify examples/vulnerable-app/sample-output/proofs.jsonl --against examples/vulnerable-app/supabase/migrations
MISMATCH: 81 probes replayed
  public.documents: STILL_VULNERABLE (1 attack that worked before still works after the fix)
  public.invoice_summaries: STILL_VULNERABLE (2 attacks that worked before still work after the fix)
  public.notes: STILL_VULNERABLE (2 attacks that worked before still work after the fix)
  public.profiles: STILL_VULNERABLE (8 attacks that worked before still work after the fix)
  public.projects: STILL_VULNERABLE (2 attacks that worked before still work after the fix)
  public.tickets: STILL_VULNERABLE (10 attacks that worked before still work after the fix)
exit code: 1
```

And the corrected app, from scratch:

```console
$ scripts/run-contained.sh rls examples/fixed-app/supabase/migrations
SECURITY REPORT (plain language)
================================
Tool: proof-audit 0.1.0
Checked: 7 tables or views
Input files read: 2
Database used: a throwaway PostgreSQL database (version 16.14 (Debian 16.14-1.pgdg13+1), local connection loopback)
Run complete: yes
Tests run: 81 (0 showed a real problem)
RESULT: 0 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 7 CLEAN.
No problem could be reproduced.
...
```

## Integration with the static auditor

`--from-audit <saas-audit.json>` reads the JSON report of the author's static auditor `saas-rescue-audit` (`saas-audit --json`; unknown keys and older versions are tolerated), probes the tables it named first, and attaches a proof status to each of its Supabase findings: PROVEN, could not be reproduced, or static only. The finding is judged by the probes it is *about*: the static auditor flagged `Owners can edit documents` (an update policy with `with check (true)`), and the database refused the update and re-assign probes for it (another policy masks the check), so that finding is shown as *could not be reproduced*, with a note that other attacks on `documents` were proven. Findings that are not about RLS (secrets, webhooks, ...) are counted as out of scope. The real report for the example app is `examples/vulnerable-app/saas-audit.json`, and its cross-check is the "STATIC AUDITOR CROSS-CHECK" section of the report above.

## Evidence for orchestrators

`proofs.jsonl` and `verification-contract.json` are made to be checked by another program. The contract has the shape of the author's NEO design (a command and an expected exit code per check), so an orchestrator can require evidence before it marks a task complete:

```json
{
  "schema": "proof-audit/verification-contract@1",
  "tool": {
    "name": "proof-audit",
    "version": "0.1.0"
  },
  "checks": [
    {
      "id": "evidence-reproduces",
      "description": "Re-runs every recorded probe in a fresh throwaway database and compares the results with the recorded verdicts.",
      "command": "proof-audit verify examples/vulnerable-app/sample-output/proofs.jsonl",
      "expectedExitCode": 0,
      "mandatory": true
    },
    {
      "id": "fix-closes-proven-holes",
      "description": "Re-runs the recorded probes against the current migrations; passes only when every probe that was proven is now denied and the legitimate-access probes still succeed.",
      "command": "proof-audit verify examples/vulnerable-app/sample-output/proofs.jsonl --against examples/vulnerable-app/supabase/migrations",
      "expectedExitCode": 0,
      "mandatory": true
    }
  ]
}
```

`proof-audit verify <proofs.jsonl>` exits 0 only if every recorded expectation holds: the recorded inputs are unchanged (otherwise exit 3, "stale"), the database gives the same answer to every recorded probe (compared by content hash), and the recorded fix still closes the recorded holes. With `--against <migrations>` it re-runs the recorded probes against other migrations and exits 0 only when every previously proven table is now verified. The decoder re-computes every hash, and the contract decoder rejects any command that is not a plain `proof-audit verify ...` invocation.

## How it works

1. **Read** the migrations with a purpose-built tolerant SQL reader (comments, dollar quotes, quoted identifiers, `BEGIN ATOMIC`, psql meta-commands). Unsupported statements are skipped with a warning and never abort a run.
2. **Build** a sandbox: the Supabase shim (roles `anon`, `authenticated`, `service_role`; `auth.users`; `auth.uid()`, `auth.role()`, `auth.jwt()` and `auth.email()` reading `request.jwt.claims`; Supabase's default privileges), then the migrations, each statement on its own with failures recorded.
3. **Model** the schema from the database's own catalogs (policies, privileges, columns, views), detect owner columns with explainable heuristics (`user_id`, `owner_id`, `created_by`, `tenant_id`, `org_id`, references to `auth.users`, defaults of `auth.uid()`).
4. **Seed** one row per synthetic user in every table from column types, names and `CHECK` constraints. A table that cannot be seeded is recorded with the database's error and its probes are INCONCLUSIVE.
5. **Probe** each table and view as `anon` and as user A (`SET LOCAL ROLE` plus `request.jwt.claims`), in a transaction that is always rolled back; classify; propose a fix; **re-run the same probes** on a fresh copy with the fix applied.

The design records are in [docs/adr](docs/adr) and the vocabulary and context map in [docs/domain.md](docs/domain.md). The code is layered `domain` (pure) ← `application` ← `infrastructure` ← `composition`, and `test/architecture` fails the build when an import points the wrong way or the pure layers touch the clock, randomness or the process.

## Tests and coverage

`npm test` runs offline (no Docker, no database, no network). Coverage is V8 coverage from vitest; the thresholds in `vitest.config.ts` fail the run below 95% for the domain, 90% for the application layer and 85% overall.

| Suite | Where | Cases | Needs |
| --- | --- | --- | --- |
| domain unit and property tests | `test/domain` | 1,051 | nothing |
| application tests with an in-memory fake database | `test/application` | 112 | nothing |
| adapter tests (fake docker, fake transport, files, args) and contract suite | `test/infrastructure`, `test/contract` | 88 | nothing |
| architecture (dependency rule) | `test/architecture` | 71 | nothing |
| command line end to end, in-memory | `test/e2e` | 25 | nothing |
| **offline total** | `npm test` | **1,347** | |
| real PostgreSQL 16.14 (analysis, sandbox, CLI) | `test/integration` | 48 | `scripts/integration.sh` |
| default container mode for real | `test/smoke` | 2 | `scripts/docker-smoke.sh` |

(Parameterised tests count once per row.) Offline coverage:

| Layer | Statements | Lines | Branches |
| --- | --- | --- | --- |
| `src/domain` | 95.25% | 97.39% | 88.85% |
| `src/application` | 96.05% | 97.06% | 82.02% |
| `src/infrastructure` | 86.26% | 87.59% | 84.31% |
| **overall** | **93.89%** | **95.76%** | **87.62%** |

The infrastructure layer is lower offline because the `pg` transport and the URL provider only run against a real server. The integration suite, measured on its own, covers 71.3% of lines overall (`pg-transport.ts` 84%, `sandbox.ts` 89%, `harness.ts` 100%). Integration coverage is reported separately: `scripts/integration.sh --coverage`.

The integration suite uses the official `postgres` image pinned by digest (16.14, created 2026-08-05; the moving `postgres:16` tag was republished after the dependency cutoff and is not used). `scripts/integration.sh` starts it on a user-defined internal docker network and runs the tests in a Node container that shares its network namespace, so the database is at `127.0.0.1` and the loopback rule applies to the tests ([ADR 0010](docs/adr/0010-integration-harness.md)). Passwords are generated at run time and never committed.

```sh
npm ci --ignore-scripts          # run it in a throwaway container, not on your machine
npm run typecheck
npm test                         # offline
npm run coverage                 # offline, with thresholds
scripts/integration.sh           # needs docker; real PostgreSQL
scripts/docker-smoke.sh          # needs docker; default container mode, through a restricted relay
npm run build
```

## Limitations

- **Seeding is heuristic.** Values come from types, names and the `CHECK` constraints the hint reader understands (enumerated strings, numeric bounds, minimum length). A regex constraint or an unusual type means the table cannot be seeded; the report says so and the probes are INCONCLUSIVE rather than guessed. One row per user is seeded, so policies that depend on many rows or on data this tool does not create are not exercised.
- **The Supabase shim approximates a project.** It has the three roles, `auth.users`, the `auth.*` helper functions, `extensions` with `uuid-ossp` and `pgcrypto`, and the default privileges on `public`. It has no GoTrue, PostgREST, `storage`, `realtime`, `vault`, other extensions, event triggers or custom JWT claims beyond `sub`, `role`, `tenant_id` and `org_id`. Migrations that depend on those produce recorded errors, not a crash. Which schemas are exposed through the API is not modelled: every user schema is probed.
- **PostgreSQL version differences.** Everything was run on 16.14. Supabase projects run other majors; behaviour of `security_invoker` views (PostgreSQL 15+), policy evaluation details and `pg_get_expr` output can differ.
- **Scope of probes.** Table-level privileges, not column-level ones. Materialized views, functions called as RPC, `FORCE ROW LEVEL SECURITY` edge cases and tables created by role-specific default privileges are not probed. A table without an owner column gets anonymous probes only.
- **A policy-admitted insert that a constraint stops is still proof**, because PostgreSQL checks row level security before table constraints (confirmed against the pinned image); the reason in the proof says so.
- **The fix is a starting point.** Policies are written for the primary owner column, with a membership table for tenant-style columns when one exists; otherwise the table is listed as needing your decision. Anything it generates is checked only against synthetic users.
- **Loopback mode is only as isolated as your server.** The default mode has no network at all; with `--database-url` you provide a throwaway server, and the tool creates roles `anon`, `authenticated` and `service_role` in it if they are missing.

## Roadmap (not implemented)

Nothing below exists yet; it is where the same idea (a proof you can replay, then a verified fix) could go next.

- Webhook signature proofs: replay a forged and a correctly signed webhook against a local handler.
- Route-handler authorization proofs: call a local route as user A for user B's resource.
- Smart-contract invariant proofs: fuzz access-control invariants against a local chain.

## Dependencies and licence

One runtime dependency (`pg`, exact pin, loopback transport only); development: TypeScript 6.0.3, vitest 5.0.5 with `@vitest/coverage-v8`, `@types/node`, `@types/pg`. All versions were resolved with `npm install --before=2026-10-24T00:00:00Z --ignore-scripts`, the lockfile is verified with `npm ci --ignore-scripts` on amd64 and arm64, `npm audit` reports 0 vulnerabilities with and without `--omit=dev`, and no locked package is newer than the cutoff. MIT licence, copyright Kien Phan.
