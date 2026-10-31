# Row level security report

| Item | Value |
|---|---|
| Tool | proof\-audit 0\.1\.0 |
| Checked | 7 tables or views |
| Input files read | 2 |
| Database used | a throwaway PostgreSQL database (version 16\.14 \(Debian 16\.14\-1\.pgdg13\+1\), local connection loopback) |
| Run complete | yes |
| Tests run | 81 (25 showed a real problem) |
| PROVEN | 6 |
| SUSPECTED | 0 |
| INCONCLUSIVE | 0 |
| CLEAN | 1 |

## Result

**6 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 1 CLEAN**

6 of 7 checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves.

## What we found

### 1. PROVEN · critical · `public.profiles`

**Table public\.profiles can be accessed by people who should not see or change its rows**

**An attacker could:** Anyone with your public anon key can read rows of public\.profiles, add rows to public\.profiles, change rows in public\.profiles and delete rows from public\.profiles, and any signed\-in user can read other users' rows, create rows in other users' names, change other users' rows and delete other users' rows\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- Row level security is switched off on this table, so the database applies no row filter at all\.
- The anon role \(your public key\) holds insert, update, delete privileges on this table\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
SELECT * FROM "public"."profiles"
```

Result: the database returned 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 1005e1751317`

**Check 2.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
INSERT INTO "public"."profiles" ("id", "display_name", "avatar_url") VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Bob', 'https://example.test/9b9fbf')
```

Result: the access policy let the row through; only a table constraint stopped it (error 23505: duplicate key value violates unique constraint "profiles\_pkey"). Access was ALLOWED. That is the problem.

Evidence: `sha256 243035d4a204`

**Check 3.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
UPDATE "public"."profiles" SET "display_name" = "display_name"
```

Result: the database accepted it and changed 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 2b6dcdc88d45`

**Check 4.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
DELETE FROM "public"."profiles"
```

Result: the database accepted it and changed 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 aefc1cea706c`

**Check 5.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
SELECT * FROM "public"."profiles" WHERE "id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database returned 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 7ecd238b7f33`

**Check 6.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
INSERT INTO "public"."profiles" ("id", "display_name", "avatar_url") VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Bob', 'https://example.test/16ff09')
```

Result: the access policy let the row through; only a table constraint stopped it (error 23505: duplicate key value violates unique constraint "profiles\_pkey"). Access was ALLOWED. That is the problem.

Evidence: `sha256 364cf1c0dcb1`

**Check 7.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
UPDATE "public"."profiles" SET "display_name" = "display_name" WHERE "id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database accepted it and changed 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 95173f5b2dc4`

**Check 8.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
DELETE FROM "public"."profiles" WHERE "id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database accepted it and changed 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 478d2c3b142c`

#### Could not be tested (no clear answer)

- Signed\-in user A hands one of their rows to user B: the statement failed with SQLSTATE 23505 before access could be judged

### 2. PROVEN · critical · `public.tickets`

**Table public\.tickets can be accessed by people who should not see or change its rows**

**An attacker could:** Anyone with your public anon key can read rows of public\.tickets, add rows to public\.tickets, change rows in public\.tickets and delete rows from public\.tickets, and any signed\-in user can read other users' rows, create rows in other users' names, create rows that belong to nobody, change other users' rows, delete other users' rows and give their own rows to another user\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- Policy "Anyone can use tickets" lets everyone write \(all\) with a condition that is always true\.
- The anon role \(your public key\) holds insert, update, delete privileges on this table\.
- No policy compares user\_id with the signed\-in user, so nothing separates one user's rows from another's\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
SELECT * FROM "public"."tickets"
```

Result: the database returned 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 90562acfca47`

**Check 2.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
INSERT INTO "public"."tickets" ("id", "user_id", "subject") VALUES ('36384538-dd35-4a35-a38e-c8a664532d19', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic subject (Bob)')
```

Result: the database accepted it and changed 1 row. Access was ALLOWED. That is the problem.

Evidence: `sha256 55ca3553570a`

**Check 3.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
UPDATE "public"."tickets" SET "subject" = "subject"
```

Result: the database accepted it and changed 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 03e56b5db03a`

**Check 4.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
DELETE FROM "public"."tickets"
```

Result: the database accepted it and changed 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 abeac5841442`

**Check 5.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
SELECT * FROM "public"."tickets" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database returned 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 58752f7fc91f`

**Check 6.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
INSERT INTO "public"."tickets" ("id", "user_id", "subject") VALUES ('ac193d51-5819-4ef0-951d-9e45259b89c3', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic subject (Bob)')
```

Result: the database accepted it and changed 1 row. Access was ALLOWED. That is the problem.

Evidence: `sha256 3f9e937a71e1`

**Check 7.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
INSERT INTO "public"."tickets" ("id", "user_id", "subject") VALUES ('e781bca1-85b3-4e1a-95b4-dd9eebe43807', NULL, 'Synthetic subject (Bob)')
```

Result: the database accepted it and changed 1 row. Access was ALLOWED. That is the problem.

Evidence: `sha256 be6c381bab9d`

**Check 8.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
UPDATE "public"."tickets" SET "subject" = "subject" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database accepted it and changed 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 91079424847d`

**Check 9.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
DELETE FROM "public"."tickets" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database accepted it and changed 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 83f93acf454e`

**Check 10.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
UPDATE "public"."tickets" SET "user_id" = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' WHERE "user_id"::text = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
```

Result: the database accepted it and changed 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 b8aac0e872d1`

### 3. PROVEN · critical · `public.notes`

**Table public\.notes can be accessed by people who should not see or change its rows**

**An attacker could:** Anyone with your public anon key can read rows of public\.notes, and any signed\-in user can read other users' rows\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- Policy "Notes are viewable by everyone" has a condition that is always true, so it admits every row for everyone \(select\)\.
- The anon role \(your public key\) holds insert, update, delete privileges on this table\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
SELECT * FROM "public"."notes"
```

Result: the database returned 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 3002c2a3c176`

**Check 2.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
SELECT * FROM "public"."notes" WHERE "user_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database returned 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 0f6cc8e547ef`

#### Attempts the database blocked

- Anonymous visitor adds a row: the database refused it (error 42501: new row violates row\-level security policy for table "notes")
- Anonymous visitor changes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
- Anonymous visitor deletes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
- Signed\-in user A adds a row owned by user B: the database refused it (error 42501: new row violates row\-level security policy for table "notes")
- Signed\-in user A changes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
- Signed\-in user A deletes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
- Signed\-in user A hands one of their rows to user B: the database refused it (error 42501: new row violates row\-level security policy for table "notes")

### 4. PROVEN · critical · `public.invoice_summaries`

**View public\.invoice\_summaries can be accessed by people who should not see or change its rows**

**An attacker could:** Anyone with your public anon key can read the rows behind public\.invoice\_summaries, and any signed\-in user can read other users' rows through the view\.

Kind: view. PROVEN: reproduced against a real database.

#### Why

- The view runs with its owner's rights \(it is not security\_invoker\), so the row level security on public\.invoices is skipped when the view is read\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
SELECT * FROM "public"."invoice_summaries"
```

Result: the database returned 2 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 84ca98065feb`

**Check 2.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
SELECT * FROM "public"."invoice_summaries" WHERE "owner_id"::text = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
```

Result: the database returned 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 db4e5ef0c5b1`

### 5. PROVEN · high · `public.documents`

**Table public\.documents can be accessed by people who should not see or change its rows**

**An attacker could:** Any signed\-in user can create rows in other users' names in public\.documents\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- Policy "Owners can edit documents" has a condition that is always true, so it admits every row for authenticated \(update\)\.
- The anon role \(your public key\) holds insert, update, delete privileges on this table\.
- Policy "Signed\-in users can add documents" does not check that owner\_id is the caller when a row is written \(insert\)\.

#### How we proved it

**Check 1.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
INSERT INTO "public"."documents" ("id", "owner_id", "title", "body") VALUES ('2511056d-6edd-4291-94ab-1c262ec4bf33', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Synthetic title (Bob)', 'Synthetic body from Bob')
```

Result: the database accepted it and changed 1 row. Access was ALLOWED. That is the problem.

Evidence: `sha256 f27281fd2ea7`

#### Attempts the database blocked

- Anonymous visitor reads rows: the database returned 0 rows (2 rows seeded for this test)
- Anonymous visitor adds a row: the database refused it (error 42501: new row violates row\-level security policy for table "documents")
- Anonymous visitor changes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
- Anonymous visitor deletes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
- Signed\-in user A reads user B's rows: the database returned 0 rows (1 row seeded for this test)
- Signed\-in user A changes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
- Signed\-in user A deletes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
- Signed\-in user A hands one of their rows to user B: the database refused it (error 42501: new row violates row\-level security policy for table "documents")

### 6. PROVEN · high · `public.projects`

**Table public\.projects can be accessed by people who should not see or change its rows**

**An attacker could:** Any signed\-in user can create rows in other users' names and give their own rows to another user in public\.projects\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- The anon role \(your public key\) holds insert, update, delete privileges on this table\.
- Policy "Projects follow the customer" does not check that owner\_id is the caller when a row is written \(insert, update\)\.
- No policy compares owner\_id with the signed\-in user, so nothing separates one user's rows from another's\.

#### How we proved it

**Check 1.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
INSERT INTO "public"."projects" ("id", "owner_id", "customer_id", "name") VALUES ('52061537-e5e0-479c-9964-19942efbc6d4', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Bob')
```

Result: the database accepted it and changed 1 row. Access was ALLOWED. That is the problem.

Evidence: `sha256 18643611b3a1`

**Check 2.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
UPDATE "public"."projects" SET "owner_id" = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' WHERE "owner_id"::text = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
```

Result: the database accepted it and changed 1 row (1 row seeded for this test). Access was ALLOWED. That is the problem.

Evidence: `sha256 5e1f67c651bf`

#### Attempts the database blocked

- Anonymous visitor reads rows: the database returned 0 rows (2 rows seeded for this test)
- Anonymous visitor adds a row: the database refused it (error 42501: new row violates row\-level security policy for table "projects")
- Anonymous visitor changes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
- Anonymous visitor deletes rows: the database ran it but changed 0 rows (2 rows seeded for this test)
- Signed\-in user A reads user B's rows: the database returned 0 rows (1 row seeded for this test)
- Signed\-in user A changes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)
- Signed\-in user A deletes user B's rows: the database ran it but changed 0 rows (1 row seeded for this test)

## Looked fine

- `public.invoices`: Table public\.invoices refused every attack we tried

## How to fix

- `public.profiles`: Fix VERIFIED: 8 attacks now fail and 3 legitimate actions still work\.
- `public.tickets`: Fix VERIFIED: 10 attacks now fail and 4 legitimate actions still work\.
- `public.notes`: Fix VERIFIED: 2 attacks now fail and 4 legitimate actions still work\.
- `public.invoice_summaries`: Fix VERIFIED: 2 attacks now fail and 1 legitimate action still works\.
- `public.documents`: Fix VERIFIED: 1 attack now fails and 4 legitimate actions still work\.
- `public.projects`: Fix VERIFIED: 2 attacks now fail and 4 legitimate actions still work\.

### Proposed SQL (starting point, review before use)

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

## Fix check

**VERIFIED**: every attack that worked before now fails, and a normal signed-in user can still read and write their own rows.

| Table | Result | Closed | Still works | Normal use broken | No clear answer | Because |
|---|---|---|---|---|---|---|
| public\.documents | VERIFIED (attacks closed, normal use works) | Signed\-in user A adds a row owned by user B | none | none | none | 1 attack now fails and 4 legitimate actions still work |
| public\.invoice\_summaries | VERIFIED (attacks closed, normal use works) | Anonymous visitor reads the view; Signed\-in user A reads user B's rows through the view | none | none | none | 2 attacks now fail and 1 legitimate action still works |
| public\.notes | VERIFIED (attacks closed, normal use works) | Anonymous visitor reads rows; Signed\-in user A reads user B's rows | none | none | none | 2 attacks now fail and 4 legitimate actions still work |
| public\.profiles | VERIFIED (attacks closed, normal use works) | Anonymous visitor reads rows; Anonymous visitor adds a row; Anonymous visitor changes rows; Anonymous visitor deletes rows; Signed\-in user A reads user B's rows; Signed\-in user A adds a row owned by user B; Signed\-in user A changes user B's rows; Signed\-in user A deletes user B's rows | none | none | none | 8 attacks now fail and 3 legitimate actions still work |
| public\.projects | VERIFIED (attacks closed, normal use works) | Signed\-in user A adds a row owned by user B; Signed\-in user A hands one of their rows to user B | none | none | none | 2 attacks now fail and 4 legitimate actions still work |
| public\.tickets | VERIFIED (attacks closed, normal use works) | Anonymous visitor reads rows; Anonymous visitor adds a row; Anonymous visitor changes rows; Anonymous visitor deletes rows; Signed\-in user A reads user B's rows; Signed\-in user A adds a row owned by user B; Signed\-in user A adds a row with no owner; Signed\-in user A changes user B's rows; Signed\-in user A deletes user B's rows; Signed\-in user A hands one of their rows to user B | none | none | none | 10 attacks now fail and 4 legitimate actions still work |

## Static auditor cross-check

Findings from saas\-audit 0\.1\.0 (project audit), checked against our tests:

| Result | Finding | Rule | Severity | Location | Table | Note |
|---|---|---|---|---|---|---|
| PROVEN by our test | Table public\.profiles has no row level security | supabase\-rls\-missing | critical | supabase/migrations/20260105090000\_init\.sql\:10 | public\.profiles | reproduced against the throwaway database\: anon\-delete, anon\-insert, anon\-read, anon\-update, cross\-delete, cross\-insert, cross\-read, cross\-update |
| PROVEN by our test | Policy "Anyone can use tickets" lets every role including anon read and write every row of tickets | supabase\-policy\-permissive | critical | supabase/migrations/20260105090000\_init\.sql\:44 | public\.tickets | reproduced against the throwaway database\: anon\-delete, anon\-insert, anon\-read, anon\-update |
| PROVEN by our test | Policy "Notes are viewable by everyone" lets every role including anon read every row of notes | supabase\-policy\-permissive | high | supabase/migrations/20260105090000\_init\.sql\:27 | public\.notes | reproduced against the throwaway database\: anon\-read |
| PROVEN by our test | No policy on tickets ties user\_id to the caller | supabase\-tenant\-unscoped | high | supabase/migrations/20260105090000\_init\.sql\:36 | public\.tickets | reproduced against the throwaway database\: cross\-delete, cross\-insert, cross\-read, cross\-update, reassign\-owner |
| could not be reproduced | Policy "Owners can edit documents" lets authenticated update every row of documents | supabase\-policy\-permissive | high | supabase/migrations/20260105090000\_init\.sql\:62 | public\.documents | the database denied every attack this finding describes \(cross\-update, reassign\-owner\); likely a false positive or covered by grants/roles; other attacks on this table were proven\: cross\-insert |

0 static findings out of scope (not about row level security, not tested here).

## What was not checked

- Authorization written in application code\: route handlers, server actions, edge functions and anything else that runs before the database\.
- Frontend code, and anything the browser does with the data it receives\.
- Exposure of secrets\: keys, tokens, \.env files and service\-role keys that ship to the client\.
- Supabase features outside Postgres row level security\: storage buckets and their policies, realtime, GraphQL, auth settings\.
- Policies that depend on data this tool does not create\: custom JWT claims other than sub, role, tenant\_id and org\_id, extensions other than uuid\-ossp and pgcrypto\.
- Materialized views, functions callable as RPC, column\-level privileges, and tables that the migrations do not create\.
- A CLEAN result means the listed attacks were refused for two synthetic users and an anonymous caller\. It is not a penetration test and does not show the table is safe\.

## Inputs

| File | Bytes | sha256 |
|---|---|---|
| examples/vulnerable\-app/supabase/migrations/20260105090000\_init\.sql | 4606 | 85a898596387da1659e7ab24d7b4ee6db383d4ade14b901b0a68cd0dfcc96775 |
| examples/vulnerable\-app/supabase/migrations/20260106120000\_profile\_trigger\.sql | 452 | d5c23be51364246d03603388dbfc8346b219321e33f23b12132d81160a73b7ef |
