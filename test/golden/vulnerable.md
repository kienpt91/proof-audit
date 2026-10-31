# Row level security report

| Item | Value |
|---|---|
| Tool | proof\-audit 0\.1\.0 |
| Checked | 7 tables or views |
| Input files read | 2 |
| Database used | a throwaway PostgreSQL database (version 16\.3, docker image postgres\:16\.3\@sha256\:0123456789abcdef) |
| Run complete | yes |
| Tests run | 8 (4 showed a real problem) |
| PROVEN | 3 |
| SUSPECTED | 1 |
| INCONCLUSIVE | 1 |
| CLEAN | 2 |

## Result

**3 PROVEN, 1 SUSPECTED, 1 INCONCLUSIVE, 2 CLEAN**

3 of 7 checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves. 2 more need a look: SUSPECTED and INCONCLUSIVE items are NOT proven and carry low confidence.

## What we found

### 1. PROVEN · critical · `public.notes`

**Notes are open to everyone**

**An attacker could:** Anyone with the public key can read, add and change every note\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- Row level security is switched off on public\.notes, so the public key can read and write every row\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
select * from public.notes
```

Result: the database returned 3 rows (3 rows seeded for this test). Access was ALLOWED. That is the problem. The anonymous role read seeded rows\.

Evidence: `sha256 ab9e3fad3ba4`

**Check 2.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
insert into public.notes (id, user_id, body)
values (gen_random_uuid(), '00000000-0000-4000-8000-00000000000a', 'x')
```

Result: the database accepted it and changed 1 row. Access was ALLOWED. That is the problem. The anonymous role inserted a row\.

Evidence: `sha256 621b56d24dd8`

#### Attempts the database blocked

- Signed\-in user deletes another user's rows: the database ran it but changed 0 rows (2 rows seeded for this test)

### 2. PROVEN · high · `public.profiles`

**Any signed\-in user can read all profiles**

**An attacker could:** Any signed\-in user can read the profiles of every other user\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- The policy "profiles\_read" allows every row\.
- No policy compares user\_id with the signed\-in user\.

#### How we proved it

**Check 1.** We acted as a signed-in user trying to reach someone else's data and ran:

```sql
select * from public.profiles
```

Result: the database returned 4 rows (2 rows seeded for this test). Access was ALLOWED. That is the problem. The signed\-in user read rows owned by someone else\.

Evidence: `sha256 d5200c7a09d8`

#### Attempts the database blocked

- Anonymous visitor reads rows: the database refused it (error 42501: permission denied for table profiles)

### 3. PROVEN · medium · `public.v_user_emails`

**A view exposes e\-mail addresses**

**An attacker could:** Anyone with the public key can read e\-mail addresses through the view\.

Kind: view. PROVEN: reproduced against a real database.

#### Why

- The view runs with its owner's rights, so row level security does not apply\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
select * from public.v_user_emails
```

Result: the database returned 2 rows. Access was ALLOWED. That is the problem. The anonymous role read rows through the view\.

Evidence: `sha256 34c9cb19c4fc`

### 4. SUSPECTED · medium · `public.messages`

**Messages may be readable by other users**

> **NOT proven.** Reading the SQL suggests a problem, but the database did not confirm it. Treat this as a lead to check, not as a fact.

**An attacker could:** A signed\-in user might read messages sent to someone else\.

Kind: table. SUSPECTED: NOT proven, low confidence.

#### Why

- The policy "msg\_read" checks only that the user is signed in\.

### 5. INCONCLUSIVE · low · `public.audit_log`

**The audit log could not be tested**

> **NOT proven.** The test could not be completed, so we cannot say whether this is a problem. Treat this as unknown, not as safe.

**An attacker could:** Unknown\: the test could not run\.

Kind: table. INCONCLUSIVE: NOT proven, the test gave no clear answer.

#### Could not be tested (no clear answer)

- Anonymous visitor reads rows: the table could not be seeded

## Looked fine

- `public.orders`: Row level security on, owner checked
- `public.settings`: Row level security on, no public access

## How to fix

- `public.notes`: Fix VERIFIED: Switch on row level security and let users touch only their own notes\.
- `public.profiles`: The proposed fix does NOT close the hole yet. The proposed policy still lets every signed\-in user read every profile\.
- `public.v_user_emails`: A fix needs a decision from you (see below). Decide whether the view should run with the rights of the caller\.
- `public.messages`: A fix needs a decision from you (see below). Decide who may read a message\: sender, receiver or both\.
- `public.audit_log`: No fix was proposed automatically. Fix the seeding problem and run again\.

### Proposed SQL (starting point, review before use)

```sql
-- public.notes: only the owner may touch a note
alter table public.notes enable row level security;
create policy "notes_owner" on public.notes
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
```

### These need a decision only you can make

- `public.messages`: Only you know whether receivers may read messages\.
- `public.v_user_emails`: Changing the view may break pages that rely on it\.

## Fix check

**PARTIAL**: only some tables are fixed and confirmed. See the table below. The rest still need work.

| Table | Result | Closed | Still works | Normal use broken | No clear answer | Because |
|---|---|---|---|---|---|---|
| public\.notes | VERIFIED (attacks closed, normal use works) | Anonymous visitor reads rows; Anonymous visitor inserts a row | none | none | none | Both attacks fail and the owner can still read their rows\. |
| public\.profiles | STILL VULNERABLE | none | Signed\-in user reads another user's rows | none | none | The proposed policy does not compare the owner column\. |
| public\.v\_user\_emails | NO FIX PROPOSED | none | none | none | none | No fix was proposed for this view\. |

## Static auditor cross-check

Findings from static\-auditor 2\.1\.0 (project acme\-app), checked against our tests:

| Result | Finding | Rule | Severity | Location | Table | Note |
|---|---|---|---|---|---|---|
| PROVEN by our test | Table without row level security | rls\-disabled | high | supabase/migrations/001\_init\.sql\:12 | public\.notes | Reproduced\: anonymous read returned 3 rows\. |
| could not be reproduced | Policy that allows everything | policy\-true | medium | supabase/migrations/002\_profiles\.sql\:4 | public\.orders | The database denied every attack on this table\. |
| static finding only, not tested | Possible gap in a dynamic policy | rls\-unknown | low | supabase/migrations/002\_profiles\.sql\:30 | none |  |

2 static findings out of scope (not about row level security, not tested here).

- one finding had no table name

## Migration statements the database rejected

2 in total. Anything after them may not have been tested as written.

- `supabase/migrations/002_profiles.sql:18` 0A000 extension "pg\_cron" is not available: `create extension pg_cron`
- `supabase/migrations/002_profiles.sql:22` 3F000 schema "cron" does not exist: `select cron.schedule('nightly', '0 3 * * *', 'select 1')`

## Test data problems

- `public.audit_log`: failed (column details has no default and is not null)

## Warnings

- 2 statements were skipped because they are not about row level security
- storage\.objects policies were not read

## What was not checked

- Storage bucket policies
- Edge functions and webhooks
- Anything outside the SQL you gave us

## Inputs

| File | Bytes | sha256 |
|---|---|---|
| supabase/migrations/001\_init\.sql | 1204 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |
| supabase/migrations/002\_profiles\.sql | 388 | bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb |
