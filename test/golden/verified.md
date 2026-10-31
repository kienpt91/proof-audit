# Row level security report

| Item | Value |
|---|---|
| Tool | proof\-audit 0\.1\.0 |
| Checked | 1 table or view |
| Input files read | 1 |
| Database used | a throwaway PostgreSQL database (version 16\.3, docker image postgres\:16\.3\@sha256\:0123456789abcdef) |
| Run complete | yes |
| Tests run | 2 (1 showed a real problem) |
| PROVEN | 1 |
| SUSPECTED | 0 |
| INCONCLUSIVE | 0 |
| CLEAN | 0 |

## Result

**1 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 0 CLEAN**

1 of 1 checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves.

## What we found

### 1. PROVEN · high · `public.todos`

**Todos are open to everyone**

**An attacker could:** Anyone with the public key can read every todo\.

Kind: table. PROVEN: reproduced against a real database.

#### Why

- Row level security is switched off on public\.todos\.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

```sql
select * from public.todos
```

Result: the database returned 5 rows (5 rows seeded for this test). Access was ALLOWED. That is the problem. The anonymous role read seeded rows\.

Evidence: `sha256 afa7badaf6a4`

## Looked fine

None.

## How to fix

- `public.todos`: Fix VERIFIED: Switch on row level security and restrict todos to their owner\.

### Proposed SQL (starting point, review before use)

```sql
alter table public.todos enable row level security;
create policy todos_owner on public.todos for all to authenticated using ((select auth.uid()) = user_id);
```

## Fix check

**VERIFIED**: every attack that worked before now fails, and a normal signed-in user can still read and write their own rows.

| Table | Result | Closed | Still works | Normal use broken | No clear answer | Because |
|---|---|---|---|---|---|---|
| public\.todos | VERIFIED (attacks closed, normal use works) | Anonymous visitor reads rows | none | none | none | The attack fails and the owner can still read their rows\. |

## What was not checked

- Storage bucket policies
- Edge functions and webhooks
- Anything outside the SQL you gave us

## Inputs

| File | Bytes | sha256 |
|---|---|---|
| supabase/migrations/001\_init\.sql | 1204 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |
