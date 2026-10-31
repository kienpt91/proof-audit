# Row level security report

| Item | Value |
|---|---|
| Tool | proof\-audit 0\.1\.0 |
| Checked | 3 tables or views |
| Input files read | 1 |
| Database used | a throwaway PostgreSQL database (version 16\.3, docker image postgres\:16\.3\@sha256\:0123456789abcdef) |
| Run complete | yes |
| Tests run | 6 (0 showed a real problem) |
| PROVEN | 0 |
| SUSPECTED | 0 |
| INCONCLUSIVE | 3 |
| CLEAN | 0 |

## Result

**0 PROVEN, 0 SUSPECTED, 3 INCONCLUSIVE, 0 CLEAN**

No problem was proven. 3 more need a look: SUSPECTED and INCONCLUSIVE items are NOT proven and carry low confidence.

## INTEGRITY\_VIOLATION\: do not trust these results

The migrations touched, or tried to touch, the test environment that every verdict depends on \(the platform functions and roles, the settings that decide how queries are resolved, the tool's own objects\)\. Nothing can be concluded from this run\: every table and view is reported as could not be judged, and no fix is proposed\.

- CREATE FUNCTION auth\.uid (redefines-platform-object; the database refused it) at `supabase/migrations/001_init.sql:4`
- CREATE EVENT TRIGGER (event-trigger; the database refused it) at `supabase/migrations/002_more.sql:12`
- function auth\.uid\(\) changed \(after the probes\) (platform-changed; the environment changed)

## What we found

### 1. INCONCLUSIVE · info · `public.notes`

**Table public\.notes could not be judged\: the test environment was touched**

> **NOT proven.** The test could not be completed, so we cannot say whether this is a problem. Treat this as unknown, not as safe.

**An attacker could:** Nothing can be concluded about public\.notes\: the migrations touched the test environment the results depend on\.

Kind: table. INCONCLUSIVE: NOT proven, the test gave no clear answer.

#### Could not be tested (no clear answer)

- rls\:public\.notes: the migrations touched the test environment the results depend on \(see the integrity section\)

### 2. INCONCLUSIVE · info · `public.orders`

**Table public\.orders could not be judged\: the test environment was touched**

> **NOT proven.** The test could not be completed, so we cannot say whether this is a problem. Treat this as unknown, not as safe.

**An attacker could:** Nothing can be concluded about public\.orders\: the migrations touched the test environment the results depend on\.

Kind: table. INCONCLUSIVE: NOT proven, the test gave no clear answer.

#### Could not be tested (no clear answer)

- rls\:public\.orders: the migrations touched the test environment the results depend on \(see the integrity section\)

### 3. INCONCLUSIVE · info · `public.profiles`

**Table public\.profiles could not be judged\: the test environment was touched**

> **NOT proven.** The test could not be completed, so we cannot say whether this is a problem. Treat this as unknown, not as safe.

**An attacker could:** Nothing can be concluded about public\.profiles\: the migrations touched the test environment the results depend on\.

Kind: table. INCONCLUSIVE: NOT proven, the test gave no clear answer.

#### Could not be tested (no clear answer)

- rls\:public\.profiles: the migrations touched the test environment the results depend on \(see the integrity section\)

## Looked fine

None.

## How to fix

Nothing to fix.

## Fix check

No fix check was run, so no fix is confirmed.

## What was not checked

- Storage bucket policies
- Edge functions and webhooks
- Anything outside the SQL you gave us

## Inputs

| File | Bytes | sha256 |
|---|---|---|
| supabase/migrations/001\_init\.sql | 1204 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |
