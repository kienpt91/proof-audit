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
| INCONCLUSIVE | 0 |
| CLEAN | 3 |

## Result

**0 PROVEN, 0 SUSPECTED, 0 INCONCLUSIVE, 3 CLEAN**

No problem could be reproduced.

## What we found

Nothing to report: no table or view showed a problem.

## Looked fine

- `public.notes`: Row level security on, owner checked
- `public.orders`: Row level security on, owner checked
- `public.profiles`: Row level security on, owner checked

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
