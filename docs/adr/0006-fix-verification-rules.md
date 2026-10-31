# 0006. When a fix may be called verified

Status: accepted

## Decision

The same probes run on a fresh copy of the sandbox (`CREATE DATABASE ... TEMPLATE`) after the fix statements are applied. Per proven table or view:

- every probe that was `PROVEN_VULNERABLE` must now be `NOT_REPRODUCED`, else `STILL_VULNERABLE`;
- every legitimate probe that was `ACCESS_OK` before must still be `ACCESS_OK`, else `BREAKS_ACCESS`;
- an unclear probe (`INCONCLUSIVE`, missing) makes the subject `UNVERIFIED`;
- with no legitimate probe that worked before, breaking normal use cannot be ruled out, so the subject is `UNVERIFIED`;
- a subject the fix does not cover is `NO_FIX`.

Overall: `VERIFIED` only when every proven subject is verified and no fix statement failed; `FIX_FAILED` when a statement was rejected; `BREAKS_ACCESS` when any subject breaks access; `PARTIAL` when only some verify; otherwise `NOT_VERIFIED`. `NOT_APPLICABLE` when nothing was proven. Reports use the word "verified" only for `VERIFIED` statuses; this is tested with a fix that closes the hole and locks everyone out.

Policies are written for the *primary owner column* only. A policy that compares another user-like column with `auth.uid()` (for example `customer_id` next to `owner_id`) is not a correct owner rule, which is the "wrong column" mistake in the example app.

## Consequences

The tool will say "partial" or "needs a decision" before it says "verified" without evidence. `proof-audit verify --against <migrations>` applies the same rule to the user's own, hand-fixed migrations.
