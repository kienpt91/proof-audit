# 0005. How probes are run and judged

Status: accepted

## Decision

- **Seeding** reads the *catalog* after the migrations ran (so `ALTER TABLE`, DO blocks and triggers are accounted for), orders tables by foreign keys, and, as the migrator, inserts one row per synthetic user with `ON CONFLICT DO NOTHING` (then as a plain insert, for tables whose rules refuse that clause) (rows created by triggers on `auth.users` are counted, not duplicated). Values come from the column type, its name, `CHECK` constraints (enumerated strings, numeric bounds, minimum length), enum labels and foreign keys. Each row has a `full` and a `minimal` attempt; if both fail, the table is recorded as not seeded with the database's error, and dependent probes are INCONCLUSIVE.
- **Probes** are anonymous `DO` blocks run by the prober ([0011](0011-trust-domains-for-the-verdicts.md)): set `request.jwt.claims`, `SET LOCAL ROLE`, execute, read `ROW_COUNT`, then raise an internal exception so the sub-transaction rolls back whatever happened. A reply that is missing or unreadable (for example because a trigger raised the block's own error code) is `not-run`, never a verdict. The recorded SQL is exactly the statement that ran.
- **Verdicts** are conservative. A statement that returns or changes rows when it should not is PROVEN. `42501` (privilege or RLS violation) is NOT_REPRODUCED. Zero rows when rows existed is NOT_REPRODUCED. Anything else is INCONCLUSIVE with the SQLSTATE. One deliberate exception: an integrity error (class 23) on an *insert* exploit probe is PROVEN, because PostgreSQL checks row level security policies before table constraints (confirmed against the pinned image by an integration test: a denied insert with a `NOT NULL` violation reports `42501`, an admitted one reports `23502`); the reason says only a constraint stopped it.
- **Views** are probed only when they sit on a table with row level security. A view that exposes no owner column cannot be probed for cross-user reads and says so.
- A table with no owner column gets anonymous probes only; its fix is a human decision (`needs-decision`), never invented.

## Consequences

Probes are deterministic given the same inputs and image. They cannot leave state behind, and a hostile migration cannot make them lie except by breaking the harness, which fails the run loudly.
