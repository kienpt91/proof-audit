# 0001. Prove access-control problems instead of only reporting them

Status: accepted

## Context

Static scanners report patterns. For row level security the pattern is often not the problem: a policy that looks permissive may be neutralised by grants or by another policy, and a policy that looks fine may let a row through because of the column it compares. Founders get a list nobody can trust, and nobody shows that a fix works.

## Decision

A finding is only called **PROVEN** when a probe against a real PostgreSQL, run as the attacker role with the attacker's JWT claims, reproduced the access. Everything else is labelled: **SUSPECTED** (a static pattern, not reproduced, low confidence), **CLEAN** (every attack was refused) or **INCONCLUSIVE** (some probes could not run). Every probe is written down as a proof with the exact SQL, the observation, a verdict and a content hash. When a static pattern exists but the database refuses every attack, the result is CLEAN: the probes win over the pattern.

Fixes follow the same rule. A fix is verified by re-running the same probes on a fresh copy of the sandbox, and the word "verified" is only produced by the verification step (see [0006](0006-fix-verification-rules.md)).

## Consequences

- Reports contain fewer, more trustworthy findings, and each one says how to replay it.
- The tool can say "clean" only for the attacks it tried. Every report lists what was not checked.
- Seeding quality bounds what can be proven. A table that cannot be seeded yields INCONCLUSIVE, never a guess.
