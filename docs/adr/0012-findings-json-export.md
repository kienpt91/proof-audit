# 0012. findings.json: a derived export in a shared shape

Status: accepted

## Context

Other tools read audit results in the `findings.json` shape that Cloudflare publishes for its open source security-audit-skill (an array of records with the verdicts `confirmed`, `needs_validation` and `rejected`). Writing our results in that shape lets them travel, but our own evidence (`proofs.jsonl`, the contract, `verify`) must not depend on a format we do not control, and the mapping must not make a result look stronger than it is.

## Decision

- `rls --out <dir>` also writes `findings.json`. It is **derived** output: built from the analysis report and the migrations, never read by `verify`, not covered by the hashes of `proofs.jsonl`. The records cite the probes that back them by id and content hash, so a claim can be checked against `proofs.jsonl`.
- Original code only. `src/domain/interchange` has typed record shapes, a fingerprint scheme, the severity anchors, the root-cause attribution, the source locator and a small conformance check written from the published description of the format; nothing of the other project is vendored, and the tests do not use the network. The check runs on the exact text before it is written, and a file that does not conform is not written.
- Honest verdicts. `confirmed` only for a probe that a real database let through (recorded SQL, claims, row count or error, hash). SUSPECTED and INCONCLUSIVE become `needs_validation` with blockers; a static finding that the database refused (`--from-audit`) becomes `rejected`; CLEAN becomes nothing. Confidence is `high` only when the before/after verification passed for the table.
- One record per table and root cause. Each proven probe is attributed to the first cause that explains it (row level security off, an always-true policy, a policy that does not tie the owner, no owner comparison, a view that bypasses row level security, else unattributed), so a table with one mistake is one record and not one per probe.
- Severity is a fixed anchor table, the same function that gives the severity in `report.json`, so the two files agree and nothing is decided per case.
- Fingerprints are built from names (kind, schema-qualified table, policy; for static findings rule, file, table, policy), percent-style encoded to the format's pattern, never from lines or counts. The static scheme is shared with the static auditor so a finding keeps its identity across validation states.
- A record without a real position in the migration SQL is not written. Positions come from the SQL reader (`SourceIndex`), with a fallback to the first statement that names the object; if there is none, the object has no record and the run says so.
- The analysis report carries the schema model it judged (`AnalysisReport.model`) so the export can name policies; it is not part of `report.json`.

## Consequences

- Input paths must be safe repository-relative paths for the file to be written; otherwise it is skipped with a message (run from the project root).
- When the file is not written, an earlier `findings.json` in the same `--out` is removed and stderr says so.
- A run with an `INTEGRITY_VIOLATION` exports no `rejected` record.
- The export inherits the limits of the tool: row level security only, two synthetic users and an anonymous caller. `rejected` means "the attacks that were run were refused".
- The format's limits (1000 records, 5 MiB) are enforced by not writing a file that exceeds them.
