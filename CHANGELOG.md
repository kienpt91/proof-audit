# Changelog

## Unreleased

### Added

- `proof-audit rls ... --out <dir>` also writes `findings.json`: the results of the run as records in the findings.json shape that Cloudflare publishes for its open source security-audit-skill (this project is not affiliated with it). PROVEN probes become `confirmed` records, one per table and root cause, with the recorded SQL, claims and answers, a severity from a fixed anchor table, the table's section of the proposed fix, and `high` confidence only when the before/after check passed; SUSPECTED and INCONCLUSIVE tables become `needs_validation` with blockers; with `--from-audit`, a static finding that the database refused becomes `rejected`. Every record points at real lines of the migrations; fingerprints are built from names, not lines. See [docs/findings-json.md](docs/findings-json.md) and [ADR 0012](docs/adr/0012-findings-json-export.md).
- The SQL reader records where each table, row level security switch, policy and view was declared (`ParseResult.sources`).
- `AnalysisReport.model`: the schema the findings were judged on (not part of `report.json`).
- `examples/vulnerable-app/sample-output/findings.json`.

### Notes

- `findings.json` is derived output. `proof-audit verify` does not read it, and the hashes of `proofs.jsonl` do not cover it. It is not written when an input path is not a safe repository-relative path or when it would not conform to the format.
- Nothing in `findings.json` is redacted or escaped; see [SECURITY.md](SECURITY.md).
