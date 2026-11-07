# Changelog

## Unreleased

### Added

- `proof-audit rls ... --out <dir>` also writes `findings.json`: the results of the run as records in the findings.json shape that Cloudflare publishes for its open source security-audit-skill (this project is not affiliated with it). PROVEN probes become `confirmed` records, one per table and root cause, with the recorded SQL, claims and answers, a severity from a fixed anchor table, the table's section of the proposed fix, and `high` confidence only when the before/after check passed; SUSPECTED and INCONCLUSIVE tables become `needs_validation` with blockers; with `--from-audit`, a static finding that the database refused becomes `rejected`. Every record points at real lines of the migrations; fingerprints are built from names, not lines. See [docs/findings-json.md](docs/findings-json.md) and [ADR 0012](docs/adr/0012-findings-json-export.md).
- The SQL reader records where each table, row level security switch, policy and view was declared (`ParseResult.sources`).
- `AnalysisReport.model`: the schema the findings were judged on (not part of `report.json`).
- `examples/vulnerable-app/sample-output/findings.json`.

### Notes

- A run with an `INTEGRITY_VIOLATION` never exports a `rejected` record (the correlation with the static report is `INCONCLUSIVE` for every table, and the note of each static finding in the reports says why).
- When `findings.json` is not written, a `findings.json` left in `--out` by an earlier run is removed and stderr says so.
- The conformance check is as strict as the reference validator on Windows device names (`com`/`lpt` with the digits 1-9 and `¹²³`, case folding by Unicode) and on the size of the canonical key of list items that must be unique.
- A position that is the first statement naming the object (not its declaration) is said so in the trace and the evidence.
- Fingerprints of `rejected` records follow `saas-audit`: names from `subject`, else the whole title; repeated ones are numbered `@2` in line order.
- The confidence reason of a `confirmed` record lists the other probes of its table that gave no clear answer.
- Locating objects the reader never saw declared tokenises the migrations once, not once per object.
- `findings.json` is derived output. `proof-audit verify` does not read it, and the hashes of `proofs.jsonl` do not cover it. It is not written when an input path is not a safe repository-relative path or when it would not conform to the format.
- Nothing in `findings.json` is redacted or escaped; see [SECURITY.md](SECURITY.md).
