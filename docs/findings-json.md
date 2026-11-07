# findings.json: the same results in a shared format

`proof-audit rls ... --out <dir>` writes `findings.json` next to the other files. It holds the results of the run as an array of records in the `findings.json` shape that Cloudflare publishes for its open source [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT licence), so that tools which read that shape can read this tool's results. This project is not affiliated with or endorsed by Cloudflare; the record types and the conformance check in `src/domain/interchange` were written here from the published description of the format, and no code, schema file or text of that project is copied or vendored. The format is only a way to write the results down: nothing in the tool depends on it, and `proof-audit verify` never reads it.

## Derived output, not evidence

`findings.json` is **derived** from the same run as `report.json`, `proofs.jsonl` and `fix.sql`, and from the migrations. It is not covered by the staleness and hash protections of `proofs.jsonl`:

- `proof-audit verify` takes one `proofs.jsonl` and never opens `findings.json` (a test replays with a tampered copy next to it, and a test fails if `verify` reads it). Edit it, delete it or replace it and the verdict of `verify` is the same.
- The records point back at the evidence: each probe that backs a record is named in its `evidence` with the probe id and the content hash recorded in `proofs.jsonl` (`sha256:<hash>`), so a reader can check any claim against `proofs.jsonl` and replay it with `verify`. That is a pointer, not a protection: nothing re-computes the file.
- To refresh it, run the tool again. The same migrations give the same bytes.

Treat a `findings.json` you did not produce yourself like any other unsigned file.

## Which results become which records

One record per **table (or view) and root cause**, never one per probe. Records are sorted by fingerprint, as the format requires.

| Result of the run | Record | What it says |
| --- | --- | --- |
| A table or view with a **PROVEN** probe | `confirmed`, one per root cause (see below) | The recorded SQL ran against a real database as `anon` or as a signed-in user and let the attack through. |
| **SUSPECTED**: a static pattern that looks risky and no probe could confirm it | `needs_validation`, one per suspicious root cause | `blockers` name why no probe could confirm it (seeding failed, the run budget ran out, ...). No severity. |
| **INCONCLUSIVE**: probes could not be run and nothing suspicious was found statically | `needs_validation` with the fingerprint kind `untested` | No root cause is claimed; the access control is unverified. |
| **CLEAN**: the database refused every attack | no record | A clean result is not a finding. |
| `INTEGRITY_VIOLATION`: the migrations touched the test environment | `needs_validation`, kind `untested`, for every table | `blockers` list the statements that touched it. Nothing is `confirmed` and nothing is `rejected` in such a run: a refusal by a tampered database does not refute a static finding, so the correlation with the static report is `INCONCLUSIVE` and stderr says that the static findings have no record. |
| `--from-audit`: a static finding of `saas-audit` that the database **refused** (`NOT_REPRODUCED`) | `rejected` | `reason` is the recorded refusal; the fingerprint is the one the static auditor gives the same finding. |
| `--from-audit`: a static finding that was proven, inconclusive or could not be matched to a table | no record | The static auditor's own export carries it. |

A table with a PROVEN probe gets `confirmed` records for the proven probes only. Its other probes that gave no clear answer (an error, a probe that could not run) and its suspicious causes that no probe proved get **no** `needs_validation` record, because the table is already reported as open; the confidence reason of each `confirmed` record of the table names them (up to five, with their count) and `proofs.jsonl` has every probe. A table with several root causes gets several records, with different fingerprints. A candidate that a later run proves keeps its fingerprint, because the fingerprint does not contain the verdict.

### Root causes

A proven probe is attributed to the first cause below that explains it, so each probe is in exactly one record:

| Order | Root cause (fingerprint kind) | Explains |
| --- | --- | --- |
| 1 | `rls-disabled` | Every probe: the table has no row level security and the client roles hold privileges. |
| 2 | `policy-always-true/<policy>` | Probes of the commands and roles the policy reaches, when its condition is always true. |
| 3 | `policy-owner-unchecked/<policy>` | Insert and update probes of the roles the policy reaches, when the policy does not tie the owner column to the caller. |
| 4 | `owner-not-compared` | The signed-in-user probes (read, insert, update, delete, reassign, null owner) when no policy compares the owner column with the caller. |
| 5 | `view-bypasses-rls` | The view probes, when the view runs with its owner's rights over a table with row level security. |
| last | `unattributed` | Probes no static cause explains (grants, rules, triggers, SQL the reader could not read). |

The causes are the ones `report.json` lists for the table; they come from the schema the database reports, not from the text of the migrations.

## Field by field

| Field | `confirmed` | `needs_validation` | `rejected` |
| --- | --- | --- | --- |
| `fingerprint` | `proof-audit/rls/<schema>.<name>/<kind>[/<policy>]` | same | `saas-audit/<rule>:<file>:<table>[:<policy>]` |
| `title`, `description` | what the attacker can do, how many of the attacks run on the table got through | the report's sentence; the title ends with "(not proven)" | the static finding's title and message |
| `root_cause` / `claimed_root_cause` | the static cause, in words | the suspicious cause, or "no root cause is claimed" | what the static auditor claimed |
| `trace` | entrypoint, propagation, sink in the migration SQL (below) | same | the flagged policy or table, then the table |
| `evidence` | the statement behind the cause, plus one line per proven probe with its id and `proofs.jsonl` hash | the statement behind the cause | the statement, the position the static auditor flagged, and the refused probes with their hashes |
| `conditions` | role and JWT claims of each actor, and the seeded rows that are attacked | | |
| `execution.payloads` | the exact SQL of every proven probe, as recorded | | |
| `execution.observed_result` | what the database answered for each probe (row count or SQLSTATE and message, truncated to 300 characters) and the verdict `PROVEN_VULNERABLE` | | |
| `remediation` | the strategy for the root cause, the fix status of the table, and the table's section of `fix.sql` as `code_changes` (`file_name` is `fix.sql`, the file written next to `findings.json`: a new migration to review, not a file in your repository) | | |
| `severity` | the anchor table below | none (the format forbids it) | none |
| `confidence` | `high` only when the before/after verification passed for the table, otherwise `medium` | | |
| `blockers`, `validation_plan` | | why no probe could confirm it, and a local plan | |
| `reason` | | | the recorded refusal, with the caveat that two synthetic users and an anonymous caller were tried |

### Positions

Every item of `trace` and `evidence` is a `file` and a `line` of the migration SQL that were taken from the SQL reader, which records where it saw each `CREATE TABLE`, `ALTER TABLE ... ROW LEVEL SECURITY`, `CREATE POLICY` / `ALTER POLICY` and `CREATE VIEW` (the line of the first token of the statement, renames and drops followed). The trace of a policy cause is: the policy statement (entrypoint), the statement that switched row level security on (propagation, when there is one) and the `CREATE TABLE` (sink). If the reader never saw an object declared (it was created by a statement the reader cannot read), the line is the first statement that names it as an identifier, which need not be a declaration (it can be a `GRANT`, a `COMMENT` or a `DROP`): the `description` of every trace step that rests on such a line, and of the first evidence item, then ends with "The reader did not see this declared ..., so the line is the first statement that names it", whatever else it says about a `CREATE`. The statements are tokenised once and looked up by identifier, so the cost does not grow with the number of such objects times the size of the input; if there is none, the table or view has **no record** and the run says so on stderr. A line is never made up.

`file` is the input path as the tool displays it: relative to the directory you ran it from. The format only allows safe repository-relative paths (no absolute path, no `..`, no `:`, no backslash, no control characters). If an input path is not one, `findings.json` is **not written** and stderr says so; run `proof-audit` from the project root. The other output files are written either way. **An earlier `findings.json` in the same `--out` is removed** in that case, and stderr says `removed findings.json of an earlier run`, so a file that does not describe this run is never left next to it; if the file cannot be removed (it is a directory, or not removable) the run fails with exit code 2 and says why.

### Severity anchors

The severity of a `confirmed` record is a function of what was proven for the record, whether the table has an owner column (a view counts as having one) and nothing else. It is the same function that gives the severity of a table in `report.json` (`severityAnchor` in `src/domain/analysis/findings.ts`; tests compare both with a separately written copy of this table for every combination of attacks), applied to the probes of the **record**. A table with several root causes has several records and each is rated by its own probes, so a record can be rated lower than the table in `report.json` (a table with an anonymous read, `critical`, and a cross-user update that belongs to another root cause: the record of the update is `high`).

| Proven attacks in the record | Owner column | Impact = overall severity |
| --- | --- | --- |
| any anonymous write (`anon-insert`, `anon-update`, `anon-delete`) | any | `critical` |
| an anonymous read (`anon-read`, `view-read-anon`) and no anonymous write | yes, or a view | `critical` |
| an anonymous read and no anonymous write | no | `medium` |
| a signed-in user reads or changes another user's rows or hands a row over (`cross-read`, `cross-insert`, `cross-update`, `cross-delete`, `reassign-owner`, `view-read-cross`) and nothing above | any | `high` |
| anything narrower (for example `null-owner-insert` alone) | any | `medium` |

Likelihood is `high` when any attack in the record needs only the public anon key, `medium` when every attack needs a signed-in account. It is reported for context and does **not** lower the overall severity, because the tool cannot tell whether sign-up is open. The overall severity is never above the impact, as the format requires. Nothing is decided per case.

### Fingerprints

A fingerprint is built from names, never from line numbers, counts or times, so a cosmetic edit that moves lines does not change it and the same input gives the same fingerprints (tests move every statement and compare). Each name is one segment: letters, digits, `.`, `_` and `-` stay and every other UTF-8 byte becomes `+` and two lowercase hex digits (`Anyone can use tickets` is `Anyone+20can+20use+20tickets`), so the result always matches the format's pattern. In `<schema>.<name>` a dot inside a name is escaped as well.

- `proof-audit/rls/public.tickets/policy-always-true/Anyone+20can+20use+20tickets`
- `proof-audit/rls/public.profiles/rls-disabled`
- `saas-audit/supabase-policy-permissive:supabase/migrations/20260105090000_init.sql:public.documents:Owners+20can+20edit+20documents` (a report with a `subject` array)
- `saas-audit/supabase-policy-permissive:supabase/migrations/20260105090000_init.sql:Policy+20+22Owners+20can+20edit+20documents+22+20lets+20authenticated+20update+20every+20row+20of+20documents` (a report without one: the whole title)

The `saas-audit/...` scheme is the one the static auditor `saas-audit` uses for its own record of the same finding, built from the `rule`, `file` and the table and policy of its JSON report (the `subject` array when the report carries one, else its title), so the same finding has the same identity before and after this tool's database has judged it. This holds for the reports that `saas-audit` writes: the names are the entries of `subject` when the report has them and the whole title when it does not, joined with `:` exactly as `saas-audit` does (a report written without `subject`, such as the committed `examples/vulnerable-app/saas-audit.json`, gives a title-based fingerprint, and the integration test checks the fingerprint built from it). When several findings of one report share a fingerprint they are numbered in the order of their lines, the first without a suffix and the next `@2`, `@3` appended to the fingerprint, as `saas-audit` numbers them; this tool counts over every finding of the report, not only over the refused ones.

## What is in the file, and what is not redacted

Nothing is redacted or escaped; the file carries what the tool knows, as found, exactly like `report.json`:

- File paths of your migrations, as displayed.
- With `--from-audit`, text of the static report you gave: the title of each refused static finding, the first 500 characters of its message, the name and version of the tool that wrote it, and the path of the file that it flagged. It is third-party text and is kept as found, like the migrations.
- SQL: the exact statements of the proven probes (they use synthetic values and synthetic users `alice@example.test` and `bob@example.test`), the proposed fix, and policy and table names from your migrations.
- The JWT claims used by the probes (synthetic) and, for errors, the database's SQLSTATE and message truncated to 300 characters.
- Text from your repository (identifiers, policy names) is **not** made safe for a terminal or for Markdown, and may contain control characters, bidi marks or markup. The tool prints its own notes about this file through the terminal sanitizer, but a program that renders `findings.json` must sanitize it for its own sink, as it must for `report.json`.
- Added by the tool: no secrets. It never reads `.env` files, keys or production data, so only what your migrations themselves put into table, policy and file names can appear.

## Limits

- The format allows at most 1000 records and 5 MiB; a run that would exceed them writes no `findings.json` and says so. `findings.json` is checked against a conformance check written for this project (`src/domain/interchange/conformance.ts`) **before** it is written: a file that does not conform is not written (and one from an earlier run in the same `--out` is removed). On two points the check is as strict as the published validator, and the tests have a row for each: Windows device names in a path (`con`, `prn`, `aux`, `nul`, `clock$`, `conin$`, `conout$`, `com1`-`com9`, `lpt1`-`lpt9` and the superscript digits `¹²³`, matched case-insensitively by Unicode rules) and the size of the canonical text of each item of a list that must be unique (1 MiB per item, 5 MiB per list).
- Only row level security is judged, for two synthetic users and an anonymous caller; `findings.json` says nothing about what the tool did not check (see "What was not checked" in the report).
- A `rejected` record means the database refused the attacks the static finding describes. It does not show that the table is safe.
