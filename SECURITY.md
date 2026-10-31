# Security

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository, or email kienphan.dev@gmail.com. Do not open a public issue for a vulnerability. This is a personal open-source project maintained on a best-effort basis: there is no service level and no bounty.

## What the tool is, and the safety boundary

`proof-audit` is defensive tooling. It reproduces access-control problems in **Postgres row level security** against a database it creates for the run, and nothing else. The boundary, enforced in code and tested:

- It connects only to (a) a container it starts itself, with no network at all, or (b) a PostgreSQL server on this machine's loopback interface that you pass with `--database-url`. Any other host is refused in the domain layer (`parseLoopbackUrl`), again in the adapter (`assertLoopbackHost`), and the URL grammar is strict: no `host=`/`hostaddr=`/`service=` options, no extra `@`, no DNS names, no short or octal IPv4 forms. Tests cover each.
- It makes no other network call during analysis. It does not scan live third-party systems.
- It never reads `.env` files, keys or production data. Input is plain SQL files you supply, a static-auditor JSON report, and its own evidence files. Seed data is synthetic (`alice@example.test`, `bob@example.test`, fixed UUIDs).
- It generates no attack tooling beyond SQL probes against the sandbox, run as `anon` and `authenticated` inside a transaction that is rolled back.

## Threat model

The migrations under analysis are **untrusted**: they may come from a repository you have not reviewed.

| Threat | What the tool does about it | Residual risk |
| --- | --- | --- |
| Migration SQL reaches the network (`dblink`, `postgres_fdw`, `COPY ... PROGRAM`) | Default mode runs the database in a container with `--network none`, no published port, `listen_addresses=''`. | In loopback mode the server's network is yours; use a throwaway server on an isolated host or network. |
| Migration SQL damages the host | Container: no capabilities, `no-new-privileges`, read-only root, tmpfs data directory, unprivileged user, 256 processes, 1 GiB memory, 1 CPU, no host mounts, `--pull never`, removed in `finally`, on SIGINT/SIGTERM, and with `docker rm -f -v`. | The SQL runs as a PostgreSQL superuser inside the container. A container escape would be a Docker vulnerability. |
| Migration SQL runs forever | `statement_timeout` 20 s, `lock_timeout` 5 s and an idle-transaction timeout are set on the database; every batch has a 120 s wall-clock limit and the run a 10 min budget. A statement that resets the timeout is still cut by the wall clock. | A pathological run ends with exit code 3 and a clear message instead of partial results. |
| Migration SQL breaks the probe harness | The harness resets the role after every statement; if it is dropped or corrupted the run fails loudly (exit 3). Probes run in rolled-back sub-transactions. | A hostile migration can make a run fail; it cannot make a proof appear that the database did not produce. |
| Hostile identifiers, policy names, comments or messages in reports | Terminal output turns every control character, escape sequence, bidi override and zero-width character into a visible escape. Markdown output escapes markup, HTML, links, mentions, pipes and newlines, uses code spans and fences longer than any backtick run in the content. Generated SQL writes unsafe identifiers and literals as `U&"..."` Unicode escapes so `fix.sql` is safe to print. JSON keeps text as found (JSON escapes control characters); a program that renders it must sanitise it for its own sink. | Text you paste elsewhere is your responsibility. |
| Hostile or oversized input files | Files are opened with `O_NOFOLLOW`/`O_NONBLOCK` and checked on the descriptor (regular file, size). Caps: 1 MiB per SQL file, 4 MiB and 500 files in all, 20 000 statements, 256 KiB per statement, 8 MiB per JSON input, 300 tables, 5 000 probes. A cap makes the run `complete: false` (exit code 3 when nothing was proven); nothing is silently dropped. | |
| Forged or edited evidence | `proofs.jsonl` is decoded with a strict schema, per-proof hashes are recomputed, the recorded inputs are re-hashed, and the database re-decides every verdict. `verification-contract.json` accepts only `proof-audit verify ...` commands with plain or single-quoted words. | A hash proves integrity, not authorship. Evidence is not signed. |
| Secrets in logs | No secret is read or logged. A refused database URL is never echoed (its password is not printed). Test passwords are generated at run time and kept in a mode-600 file that is removed on exit. The repository has a secret scanner in the pre-commit and pre-push hooks and in CI. | |
| Docker daemon access | Docker is called with fixed argument vectors through `spawn` with `shell: false`; nothing from the analysed project is ever part of an argument. | Anyone who can run docker can already do far more. |

## Limitations

What the tool proves is limited to row level security logic in the SQL you give it, against two synthetic users and an anonymous caller. It does not check application-layer authorization, frontends, secrets exposure, storage buckets, realtime or any live system; a CLEAN result is not a penetration test. The Supabase shim is an approximation, seeding is heuristic, and PostgreSQL version differences can change outcomes. The README lists these in detail.

## Dependency policy

- One runtime dependency, `pg`, used only by the loopback transport; everything else is a development dependency. `files` in `package.json` is limited to `dist`.
- Exact pins in `package.json` and a committed `package-lock.json`. Every package, direct and transitive, was resolved with `npm install --before=2026-10-24T00:00:00Z --ignore-scripts`; `check-age` reports zero packages newer than the cutoff. Installs, tests and builds run in throwaway containers; CI uses `npm ci --ignore-scripts`. No dependency needs an install script.
- Container images (Node 22 and 24, PostgreSQL 16.14) are pinned by digest; GitHub Actions are pinned to full commit SHAs. Dependabot (npm and github-actions, weekly, 7-day cooldown) ignores major bumps of `typescript` and `@types/node`.

## Open advisories

See the end of the README for the result of `npm audit` at the cutoff.
