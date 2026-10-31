# 0007. Evidence file and verification contract

Status: accepted

## Decision

`proofs.jsonl`: line 1 is a `meta` record (schema version, tool, image digest, the inputs with path, size and sha256, the fix statements and their hash); each following line is one proof, `before` proofs first, then `after` proofs. Lines are written with canonical JSON (sorted keys). The decoder is strict: exact schema, caps, hash recomputation per proof (a tampered field or hash is reported by line number, never by content), no duplicate (phase, id), no second meta line.

`proof-audit verify <proofs.jsonl>` re-reads each recorded input and refuses (exit 3, "stale") when a file changed, because a replay of changed migrations proves nothing about the recorded ones. It then rebuilds the sandbox and **generates the probes and the fix again with this tool's own planner**: every recorded proof must match the generated probe (id, role, claims, SQL, target rows) and the recorded fix must equal the generated one, otherwise the file is refused (exit 2) and none of its SQL runs, because the hashes are unkeyed and anyone can mint a valid file. Only then are the probes replayed and the content hash of each replayed proof compared with the recorded one; with a recorded fix it is applied to a fork and the `after` proofs are compared. Exit 0 only if everything is identical. Recorded input paths may not contain `..` and are only read from inside `--root`; `--against` refuses evidence that proved nothing. `--against <paths>` replays the recorded `before` probes against other migrations (for example the ones the team fixed by hand) and exits 0 only when every previously proven subject is now verified by the rules of [0006](0006-fix-verification-rules.md).

`verification-contract.json` lists checks in the shape of the author's NEO design (a command and an expected exit code): `evidence-reproduces` and, when something was proven, `fix-closes-proven-holes`. Commands are `proof-audit verify ...` with POSIX quoting. The decoder rejects any other command and any shell metacharacter outside quotes, so an orchestrator never runs an arbitrary command from a tampered file.

Exit codes: `0` ok, `1` holes proven / evidence not reproduced, `2` usage or invalid input, `3` sandbox unavailable, incomplete run, or stale inputs, `4` INTEGRITY_VIOLATION (the migrations touched the test environment).
