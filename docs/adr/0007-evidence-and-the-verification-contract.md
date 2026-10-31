# 0007. Evidence file and verification contract

Status: accepted

## Decision

`proofs.jsonl`: line 1 is a `meta` record (schema version, tool, image digest, the inputs with path, size and sha256, the fix statements and their hash); each following line is one proof, `before` proofs first, then `after` proofs. Lines are written with canonical JSON (sorted keys). The decoder is strict: exact schema, caps, hash recomputation per proof (a tampered field or hash is reported by line number, never by content), no duplicate (phase, id), no second meta line.

`proof-audit verify <proofs.jsonl>` re-reads each recorded input and refuses (exit 3, "stale") when a file changed, because a replay of changed migrations proves nothing about the recorded ones. It then rebuilds the sandbox, re-runs every recorded probe and compares the content hash of the replayed proof with the recorded one; with a recorded fix it also applies it to a fork and compares the `after` proofs. Exit 0 only if everything is identical. `--against <paths>` replays the recorded `before` probes against other migrations (for example the ones the team fixed by hand) and exits 0 only when every previously proven subject is now verified by the rules of [0006](0006-fix-verification-rules.md).

`verification-contract.json` lists checks in the shape of the author's NEO design (a command and an expected exit code): `evidence-reproduces` and, when something was proven, `fix-closes-proven-holes`. Commands are `proof-audit verify ...` with POSIX quoting. The decoder rejects any other command and any shell metacharacter outside quotes, so an orchestrator never runs an arbitrary command from a tampered file.

Exit codes: `0` ok, `1` holes proven / evidence not reproduced, `2` usage or invalid input, `3` sandbox unavailable, incomplete run, or stale inputs.
