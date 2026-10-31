# 0010. Integration tests: a pinned database next to the test container

Status: accepted

## Context

The brief asked for the test process to run in a Node container, reaching a pinned PostgreSQL started by a helper script on a user-defined network. The tool, however, refuses every host that is not loopback (see [0003](0003-throwaway-database-and-the-loopback-boundary.md)), and a container name is not loopback.

## Decision

`scripts/integration.sh` creates a user-defined `--internal` docker network (no route out), starts the pinned `postgres` image on it with a hardened configuration and a password generated at run time, and starts the test container with `--network container:<database container>`. The two containers then share one network namespace and the database is at `127.0.0.1:5432`, so the tests exercise the same loopback rule users face instead of an exception for tests. The password lives in a mode-600 file under `out/` (ignored by git) and is removed with the containers and the network on exit.

## Consequences

The loopback-only rule has no test-only escape hatch. `scripts/run-contained.sh` uses the same layout to run the tool itself without Node or a database on the host. CI runs the integration suite against a pinned service container with trust authentication on the runner.

The suite passes the server to the tool the way a user should: through `PROOF_AUDIT_DATABASE_URL` read by the tests' own support code, and through `--database-url-env` for the CLI. The tool itself never reads that variable on its own initiative.
