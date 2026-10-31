# 0004. Two transports behind one port: psql in the container, `pg` on loopback

Status: accepted

## Context

The brief allowed either the `pg` client or driving `psql` through the docker CLI, and asked for the safer and simpler design to be justified.

## Options

1. `pg` only. The container would need a published port, so it could not run with `--network none`: SQL under analysis could reach the network.
2. `psql` through `docker exec` only. Safest, but a test process inside a Node container (no docker CLI) cannot use it, so the integration tests and CI services could not run.
3. Both, behind one `SqlTransport` interface.

## Decision

Option 3. `PostgresSandbox` implements the `Sandbox` port once, on top of `SqlTransport` (`query` for statements returning one text value, `execute` for raw DDL). Every operation is a single `SELECT` against small PL/pgSQL functions in schema `proof_audit` (`try_exec`, `try_first`, `scalar`, `run_probe`, `catalog`), so both transports send and parse the same JSON. `DockerPsqlTransport` sends the script on stdin of `docker exec -i ... psql` over the container's unix socket; `PgTransport` uses `pg` against a validated loopback endpoint. The default (container) mode never touches `pg` at all.

The only runtime dependency is `pg` (exact pin, published before the cutoff), used by the loopback transport.

## Consequences

- Default mode is the safest design and has zero network surface; loopback mode exists because the tests and CI need TCP.
- The docker adapter is exercised for real by `scripts/docker-smoke.sh`: the real provider runs in a Node container without docker, and a host relay executes only the exact docker commands it issues (hardened `run`, `exec ... psql`, `inspect`, `logs`, `rm`).
