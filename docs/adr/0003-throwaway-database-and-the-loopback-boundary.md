# 0003. Only a database the tool owns, only on this machine

Status: accepted

## Context

The SQL under analysis is untrusted: it comes from someone else's repository and runs with the rights needed to create tables and roles. The tool must be unable to reach a remote database even by mistake.

## Decision

- **Default mode**: the tool starts a container from the official `postgres:16.14` image pinned by digest, with `--network none`, no published port, no capabilities, a read-only root file system, an in-memory data directory, an unprivileged user, process, memory and CPU limits, and no host mounts. The server does not listen on TCP (`listen_addresses=''`). The container starts with `--rm`, a bounded json log (`max-size=1m`) and `log_min_messages=panic`, and is removed in a `finally` block, on SIGINT, SIGTERM, SIGHUP and SIGQUIT, after an uncaught exception, and, if the process was killed outright, by the next run, which removes containers labelled `proof-audit=1` whose recorded pid is gone. After a batch timeout the server-side sessions are terminated, not only the local `docker exec`. `--pull never` means the tool never fetches an image by itself.
- **Loopback URL mode** (`--database-url`, or `--database-url-env NAME` to keep the password out of the process list; never read from the environment implicitly): for a PostgreSQL server the user started on this machine, used by the integration tests and CI. It prints a banner naming the server, refuses a server that holds databases other than `postgres` unless `--yes-this-is-throwaway` is given (loopback does not prove a server is disposable: a tunnel or a published port can lead anywhere), and runs everything from the project as a role created for the run that is not a superuser (see [0011](0011-trust-domains-for-the-verdicts.md)), so `COPY ... PROGRAM` and `ALTER SYSTEM` are not available to it. The URL is read with a strict grammar, not a general URL parser, and accepted only when the host is `localhost`, a decimal dotted-quad inside `127.0.0.0/8`, or `::1`. Query options (`host=`, `hostaddr=`, `service=`), several `@`, backslashes, short or octal IPv4 forms and every DNS name are refused. `localhost` is mapped to `127.0.0.1` so no resolver is consulted. The check is in the domain (`parseLoopbackUrl`), repeated in the adapter (`assertLoopbackHost`) and tested with hostile URLs. The tool creates a database of its own in that server and drops it afterwards; the connecting role must be a superuser.
- Seed data is synthetic; migrations are plain files; the tool reads no `.env`, no secret, no live system and makes no network call during analysis.
- The docker daemon must be on this machine: `DOCKER_HOST` with a `tcp:`, `ssh:` or `http(s):` scheme, or a current docker context with such an endpoint, is refused, because the migrations would otherwise be sent to another machine.
- Docker is invoked with fixed argument vectors through `spawn` with `shell: false`. Nothing from the analysed project is ever part of an argument vector: SQL travels on stdin.

## Consequences

- In default mode the SQL under analysis has no network to abuse (`dblink`, `COPY ... PROGRAM`, `postgres_fdw` have nowhere to go). It can still do whatever a superuser can do inside the container, which is why the container limits matter.
- In loopback mode the isolation is the user's: the server is a throwaway they started, and the tool says so in its help and in SECURITY.md.
