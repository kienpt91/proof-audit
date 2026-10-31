# 0002. Layers and a mechanically enforced dependency rule

Status: accepted

## Decision

Four layers, imports point inward only:

```
src/domain         pure: no IO, no clock, no randomness, no node:* or package imports
src/application    use cases, ports (Sandbox, Clock), report presenters; imports domain
src/infrastructure docker and psql, pg client, file readers, CLI; imports application and domain
src/composition    wires real adapters; imports everything
```

`test/architecture/layers.test.ts` reads every source file, extracts its imports and fails when a layer imports a layer it must not, when the domain or application imports `node:*` or a package, or when they touch `Date.now`, `new Date`, `Math.random`, `process.*`, `fetch` or timers. The checker has its own tests with violating snippets. Time reaches the application only through the `Clock` port, and the database only through the `Sandbox` port.

## Consequences

- SHA-256 is implemented in the domain (about 50 lines, tested against the FIPS vectors) so evidence hashing needs no `node:crypto`.
- The same analysis runs against an in-memory fake (`ModelSandbox`) in the offline suite and against PostgreSQL in the integration suite.
- Random database and container names are the only randomness; they live in infrastructure and never reach a report, so output is deterministic.
