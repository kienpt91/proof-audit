# 0009. Dependencies, pins and the install procedure

Status: accepted

- One runtime dependency: `pg`, pinned exactly, published on or before the cutoff (2026-10-24), used only by the loopback transport. Development: TypeScript 6.0.3, vitest 5.0.5 with `@vitest/coverage-v8` 5.0.5, `@types/node` 22.x, `@types/pg`.
- Installs use `npm install --before=2026-10-24T00:00:00Z --ignore-scripts --save-exact`; the lockfile was generated with `--package-lock-only` in a clean directory and is checked with `npm ci --ignore-scripts` in amd64 and arm64 containers. `node _tools/check-age.mjs` must report zero packages newer than the cutoff.
- Everything runs in containers: Node 22 and 24 images pinned by digest, PostgreSQL 16.14 pinned by digest (the moving `postgres:16` tag was republished after the cutoff, so a digest created on 2026-08-05 is used instead).
- GitHub Actions are pinned to full commit SHAs; Dependabot uses a 7-day cooldown and ignores major bumps of `typescript` and `@types/node`.
- A secret scanner runs in the pre-commit and pre-push hooks and as a separate CI job; test database passwords are generated at run time and never committed.
