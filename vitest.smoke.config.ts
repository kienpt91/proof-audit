import { defineConfig } from "vitest/config";

// Docker-mode smoke test, run by scripts/docker-smoke.sh with the relay in place.
export default defineConfig({
  test: {
    include: ["test/smoke/**/*.smoke.test.ts"],
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
