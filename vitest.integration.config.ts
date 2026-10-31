import { defineConfig } from "vitest/config";

// Integration suite: needs a throwaway local Postgres, see scripts/integration.sh.
export default defineConfig({
  test: {
    include: ["test/integration/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      reporter: ["text", "json-summary"],
      reportsDirectory: "coverage-integration",
    },
  },
});
