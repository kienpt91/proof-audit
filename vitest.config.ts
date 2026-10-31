import { defineConfig } from "vitest/config";

// Offline suite: no Docker, no database, no network. Integration tests live in
// test/integration and run through vitest.integration.config.ts.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/integration/**", "test/smoke/**", "node_modules/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/bin.ts"],
      reporter: ["text", "json-summary"],
      thresholds: {
        "src/domain/**": { lines: 95, statements: 95 },
        "src/application/**": { lines: 90, statements: 90 },
        lines: 85,
        statements: 85,
      },
    },
  },
});
