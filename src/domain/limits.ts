/** Caps on everything the tool reads or runs. Hitting a cap makes the run `complete: false`, never a crash. */
export const LIMITS = {
  /** Largest single SQL file. */
  maxSqlFileBytes: 1024 * 1024,
  /** All SQL files together. */
  maxSqlTotalBytes: 4 * 1024 * 1024,
  maxSqlFiles: 500,
  maxStatements: 20_000,
  /** Longest single statement the reader keeps whole. */
  maxStatementBytes: 256 * 1024,
  /** Largest JSON input (audit report, proofs file). */
  maxJsonBytes: 8 * 1024 * 1024,
  maxTables: 300,
  maxProbes: 5_000,
  /** Wall-clock budget for one database round trip batch, in milliseconds. */
  batchTimeoutMs: 120_000,
  /** Wall-clock budget for the whole run, in milliseconds. */
  runTimeoutMs: 600_000,
} as const;
