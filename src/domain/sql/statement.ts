import type { SchemaModel, Warning } from "../schema/model.js";

/** One input file as the application layer hands it to the domain. */
export interface SourceFile {
  /** Display path (relative, forward slashes). */
  readonly path: string;
  readonly content: string;
}

/**
 * What the sandbox should do with a statement:
 * - `sql`: run it.
 * - `transaction-control`: BEGIN / COMMIT / ROLLBACK / START TRANSACTION / END. Skipped, because the
 *   sandbox applies each statement on its own.
 * - `psql-meta`: a psql backslash command (`\connect`, `\i`). Never run.
 */
export type StatementKind = "sql" | "transaction-control" | "psql-meta";

export interface SqlStatement {
  readonly file: string;
  /** 1-based line of the first token. */
  readonly line: number;
  /** Statement text without the terminating semicolon. */
  readonly text: string;
  readonly kind: StatementKind;
}

export interface ParseResult {
  /** Every statement in input order, files in the given order. */
  readonly statements: readonly SqlStatement[];
  /** The static model built from the statements the reader understands. */
  readonly model: SchemaModel;
  /** Statements the reader skipped or could not fully read, and caps that were hit. */
  readonly warnings: readonly Warning[];
}
