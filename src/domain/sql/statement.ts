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

/** Where a statement starts: the file as given and the 1-based line of its first token. */
export interface SourceSpot {
  readonly file: string;
  readonly line: number;
}

/** The statements that shaped one table, as the SQL reader replayed them. */
export interface TableSource {
  /** The `CREATE TABLE` that declared it. */
  readonly created: SourceSpot;
  /** The last `ALTER TABLE ... ENABLE | DISABLE ROW LEVEL SECURITY`, or null when there is none. */
  readonly rowSecurity: SourceSpot | null;
  /** Per policy name, the `CREATE POLICY` (or the later `ALTER POLICY`) that gave the policy its current definition. */
  readonly policies: ReadonlyMap<string, SourceSpot>;
}

/** Positions of the objects in the final model, keyed by `schema.name`. Renames are followed; dropped objects are absent. */
export interface SourceIndex {
  readonly tables: ReadonlyMap<string, TableSource>;
  /** The `CREATE VIEW` of each view. */
  readonly views: ReadonlyMap<string, SourceSpot>;
}

export interface ParseResult {
  /** Every statement in input order, files in the given order. */
  readonly statements: readonly SqlStatement[];
  /** The static model built from the statements the reader understands. */
  readonly model: SchemaModel;
  /** Where the objects of `model` were declared. */
  readonly sources: SourceIndex;
  /** Statements the reader skipped or could not fully read, and caps that were hit. */
  readonly warnings: readonly Warning[];
  /** False when a size or count cap dropped input, so later results may be partial. */
  readonly complete: boolean;
}
