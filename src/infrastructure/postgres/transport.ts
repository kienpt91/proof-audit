/**
 * How SQL reaches a throwaway database. Two implementations exist: `psql` run inside the sandbox container
 * through `docker exec` (no network at all), and a `pg` client for a loopback URL. Everything above this
 * interface is identical for both.
 */
export interface SqlTransport {
  /** Run each statement, which must be a SELECT returning one text value, in ONE session on `database`. Returns the values in order. */
  query(database: string, statements: readonly string[]): Promise<string[]>;
  /** Run statements in one session without reading results; throws on the first error. Used for DDL such as CREATE DATABASE. */
  execute(database: string, statements: readonly string[]): Promise<void>;
}

export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransportError";
  }
}
