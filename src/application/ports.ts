import type { Environment } from "../domain/analysis/types.js";
import type { ClientRole } from "../domain/schema/model.js";
import type { ProbeObservation } from "../domain/proof/types.js";

/** Result of one statement applied to the throwaway database. */
export interface StatementOutcome {
  readonly ok: boolean;
  readonly sqlstate: string | null;
  readonly message: string | null;
}

/** Result of trying a group of alternatives in order until one succeeds. */
export interface GroupOutcome extends StatementOutcome {
  /** Index of the alternative that worked, or null when none did. */
  readonly attempt: number | null;
}

export type ScalarOutcome =
  | { readonly ok: true; readonly value: number | string | null }
  | { readonly ok: false; readonly sqlstate: string; readonly message: string };

export interface ProbeRun {
  readonly role: ClientRole;
  /** JSON text for `request.jwt.claims`. */
  readonly claims: string;
  readonly sql: string;
}

/**
 * A throwaway database the analysis may do anything to. Statements that come from the project under analysis run
 * as a role without superuser rights; `run` switches to a client role. Implementations must only ever talk to a database created for this
 * run on this machine, and must make `dispose` safe to call at any point.
 */
export interface Sandbox {
  /** Apply statements one by one in a single session, recording each outcome. A failing statement never stops the rest. */
  apply(statements: readonly string[]): Promise<StatementOutcome[]>;
  /** For each group, try the statements in order until one succeeds. */
  applyFirstSuccess(groups: readonly (readonly string[])[]): Promise<GroupOutcome[]>;
  /** Run queries that each return one value. */
  scalars(queries: readonly string[]): Promise<ScalarOutcome[]>;
  /** The catalog snapshot as parsed JSON; validated by the domain. */
  catalog(): Promise<unknown>;
  /** The platform part of the sandbox (shim functions, roles, settings, event triggers) as parsed JSON; validated by the domain. */
  fingerprint(): Promise<unknown>;
  /** Run each statement as a client role inside a transaction that is always rolled back. */
  run(probes: readonly ProbeRun[]): Promise<ProbeObservation[]>;
  /** A fresh copy of the database in its current state. */
  fork(): Promise<Sandbox>;
  dispose(): Promise<void>;
}

export interface CreatedSandbox {
  readonly sandbox: Sandbox;
  readonly environment: Omit<Environment, "postgresVersion">;
}

export interface SandboxProvider {
  create(): Promise<CreatedSandbox>;
}

export interface Clock {
  /** Milliseconds, monotonic enough for a budget. */
  now(): number;
}

/** One input file as read from disk. */
export interface LoadedFile {
  readonly path: string;
  readonly content: string;
  readonly bytes: number;
}

export interface LoadedFiles {
  readonly files: readonly LoadedFile[];
  readonly warnings: readonly string[];
  /** False when a cap dropped some input. */
  readonly complete: boolean;
}

/** Thrown when the sandbox cannot be set up; the run has no results to report. */
export class SandboxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandboxError";
  }
}
