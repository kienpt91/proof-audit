/** The part of `process` this module needs, so it can be tested without signalling the test runner. */
export interface ProcessLike {
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  readonly stderr: { write(text: string): unknown };
  exit(code: number): unknown;
}

export interface Disposable {
  disposeAll(): Promise<void>;
}

/** Signals that end the process, with the exit code a shell would report. */
export const CLEANUP_SIGNALS: readonly (readonly [string, number])[] = [
  ["SIGINT", 130],
  ["SIGTERM", 143],
  ["SIGHUP", 129],
  ["SIGQUIT", 131],
];

/**
 * Remove the throwaway database or container on every way out that can be caught: interrupt, terminate, hang-up (a
 * closed terminal or dropped SSH session), quit, an uncaught exception, an unhandled rejection. A second signal while
 * the first is being handled is ignored, so a nervous second Ctrl-C cannot abandon the cleanup. SIGKILL cannot be
 * caught: the next run removes containers whose process has gone (see `DockerSandboxProvider`).
 */
export function installCleanup(proc: ProcessLike, live: () => readonly Disposable[]): void {
  let cleaning = false;
  const run = (why: string, code: number): void => {
    if (cleaning) return;
    cleaning = true;
    proc.stderr.write(`proof-audit: ${why}, removing the throwaway database\n`);
    void Promise.all(live().map((p) => p.disposeAll().catch(() => undefined))).then(() => proc.exit(code));
  };
  for (const [signal, code] of CLEANUP_SIGNALS) proc.on(signal, () => run(signal, code));
  proc.on("uncaughtException", () => run("unexpected error", 3));
  proc.on("unhandledRejection", () => run("unexpected error", 3));
}
