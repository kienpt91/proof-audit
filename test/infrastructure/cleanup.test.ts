import { describe, expect, it } from "vitest";
import { CLEANUP_SIGNALS, installCleanup, type ProcessLike } from "../../src/infrastructure/cli/cleanup.js";

function fakeProcess() {
  const handlers = new Map<string, () => void>();
  const exits: number[] = [];
  const errors: string[] = [];
  const proc: ProcessLike = {
    on: (event, listener) => void handlers.set(event, listener as () => void),
    stderr: { write: (t) => void errors.push(t) },
    exit: (code) => void exits.push(code),
  };
  return { proc, handlers, exits, errors, emit: (event: string) => handlers.get(event)?.() };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("installCleanup", () => {
  it("handles interrupt, terminate, hang-up and quit with the exit codes a shell reports", async () => {
    for (const [signal, code] of CLEANUP_SIGNALS) {
      const f = fakeProcess();
      let disposed = 0;
      installCleanup(f.proc, () => [{ disposeAll: async () => void (disposed += 1) }]);
      f.emit(signal);
      await tick();
      expect(disposed).toBe(1);
      expect(f.exits).toEqual([code]);
      expect(f.errors[0]).toContain(signal);
    }
    expect(CLEANUP_SIGNALS.map(([s]) => s)).toEqual(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"]);
  });

  it("also cleans up after an uncaught exception and an unhandled rejection, exiting 3", async () => {
    for (const event of ["uncaughtException", "unhandledRejection"]) {
      const f = fakeProcess();
      let disposed = 0;
      installCleanup(f.proc, () => [{ disposeAll: async () => void (disposed += 1) }]);
      f.emit(event);
      await tick();
      expect(disposed).toBe(1);
      expect(f.exits).toEqual([3]);
    }
  });

  it("ignores a second signal while the first is being handled, so the cleanup is not abandoned", async () => {
    const f = fakeProcess();
    let release: () => void = () => undefined;
    let disposed = 0;
    installCleanup(f.proc, () => [{ disposeAll: () => new Promise<void>((r) => { disposed += 1; release = r; }) }]);
    f.emit("SIGINT");
    f.emit("SIGINT");
    f.emit("SIGTERM");
    expect(disposed).toBe(1);
    expect(f.exits).toEqual([]);
    release();
    await tick();
    expect(f.exits).toEqual([130]);
  });

  it("exits even when a provider fails to clean up, and cleans up every provider", async () => {
    const f = fakeProcess();
    const calls: string[] = [];
    installCleanup(f.proc, () => [
      { disposeAll: async () => { calls.push("a"); throw new Error("boom"); } },
      { disposeAll: async () => void calls.push("b") },
    ]);
    f.emit("SIGHUP");
    await tick();
    expect(calls.sort()).toEqual(["a", "b"]);
    expect(f.exits).toEqual([129]);
  });

  it("works with no provider started yet", async () => {
    const f = fakeProcess();
    installCleanup(f.proc, () => []);
    f.emit("SIGTERM");
    await tick();
    expect(f.exits).toEqual([143]);
  });
});
