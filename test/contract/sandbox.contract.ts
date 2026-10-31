import { afterEach, describe, expect, it } from "vitest";
import type { ProbeRun, Sandbox } from "../../src/application/ports.js";

/**
 * Properties every Sandbox must have, whatever is behind it: results line up with what was sent, a fork is
 * independent of its parent, and dispose can be repeated. The same suite runs against an in-memory fake,
 * a fake transport and (integration) a real PostgreSQL.
 */
export function defineSandboxContract(name: string, create: () => Promise<Sandbox>, setup: (sandbox: Sandbox) => Promise<void> = async () => undefined): void {
  describe(`Sandbox contract: ${name}`, () => {
    const open: Sandbox[] = [];
    afterEach(async () => {
      await Promise.all(open.splice(0).map((s) => s.dispose().catch(() => undefined)));
    });
    const make = async (): Promise<Sandbox> => {
      const s = await create();
      open.push(s);
      await setup(s);
      return s;
    };
    const probe: ProbeRun = { role: "anon", claims: '{"role":"anon"}', sql: 'SELECT * FROM "public"."notes"' };

    it("returns one outcome per statement, in order", async () => {
      const s = await make();
      expect(await s.apply([])).toEqual([]);
      expect(await s.apply(["SELECT 1", "SELECT 2", "SELECT 3"])).toHaveLength(3);
    });

    it("returns one outcome per group", async () => {
      const s = await make();
      const out = await s.applyFirstSuccess([["SELECT 1"], ["SELECT 2", "SELECT 3"]]);
      expect(out).toHaveLength(2);
      expect(await s.applyFirstSuccess([])).toEqual([]);
    });

    it("returns one scalar per query", async () => {
      const s = await make();
      expect(await s.scalars(["SELECT 1", "SELECT 2"])).toHaveLength(2);
      expect(await s.scalars([])).toEqual([]);
    });

    it("returns one observation per probe", async () => {
      const s = await make();
      const out = await s.run([probe, probe, probe]);
      expect(out).toHaveLength(3);
      for (const o of out) expect(["rows", "error", "not-run"]).toContain(o.status);
      expect(await s.run([])).toEqual([]);
    });

    it("returns a catalog object", async () => {
      const s = await make();
      const c = await s.catalog();
      expect(typeof c).toBe("object");
      expect(c).not.toBeNull();
    });

    it("forks into an independent sandbox that can be disposed on its own", async () => {
      const parent = await make();
      const child = await parent.fork();
      open.push(child);
      expect(child).not.toBe(parent);
      await child.dispose();
      expect(await parent.run([probe])).toHaveLength(1);
    });

    it("can be disposed more than once", async () => {
      const s = await make();
      await s.dispose();
      await expect(s.dispose()).resolves.toBeUndefined();
    });
  });
}
