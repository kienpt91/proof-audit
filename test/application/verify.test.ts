import { describe, expect, it } from "vitest";
import { analyzeRls } from "../../src/application/analyze.js";
import type { Clock, LoadedFile, Sandbox, SandboxProvider } from "../../src/application/ports.js";
import { verifyEvidence } from "../../src/application/verify.js";
import { decodeProofsJsonl, encodeProofsJsonl, type ProofsMeta } from "../../src/domain/evidence/proofs.js";
import type { Proof } from "../../src/domain/proof/types.js";
import { sealProof } from "../../src/domain/proof/hash.js";
import { ALL, model, notes } from "../helpers/model.js";
import { ModelSandbox, type ModelSandboxOptions } from "../helpers/model-sandbox.js";

const clock: Clock = { now: () => 0 };
const tool = { name: "proof-audit", version: "0.0.0-test" };
const file: LoadedFile = { path: "m/001.sql", content: "create table public.notes (id uuid primary key, user_id uuid);\n", bytes: 62 };
const open = notes({ rlsEnabled: false, policies: [], privileges: { anon: ALL, authenticated: ALL } });
const vulnerable: ModelSandboxOptions = { model: model([open]), fixed: model([notes()]) };

const providerFor = (options: ModelSandboxOptions): SandboxProvider => ({
  async create() {
    const sandbox: Sandbox = new ModelSandbox(options);
    return { sandbox, environment: { mode: "url", image: "loopback" } };
  },
});

async function evidence(options = vulnerable, files = [file]): Promise<string> {
  const report = await analyzeRls({ files, loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool }, { provider: providerFor(options), clock });
  const fix = report.fix?.statements ?? [];
  return encodeProofsJsonl({ tool, image: report.environment.image, inputs: report.inputs, fixStatements: fix, fixSha256: null }, [...report.proofs, ...(report.verification?.after ?? [])]);
}

const readInput = (files: readonly LoadedFile[]) => async (path: string) => files.find((f) => f.path === path) ?? null;

describe("verifyEvidence: replay", () => {
  it("passes when every recorded probe replays with the same result, including the fix", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: providerFor(vulnerable), clock });
    expect(r.status).toBe("ok");
    expect(r.probesChecked).toBeGreaterThan(20);
    expect(r.messages[0]).toContain("identical results");
  });

  it("fails when the database now behaves differently from the record", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: providerFor({ model: model([notes()]) }), clock });
    expect(r.status).toBe("mismatch");
    expect(r.messages.some((m) => m.includes("recorded PROVEN_VULNERABLE"))).toBe(true);
  });

  it("fails when the recorded fix no longer closes the hole", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: providerFor({ model: vulnerable.model, fixed: vulnerable.model }), clock });
    expect(r.status).toBe("mismatch");
    expect(r.messages.some((m) => m.startsWith("after "))).toBe(true);
  });

  it("is stale when an input file changed", async () => {
    const text = await evidence();
    const changed = { ...file, content: `${file.content}-- edited\n` };
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([changed]), against: null }, { provider: providerFor(vulnerable), clock });
    expect(r.status).toBe("stale");
    expect(r.messages[0]).toContain("changed since");
  });

  it("is stale when an input file is missing", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: null }, { provider: providerFor(vulnerable), clock });
    expect(r.status).toBe("stale");
    expect(r.messages[0]).toContain("not found");
  });

  it("is invalid for damaged evidence and never creates a sandbox", async () => {
    let created = 0;
    const provider: SandboxProvider = { create: async () => { created += 1; throw new Error("no"); } };
    const r = await verifyEvidence({ proofsText: "not json\n", readInput: readInput([]), against: null }, { provider, clock });
    expect(r.status).toBe("invalid");
    expect(created).toBe(0);
  });

  it("detects a tampered proof through its hash", async () => {
    const text = (await evidence()).replace('"rows":2', '"rows":3');
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: providerFor(vulnerable), clock });
    expect(r.status).toBe("invalid");
  });

  it("notes a different image without failing", async () => {
    const text = await evidence();
    const other: SandboxProvider = { create: async () => ({ sandbox: new ModelSandbox(vulnerable), environment: { mode: "url", image: "elsewhere" } }) };
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: other, clock });
    expect(r.status).toBe("ok");
    expect(r.messages.some((m) => m.startsWith("note:"))).toBe(true);
  });
});

describe("verifyEvidence: --against", () => {
  it("passes when the migrations under test no longer have the proven holes", async () => {
    const text = await evidence();
    const fixedFile = { ...file, content: "-- fixed\n" };
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: [fixedFile] }, { provider: providerFor({ model: model([notes()]) }), clock });
    expect(r.status).toBe("ok");
  });

  it("fails while a proven hole is still open", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: [file] }, { provider: providerFor(vulnerable), clock });
    expect(r.status).toBe("mismatch");
    expect(r.messages[0]).toContain("public.notes: STILL_VULNERABLE");
  });

  it("fails when the new migrations close the hole by locking everyone out", async () => {
    const text = await evidence();
    const locked = notes({ policies: [], privileges: { anon: [], authenticated: [] } });
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: [file] }, { provider: providerFor({ model: model([locked]) }), clock });
    expect(r.status).toBe("mismatch");
    expect(r.messages[0]).toContain("BREAKS_ACCESS");
  });

  it("does not need the recorded inputs to exist", async () => {
    const text = await evidence(vulnerable, [{ path: "gone.sql", content: "x", bytes: 1 }]);
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: [file] }, { provider: providerFor({ model: model([notes()]) }), clock });
    expect(r.status).toBe("ok");
  });
});

describe("verifyEvidence: the evidence file is not trusted to carry SQL", () => {
  const recorderFor = (options: ModelSandboxOptions) => {
    const sandboxes: ModelSandbox[] = [];
    const provider: SandboxProvider = {
      async create() {
        const sandbox = new ModelSandbox(options);
        sandboxes.push(sandbox);
        return { sandbox, environment: { mode: "url", image: "loopback" } };
      },
    };
    const everything = () => sandboxes.flatMap((s) => s.applied);
    return { provider, everything, sandboxes };
  };

  type Mutable<T> = { -readonly [K in keyof T]: T[K] };
  type MutableMeta = Mutable<ProofsMeta> & { fixStatements: string[] };

  async function forged(change: (meta: MutableMeta, proofs: Mutable<Proof>[]) => void): Promise<string> {
    const decoded = decodeProofsJsonl(await evidence());
    if (!decoded.ok) throw new Error(decoded.error);
    const meta: MutableMeta = { ...decoded.value.meta, fixStatements: [...decoded.value.meta.fixStatements] };
    const proofs = decoded.value.proofs.map((p) => ({ ...p }));
    change(meta, proofs);
    return encodeProofsJsonl(meta, proofs.map(({ hash: _hash, ...rest }) => sealProof(rest)));
  }

  it("refuses a recorded fix this tool did not generate, with valid hashes, and never applies it", async () => {
    const text = await forged((meta) => meta.fixStatements.push("COPY (SELECT 1) TO PROGRAM 'id'"));
    const rec = recorderFor(vulnerable);
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: rec.provider, clock });
    expect(r.status).toBe("invalid");
    expect(r.messages[0]).toContain("not the fix this tool generates");
    expect(rec.everything().some((s) => s.includes("PROGRAM"))).toBe(false);
    expect(rec.sandboxes.every((s) => s.forks === 0)).toBe(true);
  });

  it("refuses recorded probe SQL this tool did not generate, with valid hashes, and runs nothing", async () => {
    const text = await forged((_meta, proofs) => {
      const first = proofs[0];
      if (first) first.sql = "DROP TABLE public.notes";
    });
    const rec = recorderFor(vulnerable);
    const runs: string[] = [];
    const wrapped: SandboxProvider = {
      create: async () => {
        const created = await rec.provider.create();
        const run = created.sandbox.run.bind(created.sandbox);
        created.sandbox.run = async (probes) => {
          runs.push(...probes.map((p) => p.sql));
          return run(probes);
        };
        return created;
      },
    };
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: wrapped, clock });
    expect(r.status).toBe("invalid");
    expect(r.messages.join("\n")).toContain("differ from what this tool generates");
    expect(runs).toEqual([]);
  });

  it("refuses recorded claims or roles that differ from the generated probe", async () => {
    const text = await forged((_meta, proofs) => {
      const first = proofs[0];
      if (first) first.claims = '{"role":"service_role"}';
    });
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: recorderFor(vulnerable).provider, clock });
    expect(r.status).toBe("invalid");
  });

  it("refuses a probe the tool would not plan for these migrations", async () => {
    const text = await forged((_meta, proofs) => {
      const first = proofs[0];
      if (first) {
        first.id = "public.nowhere/anon-read";
        first.subject = "public.nowhere";
      }
    });
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: recorderFor(vulnerable).provider, clock });
    expect(r.status).toBe("invalid");
    expect(r.messages.join("\n")).toContain("would not run that probe");
  });

  it("refuses evidence without proofs and --against evidence without a proven attack", async () => {
    const empty = encodeProofsJsonl({ tool, image: "loopback", inputs: [], fixStatements: [], fixSha256: null }, []);
    expect((await verifyEvidence({ proofsText: empty, readInput: readInput([]), against: null }, { provider: recorderFor(vulnerable).provider, clock })).status).toBe("invalid");
    const clean = await evidence({ model: model([notes()]) });
    const r = await verifyEvidence({ proofsText: clean, readInput: readInput([]), against: [file] }, { provider: recorderFor({ model: model([notes()]) }).provider, clock });
    expect(r.status).toBe("invalid");
    expect(r.messages[0]).toContain("no proven attack");
  });

  it("refuses recorded input paths that climb out of the directory", async () => {
    const decoded = decodeProofsJsonl(await evidence());
    if (!decoded.ok) throw new Error(decoded.error);
    const text = encodeProofsJsonl({ ...decoded.value.meta, inputs: [{ path: "../../etc/passwd", sha256: "0".repeat(64), bytes: 1 }] }, decoded.value.proofs);
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: null }, { provider: recorderFor(vulnerable).provider, clock });
    expect(r.status).toBe("invalid");
  });

  it("reports an integrity violation instead of a result when the platform changed during the replay", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([file]), against: null }, { provider: recorderFor({ ...vulnerable, tamperedAfter: 3 }).provider, clock });
    expect(r.status).toBe("integrity");
    expect(r.messages[0]).toContain("platform-changed");
  });

  it("reports an integrity violation in --against mode too", async () => {
    const text = await evidence();
    const r = await verifyEvidence({ proofsText: text, readInput: readInput([]), against: [file] }, { provider: recorderFor({ model: model([notes()]), tamperedAfter: 2 }).provider, clock });
    expect(r.status).toBe("integrity");
  });
});
