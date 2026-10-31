import { describe, expect, it } from "vitest";
import { analyzeRls } from "../../src/application/analyze.js";
import type { Clock, LoadedFile, Sandbox, SandboxProvider } from "../../src/application/ports.js";
import { verifyEvidence } from "../../src/application/verify.js";
import { encodeProofsJsonl } from "../../src/domain/evidence/proofs.js";
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
