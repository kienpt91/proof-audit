import { describe, expect, it } from "vitest";
import type { LoadedFiles, SandboxProvider } from "../../src/application/ports.js";
import { decodeContract } from "../../src/domain/evidence/contract.js";
import type { LoopbackEndpoint } from "../../src/domain/safety/loopback.js";
import { runCli, type CliDeps, type TrackedProvider } from "../../src/infrastructure/cli/main.js";
import { InputError } from "../../src/infrastructure/fs/files.js";
import { ALL, model, notes } from "../helpers/model.js";
import { ModelSandbox, type ModelSandboxOptions } from "../helpers/model-sandbox.js";
import { readFileSync } from "node:fs";

const open = notes({ rlsEnabled: false, policies: [], privileges: { anon: ALL, authenticated: ALL } });
const vulnerable: ModelSandboxOptions = { model: model([open]), fixed: model([notes()]) };
const clean: ModelSandboxOptions = { model: model([notes()]) };

const SQL = "create table public.notes (id uuid primary key, user_id uuid, title text);\n";

interface Harness {
  deps: CliDeps;
  readonly out: string[];
  readonly err: string[];
  readonly written: Map<string, Record<string, string>>;
  readonly files: Map<string, string>;
  readonly endpoints: LoopbackEndpoint[];
  dockerCalls: number;
  sandboxes: ModelSandbox[];
}

function harness(options: ModelSandboxOptions, files: Record<string, string> = { "supabase/migrations/001.sql": SQL }): Harness {
  const store = new Map(Object.entries(files));
  const h: Harness = { deps: undefined as never, out: [], err: [], written: new Map(), files: store, endpoints: [], dockerCalls: 0, sandboxes: [] };
  const provider = (): TrackedProvider => {
    const p: SandboxProvider = {
      async create() {
        const sandbox = new ModelSandbox(options);
        h.sandboxes.push(sandbox);
        return { sandbox, environment: { mode: "docker", image: "postgres@sha256:test" } };
      },
    };
    return { ...p, create: p.create, disposeAll: async () => undefined };
  };
  const deps: CliDeps = {
    cwd: "/work",
    env: {},
    version: "0.0.0-test",
    clock: { now: () => 0 },
    loadSql: async (paths): Promise<LoadedFiles> => {
      const loaded = [...store.entries()].filter(([p]) => paths.some((q) => p === q || p.startsWith(`${q}/`))).map(([path, content]) => ({ path, content, bytes: content.length }));
      if (loaded.length === 0) throw new InputError(`${paths[0]}: no such file or directory`);
      return { files: loaded, warnings: [], complete: true };
    },
    readText: async (path) => {
      const t = store.get(path.startsWith("/work/") ? path.slice(6) : path);
      if (t === undefined) throw new InputError(`cannot read ${path}`);
      return t;
    },
    writeOutputs: async (dir, f) => void h.written.set(dir, { ...f }),
    dockerProvider: () => {
      h.dockerCalls += 1;
      return provider();
    },
    urlProvider: (endpoint) => {
      h.endpoints.push(endpoint);
      return provider();
    },
    stdout: (t) => void h.out.push(t),
    stderr: (t) => void h.err.push(t),
  };
  return Object.assign(h, { deps });
}

const run = (h: Harness, ...argv: string[]) => runCli(argv, h.deps);
const stdout = (h: Harness) => h.out.join("");
const stderr = (h: Harness) => h.err.join("");

describe("proof-audit rls", () => {
  it("prints the plain-language report and exits 1 when something is proven", async () => {
    const h = harness(vulnerable);
    expect(await run(h, "rls", "supabase/migrations")).toBe(1);
    expect(stdout(h)).toContain("public.notes");
    expect(stdout(h)).toContain("PROVEN");
    expect(h.dockerCalls).toBe(1);
    expect(h.sandboxes.every((s) => s.disposed)).toBe(true);
  });

  it("exits 0 on a clean schema", async () => {
    const h = harness(clean);
    expect(await run(h, "rls", "supabase/migrations")).toBe(0);
    expect(stdout(h)).toContain("refused every attack");
  });

  it("exits 0 with --fail-on none even when something is proven", async () => {
    const h = harness(vulnerable);
    expect(await run(h, "rls", "supabase/migrations", "--fail-on", "none")).toBe(0);
  });

  it("prints JSON and Markdown on request", async () => {
    const j = harness(vulnerable);
    await run(j, "rls", "supabase/migrations", "--json");
    expect(JSON.parse(stdout(j)).summary.proven).toBe(1);
    const m = harness(vulnerable);
    await run(m, "rls", "supabase/migrations", "--markdown");
    expect(stdout(m).startsWith("# ")).toBe(true);
  });

  it("keeps progress messages on stderr and the report on stdout", async () => {
    const h = harness(clean);
    await run(h, "rls", "supabase/migrations", "--json");
    expect(stderr(h)).toContain("throwaway database");
    expect(() => JSON.parse(stdout(h))).not.toThrow();
  });

  it("writes the evidence files with --out", async () => {
    const h = harness(vulnerable);
    await run(h, "rls", "supabase/migrations", "--out", "out/audit");
    const files = h.written.get("out/audit");
    expect(Object.keys(files ?? {}).sort()).toEqual(["fix.sql", "proofs.jsonl", "report.json", "report.md", "verification-contract.json"]);
    expect(files?.["fix.sql"]).toContain("STARTING POINT");
    const contract = decodeContract(files?.["verification-contract.json"] ?? "");
    expect(contract.ok && contract.value.checks.map((c) => c.command)).toEqual([
      "proof-audit verify out/audit/proofs.jsonl",
      "proof-audit verify out/audit/proofs.jsonl --against supabase/migrations",
    ]);
  });

  it("omits fix.sql and the against check when nothing was proven", async () => {
    const h = harness(clean);
    await run(h, "rls", "supabase/migrations", "--out", "o");
    const files = h.written.get("o") ?? {};
    expect("fix.sql" in files).toBe(false);
    const contract = decodeContract(files["verification-contract.json"] ?? "");
    expect(contract.ok && contract.value.checks).toHaveLength(1);
  });

  it("does not propose a fix with --no-fix", async () => {
    const h = harness(vulnerable);
    await run(h, "rls", "supabase/migrations", "--no-fix", "--json");
    expect(JSON.parse(stdout(h)).fix).toBeNull();
  });

  it("exits 2 for a missing path and 3 when the sandbox cannot run", async () => {
    const h = harness(clean);
    expect(await run(h, "rls", "nowhere")).toBe(2);
    expect(stderr(h)).toContain("no such file");
    const broken = harness({ model: model([notes()]), rejectStatement: /CREATE ROLE/ });
    expect(await run(broken, "rls", "supabase/migrations")).toBe(3);
    expect(stderr(broken)).toContain("compatibility layer");
  });

  it("exits 2 with usage for bad arguments", async () => {
    const h = harness(clean);
    expect(await run(h, "rls")).toBe(2);
    expect(stderr(h)).toContain("usage:");
  });

  it("integrates the static auditor report", async () => {
    const audit = readFileSync(new URL("../fixtures/audit/vibe-app.json", import.meta.url), "utf8");
    const h = harness(vulnerable, { "supabase/migrations/001.sql": SQL, "audit.json": audit });
    await run(h, "rls", "supabase/migrations", "--from-audit", "audit.json", "--json");
    expect(JSON.parse(stdout(h)).audit.findings.length).toBeGreaterThan(0);
  });

  it("exits 2 for an unreadable or invalid audit report", async () => {
    const h = harness(clean, { "supabase/migrations/001.sql": SQL, "audit.json": "{not json" });
    expect(await run(h, "rls", "supabase/migrations", "--from-audit", "audit.json")).toBe(2);
    expect(await run(h, "rls", "supabase/migrations", "--from-audit", "missing.json")).toBe(2);
  });

  it("exits 3 for an incomplete run that proved nothing", async () => {
    const h = harness(clean);
    h.deps = { ...h.deps, loadSql: async () => ({ files: [{ path: "a.sql", content: SQL, bytes: 5 }], warnings: ["cap"], complete: false }) };
    expect(await run(h, "rls", "a.sql")).toBe(3);
  });
});

describe("loopback enforcement", () => {
  it("refuses a remote database URL before reading anything or creating a sandbox", async () => {
    const h = harness(clean);
    const secret = "hunter2".repeat(2);
    const code = await run(h, "rls", "supabase/migrations", "--database-url", "postgres://u:" + secret + "@db.example.com:5432/app");
    expect(code).toBe(2);
    expect(stderr(h)).toContain("not a loopback address");
    expect(stderr(h)).not.toContain("hunter2");
    expect(h.endpoints).toHaveLength(0);
    expect(h.sandboxes).toHaveLength(0);
  });

  it("refuses a remote URL from the environment as well", async () => {
    const h = harness(clean);
    h.deps = { ...h.deps, env: { PROOF_AUDIT_DATABASE_URL: "postgres://u@10.0.0.5/app" } };
    expect(await run(h, "rls", "supabase/migrations")).toBe(2);
    expect(h.endpoints).toHaveLength(0);
  });

  it("hands a validated loopback endpoint to the URL provider and never starts a container", async () => {
    const h = harness(clean);
    await run(h, "rls", "supabase/migrations", "--database-url", "postgres://tester@localhost:55432/scratch");
    expect(h.endpoints).toEqual([{ host: "127.0.0.1", port: 55432, user: "tester", password: null, database: "scratch" }]);
    expect(h.dockerCalls).toBe(0);
  });

  it("applies the same rule to verify", async () => {
    const h = harness(clean, { "p.jsonl": "" });
    expect(await run(h, "verify", "p.jsonl", "--database-url", "postgres://u@example.org/db")).toBe(2);
    expect(h.endpoints).toHaveLength(0);
  });
});

describe("proof-audit verify", () => {
  async function recorded(): Promise<Harness> {
    const h = harness(vulnerable);
    await run(h, "rls", "supabase/migrations", "--out", "out");
    const files = h.written.get("out") ?? {};
    h.files.set("out/proofs.jsonl", files["proofs.jsonl"] ?? "");
    return h;
  }

  it("replays the recorded probes and exits 0 when they all hold", async () => {
    const h = await recorded();
    h.out.length = 0;
    expect(await run(h, "verify", "out/proofs.jsonl")).toBe(0);
    expect(stdout(h)).toContain("OK:");
    expect(stdout(h)).toContain("identical results");
  });

  it("exits 1 when the migrations under test still have the hole", async () => {
    const h = await recorded();
    h.out.length = 0;
    expect(await run(h, "verify", "out/proofs.jsonl", "--against", "supabase/migrations")).toBe(1);
    expect(stdout(h)).toContain("STILL_VULNERABLE");
  });

  it("exits 0 when the migrations under test no longer have the hole", async () => {
    const h = await recorded();
    const fixed = harness(clean, { "supabase/migrations/002.sql": "-- fixed\n", "out/proofs.jsonl": h.files.get("out/proofs.jsonl") ?? "" });
    expect(await run(fixed, "verify", "out/proofs.jsonl", "--against", "supabase/migrations")).toBe(0);
  });

  it("exits 3 when an input changed since the evidence was written", async () => {
    const h = await recorded();
    h.files.set("supabase/migrations/001.sql", `${SQL}-- edited\n`);
    expect(await run(h, "verify", "out/proofs.jsonl")).toBe(3);
    expect(stdout(h)).toContain("STALE");
  });

  it("exits 2 for damaged evidence and for a missing file", async () => {
    const h = harness(clean, { "bad.jsonl": "garbage\n" });
    expect(await run(h, "verify", "bad.jsonl")).toBe(2);
    expect(await run(h, "verify", "missing.jsonl")).toBe(2);
  });

  it("resolves recorded inputs from --root", async () => {
    const h = await recorded();
    const moved = harness(vulnerable, { "elsewhere/supabase/migrations/001.sql": SQL, "out/proofs.jsonl": h.files.get("out/proofs.jsonl") ?? "" });
    moved.deps = { ...moved.deps, readText: async (p: string) => { const t = moved.files.get(p); if (t === undefined) throw new InputError("x"); return t; } };
    expect(await run(moved, "verify", "out/proofs.jsonl", "--root", "elsewhere")).toBe(0);
  });
});

describe("misc commands", () => {
  it("prints help and version", async () => {
    const h = harness(clean);
    expect(await run(h, "--help")).toBe(0);
    expect(stdout(h)).toContain("proof-audit rls");
    h.out.length = 0;
    expect(await run(h, "--version")).toBe(0);
    expect(stdout(h)).toBe("proof-audit 0.0.0-test\n");
  });

  it("neutralises hostile text in error messages", async () => {
    const h = harness(clean);
    h.deps = { ...h.deps, loadSql: async () => { throw new InputError("bad \u001b[31mpath\u202e"); } };
    await run(h, "rls", "x");
    expect(stderr(h)).not.toMatch(/[\u001b\u202e]/);
    expect(stderr(h)).toContain("\\x1B");
  });
});
