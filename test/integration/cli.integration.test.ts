import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { decodeContract } from "../../src/domain/evidence/contract.js";
import { splitShellWords } from "../../src/domain/text/shell.js";
import { runCli, type CliDeps } from "../../src/infrastructure/cli/main.js";
import { loadSqlInputs, readBoundedText, writeOutputs } from "../../src/infrastructure/fs/files.js";
import { UrlSandboxProvider } from "../../src/infrastructure/postgres/url-provider.js";
import { clock, databaseUrl, endpoint, haveDatabase } from "./support.js";

const scratch = mkdtempSync(join(tmpdir(), "proof-audit-cli-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const cwd = process.cwd();
  const deps: CliDeps = {
    cwd,
    env: {},
    version: "0.1.0",
    clock,
    loadSql: (paths) => loadSqlInputs(paths, cwd),
    readText: async (path, max) => (await readBoundedText(path, max)).content,
    writeOutputs,
    dockerProvider: () => {
      throw new Error("the container provider must not be used in integration tests");
    },
    urlProvider: (e) => new UrlSandboxProvider(e),
    stdout: (t) => void out.push(t),
    stderr: (t) => void err.push(t),
  };
  return runCli(argv, deps).then((code) => ({ code, out: out.join(""), err: err.join("") }));
}

const VULN = "examples/vulnerable-app/supabase/migrations";
const FIXED = "examples/fixed-app/supabase/migrations";
const url = ["--database-url", databaseUrl];

describe.skipIf(!haveDatabase)("proof-audit CLI against real PostgreSQL", () => {
  const outDir = join(scratch, "run");

  it("exits 1 and prints the plain-language report for the vulnerable app, writing every artifact", async () => {
    const r = await run(["rls", VULN, "--out", outDir, ...url]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("PROVEN");
    expect(r.out).toContain("Fix VERIFIED");
    expect(readFileSync(join(outDir, "fix.sql"), "utf8")).toContain("STARTING POINT");
    expect(JSON.parse(readFileSync(join(outDir, "report.json"), "utf8")).summary).toMatchObject({ proven: 6, clean: 1 });
    expect(readFileSync(join(outDir, "report.md"), "utf8").startsWith("# ")).toBe(true);
    expect(readFileSync(join(outDir, "proofs.jsonl"), "utf8").split("\n")[0]).toContain('"type":"meta"');
  });

  it("writes a verification contract whose commands are plain proof-audit invocations", () => {
    const contract = decodeContract(readFileSync(join(outDir, "verification-contract.json"), "utf8"));
    if (!contract.ok) throw new Error(contract.error);
    expect(contract.value.checks.map((c) => c.id)).toEqual(["evidence-reproduces", "fix-closes-proven-holes"]);
    for (const check of contract.value.checks) {
      const words = splitShellWords(check.command);
      expect(words.ok && words.value.slice(0, 2)).toEqual(["proof-audit", "verify"]);
      expect(check.expectedExitCode).toBe(0);
    }
  });

  it("replays the recorded proofs with identical results (exit 0)", async () => {
    const r = await run(["verify", join(outDir, "proofs.jsonl"), "--root", process.cwd(), ...url]);
    expect(r.out).toContain("identical results");
    expect(r.code).toBe(0);
  });

  it("exits 1 against the vulnerable migrations and 0 against the fixed ones", async () => {
    const still = await run(["verify", join(outDir, "proofs.jsonl"), "--against", VULN, ...url]);
    expect(still.code).toBe(1);
    expect(still.out).toContain("STILL_VULNERABLE");
    const fixed = await run(["verify", join(outDir, "proofs.jsonl"), "--against", FIXED, ...url]);
    expect(fixed.code).toBe(0);
  });

  it("exits 1 against migrations that close the holes by locking everyone out", async () => {
    const locked = join(scratch, "locked");
    cpSync("examples/vulnerable-app/supabase/migrations", locked, { recursive: true });
    writeFileSync(
      join(locked, "20260107000000_lockdown.sql"),
      "revoke all on all tables in schema public from anon, authenticated;\n",
    );
    const r = await run(["verify", join(outDir, "proofs.jsonl"), "--against", locked, ...url]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("BREAKS_ACCESS");
  });

  it("exits 3 when an input changed after the evidence was written", async () => {
    const copy = join(scratch, "copy");
    cpSync("examples/vulnerable-app/supabase/migrations", copy, { recursive: true });
    const first = await run(["rls", copy, "--out", join(scratch, "copy-out"), "--fail-on", "none", ...url]);
    expect(first.code).toBe(0);
    writeFileSync(join(copy, "20260105090000_init.sql"), `${readFileSync(join(copy, "20260105090000_init.sql"), "utf8")}\n-- edited\n`);
    const r = await run(["verify", join(scratch, "copy-out", "proofs.jsonl"), ...url]);
    expect(r.code).toBe(3);
    expect(r.out).toContain("changed since");
  });

  it("exits 0 for the fixed app and writes no fix", async () => {
    const dir = join(scratch, "fixed");
    const r = await run(["rls", FIXED, "--out", dir, ...url]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("No problem could be reproduced");
    expect(() => readFileSync(join(dir, "fix.sql"))).toThrow();
    const contract = decodeContract(readFileSync(join(dir, "verification-contract.json"), "utf8"));
    expect(contract.ok && contract.value.checks).toHaveLength(1);
  });

  it("refuses a database URL that is not loopback, without connecting", async () => {
    const r = await run(["rls", VULN, "--database-url", "postgres://postgres@db.example.com:5432/postgres"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("not a loopback address");
  });

  it("prints JSON that parses and carries the same findings", async () => {
    const r = await run(["rls", VULN, "--json", "--fail-on", "none", ...url]);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).findings.filter((f: { tier: string }) => f.tier === "PROVEN")).toHaveLength(6);
  });
});
