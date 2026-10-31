import { describe, expect, it } from "vitest";
import { analyzeRls } from "../../src/application/analyze.js";
import { loadSqlInputs } from "../../src/infrastructure/fs/files.js";
import { DockerSandboxProvider, POSTGRES_IMAGE } from "../../src/infrastructure/postgres/docker-provider.js";
import { RelayDockerRunner } from "./relay-runner.js";

const relay = process.env.PROOF_AUDIT_RELAY_DIR ?? "";

describe.skipIf(relay === "")("default mode: the throwaway container, driven through the relay", () => {
  it("analyses the vulnerable example, verifies the fix and leaves no container behind", async () => {
    const docker = new RelayDockerRunner(relay);
    const provider = new DockerSandboxProvider({ docker, sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now() });
    const { files } = await loadSqlInputs(["examples/vulnerable-app/supabase/migrations"], process.cwd());
    const report = await analyzeRls(
      { files, loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool: { name: "proof-audit", version: "0.1.0" } },
      { provider, clock: { now: () => Date.now() } },
    );
    expect(report.environment).toEqual({ mode: "docker", image: POSTGRES_IMAGE, postgresVersion: expect.stringMatching(/^16\.14/) });
    expect(report.summary).toMatchObject({ proven: 6, clean: 1 });
    expect(report.verification?.status).toBe("VERIFIED");
    expect(report.complete).toBe(true);
    const verbs = docker.argvs.map((a) => a[0]);
    expect(verbs[0]).toBe("run");
    expect(verbs.at(-1)).toBe("rm");
  });

  it("analyses the fixed example against a second container", async () => {
    const docker = new RelayDockerRunner(relay);
    const provider = new DockerSandboxProvider({ docker, sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now() });
    const { files } = await loadSqlInputs(["examples/fixed-app/supabase/migrations"], process.cwd());
    const report = await analyzeRls(
      { files, loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool: { name: "proof-audit", version: "0.1.0" } },
      { provider, clock: { now: () => Date.now() } },
    );
    expect(report.summary).toMatchObject({ proven: 0, clean: 7 });
  });
});
