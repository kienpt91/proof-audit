import { readFileSync } from "node:fs";
import { loadSqlInputs, readBoundedText, writeOutputs } from "../infrastructure/fs/files.js";
import { runCli, type CliDeps, type TrackedProvider } from "../infrastructure/cli/main.js";
import { DockerSandboxProvider } from "../infrastructure/postgres/docker-provider.js";
import { UrlSandboxProvider } from "../infrastructure/postgres/url-provider.js";
import { SpawnDockerRunner } from "../infrastructure/process/runner.js";

const version: string = (() => {
  const pkg: unknown = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  return typeof pkg === "object" && pkg !== null && "version" in pkg && typeof pkg.version === "string" ? pkg.version : "0.0.0";
})();

/** Wire the real adapters and run the command line. Containers and databases are removed on exit and on SIGINT/SIGTERM. */
export async function main(argv: readonly string[]): Promise<number> {
  const live: TrackedProvider[] = [];
  const track = (p: TrackedProvider): TrackedProvider => {
    live.push(p);
    return p;
  };
  const cleanup = async (signal: NodeJS.Signals): Promise<never> => {
    process.stderr.write(`proof-audit: ${signal}, removing the throwaway database\n`);
    await Promise.all(live.map((p) => p.disposeAll().catch(() => undefined)));
    process.exit(signal === "SIGINT" ? 130 : 143);
  };
  process.once("SIGINT", () => void cleanup("SIGINT"));
  process.once("SIGTERM", () => void cleanup("SIGTERM"));

  const cwd = process.cwd();
  const deps: CliDeps = {
    cwd,
    env: process.env,
    version,
    clock: { now: () => Date.now() },
    loadSql: (paths) => loadSqlInputs(paths, cwd),
    readText: async (path, maxBytes) => (await readBoundedText(path, maxBytes)).content,
    writeOutputs,
    dockerProvider: () =>
      track(new DockerSandboxProvider({ docker: new SpawnDockerRunner(), sleep: (ms) => new Promise((r) => setTimeout(r, ms)), now: () => Date.now() })),
    urlProvider: (endpoint) => track(new UrlSandboxProvider(endpoint)),
    stdout: (text) => void process.stdout.write(text),
    stderr: (text) => void process.stderr.write(text),
  };
  return runCli(argv, deps);
}
