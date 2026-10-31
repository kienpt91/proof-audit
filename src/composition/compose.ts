import { readFileSync } from "node:fs";
import { loadSqlInputs, readBoundedText, writeOutputs } from "../infrastructure/fs/files.js";
import { installCleanup } from "../infrastructure/cli/cleanup.js";
import { runCli, type CliDeps, type TrackedProvider } from "../infrastructure/cli/main.js";
import { DockerSandboxProvider } from "../infrastructure/postgres/docker-provider.js";
import { UrlSandboxProvider } from "../infrastructure/postgres/url-provider.js";
import { SpawnDockerRunner } from "../infrastructure/process/runner.js";

const version: string = (() => {
  const pkg: unknown = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  return typeof pkg === "object" && pkg !== null && "version" in pkg && typeof pkg.version === "string" ? pkg.version : "0.0.0";
})();

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Wire the real adapters and run the command line. Containers and databases are removed on exit and on SIGINT/SIGTERM. */
export async function main(argv: readonly string[]): Promise<number> {
  const live: TrackedProvider[] = [];
  const track = (p: TrackedProvider): TrackedProvider => {
    live.push(p);
    return p;
  };
  installCleanup(process, () => live);

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
      track(
        new DockerSandboxProvider({
          docker: new SpawnDockerRunner(),
          sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
          now: () => Date.now(),
          env: process.env,
          pid: process.pid,
          isAlive,
        }),
      ),
    urlProvider: (endpoint, options) => track(new UrlSandboxProvider(endpoint, options)),
    stdout: (text) => void process.stdout.write(text),
    stderr: (text) => void process.stderr.write(text),
  };
  return runCli(argv, deps);
}
