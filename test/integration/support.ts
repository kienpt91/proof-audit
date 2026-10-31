import { analyzeRls, type AnalyzeRequest } from "../../src/application/analyze.js";
import type { LoadedFile } from "../../src/application/ports.js";
import type { AnalysisReport } from "../../src/domain/analysis/types.js";
import { parseLoopbackUrl, type LoopbackEndpoint } from "../../src/domain/safety/loopback.js";
import { loadSqlInputs } from "../../src/infrastructure/fs/files.js";
import { UrlSandboxProvider } from "../../src/infrastructure/postgres/url-provider.js";

/** Set by scripts/integration.sh; the suites are skipped (and say so) when it is missing. */
export const databaseUrl = process.env.PROOF_AUDIT_DATABASE_URL ?? "";
export const haveDatabase = databaseUrl !== "";

export function endpoint(): LoopbackEndpoint {
  const parsed = parseLoopbackUrl(databaseUrl);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}

export const clock = { now: () => Date.now() };
export const tool = { name: "proof-audit", version: "0.1.0" };

export function sqlFile(path: string, content: string): LoadedFile {
  return { path, content, bytes: Buffer.byteLength(content, "utf8") };
}

export async function exampleFiles(app: "vulnerable-app" | "fixed-app"): Promise<readonly LoadedFile[]> {
  return (await loadSqlInputs([`examples/${app}/supabase/migrations`], process.cwd())).files;
}

export function analyze(files: readonly LoadedFile[], over: Partial<AnalyzeRequest> = {}, statementTimeoutMs?: number): Promise<AnalysisReport> {
  return analyzeRls(
    { files, loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool, ...over },
    { provider: new UrlSandboxProvider(endpoint(), { ...(statementTimeoutMs === undefined ? {} : { statementTimeoutMs }) }), clock },
  );
}
