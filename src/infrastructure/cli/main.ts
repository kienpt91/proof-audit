import { isAbsolute, join, relative, resolve } from "node:path";
import { analyzeRls } from "../../application/analyze.js";
import type { Clock, LoadedFile, LoadedFiles, SandboxProvider } from "../../application/ports.js";
import { renderFindings } from "../../application/report/findings.js";
import { renderJson } from "../../application/report/json.js";
import { renderMarkdown } from "../../application/report/markdown.js";
import { renderPlain } from "../../application/report/plain.js";
import { verifyEvidence } from "../../application/verify.js";
import type { AnalysisReport } from "../../domain/analysis/types.js";
import { parseAuditReport, type ParsedAudit } from "../../domain/audit/import.js";
import { buildContract, encodeContract } from "../../domain/evidence/contract.js";
import { encodeProofsJsonl } from "../../domain/evidence/proofs.js";
import { LIMITS } from "../../domain/limits.js";
import { parseLoopbackUrl, type LoopbackEndpoint } from "../../domain/safety/loopback.js";
import { terminalText } from "../../domain/text/sanitize.js";
import { displayPath, InputError } from "../fs/files.js";
import { parseArgs, USAGE, type Command, type DatabaseChoice } from "./args.js";

export interface TrackedProvider extends SandboxProvider {
  disposeAll(): Promise<void>;
}

export interface CliDeps {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly version: string;
  readonly clock: Clock;
  readonly loadSql: (paths: readonly string[]) => Promise<LoadedFiles>;
  readonly readText: (path: string, maxBytes: number) => Promise<string>;
  /** Writes `files` into `dir` and removes the names in `stale` that are not among them; returns the names removed. */
  readonly writeOutputs: (dir: string, files: Readonly<Record<string, string>>, stale: readonly string[]) => Promise<readonly string[]>;
  /** The throwaway-container provider. */
  readonly dockerProvider: () => TrackedProvider;
  /** A provider for a Postgres server on this machine's loopback interface; only ever called with a validated endpoint. */
  readonly urlProvider: (endpoint: LoopbackEndpoint, options: { readonly yesThisIsThrowaway: boolean }) => TrackedProvider;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

const TOOL = "proof-audit";
const FINDINGS_FILE = "findings.json";

function message(e: unknown): string {
  return terminalText(e instanceof Error ? e.message : "unknown error", 400);
}

function providerFor(database: DatabaseChoice, deps: CliDeps): TrackedProvider | string {
  if (database.kind === "container") return deps.dockerProvider();
  const endpoint = parseLoopbackUrl(database.url);
  if (!endpoint.ok) return endpoint.error;
  const { host, port, database: name, password } = endpoint.value;
  deps.stderr(
    `${TOOL}: using the PostgreSQL server at ${host === "::1" ? "[::1]" : host}:${port} (database ${terminalText(name, 60)}) instead of a throwaway container. ` +
      `It must be a server you started for testing: a database and two roles are created in it for this run and removed afterwards.\n`,
  );
  if (password !== null && database.fromEnv === null) {
    deps.stderr(`${TOOL}: warning: the password in --database-url is visible to other users of this machine in the process list; use --database-url-env instead\n`);
  }
  return deps.urlProvider(endpoint.value, { yesThisIsThrowaway: database.yesThisIsThrowaway });
}

function artifacts(report: AnalysisReport, command: Extract<Command, { kind: "rls" }>, out: string, deps: CliDeps, loaded: LoadedFiles, audit: ParsedAudit | null): { readonly files: Record<string, string>; readonly stale: readonly string[]; readonly notes: readonly string[] } {
  const fix = report.fix?.statements ?? [];
  const proofs = [...report.proofs, ...(report.verification?.after ?? [])];
  const meta = { tool: report.tool, image: report.environment.image, inputs: report.inputs, fixStatements: fix, fixSha256: null };
  const files: Record<string, string> = {
    "report.md": renderMarkdown(report),
    "report.json": renderJson(report),
    "proofs.jsonl": encodeProofsJsonl(meta, proofs),
    "verification-contract.json": encodeContract(
      buildContract({
        tool: report.tool,
        proofsFile: displayPath(join(out, "proofs.jsonl"), deps.cwd),
        againstArgs: command.paths,
        hasProven: report.summary.proven > 0,
      }),
    ),
  };
  if (report.fix) files["fix.sql"] = report.fix.sql;
  // Derived from the report and the migrations; `verify` never reads it.
  const findings = renderFindings(report, loaded.files, audit);
  if (findings.json !== null) files[FINDINGS_FILE] = findings.json;
  return { files, stale: findings.json === null ? [FINDINGS_FILE] : [], notes: findings.notes };
}

async function runRls(command: Extract<Command, { kind: "rls" }>, deps: CliDeps): Promise<number> {
  const provider = providerFor(command.database, deps);
  if (typeof provider === "string") {
    deps.stderr(`${TOOL}: ${provider}\n`);
    return 2;
  }
  let loaded: LoadedFiles;
  let audit: ParsedAudit | null = null;
  try {
    loaded = await deps.loadSql(command.paths);
    if (command.fromAudit !== null) {
      const parsed = parseAuditReport(await deps.readText(command.fromAudit, LIMITS.maxJsonBytes));
      if (!parsed.ok) {
        deps.stderr(`${TOOL}: ${terminalText(parsed.error, 300)}\n`);
        return 2;
      }
      audit = parsed.value;
    }
  } catch (e) {
    deps.stderr(`${TOOL}: ${message(e)}\n`);
    return 2;
  }
  deps.stderr(`${TOOL}: reading ${loaded.files.length} SQL file(s); preparing a throwaway database\n`);
  let report: AnalysisReport;
  try {
    report = await analyzeRls(
      { files: loaded.files, loadWarnings: loaded.warnings, inputsComplete: loaded.complete, audit, proposeFix: command.proposeFix, tool: { name: TOOL, version: deps.version } },
      { provider, clock: deps.clock },
    );
  } catch (e) {
    deps.stderr(`${TOOL}: ${message(e)}\n`);
    return 3;
  } finally {
    await provider.disposeAll();
  }
  deps.stdout(command.format === "json" ? renderJson(report) : command.format === "markdown" ? renderMarkdown(report) : renderPlain(report));
  if (command.out !== null) {
    try {
      const written = artifacts(report, command, command.out, deps, loaded, audit);
      const removed = await deps.writeOutputs(command.out, written.files, written.stale);
      for (const note of written.notes) deps.stderr(`${TOOL}: ${terminalText(note, 600)}\n`);
      for (const name of removed) deps.stderr(`${TOOL}: removed ${name} of an earlier run from ${terminalText(command.out, 200)}: this run wrote none, and the old one does not describe it\n`);
      deps.stderr(`${TOOL}: wrote ${Object.keys(written.files).sort().join(", ")} to ${terminalText(command.out, 200)}\n`);
    } catch (e) {
      deps.stderr(`${TOOL}: ${message(e)}\n`);
      return 2;
    }
  }
  if (report.integrity.status === "INTEGRITY_VIOLATION") return 4;
  if (command.failOn === "proven" && report.summary.proven > 0) return 1;
  return report.complete ? 0 : 3;
}

async function runVerify(command: Extract<Command, { kind: "verify" }>, deps: CliDeps): Promise<number> {
  const provider = providerFor(command.database, deps);
  if (typeof provider === "string") {
    deps.stderr(`${TOOL}: ${provider}\n`);
    return 2;
  }
  let proofsText: string;
  let against: readonly LoadedFile[] | null = null;
  try {
    proofsText = await deps.readText(command.proofs, LIMITS.maxJsonBytes);
    if (command.against) against = (await deps.loadSql(command.against)).files;
  } catch (e) {
    deps.stderr(`${TOOL}: ${message(e)}\n`);
    return 2;
  }
  const root = command.root ?? deps.cwd;
  const readInput = async (path: string): Promise<LoadedFile | null> => {
    // A recorded path is only ever read from inside --root: no `..` and no absolute path that leaves it.
    const target = isAbsolute(path) ? path : join(root, path);
    const inside = relative(resolve(root), resolve(target));
    if (inside === "" || inside.startsWith("..") || isAbsolute(inside)) return null;
    try {
      const text = await deps.readText(target, LIMITS.maxSqlFileBytes);
      return { path, content: text, bytes: Buffer.byteLength(text, "utf8") };
    } catch (e) {
      if (e instanceof InputError) return null;
      throw e;
    }
  };
  try {
    const result = await verifyEvidence({ proofsText, readInput, against }, { provider, clock: deps.clock });
    const head = result.status === "ok" ? "OK" : result.status.toUpperCase();
    deps.stdout(`${head}: ${result.probesChecked} probes replayed\n${result.messages.map((m) => `  ${terminalText(m, 400)}`).join("\n")}\n`);
    return result.status === "ok" ? 0 : result.status === "mismatch" ? 1 : result.status === "invalid" ? 2 : result.status === "integrity" ? 4 : 3;
  } catch (e) {
    deps.stderr(`${TOOL}: ${message(e)}\n`);
    return 3;
  } finally {
    await provider.disposeAll();
  }
}

/** Entry point for the command line. Returns the exit code; never throws and never exits the process. */
export async function runCli(argv: readonly string[], deps: CliDeps): Promise<number> {
  const parsed = parseArgs(argv, deps.env);
  if (!parsed.ok) {
    deps.stderr(`${TOOL}: ${parsed.error}\n\n${USAGE}`);
    return 2;
  }
  const command = parsed.value;
  if (command.kind === "help") {
    deps.stdout(USAGE);
    return 0;
  }
  if (command.kind === "version") {
    deps.stdout(`${TOOL} ${deps.version}\n`);
    return 0;
  }
  try {
    return command.kind === "rls" ? await runRls(command, deps) : await runVerify(command, deps);
  } catch (e) {
    deps.stderr(`${TOOL}: unexpected error: ${message(e)}\n`);
    return 3;
  }
}
