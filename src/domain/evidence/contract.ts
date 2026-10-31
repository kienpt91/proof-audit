import { LIMITS } from "../limits.js";
import { err, ok, type Result } from "../result.js";
import { shellQuote, splitShellWords } from "../text/shell.js";
import { array, boolean, integer, literal, object, parseJson, string, type Validator } from "../validate.js";
import { scrubValidationError } from "./proofs.js";

export const CONTRACT_SCHEMA = "proof-audit/verification-contract@1";
const COMMAND_NAME = "proof-audit";
const MAX_CHECKS = 20;

/** One command an orchestrator may run and the exit code that means it passed. */
export interface ContractCheck {
  readonly id: string;
  readonly description: string;
  readonly command: string;
  readonly expectedExitCode: number;
  readonly mandatory: boolean;
}

export interface VerificationContract {
  readonly schema: typeof CONTRACT_SCHEMA;
  readonly tool: { readonly name: string; readonly version: string };
  readonly checks: readonly ContractCheck[];
}

export interface ContractInput {
  readonly tool: { readonly name: string; readonly version: string };
  /** Path of the evidence file as it should appear in the commands. */
  readonly proofsFile: string;
  /** The migration paths as the user gave them, for `--against`. */
  readonly againstArgs: readonly string[];
  /** Whether any probe was proven; only then is there a fix to check. */
  readonly hasProven: boolean;
}

function command(...args: readonly string[]): string {
  return [COMMAND_NAME, ...args.map(shellQuote)].join(" ");
}

/** The checks a reader (or an orchestrator) runs to confirm the evidence and, once fixed, the fix. Throws on a NUL byte in a path. */
export function buildContract(input: ContractInput): VerificationContract {
  const checks: ContractCheck[] = [
    {
      id: "evidence-reproduces",
      description: "Re-runs every recorded probe in a fresh throwaway database and compares the results with the recorded verdicts.",
      command: command("verify", input.proofsFile),
      expectedExitCode: 0,
      mandatory: true,
    },
  ];
  if (input.hasProven) {
    if (input.againstArgs.length === 0) throw new Error("a fix check needs at least one migration path for --against");
    checks.push({
      id: "fix-closes-proven-holes",
      description: "Re-runs the recorded probes against the current migrations; passes only when every probe that was proven is now denied and the legitimate-access probes still succeed.",
      command: command("verify", input.proofsFile, "--against", ...input.againstArgs),
      expectedExitCode: 0,
      mandatory: true,
    });
  }
  return { schema: CONTRACT_SCHEMA, tool: { name: input.tool.name, version: input.tool.version }, checks };
}

/** 2-space JSON with the keys in the documented order and a closing newline. */
export function encodeContract(c: VerificationContract): string {
  const doc = {
    schema: c.schema,
    tool: { name: c.tool.name, version: c.tool.version },
    checks: c.checks.map((check) => ({
      id: check.id,
      description: check.description,
      command: check.command,
      expectedExitCode: check.expectedExitCode,
      mandatory: check.mandatory,
    })),
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/** Only `proof-audit verify <args>` made of plain and single-quoted words may be run from a contract. */
const verifyCommand: Validator<string> = (value, path) => {
  const text = string({ min: 1, max: 32_768 })(value, path);
  if (!text.ok) return text;
  if (text.value.includes("\0")) return err(`${path}: contains a NUL byte`);
  const words = splitShellWords(text.value);
  if (!words.ok) return err(`${path}: ${words.error}`);
  if (words.value.length < 3 || words.value[0] !== COMMAND_NAME || words.value[1] !== "verify") {
    return err(`${path}: expected a '${COMMAND_NAME} verify <file> ...' command`);
  }
  return ok(text.value);
};

const checkShape = object({
  id: string({ pattern: /^[a-z0-9][a-z0-9-]*$/, max: 64 }),
  description: string({ max: 2_000 }),
  command: verifyCommand,
  expectedExitCode: integer({ max: 255 }),
  mandatory: boolean,
});

const contractShape = object({
  schema: literal(CONTRACT_SCHEMA),
  tool: object({ name: string({ max: 200 }), version: string({ max: 200 }) }),
  checks: array(checkShape, { max: MAX_CHECKS }),
});

/** Read a contract back. Strict: unknown keys, odd commands and duplicate ids are errors, and messages never repeat file content. */
export function decodeContract(text: string): Result<VerificationContract, string> {
  const parsed = parseJson(text, contractShape, { maxBytes: LIMITS.maxJsonBytes, label: "contract" });
  if (!parsed.ok) return err(scrubValidationError(parsed.error));
  const { schema, tool, checks } = parsed.value;
  if (checks.length === 0) return err("contract.checks: expected at least one check");
  const ids = new Set<string>();
  for (const check of checks) {
    if (ids.has(check.id)) return err("contract.checks: duplicate check id");
    ids.add(check.id);
  }
  return ok({ schema, tool, checks });
}
