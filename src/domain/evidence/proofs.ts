import type { InputFileRecord } from "../analysis/types.js";
import { canonicalJson } from "../hash/canonical-json.js";
import { sha256Hex } from "../hash/sha256.js";
import { LIMITS } from "../limits.js";
import { proofIsIntact } from "../proof/hash.js";
import type { Phase, Proof, ProbeActor, ProbeIntent, ProbeKind, Verdict } from "../proof/types.js";
import { err, ok, type Result } from "../result.js";
import { CLIENT_ROLES, COMMANDS } from "../schema/model.js";
import { array, integer, literal, nullable, object, string, type Validator } from "../validate.js";

export const PROOFS_SCHEMA = "proof-audit/proofs@1";
export const PROOFS_SEED = "deterministic-v1";
export const MAX_PROOF_LINES = 20_000;

export interface ProofsMeta {
  readonly tool: { readonly name: string; readonly version: string };
  readonly image: string;
  readonly inputs: readonly InputFileRecord[];
  readonly fixStatements: readonly string[];
  /** Derived from `fixStatements`; `encodeProofsJsonl` computes it and ignores the value given. */
  readonly fixSha256: string | null;
}

/** Digest of the fix statements as recorded: sha256 of the statements joined by a newline, null when there are none. */
export function fixDigest(statements: readonly string[]): string | null {
  return statements.length === 0 ? null : sha256Hex(statements.join("\n"));
}

/**
 * The evidence file: one canonical JSON object per line. Line 1 describes the run, every further line is
 * one proof, `before` proofs first and then `after` proofs, each group in the order given.
 */
export function encodeProofsJsonl(meta: ProofsMeta, proofs: readonly Proof[]): string {
  const lines = [
    canonicalJson({
      type: "meta",
      schema: PROOFS_SCHEMA,
      tool: { name: meta.tool.name, version: meta.tool.version },
      image: meta.image,
      inputs: meta.inputs.map((i) => ({ path: i.path, sha256: i.sha256, bytes: i.bytes })),
      fixStatements: meta.fixStatements,
      fixSha256: fixDigest(meta.fixStatements),
      seed: PROOFS_SEED,
    }),
  ];
  for (const phase of ["before", "after"] as const) {
    for (const proof of proofs) if (proof.phase === phase) lines.push(canonicalJson({ type: "proof", ...proof }));
  }
  return `${lines.join("\n")}\n`;
}

// ---- decoding -----------------------------------------------------------------------------------

const PROBE_KINDS: Record<ProbeKind, true> = {
  "anon-read": true,
  "anon-insert": true,
  "anon-update": true,
  "anon-delete": true,
  "cross-read": true,
  "cross-insert": true,
  "null-owner-insert": true,
  "cross-update": true,
  "cross-delete": true,
  "reassign-owner": true,
  "view-read-anon": true,
  "view-read-cross": true,
  "view-read-own": true,
  "own-read": true,
  "own-insert": true,
  "own-update": true,
  "own-delete": true,
};
const VERDICTS: Record<Verdict, true> = { PROVEN_VULNERABLE: true, NOT_REPRODUCED: true, INCONCLUSIVE: true, ACCESS_OK: true, ACCESS_BROKEN: true };

const probeKinds = Object.keys(PROBE_KINDS) as ProbeKind[];
const verdicts = Object.keys(VERDICTS) as Verdict[];
const hex64 = string({ pattern: /^[0-9a-f]{64}$/, max: 64 });
const shortText = string({ max: 1_000 });

const inputRecord = object({ path: string({ max: 4_096 }), sha256: hex64, bytes: integer() });

const observation: Validator<Proof["observation"]> = (value, path) => {
  const status = typeof value === "object" && value !== null && "status" in value ? value.status : undefined;
  switch (status) {
    case "rows":
      return object({ status: literal("rows"), rows: integer() })(value, path);
    case "error":
      return object({ status: literal("error"), sqlstate: string({ max: 16 }), message: string({ max: 10_000 }) })(value, path);
    case "not-run":
      return object({ status: literal("not-run"), reason: string({ max: 10_000 }) })(value, path);
    default:
      return err(`${path}.status: expected one of rows, error, not-run`);
  }
};

const proofLine = object({
  type: literal("proof"),
  id: shortText,
  subject: shortText,
  subjectKind: literal("table", "view"),
  kind: literal(...probeKinds),
  intent: literal<ProbeIntent>("exploit", "legitimate"),
  command: literal(...COMMANDS),
  actor: literal<ProbeActor>("anon", "user-a"),
  role: literal(...CLIENT_ROLES),
  claims: string({ max: 10_000 }),
  sql: string({ max: LIMITS.maxStatementBytes }),
  title: shortText,
  targetRows: nullable(integer()),
  observation,
  verdict: literal(...verdicts),
  reason: string({ max: 10_000 }),
  phase: literal<Phase>("before", "after"),
  hash: hex64,
});

const metaLine = object({
  type: literal("meta"),
  schema: literal(PROOFS_SCHEMA),
  tool: object({ name: string({ max: 200 }), version: string({ max: 200 }) }),
  image: string({ max: 1_000 }),
  inputs: array(inputRecord, { max: LIMITS.maxSqlFiles }),
  fixStatements: array(string({ max: LIMITS.maxStatementBytes }), { max: LIMITS.maxStatements }),
  fixSha256: nullable(hex64),
  seed: literal(PROOFS_SEED),
});

/** A validator's message may repeat an unknown key the file used; evidence errors never repeat file content. */
export function scrubValidationError(message: string): string {
  return message.replace(/ unexpected key .*$/s, " unexpected key");
}

function parseLine(raw: string, n: number): Result<unknown, string> {
  try {
    return ok(JSON.parse(raw));
  } catch {
    return err(`line ${n}: not valid JSON`);
  }
}

function typeOf(value: unknown): unknown {
  return typeof value === "object" && value !== null && "type" in value ? value.type : undefined;
}

/** Read an evidence file back, rejecting anything that is not exactly what `encodeProofsJsonl` writes and that no longer matches its hashes. */
export function decodeProofsJsonl(text: string): Result<{ meta: ProofsMeta; proofs: Proof[] }, string> {
  if (text.length > LIMITS.maxJsonBytes) return err(`evidence file: larger than ${LIMITS.maxJsonBytes} bytes`);
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) return err("evidence file: missing meta line");
  if (lines.length > MAX_PROOF_LINES + 1) return err(`evidence file: more than ${MAX_PROOF_LINES} proofs`);

  let meta: ProofsMeta | null = null;
  const proofs: Proof[] = [];
  const seen = new Set<string>();
  let afterStarted = false;

  for (let index = 0; index < lines.length; index++) {
    const n = index + 1;
    const raw = lines[index] ?? "";
    if (raw.trim() === "") return err(`line ${n}: blank line`);
    const parsed = parseLine(raw, n);
    if (!parsed.ok) return parsed;
    const kind = typeOf(parsed.value);

    if (index === 0) {
      if (kind !== "meta") return err("evidence file: missing meta line");
      const checked = metaLine(parsed.value, `line ${n}`);
      if (!checked.ok) return err(scrubValidationError(checked.error));
      const { type: _type, schema: _schema, seed: _seed, ...rest } = checked.value;
      if (rest.fixSha256 !== fixDigest(rest.fixStatements)) return err(`line ${n}: fixSha256 does not match fixStatements`);
      meta = rest;
      continue;
    }
    if (kind === "meta") return err(`line ${n}: second meta line`);
    if (kind !== "proof") return err(`line ${n}: expected a proof line`);
    const checked = proofLine(parsed.value, `line ${n}`);
    if (!checked.ok) return err(scrubValidationError(checked.error));
    const { type: _type, ...proof } = checked.value;
    if (!proofIsIntact(proof)) return err(`line ${n}: hash does not match the proof content (evidence was altered)`);
    if (proof.phase === "after") afterStarted = true;
    else if (afterStarted) return err(`line ${n}: a before proof follows after proofs`);
    const key = `${proof.phase}\u0000${proof.id}`;
    if (seen.has(key)) return err(`line ${n}: duplicate proof for the same probe and phase`);
    seen.add(key);
    proofs.push(proof);
  }
  if (meta === null) return err("evidence file: missing meta line");
  return ok({ meta, proofs });
}
