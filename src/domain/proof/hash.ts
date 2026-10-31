import { canonicalJson } from "../hash/canonical-json.js";
import { sha256Hex } from "../hash/sha256.js";
import type { Proof } from "./types.js";

export type UnhashedProof = Omit<Proof, "hash">;

/** sha256 over the canonical JSON of every field except `hash`. Equal evidence always has an equal hash. */
export function proofHash(proof: UnhashedProof): string {
  return sha256Hex(canonicalJson(proof));
}

export function sealProof(proof: UnhashedProof): Proof {
  return { ...proof, hash: proofHash(proof) };
}

/** True when the stored hash matches the content. */
export function proofIsIntact(proof: Proof): boolean {
  const { hash, ...rest } = proof;
  return proofHash(rest) === hash;
}
