import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../../src/domain/hash/canonical-json.js";
import { sha256Hex } from "../../../src/domain/hash/sha256.js";
import { LIMITS } from "../../../src/domain/limits.js";
import { sealProof } from "../../../src/domain/proof/hash.js";
import type { Proof, ProbeKind } from "../../../src/domain/proof/types.js";
import { decodeProofsJsonl, encodeProofsJsonl, fixDigest, type ProofsMeta } from "../../../src/domain/evidence/proofs.js";

function makeProof(kind: ProbeKind, phase: "before" | "after", over: Partial<Omit<Proof, "hash">> = {}): Proof {
  return sealProof({
    id: `public.notes/${kind}`,
    subject: "public.notes",
    subjectKind: "table",
    kind,
    intent: "exploit",
    command: "select",
    actor: "anon",
    role: "anon",
    claims: '{"role":"anon"}',
    sql: "select * from public.notes",
    title: "Anonymous visitor reads rows",
    targetRows: 2,
    observation: { status: "rows", rows: 2 },
    verdict: "PROVEN_VULNERABLE",
    reason: "the anonymous role read 2 of 2 seeded rows",
    phase,
    ...over,
  });
}

const sha = "a".repeat(64);

function makeMeta(over: Partial<ProofsMeta> = {}): ProofsMeta {
  return {
    tool: { name: "proof-audit", version: "0.1.0" },
    image: "postgres@sha256:" + sha,
    inputs: [{ path: "supabase/migrations/0001_init.sql", sha256: sha, bytes: 1234 }],
    fixStatements: [],
    fixSha256: null,
    ...over,
  };
}

const before = [
  makeProof("anon-read", "before"),
  makeProof("anon-insert", "before", { command: "insert", observation: { status: "error", sqlstate: "42501", message: "new row violates row-level security policy" }, verdict: "NOT_REPRODUCED", targetRows: null, reason: "denied" }),
  makeProof("cross-update", "before", { actor: "user-a", role: "authenticated", observation: { status: "not-run", reason: "no victim rows" }, verdict: "INCONCLUSIVE", reason: "not run" }),
  makeProof("own-read", "before", { intent: "legitimate", actor: "user-a", role: "authenticated", verdict: "ACCESS_OK", reason: "own rows readable" }),
];
const after = [makeProof("anon-read", "after", { observation: { status: "rows", rows: 0 }, verdict: "NOT_REPRODUCED", reason: "denied now" }), makeProof("own-read", "after", { intent: "legitimate", verdict: "ACCESS_BROKEN", observation: { status: "rows", rows: 0 }, reason: "locked out" })];

const fixed = makeMeta({ fixStatements: ["alter table public.notes enable row level security;", "create policy p on public.notes using (true);"] });
const text = encodeProofsJsonl(makeMeta(), [...before, ...after]);
const textWithFix = encodeProofsJsonl(fixed, [...before, ...after]);

function lines(t: string): string[] {
  return t.split("\n").slice(0, -1);
}
function join(ls: readonly string[]): string {
  return `${ls.join("\n")}\n`;
}
function edit(line: string, change: (o: Record<string, unknown>) => void): string {
  const o = JSON.parse(line) as Record<string, unknown>;
  change(o);
  return canonicalJson(o);
}
function failure(t: string): string {
  const r = decodeProofsJsonl(t);
  if (r.ok) throw new Error("expected a decode error");
  return r.error;
}

describe("encodeProofsJsonl", () => {
  it("writes a meta line, then one canonical line per proof, ending with a newline", () => {
    const ls = lines(text);
    expect(ls).toHaveLength(1 + before.length + after.length);
    expect(text.endsWith("\n")).toBe(true);
    for (const l of ls) expect(canonicalJson(JSON.parse(l))).toBe(l);
    expect(JSON.parse(ls[0] as string)).toEqual({
      type: "meta",
      schema: "proof-audit/proofs@1",
      tool: { name: "proof-audit", version: "0.1.0" },
      image: "postgres@sha256:" + sha,
      inputs: [{ path: "supabase/migrations/0001_init.sql", sha256: sha, bytes: 1234 }],
      fixStatements: [],
      fixSha256: null,
      seed: "deterministic-v1",
    });
  });

  it("puts before proofs ahead of after proofs and keeps input order inside each phase", () => {
    const shuffled = [after[1], before[2], after[0], before[0], before[3], before[1]] as Proof[];
    const decoded = decodeProofsJsonl(encodeProofsJsonl(makeMeta(), shuffled));
    expect(decoded.ok && decoded.value.proofs.map((p) => `${p.phase}:${p.kind}`)).toEqual([
      "before:cross-update",
      "before:anon-read",
      "before:own-read",
      "before:anon-insert",
      "after:own-read",
      "after:anon-read",
    ]);
  });

  it("is deterministic and tags proof lines with their type", () => {
    expect(encodeProofsJsonl(makeMeta(), [...before, ...after])).toBe(text);
    expect(JSON.parse(lines(text)[1] as string)).toMatchObject({ type: "proof", kind: "anon-read", phase: "before" });
  });

  it("derives fixSha256 from the statements, ignoring the value passed in", () => {
    const bogus = encodeProofsJsonl({ ...fixed, fixSha256: "b".repeat(64) }, before);
    expect(JSON.parse(lines(bogus)[0] as string).fixSha256).toBe(sha256Hex(fixed.fixStatements.join("\n")));
    expect(decodeProofsJsonl(bogus).ok).toBe(true);
  });

  it("encodes a run with no proofs", () => {
    const empty = encodeProofsJsonl(makeMeta(), []);
    expect(lines(empty)).toHaveLength(1);
  });
});

describe("fixDigest", () => {
  it("is null without statements and the newline-joined digest otherwise", () => {
    expect(fixDigest([])).toBeNull();
    expect(fixDigest(["a", "b"])).toBe(sha256Hex("a\nb"));
    expect(fixDigest(["a\nb"])).toBe(fixDigest(["a", "b"]));
  });
});

describe("decodeProofsJsonl: round trip", () => {
  it("returns exactly what was encoded", () => {
    const decoded = decodeProofsJsonl(text);
    expect(decoded).toEqual({ ok: true, value: { meta: makeMeta(), proofs: [...before, ...after] } });
  });

  it("round-trips fix statements and their digest", () => {
    const decoded = decodeProofsJsonl(textWithFix);
    expect(decoded.ok && decoded.value.meta).toEqual({ ...fixed, fixSha256: sha256Hex(fixed.fixStatements.join("\n")) });
  });

  it("keeps hostile text inside proofs intact", () => {
    const tricky = makeProof("anon-read", "before", { sql: "select '\n\u0000\u2028' -- \"quoted\" \\ end", reason: "line1\nline2 \ud83d\ude00", title: "日本語" });
    const decoded = decodeProofsJsonl(encodeProofsJsonl(makeMeta(), [tricky]));
    expect(decoded.ok && decoded.value.proofs).toEqual([tricky]);
  });

  it("accepts a file without the final newline", () => {
    expect(decodeProofsJsonl(text.slice(0, -1)).ok).toBe(true);
  });
});

describe("decodeProofsJsonl: tampering", () => {
  const ls = lines(text);

  it("rejects an edited field and names the line, not the content", () => {
    const tampered = [...ls];
    tampered[2] = edit(ls[2] as string, (o) => {
      o.verdict = "INCONCLUSIVE";
    });
    expect(failure(join(tampered))).toBe("line 3: hash does not match the proof content (evidence was altered)");
  });

  it("rejects an edited observation", () => {
    const tampered = [...ls];
    tampered[1] = edit(ls[1] as string, (o) => {
      o.observation = { status: "rows", rows: 0 };
    });
    expect(failure(join(tampered))).toContain("line 2:");
  });

  it("rejects an edited hash", () => {
    const tampered = [...ls];
    tampered[1] = edit(ls[1] as string, (o) => {
      o.hash = "0".repeat(64);
    });
    expect(failure(join(tampered))).toContain("line 2: hash does not match");
  });

  it("rejects a proof with its hash removed", () => {
    const tampered = [...ls];
    tampered[1] = edit(ls[1] as string, (o) => {
      delete o.hash;
    });
    expect(failure(join(tampered))).toBe("line 2.hash: missing");
  });

  it("rejects a hash that is not 64 lowercase hex digits", () => {
    const tampered = [...ls];
    tampered[1] = edit(ls[1] as string, (o) => {
      o.hash = "A".repeat(64);
    });
    expect(failure(join(tampered))).toContain("line 2.hash");
  });

  it("rejects a duplicated proof line", () => {
    expect(failure(join([...ls.slice(0, 3), ls[2] as string, ...ls.slice(3)]))).toBe("line 4: duplicate proof for the same probe and phase");
  });

  it("rejects a before proof placed after an after proof", () => {
    const moved = [...ls.slice(0, 1), ...ls.slice(5), ...ls.slice(1, 5)];
    expect(failure(join(moved))).toContain("a before proof follows after proofs");
  });

  it("rejects a second meta line", () => {
    expect(failure(join([ls[0] as string, ls[0] as string, ...ls.slice(1)]))).toBe("line 2: second meta line");
    expect(failure(join([...ls, ls[0] as string]))).toBe(`line ${ls.length + 1}: second meta line`);
  });

  it("rejects a file that does not start with the meta line", () => {
    expect(failure(join(ls.slice(1)))).toBe("evidence file: missing meta line");
    expect(failure(join([...ls.slice(1), ls[0] as string]))).toBe("evidence file: missing meta line");
    expect(failure("")).toBe("evidence file: missing meta line");
    expect(failure("\n")).toBe("line 1: blank line");
  });

  it("rejects a truncated line and does not echo it", () => {
    const cut = [...ls];
    cut[3] = (ls[3] as string).slice(0, 40);
    expect(failure(join(cut))).toBe("line 4: not valid JSON");
    expect(failure(text.slice(0, text.length - 30))).toMatch(/^line \d+: not valid JSON$/);
  });

  it("rejects blank lines inside the file, but not one trailing newline", () => {
    expect(failure(join([ls[0] as string, "", ...ls.slice(1)]))).toBe("line 2: blank line");
    expect(failure(`${text}\n`)).toBe(`line ${ls.length + 1}: blank line`);
  });

  it("rejects lines of an unknown type and non-object lines", () => {
    expect(failure(join([ls[0] as string, '{"type":"note","text":"hi"}']))).toBe("line 2: expected a proof line");
    expect(failure(join([ls[0] as string, "[]"]))).toBe("line 2: expected a proof line");
    expect(failure(join([ls[0] as string, "42"]))).toBe("line 2: expected a proof line");
    expect(failure(join([ls[0] as string, "null"]))).toBe("line 2: expected a proof line");
  });

  it("rejects an unknown schema or seed", () => {
    const wrongSchema = [edit(ls[0] as string, (o) => (o.schema = "proof-audit/proofs@2")), ...ls.slice(1)];
    expect(failure(join(wrongSchema))).toBe("line 1.schema: expected one of proof-audit/proofs@1");
    const wrongSeed = [edit(ls[0] as string, (o) => (o.seed = "random")), ...ls.slice(1)];
    expect(failure(join(wrongSeed))).toContain("line 1.seed");
  });

  it("rejects unknown keys without repeating them", () => {
    const extraProof = [...ls];
    extraProof[1] = edit(ls[1] as string, (o) => (o["SECRET-KEY-NAME"] = 1));
    const proofError = failure(join(extraProof));
    expect(proofError).toBe("line 2: unexpected key");
    const extraMeta = [edit(ls[0] as string, (o) => (o["SECRET-KEY-NAME"] = 1)), ...ls.slice(1)];
    expect(failure(join(extraMeta))).toBe("line 1: unexpected key");
    const nested = [...ls];
    nested[1] = edit(ls[1] as string, (o) => (o.observation = { status: "rows", rows: 1, "SECRET-KEY-NAME": 1 }));
    expect(failure(join(nested))).not.toContain("SECRET");
  });

  it("rejects values outside the enums and types", () => {
    for (const [field, value] of [
      ["kind", "anon-launch"],
      ["verdict", "PROVEN"],
      ["command", "truncate"],
      ["role", "service_role"],
      ["actor", "root"],
      ["phase", "during"],
      ["intent", "both"],
      ["subjectKind", "function"],
      ["targetRows", "2"],
      ["targetRows", -1],
      ["sql", 5],
    ] as const) {
      const tampered = [...ls];
      tampered[1] = edit(ls[1] as string, (o) => (o[field] = value));
      expect(failure(join(tampered)), `${field}=${String(value)}`).toContain(`line 2.${field}`);
    }
  });

  it("rejects a malformed observation", () => {
    for (const observation of [null, [], "rows", { status: "rows" }, { status: "rows", rows: 1.5 }, { status: "weird" }, { status: "error", sqlstate: "42501" }]) {
      const tampered = [...ls];
      tampered[1] = edit(ls[1] as string, (o) => (o.observation = observation));
      expect(failure(join(tampered)), JSON.stringify(observation)).toContain("line 2.observation");
    }
  });

  it("rejects a meta line with bad inputs", () => {
    const badSha = [edit(ls[0] as string, (o) => (o.inputs = [{ path: "a.sql", sha256: "xyz", bytes: 1 }])), ...ls.slice(1)];
    expect(failure(join(badSha))).toContain("line 1.inputs[0].sha256");
    const negative = [edit(ls[0] as string, (o) => (o.inputs = [{ path: "a.sql", sha256: sha, bytes: -1 }])), ...ls.slice(1)];
    expect(failure(join(negative))).toContain("line 1.inputs[0].bytes");
  });

  it.each(["../outside.sql", "a/../../b.sql", "..", "a/..", "a\\..\\b.sql", "x\u0000y.sql", ""])("rejects the recorded input path %j, which could name something outside the directory it is resolved against", (path) => {
    const bad = [edit(ls[0] as string, (o) => (o.inputs = [{ path, sha256: sha, bytes: 1 }])), ...ls.slice(1)];
    expect(failure(join(bad))).toContain("line 1.inputs[0].path");
  });

  it.each(["supabase/migrations/001.sql", "a.sql", "dir/..hidden/x.sql", "/abs/inside/root.sql", "a..b/c.sql"])("accepts the recorded input path %j", (path) => {
    const good = [edit(ls[0] as string, (o) => (o.inputs = [{ path, sha256: sha, bytes: 1 }])), ...ls.slice(1)];
    expect(decodeProofsJsonl(join(good)).ok).toBe(true);
  });
});

describe("decodeProofsJsonl: fixSha256", () => {
  const ls = lines(textWithFix);

  it("rejects fix statements that were edited after the digest was taken", () => {
    const changed = [edit(ls[0] as string, (o) => (o.fixStatements = ["drop table public.notes;"])), ...ls.slice(1)];
    expect(failure(join(changed))).toBe("line 1: fixSha256 does not match fixStatements");
  });

  it("rejects a statement appended to the fix", () => {
    const changed = [edit(ls[0] as string, (o) => (o.fixStatements = [...(o.fixStatements as string[]), "select 1;"])), ...ls.slice(1)];
    expect(failure(join(changed))).toBe("line 1: fixSha256 does not match fixStatements");
  });

  it("rejects a removed digest and a digest without statements", () => {
    const removed = [edit(ls[0] as string, (o) => (o.fixSha256 = null)), ...ls.slice(1)];
    expect(failure(join(removed))).toBe("line 1: fixSha256 does not match fixStatements");
    const orphan = [edit(lines(text)[0] as string, (o) => (o.fixSha256 = sha)), ...lines(text).slice(1)];
    expect(failure(join(orphan))).toBe("line 1: fixSha256 does not match fixStatements");
  });

  it("rejects a digest that is not hex", () => {
    const changed = [edit(ls[0] as string, (o) => (o.fixSha256 = "nope")), ...ls.slice(1)];
    expect(failure(join(changed))).toContain("line 1.fixSha256");
  });
});

describe("decodeProofsJsonl: limits", () => {
  it("rejects a file larger than the JSON cap without parsing it", () => {
    expect(failure("x".repeat(LIMITS.maxJsonBytes + 1))).toBe(`evidence file: larger than ${LIMITS.maxJsonBytes} bytes`);
  });

  it("rejects more than 20000 proof lines before parsing any of them", () => {
    expect(failure("x\n".repeat(20_002))).toBe("evidence file: more than 20000 proofs");
  });

  it("rejects an over-long sql text and an over-long id", () => {
    const ls = lines(text);
    const long = [...ls];
    long[1] = edit(ls[1] as string, (o) => (o.id = "x".repeat(1_001)));
    expect(failure(join(long))).toContain("line 2.id");
    const sql = [...ls];
    sql[1] = edit(ls[1] as string, (o) => (o.sql = "x".repeat(LIMITS.maxStatementBytes + 1)));
    expect(failure(join(sql))).toContain("line 2.sql");
  });

  it("never repeats a hostile payload in any error", () => {
    const ls = lines(text);
    const payload = "SECRET-PAYLOAD";
    const variants = [
      join([...ls.slice(0, 1), edit(ls[1] as string, (o) => (o.reason = payload.repeat(2_000)))]),
      join([...ls.slice(0, 1), edit(ls[1] as string, (o) => (o.kind = payload))]),
      join([...ls.slice(0, 1), `{"type":"proof","x":"${payload}`]),
      join([edit(ls[0] as string, (o) => (o.schema = payload)), ...ls.slice(1)]),
    ];
    for (const v of variants) expect(failure(v)).not.toContain("SECRET");
  });
});
