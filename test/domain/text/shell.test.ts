import { describe, expect, it } from "vitest";
import { shellQuote, splitShellWords } from "../../../src/domain/text/shell.js";

/** Small deterministic generator so the property tests are reproducible. */
function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const ALPHABET = [..."abcXYZ019 \t\n\r'\"\\$`;&|<>()*?[]{}~#!%^=:,./-_@+éß日本語😀\u0001\u007f"];

function randomString(next: () => number, maxLength: number): string {
  const length = Math.floor(next() * maxLength);
  let out = "";
  for (let i = 0; i < length; i++) out += ALPHABET[Math.floor(next() * ALPHABET.length)] ?? "";
  return out;
}

describe("shellQuote", () => {
  it("leaves plain words alone", () => {
    expect(shellQuote("proofs.jsonl")).toBe("proofs.jsonl");
    expect(shellQuote("supabase/migrations/0001_init.sql")).toBe("supabase/migrations/0001_init.sql");
    expect(shellQuote("--against")).toBe("--against");
    expect(shellQuote("a=b:c,d@e%f+g")).toBe("a=b:c,d@e%f+g");
  });

  it("quotes the empty string", () => {
    expect(shellQuote("")).toBe("''");
  });

  it("quotes spaces and shell metacharacters in single quotes", () => {
    expect(shellQuote("my file.sql")).toBe("'my file.sql'");
    expect(shellQuote("$(rm -rf ~)")).toBe("'$(rm -rf ~)'");
    expect(shellQuote("a;b")).toBe("'a;b'");
    expect(shellQuote("`id`")).toBe("'`id`'");
    expect(shellQuote("*.sql")).toBe("'*.sql'");
  });

  it("writes an embedded single quote as '\\''", () => {
    expect(shellQuote("it's")).toBe("'it'\\''s'");
    expect(shellQuote("'")).toBe("''\\'''");
  });

  it("rejects a NUL byte", () => {
    expect(() => shellQuote("a\0b")).toThrow(/NUL/);
    expect(() => shellQuote("\0")).toThrow(/NUL/);
  });
});

describe("splitShellWords", () => {
  it("splits plain words on spaces and tabs", () => {
    expect(splitShellWords("proof-audit  verify\tfile.jsonl")).toEqual({ ok: true, value: ["proof-audit", "verify", "file.jsonl"] });
  });

  it("returns no words for an empty or blank line", () => {
    expect(splitShellWords("")).toEqual({ ok: true, value: [] });
    expect(splitShellWords("   ")).toEqual({ ok: true, value: [] });
  });

  it("reads single-quoted words, including empty ones and quote joins", () => {
    expect(splitShellWords("'a b' '' x'y z'w")).toEqual({ ok: true, value: ["a b", "", "xy zw"] });
    expect(splitShellWords("'it'\\''s'")).toEqual({ ok: true, value: ["it's"] });
  });

  it("keeps shell syntax literal inside single quotes", () => {
    expect(splitShellWords("'$(x) `y` ; | & < > ( ) \\ *'")).toEqual({ ok: true, value: ["$(x) `y` ; | & < > ( ) \\ *"] });
  });

  it.each(["a$b", "a`b`", "a;b", "a&b", "a|b", "a<b", "a>b", "(a)", "a\\b", "a\nb", "\"a\"", "a*", "~", "a b #c", "a\rb", "a{b}"])(
    "rejects %j outside quotes",
    (command) => {
      const result = splitShellWords(command);
      expect(result.ok).toBe(false);
    },
  );

  it("rejects an unterminated quote", () => {
    const result = splitShellWords("verify 'oops");
    expect(result.ok).toBe(false);
  });

  it("names a position and never repeats the text", () => {
    const result = splitShellWords("verify x;secret-token");
    expect(result).toEqual({ ok: false, error: "unsupported character at position 8" });
  });

  it("round-trips fixed hostile arguments", () => {
    const args = ["", " ", "'", "''", "a'b", "it's \"fine\"", "$HOME", "`x`", "a\nb", "tab\there", "日本語 😀", "--flag=value with space", "\\", "\\'", "'\\''"];
    const line = args.map(shellQuote).join(" ");
    expect(splitShellWords(line)).toEqual({ ok: true, value: args });
  });

  it("round-trips 2000 random strings without NUL", () => {
    const next = lcg(20240607);
    for (let i = 0; i < 2000; i++) {
      const argv = [randomString(next, 12), randomString(next, 40), randomString(next, 3)];
      const line = argv.map(shellQuote).join(" ");
      const result = splitShellWords(line);
      expect(result).toEqual({ ok: true, value: argv });
    }
  });

  it("never produces a word with anything outside quotes except plain characters or the \\' escape", () => {
    const next = lcg(7);
    for (let i = 0; i < 500; i++) {
      const quoted = shellQuote(randomString(next, 30));
      expect(quoted).toMatch(/^(?:[A-Za-z0-9_@%+=:,./-]+|(?:'[^']*'|\\')+)$/);
    }
  });
});
