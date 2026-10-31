import { describe, expect, it } from "vitest";
import { tokenize, type Token } from "../../../src/domain/sql/tokenizer.js";

const kinds = (source: string): string[] => tokenize(source).map((t) => t.kind);
const values = (source: string): string[] => tokenize(source).map((t) => t.value);

function only(source: string): Token {
  const tokens = tokenize(source);
  expect(tokens).toHaveLength(1);
  return tokens[0] as Token;
}

describe("tokenize words, numbers and punctuation", () => {
  it("lower-cases words but keeps the raw text", () => {
    const t = only("SeLeCt");
    expect(t.kind).toBe("word");
    expect(t.value).toBe("select");
    expect(t.text).toBe("SeLeCt");
  });

  it("reports start and end offsets that slice back to the text", () => {
    const source = "  create   table  ";
    for (const t of tokenize(source)) expect(source.slice(t.start, t.end)).toBe(t.text);
  });

  it("splits qualified names on dots", () => {
    expect(values("auth.uid()")).toEqual(["auth", ".", "uid", "(", ")"]);
    expect(kinds("auth.uid()")).toEqual(["word", "punct", "word", "punct", "punct"]);
  });

  it("reads integers, decimals, exponents and hex as single numbers", () => {
    expect(values("1 2.5 .5 3e10 1.5E-3 0xFF")).toEqual(["1", "2.5", ".5", "3e10", "1.5E-3", "0xFF"]);
    expect(kinds("1 2.5 .5 3e10 1.5E-3 0xFF").every((k) => k === "number")).toBe(true);
  });

  it("does not treat the dot of t.1 style qualifiers as a decimal point", () => {
    expect(values("a.b")).toEqual(["a", ".", "b"]);
    expect(kinds("x[1].y")).toEqual(["word", "punct", "number", "punct", "punct", "word"]);
  });

  it("keeps words with dollars and digits together", () => {
    expect(values("col_1$x")).toEqual(["col_1$x"]);
  });

  it("treats positional parameters as one word", () => {
    expect(values("$1 + $12")).toEqual(["$1", "+", "$12"]);
  });

  it("treats non-ASCII letters as identifier characters", () => {
    expect(values("café_é")).toEqual(["café_é"]);
  });
});

describe("tokenize operators", () => {
  it("recognises the multi-character operators", () => {
    expect(values("a::b ->> c -> d <= e >= f <> g != h || i")).toEqual(
      ["a", "::", "b", "->>", "c", "->", "d", "<=", "e", ">=", "f", "<>", "g", "!=", "h", "||", "i"],
    );
  });

  it("splits a trailing minus off an operator without special characters", () => {
    expect(values("a=-1")).toEqual(["a", "=", "-", "1"]);
  });

  it("keeps a trailing minus when the operator has a special character", () => {
    expect(values("a @- b")).toEqual(["a", "@-", "b"]);
  });

  it("stops an operator run at a comment opener", () => {
    expect(values("a =/* c */ b")).toEqual(["a", "=", "b"]);
    expect(values("a =-- c\n b")).toEqual(["a", "=", "b"]);
  });

  it("turns stray characters into one-character operators instead of failing", () => {
    expect(kinds("a { b } c")).toEqual(["word", "operator", "word", "operator", "word"]);
  });

  it("handles an astral character as one token", () => {
    expect(tokenize("😀")).toHaveLength(1);
  });
});

describe("tokenize comments", () => {
  it("drops line comments", () => {
    expect(values("a -- hidden\nb")).toEqual(["a", "b"]);
  });

  it("drops block comments and counts their newlines", () => {
    const tokens = tokenize("a /* x\n y\n */ b");
    expect(tokens.map((t) => t.line)).toEqual([1, 3]);
  });

  it("nests block comments", () => {
    expect(values("a /* outer /* inner */ still comment */ b")).toEqual(["a", "b"]);
  });

  it("runs an unterminated block comment to the end of input", () => {
    expect(values("a /* never closed b c")).toEqual(["a"]);
  });

  it("does not start a comment inside a string", () => {
    expect(values("'-- not a comment' x")).toEqual(["-- not a comment", "x"]);
    expect(values("'/* no */' x")).toEqual(["/* no */", "x"]);
  });

  it("ends a line comment at CRLF line breaks", () => {
    expect(values("a -- c\r\nb")).toEqual(["a", "b"]);
  });
});

describe("tokenize strings", () => {
  it("unescapes doubled quotes", () => {
    expect(only("'it''s'").value).toBe("it's");
  });

  it("keeps backslashes literal in plain strings", () => {
    expect(only("'a\\nb'").value).toBe("a\\nb");
  });

  it("interprets backslash escapes in E strings", () => {
    const t = only("E'it\\'s\\n'");
    expect(t.kind).toBe("string");
    expect(t.value).toBe("it's\n");
    expect(t.text).toBe("E'it\\'s\\n'");
  });

  it("lets an E string span an escaped quote without ending early", () => {
    expect(values("e'a\\'b' c")).toEqual(["a'b", "c"]);
  });

  it("runs an unterminated string to the end of input", () => {
    const t = only("'never ends ; select");
    expect(t.kind).toBe("string");
    expect(t.value).toBe("never ends ; select");
  });

  it("keeps a lone trailing backslash of an unterminated E string", () => {
    expect(only("E'abc\\").value).toBe("abc\\");
  });

  it("reads bit and hex string prefixes as strings", () => {
    expect(kinds("B'101' X'ff' N'x'")).toEqual(["string", "string", "string"]);
  });

  it("does not take a prefix letter that is part of a longer word", () => {
    expect(kinds("price'x'")).toEqual(["word", "string"]);
  });

  it("reads U& strings and identifiers", () => {
    expect(kinds("U&'d\\0061t' U&\"d\\0061t\"")).toEqual(["string", "quoted-ident"]);
  });

  it("counts newlines inside strings for later line numbers", () => {
    const tokens = tokenize("'a\nb\nc' x");
    expect(tokens.map((t) => t.line)).toEqual([1, 3]);
  });
});

describe("tokenize dollar quotes", () => {
  it("reads $$ bodies without delimiters", () => {
    const t = only("$$ select ';' $$");
    expect(t.kind).toBe("dollar-string");
    expect(t.value).toBe(" select ';' ");
  });

  it("reads tagged bodies and only closes on the same tag", () => {
    const t = only("$fn$ a $$ b $other$ c $fn$");
    expect(t.value).toBe(" a $$ b $other$ c ");
  });

  it("runs an unterminated dollar quote to the end of input", () => {
    const t = only("$tag$ never closed ; end");
    expect(t.kind).toBe("dollar-string");
    expect(t.value).toBe(" never closed ; end");
  });

  it("keeps the delimiters in the raw text", () => {
    expect(only("$a$x$a$").text).toBe("$a$x$a$");
  });

  it("does not open a dollar quote for $1 or a tag that starts with a digit", () => {
    expect(kinds("$1$ x")).toEqual(["word", "operator", "word"]);
  });

  it("treats a lone dollar sign as an operator", () => {
    expect(kinds("a $ b")).toEqual(["word", "operator", "word"]);
  });

  it("counts newlines inside the body", () => {
    expect(tokenize("$$a\nb$$ x").map((t) => t.line)).toEqual([1, 2]);
  });
});

describe("tokenize quoted identifiers", () => {
  it("preserves case and drops the quotes", () => {
    const t = only('"MixedCase"');
    expect(t.kind).toBe("quoted-ident");
    expect(t.value).toBe("MixedCase");
  });

  it("unescapes doubled quotes", () => {
    expect(only('"a""b"').value).toBe('a"b');
  });

  it("runs an unterminated quoted identifier to the end of input", () => {
    expect(only('"never').value).toBe("never");
  });

  it("allows semicolons and spaces inside", () => {
    expect(only('"a; b"').value).toBe("a; b");
  });
});

describe("tokenize psql meta-commands", () => {
  it("emits a backslash line as one meta token", () => {
    const tokens = tokenize("\\connect mydb\nselect 1;");
    expect(tokens[0]?.kind).toBe("meta");
    expect(tokens[0]?.text).toBe("\\connect mydb");
    expect(tokens[1]?.value).toBe("select");
    expect(tokens[1]?.line).toBe(2);
  });

  it("allows leading blanks before the backslash", () => {
    expect(tokenize("   \t\\i file.sql")[0]?.kind).toBe("meta");
  });

  it("does not treat a backslash after other text as a meta-command", () => {
    expect(kinds("select \\ 1")).toEqual(["word", "operator", "number"]);
  });

  it("does not look for meta-commands inside strings", () => {
    expect(kinds("'a\n\\b'")).toEqual(["string"]);
  });

  it("drops trailing whitespace from the meta text", () => {
    expect(only("\\q   \r").text).toBe("\\q");
  });
});

describe("tokenize line numbers", () => {
  it("numbers lines from one", () => {
    expect(tokenize("a\nb\n\nc").map((t) => t.line)).toEqual([1, 2, 4]);
  });

  it("counts lines across comments and strings consistently", () => {
    const tokens = tokenize("a -- c\n/* x\n*/ 'p\nq' z");
    expect(tokens.map((t) => [t.value, t.line])).toEqual([["a", 1], ["p\nq", 3], ["z", 4]]);
  });
});

describe("tokenize robustness", () => {
  it("returns no tokens for empty and whitespace-only input", () => {
    expect(tokenize("")).toEqual([]);
    expect(tokenize(" \n\t \r\n")).toEqual([]);
  });

  it("never throws on random bytes", () => {
    let seed = 12345;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed;
    };
    for (let i = 0; i < 200; i++) {
      let s = "";
      for (let j = 0; j < 80; j++) s += String.fromCharCode(next() % 128);
      expect(() => tokenize(s)).not.toThrow();
    }
  });

  it("stays linear on a megabyte of nested comment openers", () => {
    const started = Date.now();
    const tokens = tokenize("/*".repeat(500_000));
    expect(tokens).toEqual([]);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("stays linear on many unterminated dollar quote openers", () => {
    const started = Date.now();
    const tokens = tokenize("$a$ ".repeat(200_000));
    expect(tokens.length).toBeGreaterThan(0);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("stays linear on a long run of quote characters", () => {
    const started = Date.now();
    tokenize("'".repeat(1_000_000));
    tokenize('"'.repeat(1_000_000));
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("stays linear on many short tokens", () => {
    const started = Date.now();
    expect(tokenize("a,".repeat(400_000))).toHaveLength(800_000);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
