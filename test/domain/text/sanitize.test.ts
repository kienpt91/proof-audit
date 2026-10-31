import { describe, expect, it } from "vitest";
import {
  escapeMarkdown,
  markdownCode,
  markdownFence,
  terminalText,
  truncateCodePoints,
  visibleEscapes,
} from "../../../src/domain/text/sanitize.js";

/** Everything a single-line renderer must never emit, newline included. */
const FORBIDDEN_SINGLE_LINE = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFFE\uFFFF\u{E0000}-\u{E007F}]|[\uD800-\uDFFF]/u;
/** Same, but real newlines and tabs are allowed (fenced blocks). */
const FORBIDDEN_MULTI_LINE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFFE\uFFFF\u{E0000}-\u{E007F}]|[\uD800-\uDFFF]/u;

const PIECES = [
  "a", "Z", " ", "  ", "\n", "\r\n", "\r", "\t", "\u001b[31m", "\u001b[0m", "\u001b]8;;http://e.example\u0007", "\u001b]0;title\u001b\\",
  "\u009b31m", "\u0000", "\u007f", "\u0085", "\u202e", "\u2066", "\u200b", "\u200d", "\u2060", "\ufeff", "\u2028", "\u2029", "\u061c", "\u200e",
  "\ud800", "\udfff", "😀", "é", "漢", "`", "``", "```", "`````", "|", "<b>", "</script>", "&amp;", "&", "[x](y)", "![i](u)", "@all", "# ", "- ", "1. ", "> ",
  "***", "___", "~~", "$$", "=", "\\", "\\`", "http://x.example", "www.x.example", "a@b.example", "\u00ad", "\u{e0041}",
];

/** Deterministic pseudo-random corpus of hostile strings. */
function corpus(count: number): string[] {
  let state = 0x2545f491;
  const next = (): number => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const length = next() % 12;
    let s = "";
    for (let j = 0; j < length; j++) s += PIECES[next() % PIECES.length] ?? "";
    out.push(s);
  }
  return out;
}

const CORPUS = corpus(300);

/** Reads a code span the way CommonMark does and returns its content. */
function readCodeSpan(span: string): string {
  const open = /^`+/.exec(span)?.[0] ?? "";
  expect(open.length).toBeGreaterThan(0);
  expect(span.endsWith(open)).toBe(true);
  let content = span.slice(open.length, span.length - open.length);
  for (const run of content.match(/`+/g) ?? []) expect(run.length).not.toBe(open.length);
  if (content.length > 1 && content.startsWith(" ") && content.endsWith(" ") && content.trim().length > 0) {
    content = content.slice(1, -1);
  }
  return content;
}

describe("visibleEscapes", () => {
  it("leaves printable text untouched", () => {
    const text = "Plain text, ünïcödé, 漢字, emoji 😀, symbols <>&`*_ and \\ backslash.";
    expect(visibleEscapes(text)).toBe(text);
  });

  it("returns the empty string for the empty string", () => {
    expect(visibleEscapes("")).toBe("");
  });

  it("shows every C0 control, including TAB, LF and CR, as \\xNN", () => {
    for (let cp = 0; cp <= 0x1f; cp++) {
      const expected = `\\x${cp.toString(16).toUpperCase().padStart(2, "0")}`;
      expect(visibleEscapes(String.fromCodePoint(cp))).toBe(expected);
    }
  });

  it("shows DEL and every C1 control as \\xNN", () => {
    expect(visibleEscapes("\u007f")).toBe("\\x7F");
    for (let cp = 0x80; cp <= 0x9f; cp++) {
      expect(visibleEscapes(String.fromCodePoint(cp))).toBe(`\\x${cp.toString(16).toUpperCase()}`);
    }
  });

  it("makes an ANSI colour sequence readable and inert", () => {
    const out = visibleEscapes("\u001b[31mred\u001b[0m");
    expect(out).toBe("\\x1B[31mred\\x1B[0m");
    expect(out).not.toContain("\u001b");
  });

  it("neutralises OSC hyperlinks closed by BEL and by ST", () => {
    const bel = visibleEscapes("\u001b]8;;http://evil.example\u0007click\u001b]8;;\u0007");
    expect(bel).toBe("\\x1B]8;;http://evil.example\\x07click\\x1B]8;;\\x07");
    const st = visibleEscapes("\u001b]0;pwned\u001b\\");
    expect(st).toBe("\\x1B]0;pwned\\x1B\\");
    expect(`${bel}${st}`).not.toMatch(FORBIDDEN_SINGLE_LINE);
  });

  it("neutralises the one-byte C1 CSI and an unterminated sequence", () => {
    expect(visibleEscapes("\u009b2J")).toBe("\\x9B2J");
    expect(visibleEscapes("\u001b[")).toBe("\\x1B[");
  });

  it("shows bidi controls as \\u{XXXX}", () => {
    for (const cp of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c]) {
      expect(visibleEscapes(`a${String.fromCodePoint(cp)}b`)).toBe(`a\\u{${cp.toString(16).toUpperCase().padStart(4, "0")}}b`);
    }
  });

  it("shows zero-width characters, BOM and soft hyphen", () => {
    expect(visibleEscapes("a\u200bb\u200cc\u200dd\u2060e\ufefff\u00adg")).toBe(
      "a\\u{200B}b\\u{200C}c\\u{200D}d\\u{2060}e\\u{FEFF}f\\u{00AD}g",
    );
  });

  it("shows line and paragraph separators", () => {
    expect(visibleEscapes("a\u2028b\u2029c")).toBe("a\\u{2028}b\\u{2029}c");
  });

  it("shows Unicode tag characters used for invisible payloads", () => {
    expect(visibleEscapes("x\u{e0041}y")).toBe("x\\u{E0041}y");
  });

  it("shows lone surrogates but keeps valid pairs", () => {
    expect(visibleEscapes("a\ud800b")).toBe("a\\u{D800}b");
    expect(visibleEscapes("a\udfffb")).toBe("a\\u{DFFF}b");
    expect(visibleEscapes("\ud83d")).toBe("\\u{D83D}");
    expect(visibleEscapes("😀")).toBe("😀");
  });

  it("is idempotent and its output is free of forbidden characters over a hostile corpus", () => {
    for (const s of CORPUS) {
      const once = visibleEscapes(s);
      expect(once).not.toMatch(FORBIDDEN_SINGLE_LINE);
      expect(visibleEscapes(once)).toBe(once);
    }
  });
});

describe("terminalText", () => {
  it("shows newlines, carriage returns and tabs as visible escapes on one line", () => {
    expect(terminalText("a\nb\r\nc\td")).toBe("a\\nb\\r\\nc\\td");
  });

  it("neutralises ANSI, bidi and zero-width characters", () => {
    const out = terminalText("\u001b[2Jwipe \u202eevil\u202c \u200bz");
    expect(out).toBe("\\x1B[2Jwipe \\u{202E}evil\\u{202C} \\u{200B}z");
  });

  it("does not truncate when no limit is given or the text fits exactly", () => {
    expect(terminalText("abcdef")).toBe("abcdef");
    expect(terminalText("abcdef", 6)).toBe("abcdef");
  });

  it("truncates by code points with an ellipsis that counts toward the limit", () => {
    expect(terminalText("abcdefgh", 5)).toBe("abcd…");
    expect(Array.from(terminalText("abcdefgh", 5))).toHaveLength(5);
  });

  it("never splits an astral character", () => {
    expect(terminalText("😀😀😀😀😀", 3)).toBe("😀😀…");
  });

  it("never cuts an escape in the middle", () => {
    expect(terminalText("ab\u202ecd", 4)).toBe("ab…");
    expect(terminalText("ab\u202ecd", 11)).toBe("ab\\u{202E}…");
  });

  it("handles degenerate limits", () => {
    expect(terminalText("abc", 0)).toBe("");
    expect(terminalText("abc", -3)).toBe("");
    expect(terminalText("abc", 1)).toBe("…");
  });

  it("always yields one clean line over a hostile corpus", () => {
    for (const s of CORPUS) {
      expect(terminalText(s)).not.toMatch(FORBIDDEN_SINGLE_LINE);
      expect(terminalText(s, 7)).not.toMatch(FORBIDDEN_SINGLE_LINE);
      expect(Array.from(terminalText(s, 7)).length).toBeLessThanOrEqual(7);
    }
  });
});

describe("escapeMarkdown", () => {
  it("backslash-escapes every markdown special", () => {
    for (const ch of "\\`*_{}[]()#+-.!|~$@:=") {
      expect(escapeMarkdown(`a${ch}b`)).toBe(`a\\${ch}b`);
    }
  });

  it("turns < > & into entities instead of backslash escapes", () => {
    expect(escapeMarkdown("<")).toBe("&lt;");
    expect(escapeMarkdown(">")).toBe("&gt;");
    expect(escapeMarkdown("&")).toBe("&amp;");
  });

  it("cannot form a tag, even an event handler", () => {
    const out = escapeMarkdown("<img src=x onerror=alert(1)>");
    expect(out).not.toContain("<");
    expect(out).not.toContain(">");
    expect(out).toBe("&lt;img src\\=x onerror\\=alert\\(1\\)&gt;");
  });

  it("does not let an existing entity decode", () => {
    expect(escapeMarkdown("&lt;script&gt;")).toBe("&amp;lt;script&amp;gt;");
  });

  it("cannot form a link, image or autolink", () => {
    const out = escapeMarkdown("[x](http://evil.example) ![i](u) www.evil.example a@evil.example");
    expect(out).not.toMatch(/(^|[^\\])[[\]()]/);
    expect(out).not.toMatch(/[^\\]:\/\//);
    expect(out).not.toMatch(/(^|[^\\])@/);
    expect(out).not.toContain("www.");
  });

  it("cannot break a table cell", () => {
    expect(escapeMarkdown("a | b |")).toBe("a \\| b \\|");
  });

  it("cannot start a heading, list, quote, rule or setext underline", () => {
    for (const line of ["# h", "## h", "- item", "+ item", "* item", "1. item", "> quote", "---", "***", "___", "===", "    code"]) {
      const out = escapeMarkdown(line);
      expect(out).not.toMatch(/^\s*([#>*+=_-]|\d+\.)/);
    }
  });

  it("is one visible line", () => {
    expect(escapeMarkdown("a\nb\r\nc")).toBe("a\\\\nb\\\\r\\\\nc");
  });

  it("neutralises ANSI and bidi", () => {
    const out = escapeMarkdown("\u001b[31m\u202e");
    expect(out).not.toMatch(FORBIDDEN_SINGLE_LINE);
    expect(out).toBe("\\\\x1B\\[31m\\\\u\\{202E\\}");
  });

  it("leaves ordinary words alone", () => {
    expect(escapeMarkdown("Hello world 42")).toBe("Hello world 42");
  });

  it("truncates before escaping so no escape is left dangling", () => {
    expect(escapeMarkdown("a.b.c.d.e", 4)).toBe("a\\.b…");
    expect(escapeMarkdown("x".repeat(50), 10)).toBe(`${"x".repeat(9)}…`);
  });

  it("never emits raw < > & or line breaks over a hostile corpus", () => {
    for (const s of CORPUS) {
      const out = escapeMarkdown(s);
      expect(out).not.toMatch(FORBIDDEN_SINGLE_LINE);
      expect(out.replace(/&(lt|gt|amp);/g, "")).not.toMatch(/[<>&]/);
      expect(out).not.toMatch(/(^|[^\\])[[\]`|*]/);
    }
  });
});

describe("markdownCode", () => {
  it("wraps plain text in single backticks", () => {
    expect(markdownCode("public.notes")).toBe("`public.notes`");
  });

  it("uses a delimiter longer than any backtick run inside, for runs of 1 to 5", () => {
    for (let n = 1; n <= 5; n++) {
      const text = `a${"`".repeat(n)}b`;
      const span = markdownCode(text);
      expect(span.startsWith("`".repeat(n + 1))).toBe(true);
      expect(readCodeSpan(span)).toBe(text);
    }
  });

  it("uses the longest run when several runs are present", () => {
    const text = "`a``b```c";
    const span = markdownCode(text);
    expect(/^`+/.exec(span)?.[0]).toHaveLength(4);
    expect(readCodeSpan(span)).toBe(text);
  });

  it("pads content that starts or ends with a backtick", () => {
    for (const text of ["`x", "x`", "`", "``"]) {
      expect(readCodeSpan(markdownCode(text))).toBe(text);
    }
    expect(markdownCode("`x")).toBe("`` `x ``");
  });

  it("preserves leading and trailing spaces", () => {
    for (const text of [" x", "x ", " x ", "  "]) {
      expect(readCodeSpan(markdownCode(text))).toBe(text);
    }
  });

  it("turns newlines into spaces and stays on one line", () => {
    expect(markdownCode("a\nb\r\nc")).toBe("`a b  c`");
  });

  it("shows ANSI and bidi as visible text", () => {
    expect(markdownCode("\u001b[31m\u202e")).toBe("`\\x1B[31m\\u{202E}`");
  });

  it("returns a safe span for the empty string", () => {
    expect(markdownCode("")).toBe("` `");
  });

  it("truncates", () => {
    expect(markdownCode("abcdefgh", 4)).toBe("`abc…`");
  });

  it("always round-trips to the visible text over a hostile corpus", () => {
    for (const s of CORPUS) {
      const span = markdownCode(s);
      expect(span).not.toMatch(FORBIDDEN_SINGLE_LINE);
      const flattened = visibleEscapes(s.replace(/[\r\n]/g, " "));
      expect(readCodeSpan(span)).toBe(flattened.length === 0 ? " " : flattened);
    }
  });
});

describe("markdownFence", () => {
  it("fences with three backticks when the content has none", () => {
    expect(markdownFence("select 1", "sql")).toBe("```sql\nselect 1\n```");
  });

  it("makes the fence longer than any backtick run in the content, for runs of 0 to 5", () => {
    for (let n = 0; n <= 5; n++) {
      const content = `before\n${"`".repeat(n)}\nafter`;
      const out = markdownFence(content);
      const fence = /^`+/.exec(out)?.[0] ?? "";
      expect(fence.length).toBe(Math.max(3, n + 1));
      const lines = out.split("\n");
      expect(lines[lines.length - 1]).toBe(fence);
      for (const line of lines.slice(1, -1)) expect(/^`+$/.test(line) && line.length >= fence.length).toBe(false);
    }
  });

  it("keeps real newlines and tabs", () => {
    expect(markdownFence("a\n\tb")).toBe("```\na\n\tb\n```");
  });

  it("normalises CRLF but shows a lone CR", () => {
    expect(markdownFence("a\r\nb\rc")).toBe("```\na\nb\\x0Dc\n```");
  });

  it("neutralises ANSI, bidi, zero-width and separators inside the block", () => {
    const out = markdownFence("x\u001b[31m\u202e\u200b\u2028\u0000y");
    expect(out).toBe("```\nx\\x1B[31m\\u{202E}\\u{200B}\\u{2028}\\x00y\n```");
  });

  it("reduces the info string to safe characters", () => {
    expect(markdownFence("x", "sql\n```evil")).toBe("```sqlevil\nx\n```");
    expect(markdownFence("x", "`<b>`")).toBe("```b\nx\n```");
  });

  it("cannot be closed early by hostile content over a corpus", () => {
    for (const s of CORPUS) {
      const out = markdownFence(s, "sql");
      expect(out).not.toMatch(FORBIDDEN_MULTI_LINE);
      const lines = out.split("\n");
      const fence = /^`+/.exec(lines[0] ?? "")?.[0] ?? "";
      expect(fence.length).toBeGreaterThanOrEqual(3);
      for (const line of lines.slice(1, -1)) {
        const run = /^ {0,3}(`+)\s*$/.exec(line)?.[1];
        if (run !== undefined) expect(run.length).toBeLessThan(fence.length);
      }
      expect(lines[lines.length - 1]).toBe(fence);
    }
  });
});

describe("truncateCodePoints", () => {
  it("returns short text unchanged", () => {
    expect(truncateCodePoints("abc", 3)).toBe("abc");
    expect(truncateCodePoints("abc", 10)).toBe("abc");
  });

  it("ends with an ellipsis within the limit", () => {
    expect(truncateCodePoints("abcdef", 4)).toBe("abc…");
  });

  it("counts astral characters as one", () => {
    expect(truncateCodePoints("😀😀😀😀", 4)).toBe("😀😀😀😀");
    expect(truncateCodePoints("😀😀😀😀", 3)).toBe("😀😀…");
    expect(truncateCodePoints("a😀b😀c", 4)).toBe("a😀b…");
  });

  it("handles zero, one and negative limits", () => {
    expect(truncateCodePoints("abc", 0)).toBe("");
    expect(truncateCodePoints("abc", -1)).toBe("");
    expect(truncateCodePoints("abc", 1)).toBe("…");
  });

  it("never produces more code points than the limit", () => {
    for (const s of CORPUS) expect(Array.from(truncateCodePoints(s, 5)).length).toBeLessThanOrEqual(5);
  });
});
