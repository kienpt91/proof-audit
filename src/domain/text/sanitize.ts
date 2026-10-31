/**
 * Text from an audited repository is hostile by default: it can carry terminal escape sequences, bidi
 * overrides, zero-width characters, markdown structure or raw HTML. Everything below turns such text into
 * inert, visible text. All functions are pure.
 */

const ELLIPSIS = "…";

type Layout = "escape" | "named" | "keep-lines" | "space-lines";

function hex(cp: number, minWidth: number): string {
  return cp.toString(16).toUpperCase().padStart(minWidth, "0");
}

/** Non-control code points that render as nothing or reorder text. */
function isInvisibleFormat(cp: number): boolean {
  return (
    cp === 0x00ad ||
    cp === 0x061c ||
    cp === 0x180e ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x2028 && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0xfeff ||
    cp === 0xfffe ||
    cp === 0xffff ||
    (cp >= 0xe0000 && cp <= 0xe007f)
  );
}

function tokenFor(ch: string, layout: Layout): string {
  const cp = ch.codePointAt(0) ?? 0;
  if (cp === 0x0a || cp === 0x0d || cp === 0x09) {
    if (layout === "named") return cp === 0x0a ? "\\n" : cp === 0x0d ? "\\r" : "\\t";
    if (layout === "keep-lines" && cp !== 0x0d) return ch;
    if (layout === "space-lines" && cp !== 0x09) return " ";
  }
  if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return `\\x${hex(cp, 2)}`;
  if ((cp >= 0xd800 && cp <= 0xdfff) || isInvisibleFormat(cp)) return `\\u{${hex(cp, 4)}}`;
  return ch;
}

function tokens(text: string, layout: Layout): string[] {
  const out: string[] = [];
  // `for..of` walks code points; a lone surrogate comes through as a single unit.
  for (const ch of text) out.push(tokenFor(ch, layout));
  return out;
}

/** Joins tokens; when the total exceeds `max` code points keeps whole tokens and ends with an ellipsis. */
function joinLimited(parts: readonly string[], max: number | undefined): string {
  if (max === undefined) return parts.join("");
  const limit = Math.floor(max);
  let total = 0;
  const lengths = parts.map((p) => Array.from(p).length);
  for (const l of lengths) total += l;
  if (total <= limit) return parts.join("");
  if (limit <= 0) return "";
  const budget = limit - 1;
  let used = 0;
  let out = "";
  for (let i = 0; i < parts.length; i++) {
    const l = lengths[i] ?? 0;
    if (used + l > budget) break;
    out += parts[i] ?? "";
    used += l;
  }
  return out + ELLIPSIS;
}

/**
 * Replaces every control character (C0, DEL, C1, including TAB, CR and LF), bidi control, zero-width and
 * invisible formatting character, line/paragraph separator and lone surrogate by visible text:
 * `\xNN` for controls, `\u{XXXX}` for the rest. An ANSI sequence therefore stays readable
 * (`\x1B[31m`, `\x1B]8;;http://x\x07`) but can no longer act on a terminal. Printable text is untouched.
 */
export function visibleEscapes(text: string): string {
  return tokens(text, "escape").join("");
}

/** Single-line text safe for a terminal: newlines, CR and TAB show as `\n`, `\r`, `\t`. */
export function terminalText(text: string, maxLength?: number): string {
  return joinLimited(tokens(text, "named"), maxLength);
}

const MD_SPECIALS = "\\`*_{}[]()#+-.!|~$@:=";

function mdEscapeChar(ch: string): string {
  if (ch === "<") return "&lt;";
  if (ch === ">") return "&gt;";
  if (ch === "&") return "&amp;";
  return MD_SPECIALS.includes(ch) ? `\\${ch}` : ch;
}

/**
 * Markdown text with no way to form a tag, entity, link, image, mention, table cell break, heading or
 * list: visible escapes first, then every markdown special is backslash-escaped and `< > &` become
 * entities. Always a single line. The length limit applies before markdown escaping.
 */
export function escapeMarkdown(text: string, maxLength?: number): string {
  const visible = joinLimited(tokens(text, "named"), maxLength);
  let out = "";
  for (const ch of visible) out += mdEscapeChar(ch);
  return out;
}

function longestBacktickRun(s: string): number {
  let longest = 0;
  let run = 0;
  for (const ch of s) {
    run = ch === "`" ? run + 1 : 0;
    if (run > longest) longest = run;
  }
  return longest;
}

/** Inline code span that cannot be closed early by its own content. */
export function markdownCode(text: string, maxLength?: number): string {
  const content = joinLimited(tokens(text, "space-lines"), maxLength);
  const delimiter = "`".repeat(longestBacktickRun(content) + 1);
  if (content.length === 0) return "` `";
  const edgeSpace = (content.startsWith(" ") || content.endsWith(" ")) && content.trim().length > 0;
  const pad = content.startsWith("`") || content.endsWith("`") || edgeSpace;
  return pad ? `${delimiter} ${content} ${delimiter}` : `${delimiter}${content}${delimiter}`;
}

/**
 * Fenced code block. The fence is longer than any backtick run in the content (at least 3). Real newlines
 * and tabs are kept; every other control, ANSI, bidi and invisible character is made visible. The info
 * string is reduced to `[A-Za-z0-9_-]`.
 */
export function markdownFence(content: string, info?: string): string {
  const body = joinLimited(tokens(content.replace(/\r\n/g, "\n"), "keep-lines"), undefined);
  const fence = "`".repeat(Math.max(3, longestBacktickRun(body) + 1));
  const lang = (info ?? "").replace(/[^A-Za-z0-9_-]/g, "");
  return `${fence}${lang}\n${body}\n${fence}`;
}

/** Keeps at most `max` code points; longer text ends with an ellipsis that counts toward `max`. */
export function truncateCodePoints(text: string, max: number): string {
  const limit = Math.floor(max);
  const cps = Array.from(text);
  if (cps.length <= limit) return text;
  if (limit <= 0) return "";
  return cps.slice(0, limit - 1).join("") + ELLIPSIS;
}
