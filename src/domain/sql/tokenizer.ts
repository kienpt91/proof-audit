/**
 * A tolerant SQL tokenizer. It never throws and always makes progress, so any byte sequence yields a
 * token list in time linear in the input. Whitespace and comments are dropped (their newlines still
 * count towards line numbers). Unterminated strings, comments and dollar quotes run to the end of input.
 */

export type TokenKind =
  | "word"
  | "quoted-ident"
  | "string"
  | "dollar-string"
  | "number"
  | "punct"
  | "operator"
  | "meta";

export interface Token {
  readonly kind: TokenKind;
  /** Raw source text. */
  readonly text: string;
  /**
   * words: lower-cased; quoted-ident: unquoted with case preserved; string and dollar-string: contents
   * without delimiters; everything else: the text.
   */
  readonly value: string;
  /** 1-based line of the first character. */
  readonly line: number;
  /** Offset of the first character in the source. */
  readonly start: number;
  /** Offset one past the last character. */
  readonly end: number;
}

const OPERATOR_CHARS = "+-*/<>=~!@#%^&|`?";
const SPECIAL_OPERATOR_CHARS = "~!@#%^&|`?";
const PUNCTUATION = "(),;.[]";

function isIdentStart(c: number): boolean {
  return (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 95 || c >= 128;
}

function isDigit(c: number): boolean {
  return c >= 48 && c <= 57;
}

function isIdentPart(c: number): boolean {
  return isIdentStart(c) || isDigit(c) || c === 36;
}

function isHexDigit(c: number): boolean {
  return isDigit(c) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
}

function isBlank(c: number): boolean {
  return c === 32 || c === 9 || c === 13 || c === 12 || c === 11;
}

function countNewlines(source: string, from: number, to: number): number {
  let count = 0;
  for (let i = from; i < to; i++) {
    if (source.charCodeAt(i) === 10) count++;
  }
  return count;
}

function unescapeBackslash(ch: string): string {
  switch (ch) {
    case "n":
      return "\n";
    case "t":
      return "\t";
    case "r":
      return "\r";
    case "b":
      return "\b";
    case "f":
      return "\f";
    default:
      return ch;
  }
}

interface Scanned {
  readonly end: number;
  readonly value: string;
}

/** Scans a quoted run starting at the opening quote `open`. A doubled quote is an escaped quote. */
function scanDelimited(source: string, open: number, quote: string, backslash: boolean): Scanned {
  const n = source.length;
  let j = open + 1;
  let chunkStart = j;
  let out = "";
  while (j < n) {
    const ch = source[j];
    if (backslash && ch === "\\") {
      if (j + 1 < n) {
        out += source.slice(chunkStart, j) + unescapeBackslash(source[j + 1] ?? "");
        j += 2;
        chunkStart = j;
      } else {
        j++;
      }
      continue;
    }
    if (ch === quote) {
      if (source[j + 1] === quote) {
        out += source.slice(chunkStart, j + 1);
        j += 2;
        chunkStart = j;
        continue;
      }
      out += source.slice(chunkStart, j);
      return { end: j + 1, value: out };
    }
    j++;
  }
  out += source.slice(chunkStart, n);
  return { end: n, value: out };
}

/** Returns the opening delimiter (`$$` or `$tag$`) at `i`, or null when the `$` does not open a dollar quote. */
function dollarTagAt(source: string, i: number): string | null {
  let j = i + 1;
  const first = source.charCodeAt(j);
  if (Number.isNaN(first)) return null;
  if (first === 36) return "$$";
  if (!isIdentStart(first)) return null;
  j++;
  while (j < source.length) {
    const c = source.charCodeAt(j);
    if (c === 36) return source.slice(i, j + 1);
    if (!isIdentStart(c) && !isDigit(c)) return null;
    j++;
  }
  return null;
}

export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  const n = source.length;
  let i = 0;
  let line = 1;
  let atLineStart = true;

  const push = (kind: TokenKind, start: number, end: number, value: string, tokenLine: number): void => {
    tokens.push({ kind, text: source.slice(start, end), value, line: tokenLine, start, end });
  };

  while (i < n) {
    const c = source.charCodeAt(i);
    const next = source.charCodeAt(i + 1);

    if (c === 10) {
      line++;
      i++;
      atLineStart = true;
      continue;
    }
    if (isBlank(c)) {
      i++;
      continue;
    }

    // psql meta-command: a backslash that is the first non-blank character of its line.
    if (c === 92 && atLineStart) {
      let j = source.indexOf("\n", i);
      if (j === -1) j = n;
      let e = j;
      while (e > i && (isBlank(source.charCodeAt(e - 1)) || source.charCodeAt(e - 1) === 10)) e--;
      push("meta", i, e, source.slice(i, e), line);
      i = j;
      atLineStart = false;
      continue;
    }
    atLineStart = false;

    // Comments.
    if (c === 45 && next === 45) {
      const j = source.indexOf("\n", i);
      i = j === -1 ? n : j;
      continue;
    }
    if (c === 47 && next === 42) {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        const d = source.charCodeAt(j);
        if (d === 47 && source.charCodeAt(j + 1) === 42) {
          depth++;
          j += 2;
        } else if (d === 42 && source.charCodeAt(j + 1) === 47) {
          depth--;
          j += 2;
        } else {
          j++;
        }
      }
      line += countNewlines(source, i, j);
      i = j;
      continue;
    }

    const startLine = line;

    // Words, and the string prefixes E'..', B'..', X'..', N'..', U&'..' / U&"..".
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(source.charCodeAt(j))) j++;
      const word = source.slice(i, j);
      const lower = word.toLowerCase();
      const after = source[j];
      if (after === "'" && (lower === "e" || lower === "b" || lower === "x" || lower === "n")) {
        const scanned = scanDelimited(source, j, "'", lower === "e");
        line += countNewlines(source, i, scanned.end);
        push("string", i, scanned.end, scanned.value, startLine);
        i = scanned.end;
        continue;
      }
      if (lower === "u" && after === "&" && (source[j + 1] === '"' || source[j + 1] === "'")) {
        const quote = source[j + 1] ?? '"';
        const scanned = scanDelimited(source, j + 1, quote, false);
        line += countNewlines(source, i, scanned.end);
        push(quote === '"' ? "quoted-ident" : "string", i, scanned.end, scanned.value, startLine);
        i = scanned.end;
        continue;
      }
      push("word", i, j, lower, startLine);
      i = j;
      continue;
    }

    if (c === 39) {
      const scanned = scanDelimited(source, i, "'", false);
      line += countNewlines(source, i, scanned.end);
      push("string", i, scanned.end, scanned.value, startLine);
      i = scanned.end;
      continue;
    }
    if (c === 34) {
      const scanned = scanDelimited(source, i, '"', false);
      line += countNewlines(source, i, scanned.end);
      push("quoted-ident", i, scanned.end, scanned.value, startLine);
      i = scanned.end;
      continue;
    }

    if (c === 36) {
      const tag = dollarTagAt(source, i);
      if (tag !== null) {
        const bodyStart = i + tag.length;
        const close = source.indexOf(tag, bodyStart);
        const end = close === -1 ? n : close + tag.length;
        const value = source.slice(bodyStart, close === -1 ? n : close);
        line += countNewlines(source, i, end);
        push("dollar-string", i, end, value, startLine);
        i = end;
        continue;
      }
      if (isDigit(next)) {
        let j = i + 1;
        while (j < n && isDigit(source.charCodeAt(j))) j++;
        push("word", i, j, source.slice(i, j), startLine);
        i = j;
        continue;
      }
      push("operator", i, i + 1, "$", startLine);
      i++;
      continue;
    }

    // Numbers (a leading dot counts only when it cannot be a qualifier separator).
    const prevChar = i > 0 ? source.charCodeAt(i - 1) : 32;
    const dotNumber = c === 46 && isDigit(next) && !isIdentPart(prevChar) && prevChar !== 34 && prevChar !== 41 && prevChar !== 93;
    if (isDigit(c) || dotNumber) {
      let j = i;
      if (c === 48 && (next === 120 || next === 88) && isHexDigit(source.charCodeAt(i + 2))) {
        j = i + 2;
        while (j < n && isHexDigit(source.charCodeAt(j))) j++;
      } else {
        while (j < n && (isDigit(source.charCodeAt(j)) || source.charCodeAt(j) === 95)) j++;
        if (source.charCodeAt(j) === 46 && isDigit(source.charCodeAt(j + 1))) {
          j++;
          while (j < n && isDigit(source.charCodeAt(j))) j++;
        }
        const e = source.charCodeAt(j);
        if (e === 101 || e === 69) {
          let k = j + 1;
          const sign = source.charCodeAt(k);
          if (sign === 43 || sign === 45) k++;
          if (isDigit(source.charCodeAt(k))) {
            while (k < n && isDigit(source.charCodeAt(k))) k++;
            j = k;
          }
        }
      }
      push("number", i, j, source.slice(i, j), startLine);
      i = j;
      continue;
    }

    if (PUNCTUATION.includes(source[i] ?? "")) {
      push("punct", i, i + 1, source[i] ?? "", startLine);
      i++;
      continue;
    }

    if (c === 58) {
      const len = next === 58 ? 2 : 1;
      push("operator", i, i + len, source.slice(i, i + len), startLine);
      i += len;
      continue;
    }

    if (OPERATOR_CHARS.includes(source[i] ?? "")) {
      let j = i + 1;
      while (j < n && OPERATOR_CHARS.includes(source[j] ?? "")) {
        const a = source.charCodeAt(j);
        const b = source.charCodeAt(j + 1);
        if ((a === 45 && b === 45) || (a === 47 && b === 42)) break;
        j++;
      }
      let run = source.slice(i, j);
      let special = false;
      for (const ch of run) {
        if (SPECIAL_OPERATOR_CHARS.includes(ch)) {
          special = true;
          break;
        }
      }
      if (!special) {
        while (run.length > 1 && (run.endsWith("+") || run.endsWith("-"))) run = run.slice(0, -1);
      }
      push("operator", i, i + run.length, run, startLine);
      i += run.length;
      continue;
    }

    // Anything else (braces, stray backslashes, control characters) is a one-character operator.
    const cp = source.codePointAt(i) ?? c;
    const len = cp > 0xffff ? 2 : 1;
    push("operator", i, i + len, source.slice(i, i + len), startLine);
    i += len;
  }

  return tokens;
}
