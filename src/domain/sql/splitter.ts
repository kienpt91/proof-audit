/**
 * Splits one SQL file into statements on `;` outside strings, dollar quotes, comments and
 * SQL-standard function bodies (`BEGIN ATOMIC ... END`). Never throws.
 */
import { LIMITS } from "../limits.js";
import type { Warning } from "../schema/model.js";
import type { SourceFile, SqlStatement, StatementKind } from "./statement.js";
import { tokenize, type Token } from "./tokenizer.js";

export interface SplitOptions {
  readonly maxStatementBytes?: number;
  readonly maxStatements?: number;
}

export interface SplitResult {
  readonly statements: SqlStatement[];
  readonly warnings: Warning[];
  /** False when a size or count cap dropped input. */
  readonly complete: boolean;
}

/** UTF-8 length of a string without allocating; lone surrogates count as 3 bytes like the replacement character. */
function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

function isWord(token: Token | undefined, word: string): boolean {
  return token !== undefined && token.kind === "word" && token.value === word;
}

function classify(tokens: readonly Token[], first: number): StatementKind {
  const head = tokens[first];
  if (head === undefined || head.kind !== "word") return "sql";
  switch (head.value) {
    case "begin":
      return isWord(tokens[first + 1], "atomic") ? "sql" : "transaction-control";
    case "start":
      return isWord(tokens[first + 1], "transaction") ? "transaction-control" : "sql";
    case "commit":
    case "end":
    case "rollback":
      return "transaction-control";
    default:
      return "sql";
  }
}

export function splitStatements(file: SourceFile, options: SplitOptions = {}): SplitResult {
  const maxBytes = options.maxStatementBytes ?? LIMITS.maxStatementBytes;
  const maxCount = options.maxStatements ?? LIMITS.maxStatements;
  const tokens = tokenize(file.content);
  const statements: SqlStatement[] = [];
  const warnings: Warning[] = [];
  let complete = true;
  let stopped = false;

  const warn = (line: number, message: string): void => {
    warnings.push({ file: file.path, line, message });
  };

  /** Adds a statement; returns false once the statement cap is hit. */
  const emit = (statement: SqlStatement): boolean => {
    if (statements.length >= maxCount) {
      warn(statement.line, `statement limit of ${maxCount} reached; the rest of the file was not read`);
      complete = false;
      stopped = true;
      return false;
    }
    statements.push(statement);
    return true;
  };

  const flush = (from: number, to: number): void => {
    const first = tokens[from];
    const last = tokens[to - 1];
    if (first === undefined || last === undefined) return;
    const span = last.end - first.start;
    if (span > maxBytes || (span * 3 > maxBytes && utf8Length(file.content.slice(first.start, last.end)) > maxBytes)) {
      warn(first.line, `statement longer than ${maxBytes} bytes was dropped`);
      complete = false;
      return;
    }
    emit({
      file: file.path,
      line: first.line,
      text: file.content.slice(first.start, last.end),
      kind: classify(tokens, from),
    });
  };

  let start = -1;
  /** Nesting inside `BEGIN ATOMIC ... END`: 0 outside a body, 1 directly in it, more inside CASE. */
  let atomic = 0;

  for (let idx = 0; idx < tokens.length && !stopped; idx++) {
    const token = tokens[idx];
    if (token === undefined) break;

    if (token.kind === "meta") {
      if (start >= 0) flush(start, idx);
      start = -1;
      atomic = 0;
      if (stopped) break;
      if (emit({ file: file.path, line: token.line, text: token.text, kind: "psql-meta" })) {
        warn(token.line, "psql meta-command skipped");
      }
      continue;
    }

    if (token.kind === "punct" && token.text === ";" && atomic === 0) {
      if (start >= 0) flush(start, idx);
      start = -1;
      continue;
    }

    if (start < 0) start = idx;

    if (token.kind === "word" && !(tokens[idx - 1]?.text === ".")) {
      if (atomic === 0) {
        if (token.value === "begin" && isWord(tokens[idx + 1], "atomic")) {
          atomic = 1;
          idx++;
        }
      } else if (token.value === "case") {
        atomic++;
      } else if (token.value === "end") {
        atomic--;
      }
    }
  }

  if (start >= 0 && !stopped) flush(start, tokens.length);

  return { statements, warnings, complete };
}
