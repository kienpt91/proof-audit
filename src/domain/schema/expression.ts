/**
 * Static facts about a policy or check expression: does it fold to a constant, does it look at the
 * caller, which columns does it tie to the caller. Works on hand-written SQL and on the normalised text
 * Postgres prints (`pg_get_expr`): extra parentheses, `( SELECT auth.uid() AS uid)`, `'x'::text`.
 *
 * Boolean structure is parsed from tokens, not regexes. Anything that is not understood is treated
 * conservatively: it never folds to a constant and binds no column.
 */
import { tokenize, type Token } from "../sql/tokenizer.js";

export interface ExpressionFacts {
  /** Folds to TRUE for every row: `true`, `1 = 1`, `x OR true`, `NOT false`, ... */
  readonly alwaysTrue: boolean;
  /** Folds to FALSE (or NULL, which a policy treats as no access) for every row. */
  readonly alwaysFalse: boolean;
  /** Mentions `auth.uid()`, `auth.jwt()`, `auth.role()`, `auth.email()`, `current_setting('request.jwt...')` or `current_user`. */
  readonly usesCallerIdentity: boolean;
  /** Columns directly compared with a caller-identity value (see {@link analyzeExpression}). */
  readonly callerBoundColumns: string[];
  /** Columns that appear as identifiers, as spelled in the `columns` argument. */
  readonly mentionedColumns: string[];
}

type Tri = "true" | "false" | "null" | "unknown";

type Literal =
  | { readonly t: "bool"; readonly v: boolean }
  | { readonly t: "num"; readonly v: number }
  | { readonly t: "str"; readonly v: string }
  | { readonly t: "null" };

interface Context {
  readonly toks: readonly Token[];
  /** For an opening `(` or `[`, the index of its closer; -1 when unclosed or not an opener. */
  readonly match: Int32Array;
  /** Lower-case column name to its spelling in the caller's list. */
  readonly columns: ReadonlyMap<string, string>;
  /** Accept any identifier as a column (used inside membership subqueries). */
  readonly acceptAll: boolean;
  /** Lower-case names of columns found bound to the caller. */
  readonly bound: Set<string>;
}

/** Recursion limit: beyond it a sub-expression is unknown, which keeps hostile nesting cheap. */
const MAX_DEPTH = 100;

const COMPARISONS: Record<string, true> = { "=": true, "<>": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true };
const JSON_OPS: Record<string, true> = { "->": true, "->>": true, "#>": true, "#>>": true };
const SUBQUERY_END: Record<string, true> = {
  group: true, order: true, limit: true, having: true, union: true, except: true, intersect: true, window: true, offset: true,
  fetch: true, for: true,
};
/** Words after a table name that are clause keywords, not an alias. */
const NOT_ALIAS: Record<string, true> = {
  where: true, on: true, using: true, join: true, inner: true, left: true, right: true, full: true, cross: true, natural: true,
  group: true, order: true, limit: true, having: true, union: true, except: true, intersect: true, window: true, offset: true,
  fetch: true, for: true, and: true, or: true, not: true, lateral: true,
};
const TEXT_TYPES: Record<string, true> = {
  text: true, varchar: true, "character varying": true, character: true, char: true, bpchar: true, name: true, citext: true,
};
const NUMBER_TYPES: Record<string, true> = {
  int: true, int2: true, int4: true, int8: true, integer: true, smallint: true, bigint: true, numeric: true, decimal: true,
  real: true, float: true, float4: true, float8: true, "double precision": true,
};
const TRUE_STRINGS: Record<string, true> = { t: true, true: true, y: true, yes: true, on: true, "1": true };
const FALSE_STRINGS: Record<string, true> = { f: true, false: true, n: true, no: true, off: true, "0": true };

function isIdent(t: Token | undefined): t is Token & { readonly kind: "word" | "quoted-ident" } {
  return t !== undefined && (t.kind === "word" || t.kind === "quoted-ident");
}

/** Lower-case spelling of an identifier token. */
function identName(t: Token): string {
  return t.kind === "word" ? t.value : t.value.toLowerCase();
}

function isWord(t: Token | undefined, word: string): boolean {
  return t !== undefined && t.kind === "word" && t.value === word;
}

function isPunct(t: Token | undefined, ch: string): boolean {
  return t !== undefined && t.kind === "punct" && t.text === ch;
}

function matchGroups(toks: readonly Token[]): Int32Array {
  const match = new Int32Array(toks.length).fill(-1);
  const stack: number[] = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t === undefined || t.kind !== "punct") continue;
    if (t.text === "(" || t.text === "[") {
      stack.push(i);
    } else if (t.text === ")" || t.text === "]") {
      const open = stack.pop();
      if (open !== undefined) match[open] = i;
    }
  }
  return match;
}

/** Closer of the group opening at `i` when it lies inside `[.., hi)`, else -1. */
function closerIn(ctx: Context, i: number, hi: number): number {
  const m = ctx.match[i] ?? -1;
  return m >= 0 && m < hi ? m : -1;
}

/**
 * First index in `[lo, hi)` at nesting depth zero (outside groups and CASE..END) whose token satisfies
 * `pred`; -1 when none. An unclosed group swallows the rest of the range.
 */
function findTop(ctx: Context, lo: number, hi: number, pred: (t: Token, i: number) => boolean, last = false): number {
  let found = -1;
  let caseDepth = 0;
  for (let i = lo; i < hi; i++) {
    const t = ctx.toks[i];
    if (t === undefined) break;
    if (t.kind === "punct" && (t.text === "(" || t.text === "[")) {
      const m = closerIn(ctx, i, hi);
      if (m < 0) break;
      i = m;
      continue;
    }
    if (t.kind === "word" && !isPunct(ctx.toks[i - 1], ".")) {
      if (t.value === "case") caseDepth++;
      else if (t.value === "end") caseDepth = Math.max(0, caseDepth - 1);
    }
    if (caseDepth === 0 && pred(t, i)) {
      if (!last) return i;
      found = i;
    }
  }
  return found;
}

/** Splits `[lo, hi)` on a top-level `and` / `or` (an `and` that belongs to `BETWEEN` does not split). */
function splitTop(ctx: Context, lo: number, hi: number, word: "and" | "or"): Array<[number, number]> {
  const parts: Array<[number, number]> = [];
  let from = lo;
  let between = 0;
  let caseDepth = 0;
  for (let i = lo; i < hi; i++) {
    const t = ctx.toks[i];
    if (t === undefined) break;
    if (t.kind === "punct" && (t.text === "(" || t.text === "[")) {
      const m = closerIn(ctx, i, hi);
      if (m < 0) break;
      i = m;
      continue;
    }
    if (t.kind !== "word" || isPunct(ctx.toks[i - 1], ".")) continue;
    if (t.value === "case") caseDepth++;
    else if (t.value === "end") caseDepth = Math.max(0, caseDepth - 1);
    else if (caseDepth === 0) {
      if (word === "and" && t.value === "between") between++;
      else if (t.value === word) {
        if (word === "and" && between > 0) {
          between--;
        } else {
          parts.push([from, i]);
          from = i + 1;
        }
      }
    }
  }
  parts.push([from, hi]);
  return parts;
}

function startsSubquery(ctx: Context, open: number): boolean {
  const next = ctx.toks[open + 1];
  return isWord(next, "select") || isWord(next, "with");
}

/** True when `[lo, hi)` is one parenthesised group that is not a subquery. */
function isPlainGroup(ctx: Context, lo: number, hi: number): boolean {
  return isPunct(ctx.toks[lo], "(") && closerIn(ctx, lo, hi) === hi - 1 && !startsSubquery(ctx, lo);
}

function orTri(parts: readonly Tri[]): Tri {
  if (parts.includes("true")) return "true";
  if (parts.includes("unknown")) return "unknown";
  if (parts.includes("null")) return "null";
  return "false";
}

function andTri(parts: readonly Tri[]): Tri {
  if (parts.includes("false")) return "false";
  if (parts.includes("unknown")) return "unknown";
  if (parts.includes("null")) return "null";
  return "true";
}

function notTri(t: Tri): Tri {
  if (t === "true") return "false";
  if (t === "false") return "true";
  return t;
}

/** Type name after `::` or `AS`: the words of `[lo, hi)` joined, parameters and array marks dropped. */
function castTypeName(ctx: Context, lo: number, hi: number): string {
  const words: string[] = [];
  for (let i = lo; i < hi; i++) {
    const t = ctx.toks[i];
    if (t === undefined) break;
    if (t.kind === "word") words.push(t.value);
    else if (t.kind === "quoted-ident") words.push(t.value.toLowerCase());
    else if (isPunct(t, "(") || isPunct(t, "[")) {
      const m = closerIn(ctx, i, hi);
      if (m < 0) break;
      i = m;
    }
  }
  // `pg_catalog.text` and the like: keep the last dotted component.
  return words.join(" ").replace(/^(?:[\w$]+ )*?(pg_catalog|public) /, "");
}

function applyCast(lit: Literal, type: string): Literal | undefined {
  if (lit.t === "null") return lit;
  const isBool = type === "boolean" || type === "bool";
  if (lit.t === "bool") return isBool ? lit : undefined;
  if (lit.t === "str") {
    if (isBool) {
      const s = lit.v.trim().toLowerCase();
      if (TRUE_STRINGS[s] === true) return { t: "bool", v: true };
      if (FALSE_STRINGS[s] === true) return { t: "bool", v: false };
      return undefined;
    }
    return TEXT_TYPES[type] === true ? lit : undefined;
  }
  return NUMBER_TYPES[type] === true ? lit : undefined;
}

function parseLiteral(ctx: Context, lo0: number, hi0: number): Literal | undefined {
  let lo = lo0;
  let hi = hi0;
  for (let guard = 0; guard < MAX_DEPTH; guard++) {
    if (lo >= hi) return undefined;
    if (isPlainGroup(ctx, lo, hi)) {
      lo++;
      hi--;
      continue;
    }
    const cast = findTop(ctx, lo, hi, (t) => t.kind === "operator" && t.text === "::", true);
    if (cast > lo) {
      const inner = parseLiteral(ctx, lo, cast);
      return inner === undefined ? undefined : applyCast(inner, castTypeName(ctx, cast + 1, hi));
    }
    if (isWord(ctx.toks[lo], "cast") && isPunct(ctx.toks[lo + 1], "(") && closerIn(ctx, lo + 1, hi) === hi - 1) {
      const as = findTop(ctx, lo + 2, hi - 1, (t) => isWord(t, "as"));
      if (as < 0) return undefined;
      const inner = parseLiteral(ctx, lo + 2, as);
      return inner === undefined ? undefined : applyCast(inner, castTypeName(ctx, as + 1, hi - 1));
    }
    break;
  }
  const first = ctx.toks[lo];
  if (first === undefined) return undefined;
  if (hi - lo === 1) {
    if (first.kind === "word") {
      if (first.value === "true") return { t: "bool", v: true };
      if (first.value === "false") return { t: "bool", v: false };
      if (first.value === "null") return { t: "null" };
      return undefined;
    }
    if (first.kind === "string" || first.kind === "dollar-string") return { t: "str", v: first.value };
    if (first.kind === "number") {
      const v = Number(first.text.replace(/_/g, ""));
      return Number.isNaN(v) ? undefined : { t: "num", v };
    }
    return undefined;
  }
  if (hi - lo === 2 && first.kind === "operator" && (first.text === "-" || first.text === "+")) {
    const n = ctx.toks[lo + 1];
    if (n !== undefined && n.kind === "number") {
      const v = Number(n.text.replace(/_/g, ""));
      return Number.isNaN(v) ? undefined : { t: "num", v: first.text === "-" ? -v : v };
    }
  }
  return undefined;
}

function foldComparison(a: Literal | undefined, b: Literal | undefined, op: string): Tri {
  if (a === undefined || b === undefined) return "unknown";
  if (a.t === "null" || b.t === "null") return "null";
  const equality = op === "=" || op === "<>" || op === "!=";
  let cmp: number;
  if (a.t === "num" && b.t === "num") {
    cmp = a.v === b.v ? 0 : a.v < b.v ? -1 : 1;
  } else if (equality && a.t === "str" && b.t === "str") {
    cmp = a.v === b.v ? 0 : 1;
  } else if (equality && a.t === "bool" && b.t === "bool") {
    cmp = a.v === b.v ? 0 : 1;
  } else {
    return "unknown";
  }
  let holds: boolean;
  switch (op) {
    case "=":
      holds = cmp === 0;
      break;
    case "<>":
    case "!=":
      holds = cmp !== 0;
      break;
    case "<":
      holds = cmp < 0;
      break;
    case ">":
      holds = cmp > 0;
      break;
    case "<=":
      holds = cmp <= 0;
      break;
    default:
      holds = cmp >= 0;
  }
  return holds ? "true" : "false";
}

/** The argument tokens of `name ( first-arg ...)` when `[lo, hi)` is exactly that call; `[start, end)` of the first argument. */
function firstArgOfCall(ctx: Context, lo: number, hi: number, name: string): [number, number] | null {
  if (!isWord(ctx.toks[lo], name) || !isPunct(ctx.toks[lo + 1], "(") || closerIn(ctx, lo + 1, hi) !== hi - 1) return null;
  const comma = findTop(ctx, lo + 2, hi - 1, (t) => isPunct(t, ","));
  return [lo + 2, comma < 0 ? hi - 1 : comma];
}

/** `schema . fn ( )` over exactly `[lo, hi)`. */
function isAuthCall(ctx: Context, lo: number, hi: number, fn: string): boolean {
  const t = ctx.toks;
  return (
    hi - lo === 5 &&
    isIdent(t[lo]) && identName(t[lo] as Token) === "auth" &&
    isPunct(t[lo + 1], ".") &&
    isIdent(t[lo + 2]) && identName(t[lo + 2] as Token) === fn &&
    isPunct(t[lo + 3], "(") &&
    isPunct(t[lo + 4], ")")
  );
}

/** `auth.jwt()` or `current_setting('request.jwt.claims'...)` over exactly `[lo, hi)`. */
function isClaimsSource(ctx: Context, lo0: number, hi0: number): boolean {
  let lo = lo0;
  let hi = hi0;
  for (let guard = 0; guard < MAX_DEPTH * 4 && lo < hi; guard++) {
    if (isPlainGroup(ctx, lo, hi)) {
      lo++;
      hi--;
      continue;
    }
    const cast = findTop(ctx, lo, hi, (t) => t.kind === "operator" && t.text === "::", true);
    if (cast > lo) {
      hi = cast;
      continue;
    }
    const op = findTop(ctx, lo, hi, (t) => t.kind === "operator" && JSON_OPS[t.text] === true, true);
    if (op > lo) {
      hi = op;
      continue;
    }
    break;
  }
  if (isAuthCall(ctx, lo, hi, "jwt")) return true;
  const arg = firstArgOfCall(ctx, lo, hi, "current_setting");
  const s = arg === null ? undefined : ctx.toks[arg[0]];
  return s !== undefined && s.kind === "string" && s.value.startsWith("request.jwt.claims");
}

/** Is `[lo, hi)` a value that identifies the caller (`auth.uid()`, a JWT claim, ...)? */
function isIdentityValue(ctx: Context, lo0: number, hi0: number): boolean {
  let lo = lo0;
  let hi = hi0;
  for (let guard = 0; guard < MAX_DEPTH * 4; guard++) {
    if (lo >= hi) return false;
    if (isPlainGroup(ctx, lo, hi)) {
      lo++;
      hi--;
      continue;
    }
    // Scalar subquery with no table: `( SELECT auth.uid() AS uid)`.
    if (isPunct(ctx.toks[lo], "(") && closerIn(ctx, lo, hi) === hi - 1 && isWord(ctx.toks[lo + 1], "select")) {
      let end = hi - 1;
      const as = ctx.toks[end - 2];
      if (isWord(as, "as") && isIdent(ctx.toks[end - 1])) end -= 2;
      if (findTop(ctx, lo + 2, end, (t) => isWord(t, "from") || isWord(t, "where")) >= 0) return false;
      lo += 2;
      hi = end;
      continue;
    }
    // A JSON path into the claims: `auth.jwt() -> 'app_metadata' ->> 'org_id'`. Checked before casts, which bind tighter.
    const op = findTop(ctx, lo, hi, (t) => t.kind === "operator" && JSON_OPS[t.text] === true, true);
    if (op > lo) return isClaimsSource(ctx, lo, op);
    const cast = findTop(ctx, lo, hi, (t) => t.kind === "operator" && t.text === "::", true);
    if (cast > lo) {
      hi = cast;
      continue;
    }
    if (isWord(ctx.toks[lo], "cast") && isPunct(ctx.toks[lo + 1], "(") && closerIn(ctx, lo + 1, hi) === hi - 1) {
      const as = findTop(ctx, lo + 2, hi - 1, (t) => isWord(t, "as"));
      if (as < 0) return false;
      hi = as;
      lo += 2;
      continue;
    }
    const nullif = firstArgOfCall(ctx, lo, hi, "nullif");
    if (nullif !== null) {
      [lo, hi] = nullif;
      continue;
    }
    break;
  }
  if (isAuthCall(ctx, lo, hi, "uid") || isAuthCall(ctx, lo, hi, "email")) return true;
  const arg = firstArgOfCall(ctx, lo, hi, "current_setting");
  const s = arg === null ? undefined : ctx.toks[arg[0]];
  return s !== undefined && s.kind === "string" && s.value.startsWith("request.jwt.claim.");
}

/** Is `[lo, hi)` a list or subquery whose members are all the caller (or, for a subquery, filtered to the caller)? */
function isIdentityCollection(ctx: Context, lo0: number, hi0: number): boolean {
  let lo = lo0;
  let hi = hi0;
  for (let guard = 0; guard < MAX_DEPTH && lo < hi; guard++) {
    if (isPunct(ctx.toks[lo], "(") && closerIn(ctx, lo, hi) === hi - 1) {
      if (startsSubquery(ctx, lo)) return subqueryFiltersByCaller(ctx, lo + 1, hi - 1);
      const items = commaItems(ctx, lo + 1, hi - 1);
      const only = items[0];
      if (items.length === 1 && only !== undefined) {
        [lo, hi] = only;
        continue;
      }
      return items.every(([a, b]) => isIdentityValue(ctx, a, b));
    }
    break;
  }
  if (lo >= hi) return false;
  if (isWord(ctx.toks[lo], "array") && isPunct(ctx.toks[lo + 1], "[") && closerIn(ctx, lo + 1, hi) === hi - 1) {
    return commaItems(ctx, lo + 2, hi - 1).every(([a, b]) => isIdentityValue(ctx, a, b));
  }
  return isIdentityValue(ctx, lo, hi);
}

function commaItems(ctx: Context, lo: number, hi: number): Array<[number, number]> {
  const items: Array<[number, number]> = [];
  let from = lo;
  for (;;) {
    const comma = findTop(ctx, from, hi, (t) => isPunct(t, ","));
    if (comma < 0) break;
    items.push([from, comma]);
    from = comma + 1;
  }
  items.push([from, hi]);
  return items;
}

/** Does the `WHERE` of the subquery in `[lo, hi)` compare something with the caller's identity? */
function subqueryFiltersByCaller(ctx: Context, lo: number, hi: number): boolean {
  const where = findTop(ctx, lo, hi, (t) => isWord(t, "where"));
  if (where < 0) return false;
  const stop = findTop(ctx, where + 1, hi, (t) => t.kind === "word" && SUBQUERY_END[t.value] === true);
  const sub: Context = { ...ctx, acceptAll: true, bound: new Set() };
  analyzeRange(sub, where + 1, stop < 0 ? hi : stop, false, 1);
  return sub.bound.size > 0;
}

/** The lower-case column name when `[lo, hi)` is a plain (possibly qualified, cast or parenthesised) column reference. */
function asColumn(ctx: Context, lo0: number, hi0: number): string | null {
  let lo = lo0;
  let hi = hi0;
  for (let guard = 0; guard < MAX_DEPTH && lo < hi; guard++) {
    if (isPlainGroup(ctx, lo, hi)) {
      lo++;
      hi--;
      continue;
    }
    const cast = findTop(ctx, lo, hi, (t) => t.kind === "operator" && t.text === "::", true);
    if (cast > lo) {
      hi = cast;
      continue;
    }
    const head = ctx.toks[lo];
    if (head !== undefined && head.kind === "word" && (head.value === "any" || head.value === "some") && isPlainGroup(ctx, lo + 1, hi)) {
      lo += 2;
      hi--;
      continue;
    }
    break;
  }
  const length = hi - lo;
  if (length !== 1 && length !== 3 && length !== 5) return null;
  for (let i = lo; i < hi; i++) {
    const t = ctx.toks[i];
    const wantIdent = (i - lo) % 2 === 0;
    if (wantIdent ? !isIdent(t) : !isPunct(t, ".")) return null;
  }
  const last = ctx.toks[hi - 1];
  if (last === undefined) return null;
  const name = identName(last);
  return ctx.acceptAll || ctx.columns.has(name) ? name : null;
}

/** `=` / `IN` operand pairing: records the column when `colSide` is a column and `valueSide` is the caller. */
function bindIfCaller(ctx: Context, colLo: number, colHi: number, valLo: number, valHi: number): void {
  const column = asColumn(ctx, colLo, colHi);
  if (column === null) return;
  const head = ctx.toks[valLo];
  if (head !== undefined && head.kind === "word" && (head.value === "any" || head.value === "some") && isPunct(ctx.toks[valLo + 1], "(") && closerIn(ctx, valLo + 1, valHi) === valHi - 1) {
    if (isIdentityCollection(ctx, valLo + 1, valHi)) ctx.bound.add(column);
    return;
  }
  if (isIdentityValue(ctx, valLo, valHi)) ctx.bound.add(column);
}

function analyzeLeaf(ctx: Context, lo: number, hi: number, negated: boolean): Tri {
  const stop = findTop(
    ctx,
    lo,
    hi,
    (t) =>
      (t.kind === "operator" && COMPARISONS[t.text] === true) ||
      (t.kind === "word" && (t.value === "in" || t.value === "is" || t.value === "between" || t.value === "like" || t.value === "ilike")),
  );
  if (stop < 0) return literalTri(parseLiteral(ctx, lo, hi));
  const t = ctx.toks[stop];
  if (t === undefined) return "unknown";
  if (t.kind === "operator") {
    if (!negated && t.text === "=") {
      bindIfCaller(ctx, lo, stop, stop + 1, hi);
      bindIfCaller(ctx, stop + 1, hi, lo, stop);
    }
    return foldComparison(parseLiteral(ctx, lo, stop), parseLiteral(ctx, stop + 1, hi), t.text);
  }
  if (t.value === "in") {
    const notIn = isWord(ctx.toks[stop - 1], "not");
    const colHi = notIn ? stop - 1 : stop;
    if (!negated && !notIn && isPunct(ctx.toks[stop + 1], "(") && closerIn(ctx, stop + 1, hi) === hi - 1) {
      const column = asColumn(ctx, lo, colHi);
      if (column !== null && isIdentityCollection(ctx, stop + 1, hi)) ctx.bound.add(column);
    }
  }
  return "unknown";
}

function literalTri(lit: Literal | undefined): Tri {
  if (lit === undefined) return "unknown";
  if (lit.t === "bool") return lit.v ? "true" : "false";
  if (lit.t === "null") return "null";
  return "unknown";
}

function analyzeRange(ctx: Context, lo0: number, hi0: number, negated: boolean, depth: number): Tri {
  let lo = lo0;
  let hi = hi0;
  if (depth > MAX_DEPTH) return "unknown";
  while (lo < hi && isPlainGroup(ctx, lo, hi)) {
    lo++;
    hi--;
  }
  if (lo >= hi) return "unknown";

  const ors = splitTop(ctx, lo, hi, "or");
  if (ors.length > 1) return orTri(ors.map(([a, b]) => analyzeRange(ctx, a, b, negated, depth + 1)));
  const ands = splitTop(ctx, lo, hi, "and");
  if (ands.length > 1) return andTri(ands.map(([a, b]) => analyzeRange(ctx, a, b, negated, depth + 1)));

  if (isWord(ctx.toks[lo], "not") && hi - lo > 1) {
    return notTri(analyzeRange(ctx, lo + 1, hi, !negated, depth + 1));
  }
  return analyzeLeaf(ctx, lo, hi, negated);
}

function scanIdentityUse(toks: readonly Token[]): boolean {
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t === undefined) continue;
    if (isWord(t, "current_user")) return true;
    if (isWord(t, "current_setting") && isPunct(toks[i + 1], "(")) {
      const arg = toks[i + 2];
      if (arg !== undefined && arg.kind === "string" && arg.value.startsWith("request.jwt")) return true;
    }
    if (isIdent(t) && identName(t) === "auth" && isPunct(toks[i + 1], ".") && isIdent(toks[i + 2]) && isPunct(toks[i + 3], "(")) {
      const fn = identName(toks[i + 2] as Token);
      if (fn === "uid" || fn === "jwt" || fn === "role" || fn === "email") return true;
    }
  }
  return false;
}

/** Relation names and aliases introduced by `FROM` / `JOIN` (lower-case). */
function declaredRelations(toks: readonly Token[]): Set<string> {
  const declared = new Set<string>();
  for (let i = 0; i < toks.length; i++) {
    if (!isWord(toks[i], "from") && !isWord(toks[i], "join")) continue;
    let j = i + 1;
    let last: Token | undefined;
    while (isIdent(toks[j])) {
      last = toks[j];
      if (isPunct(toks[j + 1], ".") && isIdent(toks[j + 2])) j += 2;
      else {
        j++;
        break;
      }
    }
    if (last === undefined) continue;
    declared.add(identName(last));
    const next = toks[j];
    if (isWord(next, "as") && isIdent(toks[j + 1])) declared.add(identName(toks[j + 1] as Token));
    else if (isIdent(next) && !(next.kind === "word" && NOT_ALIAS[next.value] === true)) declared.add(identName(next));
  }
  return declared;
}

function scanMentions(toks: readonly Token[], columns: ReadonlyMap<string, string>): Set<string> {
  const mentioned = new Set<string>();
  if (columns.size === 0) return mentioned;
  const declared = declaredRelations(toks);
  const openSubquery: boolean[] = [];
  let subDepth = 0;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t === undefined) continue;
    if (isPunct(t, "(")) {
      const sub = isWord(toks[i + 1], "select") || isWord(toks[i + 1], "with");
      openSubquery.push(sub);
      if (sub) subDepth++;
      continue;
    }
    if (isPunct(t, ")")) {
      if (openSubquery.pop() === true) subDepth--;
      continue;
    }
    if (!isIdent(t)) continue;
    const next = toks[i + 1];
    if (isPunct(next, "(") || isPunct(next, ".")) continue;
    const name = identName(t);
    if (!columns.has(name)) continue;
    if (isPunct(toks[i - 1], ".")) {
      const qualifier = toks[i - 2];
      const foreign = subDepth > 0 && isIdent(qualifier) && declared.has(identName(qualifier));
      if (!foreign) mentioned.add(name);
    } else if (subDepth === 0) {
      mentioned.add(name);
    }
  }
  return mentioned;
}

export function analyzeExpression(expression: string | null, columns: readonly string[]): ExpressionFacts {
  const none: ExpressionFacts = { alwaysTrue: false, alwaysFalse: false, usesCallerIdentity: false, callerBoundColumns: [], mentionedColumns: [] };
  if (expression === null) return none;
  const toks = tokenize(expression);
  if (toks.length === 0) return none;

  const spelled = new Map<string, string>();
  for (const c of columns) {
    const key = c.toLowerCase();
    if (!spelled.has(key)) spelled.set(key, c);
  }
  const ctx: Context = { toks, match: matchGroups(toks), columns: spelled, acceptAll: false, bound: new Set() };
  const tri = analyzeRange(ctx, 0, toks.length, false, 0);
  const mentioned = scanMentions(toks, spelled);

  const ordered = (names: ReadonlySet<string>): string[] => {
    const out: string[] = [];
    for (const [key, original] of spelled) if (names.has(key)) out.push(original);
    return out;
  };

  return {
    alwaysTrue: tri === "true",
    alwaysFalse: tri === "false" || tri === "null",
    usesCallerIdentity: scanIdentityUse(toks),
    callerBoundColumns: ordered(ctx.bound),
    mentionedColumns: ordered(mentioned),
  };
}
