/**
 * The static SQL reader: replays migration statements in order and builds the schema model
 * (tables, columns, policies, privileges, views). It understands the statements that matter for access
 * analysis and skips the rest; things that matter but could not be read become warnings. Never throws.
 */
import { LIMITS } from "../limits.js";
import {
  COMMANDS,
  CLIENT_ROLES,
  qualified,
  qualifiedKey,
  type ClientRole,
  type Column,
  type ColumnRef,
  type Command,
  type Policy,
  type PolicyCommand,
  type QualifiedName,
  type SchemaModel,
  type Table,
  type View,
  type Warning,
} from "../schema/model.js";
import { defaultPrivileges, EXPOSED_SCHEMAS } from "../supabase/defaults.js";
import { splitStatements } from "./splitter.js";
import type { ParseResult, SourceFile, SqlStatement } from "./statement.js";
import { tokenize, type Token } from "./tokenizer.js";

export interface ParseOptions {
  readonly maxStatementBytes?: number;
  readonly maxStatements?: number;
}

// ---------------------------------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------------------------------

function isIdentToken(t: Token | undefined): t is Token & { readonly kind: "word" | "quoted-ident" } {
  return t !== undefined && (t.kind === "word" || t.kind === "quoted-ident");
}

/** Cursor over a token list. */
class Stream {
  pos = 0;

  constructor(readonly toks: readonly Token[]) {}

  peek(offset = 0): Token | undefined {
    return this.toks[this.pos + offset];
  }

  atEnd(): boolean {
    return this.pos >= this.toks.length;
  }

  next(): Token | undefined {
    const t = this.toks[this.pos];
    if (t !== undefined) this.pos++;
    return t;
  }

  isWord(word: string, offset = 0): boolean {
    const t = this.toks[this.pos + offset];
    return t !== undefined && t.kind === "word" && t.value === word;
  }

  /** Consumes the words when they all follow in order; otherwise consumes nothing. */
  eatWords(...words: string[]): boolean {
    for (let k = 0; k < words.length; k++) {
      if (!this.isWord(words[k] ?? "", k)) return false;
    }
    this.pos += words.length;
    return true;
  }

  eatWord(word: string): boolean {
    return this.eatWords(word);
  }

  isPunct(ch: string, offset = 0): boolean {
    const t = this.toks[this.pos + offset];
    return t !== undefined && t.kind === "punct" && t.text === ch;
  }

  eatPunct(ch: string): boolean {
    if (!this.isPunct(ch)) return false;
    this.pos++;
    return true;
  }

  eatOperator(op: string): boolean {
    const t = this.toks[this.pos];
    if (t === undefined || t.kind !== "operator" || t.text !== op) return false;
    this.pos++;
    return true;
  }

  /** Consumes a word or quoted identifier; words are lower-case, quoted identifiers exact. */
  ident(): string | null {
    const t = this.toks[this.pos];
    if (!isIdentToken(t)) return null;
    this.pos++;
    return t.value;
  }

  /** At `(`: consumes through the matching `)` and returns the tokens between. */
  group(): Token[] | null {
    if (!this.isPunct("(")) return null;
    this.pos++;
    const start = this.pos;
    let depth = 1;
    while (this.pos < this.toks.length) {
      const t = this.toks[this.pos];
      if (t !== undefined && t.kind === "punct") {
        if (t.text === "(") depth++;
        else if (t.text === ")") {
          depth--;
          if (depth === 0) {
            this.pos++;
            return this.toks.slice(start, this.pos - 1);
          }
        }
      }
      this.pos++;
    }
    return this.toks.slice(start);
  }

  rest(): Token[] {
    const out = this.toks.slice(this.pos);
    this.pos = this.toks.length;
    return out;
  }

  /** Skips one token, or one whole parenthesised group. */
  skip(): void {
    if (this.isPunct("(")) this.group();
    else this.next();
  }
}

/** Source text of the tokens with every run of whitespace or comments collapsed to one space. */
function joinTokens(tokens: readonly Token[]): string {
  let out = "";
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === undefined) continue;
    const prev = tokens[i - 1];
    if (prev !== undefined && t.start > prev.end) out += " ";
    out += t.text;
  }
  return out;
}

/** Splits at commas outside parentheses and brackets; empty items are dropped. */
function splitCommas(tokens: readonly Token[]): Token[][] {
  const items: Token[][] = [];
  let current: Token[] = [];
  let depth = 0;
  for (const t of tokens) {
    if (t.kind === "punct") {
      if (t.text === "(" || t.text === "[") depth++;
      else if ((t.text === ")" || t.text === "]") && depth > 0) depth--;
      else if (t.text === "," && depth === 0) {
        if (current.length > 0) items.push(current);
        current = [];
        continue;
      }
    }
    current.push(t);
  }
  if (current.length > 0) items.push(current);
  return items;
}

/** At most 60 characters of statement text, for messages. */
function snip(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > 60 ? `${flat.slice(0, 60)}…` : flat;
}

function quoteIfNeeded(name: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

// ---------------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------------

interface RawName {
  readonly schema: string | null;
  readonly name: string;
}

/** `a`, `a.b` or `a.b.c` (the database part is dropped). */
function parseName(s: Stream): RawName | null {
  const first = s.ident();
  if (first === null) return null;
  const parts = [first];
  while (s.isPunct(".") && isIdentToken(s.peek(1))) {
    s.next();
    const part = s.ident();
    if (part !== null) parts.push(part);
  }
  const name = parts[parts.length - 1] ?? first;
  return { schema: parts.length > 1 ? (parts[parts.length - 2] ?? null) : null, name };
}

function parseNameList(s: Stream): RawName[] {
  const names: RawName[] = [];
  do {
    const n = parseName(s);
    if (n === null) break;
    names.push(n);
  } while (s.eatPunct(","));
  return names;
}

// ---------------------------------------------------------------------------------------------------
// Model state
// ---------------------------------------------------------------------------------------------------

type Privs = Record<ClientRole, Set<Command>>;

interface ColState {
  name: string;
  type: string;
  notNull: boolean;
  hasDefault: boolean;
  defaultExpr: string | null;
  generated: boolean;
  primaryKey: boolean;
  unique: boolean;
  references: ColumnRef | null;
}

interface TableState {
  name: QualifiedName;
  columns: ColState[];
  rlsEnabled: boolean;
  rlsForced: boolean;
  policies: Policy[];
  checks: string[];
  privileges: Privs;
}

interface ViewState {
  name: QualifiedName;
  columns: string[];
  securityInvoker: boolean;
  definition: string | null;
  dependsOn: QualifiedName[];
  privileges: Privs;
}

interface DefaultOp {
  /** Schemas the change applies to; null means every schema. */
  readonly schemas: readonly string[] | null;
  readonly grant: boolean;
  readonly roles: readonly ClientRole[];
  readonly commands: readonly Command[];
}

function applyPrivileges(state: Privs, grant: boolean, roles: readonly ClientRole[], commands: readonly Command[]): void {
  for (const role of roles) {
    for (const command of commands) {
      if (grant) state[role].add(command);
      else state[role].delete(command);
    }
  }
}

function freezePrivileges(state: Privs): Record<ClientRole, readonly Command[]> {
  return {
    anon: COMMANDS.filter((c) => state.anon.has(c)),
    authenticated: COMMANDS.filter((c) => state.authenticated.has(c)),
  };
}

class Builder {
  readonly tables = new Map<string, TableState>();
  readonly views = new Map<string, ViewState>();
  readonly defaultOps: DefaultOp[] = [];
  readonly warnings: Warning[] = [];
  /** First schema of the current `search_path`: where unqualified names live. */
  schema = "public";
  file = "";
  line = 0;

  warn(message: string): void {
    this.warnings.push({ file: this.file, line: this.line, message });
  }

  resolve(raw: RawName): QualifiedName {
    return qualified(raw.schema ?? this.schema, raw.name);
  }

  /** Privileges of a relation created now in `schema`: Supabase defaults, then ALTER DEFAULT PRIVILEGES in order. */
  initialPrivileges(schema: string): Privs {
    const base = defaultPrivileges(schema);
    const state: Privs = { anon: new Set(base.anon), authenticated: new Set(base.authenticated) };
    for (const op of this.defaultOps) {
      if (op.schemas === null || op.schemas.includes(schema)) applyPrivileges(state, op.grant, op.roles, op.commands);
    }
    return state;
  }

  /** Warns about a missing relation only where it can matter: in schemas the API exposes. */
  warnUnknown(what: string, name: QualifiedName): void {
    if (EXPOSED_SCHEMAS.includes(name.schema)) this.warn(`${what} refers to ${snip(qualifiedKey(name))}, which no earlier statement creates`);
  }
}

function newTable(b: Builder, name: QualifiedName): TableState {
  return { name, columns: [], rlsEnabled: false, rlsForced: false, policies: [], checks: [], privileges: b.initialPrivileges(name.schema) };
}

function newColumn(name: string, type: string): ColState {
  return { name, type, notNull: false, hasDefault: false, defaultExpr: null, generated: false, primaryKey: false, unique: false, references: null };
}

function freezeColumn(c: ColState): Column {
  return { ...c, enumLabels: null };
}

function freezeTable(t: TableState): Table {
  return {
    name: t.name,
    columns: t.columns.map(freezeColumn),
    rlsEnabled: t.rlsEnabled,
    rlsForced: t.rlsForced,
    policies: t.policies,
    checks: t.checks,
    privileges: freezePrivileges(t.privileges),
    origin: "parsed",
  };
}

function freezeView(v: ViewState): View {
  return {
    name: v.name,
    columns: v.columns,
    securityInvoker: v.securityInvoker,
    definition: v.definition,
    dependsOn: v.dependsOn,
    privileges: freezePrivileges(v.privileges),
    origin: "parsed",
  };
}

// ---------------------------------------------------------------------------------------------------
// Types and column definitions
// ---------------------------------------------------------------------------------------------------

const TYPE_STOPS: Record<string, true> = {
  constraint: true, not: true, null: true, default: true, primary: true, unique: true, references: true, check: true,
  generated: true, collate: true, compression: true, storage: true, deferrable: true, initially: true, using: true,
};

const SERIALS: Record<string, string> = {
  serial: "integer", serial4: "integer", smallserial: "smallint", serial2: "smallint", bigserial: "bigint", serial8: "bigint",
};

const SINGLE_TYPES: Record<string, string> = {
  int: "integer", int4: "integer", integer: "integer", int8: "bigint", bigint: "bigint", int2: "smallint", smallint: "smallint",
  bool: "boolean", boolean: "boolean", float8: "double precision", "double precision": "double precision", float4: "real",
  real: "real", decimal: "numeric", numeric: "numeric", varchar: "character varying", "character varying": "character varying",
  "char varying": "character varying", char: "character", bpchar: "character", character: "character", "bit varying": "bit varying",
  varbit: "bit varying",
};

interface ReadType {
  readonly type: string;
  readonly serial: boolean;
}

function readType(s: Stream): ReadType {
  const words: string[] = [];
  const post: string[] = [];
  let mod = "";
  let hasMod = false;
  let array = false;
  let custom = false;

  for (;;) {
    const t = s.peek();
    if (t === undefined) break;
    if (t.kind === "word" && TYPE_STOPS[t.value] === true) break;
    if (isIdentToken(t)) {
      if (hasMod) {
        post.push(t.value.toLowerCase());
        s.next();
      } else if (words.length === 0) {
        const parts = [{ value: t.value, quoted: t.kind === "quoted-ident" }];
        s.next();
        while (s.isPunct(".") && isIdentToken(s.peek(1))) {
          s.next();
          const part = s.next();
          if (part !== undefined) parts.push({ value: part.value, quoted: part.kind === "quoted-ident" });
        }
        while (parts.length > 1 && (parts[0]?.value === "public" || parts[0]?.value === "pg_catalog")) parts.shift();
        const only = parts[0];
        if (parts.length === 1 && only !== undefined && !only.quoted) words.push(only.value);
        else {
          custom = true;
          words.push(parts.map((p) => quoteIfNeeded(p.value)).join("."));
        }
      } else if (t.kind === "word" && t.value === "array") {
        array = true;
        s.next();
      } else {
        words.push(t.value.toLowerCase());
        s.next();
      }
      continue;
    }
    if (t.kind === "punct" && t.text === "(") {
      const inner = s.group() ?? [];
      mod = `(${inner.map((x) => x.text).join("")})`;
      hasMod = true;
      continue;
    }
    if (t.kind === "punct" && t.text === "[") {
      while (!s.atEnd() && !s.isPunct("]")) s.next();
      s.next();
      array = true;
      continue;
    }
    break;
  }

  if (words.length === 0) return { type: "unknown", serial: false };
  const suffix = array ? "[]" : "";
  const head = words[0] ?? "";
  const joined = words.join(" ");

  if (!custom && words.length === 1 && SERIALS[head] !== undefined) return { type: `${SERIALS[head]}${suffix}`, serial: true };
  if (custom) return { type: `${joined}${mod}${suffix}`, serial: false };

  if (head === "timestamp" || head === "timestamptz" || head === "time" || head === "timetz") {
    const all = [...words, ...post];
    const withZone = head.endsWith("tz") || (all.includes("with") && !all.includes("without"));
    const base = head.startsWith("timestamp") ? "timestamp" : "time";
    return { type: `${base}${mod} ${withZone ? "with" : "without"} time zone${suffix}`, serial: false };
  }
  if (head === "float") {
    const n = Number(mod.slice(1, -1));
    return { type: `${mod !== "" && n <= 24 ? "real" : "double precision"}${suffix}`, serial: false };
  }
  const base = SINGLE_TYPES[joined] ?? joined;
  const withMod = base === "character" && mod === "" ? "(1)" : mod;
  const tail = post.length > 0 ? ` ${post.join(" ")}` : "";
  return { type: `${base}${withMod}${tail}${suffix}`, serial: false };
}

const DEFAULT_STOPS: Record<string, true> = {
  not: true, null: true, primary: true, unique: true, references: true, check: true, constraint: true, generated: true,
  deferrable: true, initially: true, collate: true,
};

/** The expression of `DEFAULT expr`, up to the next column constraint. */
function readDefaultExpr(s: Stream): string | null {
  const start = s.pos;
  s.skip();
  while (!s.atEnd()) {
    const t = s.peek();
    if (t !== undefined && t.kind === "word" && DEFAULT_STOPS[t.value] === true) {
      const prev = s.toks[s.pos - 1];
      const isPredicate = (t.value === "not" || t.value === "null") && prev !== undefined && prev.kind === "word" && (prev.value === "is" || prev.value === "not");
      if (!isPredicate) break;
    }
    s.skip();
  }
  const tokens = s.toks.slice(start, s.pos);
  return tokens.length === 0 ? null : joinTokens(tokens);
}

/** After `GENERATED`: `ALWAYS AS (expr) STORED` or `ALWAYS|BY DEFAULT AS IDENTITY [(options)]`. */
function readGenerated(s: Stream, col: ColState): void {
  let always = false;
  if (s.eatWord("always")) always = true;
  else s.eatWords("by", "default");
  if (!s.eatWord("as")) return;
  if (s.eatWord("identity")) {
    if (s.isPunct("(")) s.group();
    col.generated = always;
    col.hasDefault = true;
    return;
  }
  const expr = s.group();
  if (expr !== null) {
    col.generated = true;
    col.hasDefault = true;
    col.defaultExpr = joinTokens(expr);
  }
  if (!s.eatWord("stored")) s.eatWord("virtual");
}

function readReference(b: Builder, s: Stream): ColumnRef | null {
  const target = parseName(s);
  if (target === null) return null;
  const cols = s.isPunct("(") ? columnNames(s.group() ?? []) : [];
  const q = b.resolve(target);
  return { schema: q.schema, table: q.name, column: cols[0] ?? "id" };
}

function columnNames(tokens: readonly Token[]): string[] {
  const names: string[] = [];
  for (const item of splitCommas(tokens)) {
    const first = item[0];
    if (isIdentToken(first)) names.push(first.value);
  }
  return names;
}

/** Everything after the column name: type, then constraints in any order. */
function readColumnDef(b: Builder, s: Stream, name: string, checks: string[]): ColState {
  const { type, serial } = readType(s);
  const col = newColumn(name, type);
  if (serial) {
    col.hasDefault = true;
    col.notNull = true;
  }
  while (!s.atEnd()) {
    const t = s.peek();
    if (t === undefined) break;
    if (t.kind !== "word") {
      s.skip();
      continue;
    }
    switch (t.value) {
      case "constraint":
        s.next();
        s.ident();
        break;
      case "not":
        s.next();
        if (s.eatWord("null")) col.notNull = true;
        break;
      case "default":
        s.next();
        col.defaultExpr = readDefaultExpr(s);
        col.hasDefault = true;
        break;
      case "primary":
        s.next();
        s.eatWord("key");
        col.primaryKey = true;
        col.notNull = true;
        break;
      case "unique":
        s.next();
        col.unique = true;
        break;
      case "references":
        s.next();
        col.references = readReference(b, s);
        break;
      case "check": {
        s.next();
        const inner = s.group();
        if (inner !== null) checks.push(`CHECK (${joinTokens(inner)})`);
        break;
      }
      case "generated":
        s.next();
        readGenerated(s, col);
        break;
      default:
        s.next();
    }
  }
  return col;
}

function findColumn(table: TableState, name: string): ColState | undefined {
  return table.columns.find((c) => c.name === name);
}

/** `[CONSTRAINT n] PRIMARY KEY (..) | UNIQUE (..) | FOREIGN KEY (..) REFERENCES t(..) | CHECK (..)`; anything else is ignored. */
function applyTableConstraint(b: Builder, s: Stream, table: TableState): void {
  if (s.eatWord("constraint")) s.ident();
  const head = s.peek();
  if (head === undefined || head.kind !== "word") return;
  switch (head.value) {
    case "primary": {
      s.next();
      s.eatWord("key");
      for (const name of columnNames(s.group() ?? [])) {
        const col = findColumn(table, name);
        if (col !== undefined) {
          col.primaryKey = true;
          col.notNull = true;
        }
      }
      break;
    }
    case "unique": {
      s.next();
      s.eatWords("nulls", "not", "distinct");
      const names = columnNames(s.group() ?? []);
      const only = names.length === 1 ? findColumn(table, names[0] ?? "") : undefined;
      if (only !== undefined) only.unique = true;
      break;
    }
    case "foreign": {
      s.next();
      s.eatWord("key");
      const own = columnNames(s.group() ?? []);
      if (!s.eatWord("references")) return;
      const target = parseName(s);
      if (target === null) return;
      const remote = s.isPunct("(") ? columnNames(s.group() ?? []) : [];
      const q = b.resolve(target);
      own.forEach((name, i) => {
        const col = findColumn(table, name);
        if (col !== undefined) col.references = { schema: q.schema, table: q.name, column: remote[i] ?? "id" };
      });
      break;
    }
    case "check": {
      s.next();
      const inner = s.group();
      if (inner !== null) table.checks.push(`CHECK (${joinTokens(inner)})`);
      break;
    }
    default:
  }
}

// ---------------------------------------------------------------------------------------------------
// SELECT analysis for views: output names and the relations read
// ---------------------------------------------------------------------------------------------------

const SELECT_LIST_END: Record<string, true> = {
  from: true, union: true, except: true, intersect: true, where: true, group: true, order: true, limit: true, into: true,
  window: true, having: true, offset: true, fetch: true, for: true,
};

/** Words that cannot be an implicit alias because they continue or finish an expression. */
const NOT_AN_ALIAS: Record<string, true> = {
  and: true, or: true, not: true, is: true, in: true, like: true, ilike: true, similar: true, between: true, distinct: true,
  then: true, else: true, when: true, at: true, to: true, escape: true, isnull: true, notnull: true, from: true, collate: true,
  array: true, case: true, interval: true, over: true, null: true, true: true, false: true, end: true, zone: true,
  varying: true, precision: true, select: true,
};

/** Words that continue an expression, so the word after them is an operand rather than an alias. */
const OPERATOR_WORDS: Record<string, true> = {
  and: true, or: true, not: true, is: true, in: true, like: true, ilike: true, similar: true, between: true, distinct: true,
  then: true, else: true, when: true, at: true, to: true, escape: true, from: true, collate: true, array: true, case: true,
  interval: true, over: true, select: true,
};

const STAR = "*";

function itemOutputName(item: readonly Token[]): string {
  const n = item.length;
  const last = item[n - 1];
  if (last === undefined) return "?column?";
  if (last.kind === "operator" && last.text === "*" && (n === 1 || item[n - 2]?.text === ".")) return STAR;
  const asWord = item[n - 2];
  if (n >= 3 && asWord !== undefined && asWord.kind === "word" && asWord.value === "as" && isIdentToken(last)) return last.value;
  const before = item[n - 2];
  if (n >= 2 && isIdentToken(last) && before !== undefined && !(last.kind === "word" && NOT_AN_ALIAS[last.value] === true)) {
    const operandEnd =
      (before.kind === "word" && OPERATOR_WORDS[before.value] !== true) ||
      before.kind === "quoted-ident" ||
      before.kind === "string" ||
      before.kind === "number" ||
      (before.kind === "punct" && (before.text === ")" || before.text === "]"));
    if (operandEnd) return last.value;
  }
  // No alias: drop trailing casts, then name the expression the way Postgres does.
  let end = n;
  for (let depth = 0, i = 0; i < n; i++) {
    const t = item[i];
    if (t === undefined) break;
    if (t.kind === "punct" && (t.text === "(" || t.text === "[")) depth++;
    else if (t.kind === "punct" && (t.text === ")" || t.text === "]")) depth = Math.max(0, depth - 1);
    else if (depth === 0 && t.kind === "operator" && t.text === "::") {
      end = i;
      break;
    }
  }
  const expr = item.slice(0, end);
  const lastExpr = expr[expr.length - 1];
  if (lastExpr === undefined) return "?column?";
  const dotted = expr.every((t, i) => (i % 2 === 0 ? isIdentToken(t) : t.kind === "punct" && t.text === "."));
  if (dotted && expr.length % 2 === 1) return lastExpr.value;
  const head = expr[0];
  if (head !== undefined && head.kind === "word") {
    if (head.value === "case") return "case";
    if (expr[1]?.text === "(" && lastExpr.text === ")") return head.value;
  }
  return "?column?";
}

/** Best-effort output column names of the first SELECT in `tokens`; `[]` when a `*` makes them unknowable. */
function selectOutputNames(tokens: readonly Token[]): string[] {
  let from = -1;
  let depth = 0;
  let firstAny = -1;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === undefined) break;
    if (t.kind === "punct" && t.text === "(") depth++;
    else if (t.kind === "punct" && t.text === ")") depth = Math.max(0, depth - 1);
    else if (t.kind === "word" && t.value === "select") {
      if (firstAny < 0) firstAny = i;
      if (depth === 0) {
        from = i;
        break;
      }
    }
  }
  if (from < 0) from = firstAny;
  if (from < 0) return [];

  let i = from + 1;
  const head = tokens[i];
  if (head !== undefined && head.kind === "word" && head.value === "all") i++;
  else if (head !== undefined && head.kind === "word" && head.value === "distinct") {
    i++;
    if (tokens[i]?.kind === "word" && tokens[i]?.value === "on") {
      i++;
      let d = 0;
      for (; i < tokens.length; i++) {
        const t = tokens[i];
        if (t?.kind === "punct" && t.text === "(") d++;
        else if (t?.kind === "punct" && t.text === ")") {
          d--;
          if (d <= 0) {
            i++;
            break;
          }
        }
      }
    }
  }

  const items: Token[][] = [];
  let current: Token[] = [];
  let nesting = 0;
  for (; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === undefined) break;
    if (t.kind === "punct") {
      if (t.text === "(" || t.text === "[") nesting++;
      else if (t.text === ")" || t.text === "]") {
        if (nesting === 0) break;
        nesting--;
      } else if (t.text === "," && nesting === 0) {
        items.push(current);
        current = [];
        continue;
      }
    } else if (nesting === 0 && t.kind === "word" && SELECT_LIST_END[t.value] === true) {
      break;
    }
    current.push(t);
  }
  items.push(current);

  const names: string[] = [];
  for (const item of items) {
    if (item.length === 0) continue;
    const name = itemOutputName(item);
    if (name === STAR) return [];
    names.push(name);
  }
  return names;
}

const NOT_A_TABLE_FROM: Record<string, true> = { extract: true, substring: true, trim: true, overlay: true, position: true };
const CLAUSE_END: Record<string, true> = {
  where: true, group: true, order: true, having: true, limit: true, union: true, intersect: true, except: true, window: true,
  offset: true, fetch: true, for: true, returning: true,
};

/** Relations a view definition reads: names after FROM and JOIN (and comma-joined ones), best effort. */
function viewDependencies(tokens: readonly Token[], schema: string): QualifiedName[] {
  const cte = new Set<string>();
  for (let i = 0; i + 2 < tokens.length; i++) {
    const t = tokens[i];
    if (!isIdentToken(t) || tokens[i + 1]?.kind !== "word" || tokens[i + 1]?.value !== "as") continue;
    const after = tokens[i + 2];
    const opens = after?.text === "(" || (after?.kind === "word" && (after.value === "materialized" || after.value === "not"));
    const before = tokens[i - 1];
    if (opens && before !== undefined && ((before.kind === "word" && (before.value === "with" || before.value === "recursive")) || before.text === ",")) {
      cte.add(t.value);
    }
  }

  const found = new Map<string, QualifiedName>();
  const stack: Array<{ from: boolean; opener: string }> = [{ from: false, opener: "" }];
  let expectRelation = false;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const top = stack[stack.length - 1];
    if (t === undefined || top === undefined) break;
    if (t.kind === "punct") {
      if (t.text === "(") {
        const prev = tokens[i - 1];
        stack.push({ from: false, opener: prev !== undefined && prev.kind === "word" ? prev.value : "" });
        expectRelation = false;
      } else if (t.text === ")") {
        if (stack.length > 1) stack.pop();
        expectRelation = false;
      } else if (t.text === "," && top.from) {
        expectRelation = true;
      }
      continue;
    }
    if (t.kind === "word") {
      const prev = tokens[i - 1];
      if (t.value === "select") {
        top.from = false;
        expectRelation = false;
        continue;
      }
      if (t.value === "from") {
        if ((prev?.kind === "word" && prev.value === "distinct") || NOT_A_TABLE_FROM[top.opener] === true) continue;
        top.from = true;
        expectRelation = true;
        continue;
      }
      if (t.value === "join") {
        top.from = true;
        expectRelation = true;
        continue;
      }
      if (CLAUSE_END[t.value] === true) {
        top.from = false;
        expectRelation = false;
        continue;
      }
      if (expectRelation && (t.value === "lateral" || t.value === "only")) continue;
    }
    if (!expectRelation) continue;
    expectRelation = false;
    if (!isIdentToken(t)) continue;
    const parts = [t.value];
    let j = i + 1;
    while (tokens[j]?.kind === "punct" && tokens[j]?.text === "." && isIdentToken(tokens[j + 1])) {
      parts.push(tokens[j + 1]?.value ?? "");
      j += 2;
    }
    i = j - 1;
    if (tokens[j]?.kind === "punct" && tokens[j]?.text === "(") continue; // a function call, not a table
    const name = parts[parts.length - 1] ?? "";
    const owner = parts.length > 1 ? (parts[parts.length - 2] ?? schema) : schema;
    if (parts.length === 1 && cte.has(name)) continue;
    found.set(`${owner}.${name}`, qualified(owner, name));
  }
  return [...found.values()];
}

// ---------------------------------------------------------------------------------------------------
// CREATE TABLE
// ---------------------------------------------------------------------------------------------------

const TABLE_CONSTRAINT_START: Record<string, true> = { constraint: true, primary: true, unique: true, foreign: true, check: true, exclude: true };

function createTable(b: Builder, s: Stream, temp: boolean): void {
  const ifNotExists = s.eatWords("if", "not", "exists");
  const raw = parseName(s);
  if (raw === null) {
    b.warn("CREATE TABLE without a readable name");
    return;
  }
  if (temp) return;
  const name = b.resolve(raw);
  const key = qualifiedKey(name);
  if (ifNotExists && b.tables.has(key)) return;
  const table = newTable(b, name);
  b.tables.set(key, table);

  if (s.eatWords("partition", "of")) {
    const parent = parseName(s);
    const source = parent === null ? undefined : b.tables.get(qualifiedKey(b.resolve(parent)));
    if (source !== undefined) table.columns = source.columns.map((c) => ({ ...c }));
    b.warn(`CREATE TABLE ${snip(key)} PARTITION OF: columns copied from the parent, partition bounds not read`);
    return;
  }
  if (s.isWord("of")) {
    b.warn(`CREATE TABLE ${snip(key)} OF a composite type: columns not read`);
    return;
  }

  let items: Token[] | null = null;
  if (s.isPunct("(")) items = s.group();
  if (s.isWord("as")) {
    s.next();
    const names = items !== null ? columnNames(items) : selectOutputNames(s.rest());
    table.columns = names.map((n) => newColumn(n, "unknown"));
    b.warn(`CREATE TABLE ${snip(key)} AS SELECT: column types not known`);
    return;
  }
  if (items === null) {
    b.warn(`CREATE TABLE ${snip(key)}: could not read the column list`);
    return;
  }

  const constraints: Token[][] = [];
  for (const item of splitCommas(items)) {
    const first = item[0];
    if (first === undefined) continue;
    if (first.kind === "word" && TABLE_CONSTRAINT_START[first.value] === true) {
      constraints.push(item);
    } else if (first.kind === "word" && first.value === "like") {
      b.warn(`CREATE TABLE ${snip(key)} ... LIKE: columns of the source table not copied`);
    } else if (isIdentToken(first)) {
      const cs = new Stream(item);
      const colName = cs.ident() ?? first.value;
      const col = readColumnDef(b, cs, colName, table.checks);
      const existing = table.columns.findIndex((c) => c.name === colName);
      if (existing >= 0) table.columns[existing] = col;
      else table.columns.push(col);
    } else {
      b.warn(`CREATE TABLE ${snip(key)}: unreadable column definition: ${snip(joinTokens(item))}`);
    }
  }
  for (const item of constraints) applyTableConstraint(b, new Stream(item), table);
  if (s.isWord("inherits")) b.warn(`CREATE TABLE ${snip(key)} INHERITS: inherited columns not copied`);
}

// ---------------------------------------------------------------------------------------------------
// ALTER TABLE
// ---------------------------------------------------------------------------------------------------

interface Subject {
  name: QualifiedName;
  key: string;
  table: TableState | undefined;
  /** Set once a missing table has been reported for this statement. */
  reported: boolean;
}

/** Re-points foreign keys and view dependencies after a table moved or was renamed. */
function followRename(b: Builder, from: QualifiedName, to: QualifiedName): void {
  for (const t of b.tables.values()) {
    for (const c of t.columns) {
      if (c.references !== null && c.references.schema === from.schema && c.references.table === from.name) {
        c.references = { ...c.references, schema: to.schema, table: to.name };
      }
    }
  }
  for (const v of b.views.values()) {
    v.dependsOn = v.dependsOn.map((d) => (d.schema === from.schema && d.name === from.name ? to : d));
  }
}

/** Re-keys an entry of an insertion-ordered map without moving it. */
function rekey<V>(map: Map<string, V>, oldKey: string, newKey: string, value: V): void {
  const entries = [...map];
  map.clear();
  for (const [k, v] of entries) {
    if (k === oldKey) map.set(newKey, value);
    else if (k !== newKey) map.set(k, v);
  }
}

function relocateTable(b: Builder, subject: Subject, to: QualifiedName): void {
  const table = subject.table;
  if (table === undefined) return;
  const from = table.name;
  table.name = to;
  const oldKey = subject.key;
  subject.name = to;
  subject.key = qualifiedKey(to);
  rekey(b.tables, oldKey, subject.key, table);
  followRename(b, from, to);
}

function needTable(b: Builder, subject: Subject, action: string): TableState | undefined {
  if (subject.table === undefined && !subject.reported) {
    subject.reported = true;
    b.warnUnknown(`ALTER TABLE ${action}`, subject.name);
  }
  return subject.table;
}

function readRowLevelSecurity(s: Stream): boolean {
  return s.eatWords("row", "level", "security") || s.eatWords("row", "security");
}

const BENIGN_TABLE_ACTIONS: Record<string, true> = {
  owner: true, replica: true, cluster: true, inherit: true, of: true, not: true, attach: true, detach: true, validate: true,
  reset: true, no: true, rename: true,
};

function alterColumn(b: Builder, s: Stream, subject: Subject): void {
  s.eatWord("column");
  const name = s.ident();
  if (name === null) {
    b.warn("ALTER TABLE ALTER COLUMN without a readable column name");
    return;
  }
  const table = needTable(b, subject, "ALTER COLUMN");
  const col = table === undefined ? undefined : findColumn(table, name);
  const known = table === undefined || col !== undefined;
  if (!known) b.warn(`ALTER TABLE ${snip(subject.key)} ALTER COLUMN ${snip(name)}: no such column`);

  if (s.eatWords("set", "not", "null")) {
    if (col !== undefined) col.notNull = true;
  } else if (s.eatWords("drop", "not", "null")) {
    if (col !== undefined) col.notNull = false;
  } else if (s.eatWords("set", "default")) {
    const expr = readDefaultExpr(s);
    if (col !== undefined) {
      col.hasDefault = true;
      col.defaultExpr = expr;
    }
  } else if (s.eatWords("drop", "default")) {
    if (col !== undefined && !col.generated) {
      col.hasDefault = false;
      col.defaultExpr = null;
    }
  } else if (s.eatWords("set", "data", "type") || s.eatWord("type")) {
    const { type } = readType(s);
    if (col !== undefined) col.type = type;
  } else if (s.eatWords("add", "generated")) {
    if (col !== undefined) readGenerated(s, col);
  } else if (s.eatWords("drop", "identity") || s.eatWords("drop", "expression")) {
    if (col !== undefined) {
      col.generated = false;
      col.hasDefault = false;
      col.defaultExpr = null;
    }
  } else if (s.eatWords("set", "generated")) {
    if (col !== undefined) col.generated = s.isWord("always");
  } else if (!(s.isWord("set") || s.isWord("reset") || s.isWord("restart") || s.isWord("add") || s.isWord("drop"))) {
    b.warn(`ALTER TABLE ${snip(subject.key)}: unsupported ALTER COLUMN action: ${snip(joinTokens(s.toks.slice(s.pos)))}`);
  }
}

function tableAction(b: Builder, s: Stream, subject: Subject): void {
  const head = s.peek();
  if (head === undefined || head.kind !== "word") {
    b.warn(`ALTER TABLE ${snip(subject.key)}: unreadable action`);
    return;
  }
  switch (head.value) {
    case "enable":
    case "disable":
    case "force": {
      s.next();
      if (readRowLevelSecurity(s)) {
        const table = needTable(b, subject, "ROW LEVEL SECURITY");
        if (table === undefined) return;
        if (head.value === "force") table.rlsForced = true;
        else table.rlsEnabled = head.value === "enable";
      } else if (!(s.isWord("trigger") || s.isWord("rule") || s.isWord("replica") || s.isWord("always"))) {
        b.warn(`ALTER TABLE ${snip(subject.key)}: unsupported ${head.value.toUpperCase()} action`);
      }
      return;
    }
    case "no":
      if (s.isWord("force", 1)) {
        s.pos += 2;
        if (readRowLevelSecurity(s)) {
          const table = needTable(b, subject, "NO FORCE ROW LEVEL SECURITY");
          if (table !== undefined) table.rlsForced = false;
        } else {
          b.warn(`ALTER TABLE ${snip(subject.key)}: unsupported NO FORCE action`);
        }
      }
      return;
    case "add": {
      s.next();
      const next = s.peek();
      if (next !== undefined && next.kind === "word" && TABLE_CONSTRAINT_START[next.value] === true) {
        const table = needTable(b, subject, "ADD CONSTRAINT");
        if (table !== undefined) applyTableConstraint(b, s, table);
        return;
      }
      s.eatWord("column");
      const ifNotExists = s.eatWords("if", "not", "exists");
      const name = s.ident();
      if (name === null) {
        b.warn(`ALTER TABLE ${snip(subject.key)}: ADD COLUMN without a readable name`);
        return;
      }
      const table = needTable(b, subject, "ADD COLUMN");
      const checks: string[] = [];
      const col = readColumnDef(b, s, name, checks);
      if (table === undefined) return;
      table.checks.push(...checks);
      const at = table.columns.findIndex((c) => c.name === name);
      if (at < 0) table.columns.push(col);
      else if (!ifNotExists) table.columns[at] = col;
      return;
    }
    case "drop": {
      s.next();
      if (s.isWord("constraint") || s.isWord("trigger") || s.isWord("rule")) return;
      s.eatWord("column");
      s.eatWords("if", "exists");
      const name = s.ident();
      if (name === null) {
        b.warn(`ALTER TABLE ${snip(subject.key)}: DROP COLUMN without a readable name`);
        return;
      }
      const table = needTable(b, subject, "DROP COLUMN");
      if (table !== undefined) table.columns = table.columns.filter((c) => c.name !== name);
      return;
    }
    case "alter": {
      s.next();
      if (s.isWord("constraint")) return;
      alterColumn(b, s, subject);
      return;
    }
    case "rename": {
      s.next();
      if (s.eatWord("to")) {
        const to = s.ident();
        if (to !== null && subject.table !== undefined) relocateTable(b, subject, qualified(subject.table.name.schema, to));
        return;
      }
      if (s.isWord("constraint")) return;
      s.eatWord("column");
      const from = s.ident();
      if (from === null || !s.eatWord("to")) {
        b.warn(`ALTER TABLE ${snip(subject.key)}: unreadable RENAME`);
        return;
      }
      const to = s.ident();
      const table = needTable(b, subject, "RENAME COLUMN");
      const col = table === undefined ? undefined : findColumn(table, from);
      if (table === undefined || col === undefined || to === null) return;
      col.name = to;
      for (const other of b.tables.values()) {
        for (const c of other.columns) {
          const ref = c.references;
          if (ref !== null && ref.schema === table.name.schema && ref.table === table.name.name && ref.column === from) {
            c.references = { ...ref, column: to };
          }
        }
      }
      return;
    }
    case "set": {
      s.next();
      if (s.eatWord("schema")) {
        const schema = s.ident();
        if (schema !== null && subject.table !== undefined) relocateTable(b, subject, qualified(schema, subject.table.name.name));
      }
      return;
    }
    default:
      if (BENIGN_TABLE_ACTIONS[head.value] !== true) b.warn(`ALTER TABLE ${snip(subject.key)}: unsupported action: ${snip(joinTokens(s.toks))}`);
  }
}

function alterTable(b: Builder, s: Stream): void {
  s.eatWords("if", "exists");
  s.eatWord("only");
  const raw = parseName(s);
  if (raw === null) {
    b.warn("ALTER TABLE without a readable name");
    return;
  }
  s.eatOperator("*");
  const name = b.resolve(raw);
  const key = qualifiedKey(name);
  const subject: Subject = { name, key, table: b.tables.get(key), reported: false };
  for (const action of splitCommas(s.rest())) tableAction(b, new Stream(action), subject);
}

// ---------------------------------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------------------------------

const CURRENT_ROLE_WORDS: Record<string, true> = { current_user: true, session_user: true, current_role: true, public: true };

/** Role names up to a stop token; commas and the `GROUP` prefix are skipped. */
function readRoleNames(s: Stream, stop: (t: Token) => boolean): string[] {
  const names: string[] = [];
  while (!s.atEnd()) {
    const t = s.peek();
    if (t === undefined || stop(t)) break;
    s.next();
    if (t.kind === "word" && t.value === "group") continue;
    if (isIdentToken(t) || t.kind === "string") names.push(t.value);
  }
  return names;
}

function policyRoles(s: Stream): string[] {
  const names = readRoleNames(s, (t) => t.kind === "word" && (t.value === "using" || t.value === "with"));
  const roles: string[] = [];
  for (const raw of names) {
    const role = CURRENT_ROLE_WORDS[raw] === true ? "public" : raw;
    if (!roles.includes(role)) roles.push(role);
  }
  return roles.length > 0 ? roles : ["public"];
}

const POLICY_COMMANDS: Record<string, PolicyCommand> = { all: "all", select: "select", insert: "insert", update: "update", delete: "delete" };

interface PolicyClauses {
  permissive?: boolean;
  command?: PolicyCommand;
  roles?: string[];
  using?: string;
  withCheck?: string;
  rename?: string;
}

/** Reads the clauses after `ON table`. Returns false when a clause could not be understood. */
function readPolicyClauses(s: Stream, out: PolicyClauses, allowRename: boolean): boolean {
  while (!s.atEnd()) {
    if (s.eatWord("as")) {
      const w = s.next();
      if (w === undefined || (w.value !== "permissive" && w.value !== "restrictive")) return false;
      out.permissive = w.value === "permissive";
    } else if (s.eatWord("for")) {
      const w = s.next();
      const command = w === undefined ? undefined : POLICY_COMMANDS[w.value];
      if (command === undefined) return false;
      out.command = command;
    } else if (s.eatWord("to")) {
      out.roles = policyRoles(s);
    } else if (s.eatWord("using")) {
      const inner = s.group();
      if (inner === null) return false;
      out.using = joinTokens(inner);
    } else if (s.isWord("with") && s.isWord("check", 1)) {
      s.pos += 2;
      const inner = s.group();
      if (inner === null) return false;
      out.withCheck = joinTokens(inner);
    } else if (allowRename && s.eatWords("rename", "to")) {
      const to = s.ident();
      if (to === null) return false;
      out.rename = to;
    } else {
      return false;
    }
  }
  return true;
}

function policyTarget(b: Builder, s: Stream, verb: string): { name: string; table: TableState | undefined; qname: QualifiedName } | null {
  s.eatWords("if", "exists");
  const name = s.ident();
  if (name === null || !s.eatWord("on")) {
    b.warn(`${verb} POLICY: could not read the policy name and table`);
    return null;
  }
  const raw = parseName(s);
  if (raw === null) {
    b.warn(`${verb} POLICY ${snip(name)}: could not read the table name`);
    return null;
  }
  const qname = b.resolve(raw);
  const table = b.tables.get(qualifiedKey(qname));
  if (table === undefined) b.warnUnknown(`${verb} POLICY ${snip(name)}`, qname);
  return { name, table, qname };
}

function createPolicy(b: Builder, s: Stream): void {
  const target = policyTarget(b, s, "CREATE");
  if (target === null) return;
  const clauses: PolicyClauses = {};
  if (!readPolicyClauses(s, clauses, false)) b.warn(`CREATE POLICY ${snip(target.name)}: unreadable clause: ${snip(joinTokens(s.toks.slice(s.pos)))}`);
  if (target.table === undefined) return;
  const policy: Policy = {
    name: target.name,
    command: clauses.command ?? "all",
    permissive: clauses.permissive ?? true,
    roles: clauses.roles ?? ["public"],
    using: clauses.using ?? null,
    withCheck: clauses.withCheck ?? null,
  };
  const at = target.table.policies.findIndex((p) => p.name === policy.name);
  if (at >= 0) target.table.policies[at] = policy;
  else target.table.policies.push(policy);
}

function alterPolicy(b: Builder, s: Stream): void {
  const target = policyTarget(b, s, "ALTER");
  if (target === null) return;
  const clauses: PolicyClauses = {};
  if (!readPolicyClauses(s, clauses, true)) b.warn(`ALTER POLICY ${snip(target.name)}: unreadable clause`);
  const table = target.table;
  if (table === undefined) return;
  const at = table.policies.findIndex((p) => p.name === target.name);
  const old = table.policies[at];
  if (old === undefined) {
    b.warn(`ALTER POLICY ${snip(target.name)}: no such policy on ${snip(qualifiedKey(target.qname))}`);
    return;
  }
  table.policies[at] = {
    ...old,
    name: clauses.rename ?? old.name,
    roles: clauses.roles ?? old.roles,
    using: clauses.using ?? old.using,
    withCheck: clauses.withCheck ?? old.withCheck,
  };
}

function dropPolicy(b: Builder, s: Stream): void {
  const ifExists = s.isWord("if") && s.isWord("exists", 1);
  const target = policyTarget(b, s, "DROP");
  if (target === null || target.table === undefined) return;
  const before = target.table.policies.length;
  target.table.policies = target.table.policies.filter((p) => p.name !== target.name);
  if (before === target.table.policies.length && !ifExists) b.warn(`DROP POLICY ${snip(target.name)}: no such policy on ${snip(qualifiedKey(target.qname))}`);
}

// ---------------------------------------------------------------------------------------------------
// GRANT / REVOKE / ALTER DEFAULT PRIVILEGES
// ---------------------------------------------------------------------------------------------------

function clientRoles(names: readonly string[]): ClientRole[] {
  const roles = new Set<ClientRole>();
  for (const n of names) {
    if (n === "public") for (const r of CLIENT_ROLES) roles.add(r);
    else if (n === "anon" || n === "authenticated") roles.add(n);
  }
  return CLIENT_ROLES.filter((r) => roles.has(r));
}

/** Table-level commands named by a privilege list; column-level items and other privileges are ignored. */
function privilegeCommands(tokens: readonly Token[]): Command[] {
  const commands = new Set<Command>();
  for (const item of splitCommas(tokens)) {
    if (item.some((t) => t.kind === "punct" && t.text === "(")) continue;
    const head = item[0];
    if (head === undefined || head.kind !== "word") continue;
    if (head.value === "all") for (const c of COMMANDS) commands.add(c);
    else if (head.value === "select" || head.value === "insert" || head.value === "update" || head.value === "delete") commands.add(head.value);
  }
  return COMMANDS.filter((c) => commands.has(c));
}

const GRANT_ROLE_STOP = (t: Token): boolean =>
  t.kind === "word" && (t.value === "with" || t.value === "granted" || t.value === "cascade" || t.value === "restrict");

const NON_TABLE_OBJECTS: Record<string, true> = {
  sequence: true, function: true, procedure: true, routine: true, schema: true, database: true, domain: true, type: true,
  language: true, foreign: true, large: true, tablespace: true, parameter: true, all: true,
};

function readPrivilegeTokens(s: Stream): Token[] | null {
  const tokens: Token[] = [];
  while (!s.atEnd() && !s.isWord("on")) {
    const t = s.next();
    if (t !== undefined) tokens.push(t);
  }
  if (s.atEnd()) return null;
  s.next();
  return tokens;
}

function handleGrant(b: Builder, s: Stream, grant: boolean): void {
  s.next();
  const optionOnly = !grant && s.eatWords("grant", "option", "for");
  const privTokens = readPrivilegeTokens(s);
  if (privTokens === null) return; // role membership: GRANT role TO role
  const commands = privilegeCommands(privTokens);

  let names: RawName[] = [];
  let schemas: string[] | null = null;
  if (s.isWord("all") && s.isWord("tables", 1) && s.isWord("in", 2) && s.isWord("schema", 3)) {
    s.pos += 4;
    schemas = parseNameList(s).map((n) => n.name);
  } else {
    const head = s.peek();
    if (head !== undefined && head.kind === "word" && NON_TABLE_OBJECTS[head.value] === true) return;
    s.eatWord("table");
    names = parseNameList(s);
  }
  if (!s.eatWord(grant ? "to" : "from")) {
    b.warn(`${grant ? "GRANT" : "REVOKE"}: could not read the role list`);
    return;
  }
  const roles = clientRoles(readRoleNames(s, GRANT_ROLE_STOP));
  if (optionOnly || roles.length === 0 || commands.length === 0) return;

  if (schemas !== null) {
    for (const t of b.tables.values()) if (schemas.includes(t.name.schema)) applyPrivileges(t.privileges, grant, roles, commands);
    for (const v of b.views.values()) if (schemas.includes(v.name.schema)) applyPrivileges(v.privileges, grant, roles, commands);
    return;
  }
  for (const raw of names) {
    const q = b.resolve(raw);
    const key = qualifiedKey(q);
    const target = b.tables.get(key) ?? b.views.get(key);
    if (target === undefined) b.warnUnknown(grant ? "GRANT" : "REVOKE", q);
    else applyPrivileges(target.privileges, grant, roles, commands);
  }
}

function alterDefaultPrivileges(b: Builder, s: Stream): void {
  let schemas: string[] | null = null;
  for (;;) {
    if (s.isWord("for") && (s.isWord("role", 1) || s.isWord("user", 1))) {
      s.pos += 2;
      readRoleNames(s, (t) => t.kind === "word" && (t.value === "in" || t.value === "grant" || t.value === "revoke"));
    } else if (s.eatWords("in", "schema")) {
      schemas = parseNameList(s).map((n) => n.name);
    } else break;
  }
  let grant: boolean;
  if (s.eatWord("grant")) grant = true;
  else if (s.eatWord("revoke")) grant = false;
  else {
    b.warn("ALTER DEFAULT PRIVILEGES: expected GRANT or REVOKE");
    return;
  }
  const optionOnly = !grant && s.eatWords("grant", "option", "for");
  const privTokens = readPrivilegeTokens(s);
  if (privTokens === null || !s.eatWord("tables")) return; // sequences, functions and types do not affect row access
  if (!s.eatWord(grant ? "to" : "from")) {
    b.warn("ALTER DEFAULT PRIVILEGES: could not read the role list");
    return;
  }
  const roles = clientRoles(readRoleNames(s, GRANT_ROLE_STOP));
  const commands = privilegeCommands(privTokens);
  if (!optionOnly && roles.length > 0 && commands.length > 0) b.defaultOps.push({ schemas, grant, roles, commands });
}

// ---------------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------------

const TRUTHY: Record<string, true> = { true: true, on: true, yes: true, "1": true, t: true };

/** The `security_invoker` setting named in `(a = b, ...)` options, or undefined when absent. `reset` reads names only. */
function securityInvokerOption(options: readonly Token[], reset: boolean): boolean | undefined {
  for (const item of splitCommas(options)) {
    const it = new Stream(item);
    if (it.ident() !== "security_invoker") continue;
    if (reset) return false;
    if (!it.eatOperator("=")) return true;
    const v = it.next();
    return v !== undefined && TRUTHY[v.value.toLowerCase()] === true;
  }
  return undefined;
}

function createView(b: Builder, s: Stream, temp: boolean, orReplace: boolean): void {
  s.eatWords("if", "not", "exists");
  const raw = parseName(s);
  if (raw === null) {
    b.warn("CREATE VIEW without a readable name");
    return;
  }
  if (temp) return;
  const name = b.resolve(raw);
  const key = qualifiedKey(name);
  let explicit: string[] | null = null;
  let invoker = false;
  while (!s.atEnd() && !s.isWord("as")) {
    if (s.eatWord("with")) {
      const options = s.group();
      if (options !== null) invoker = securityInvokerOption(options, false) ?? invoker;
    } else if (s.isPunct("(") && explicit === null) {
      explicit = columnNames(s.group() ?? []);
    } else {
      s.next();
    }
  }
  if (!s.eatWord("as")) {
    b.warn(`CREATE VIEW ${snip(key)}: could not find AS`);
    return;
  }
  const body = s.rest();
  const existing = orReplace ? b.views.get(key) : undefined;
  b.views.set(key, {
    name,
    columns: explicit ?? selectOutputNames(body),
    securityInvoker: invoker,
    definition: body.length === 0 ? null : joinTokens(body),
    dependsOn: viewDependencies(body, b.schema),
    privileges: existing?.privileges ?? b.initialPrivileges(name.schema),
  });
}

function alterView(b: Builder, s: Stream): void {
  s.eatWords("if", "exists");
  const raw = parseName(s);
  if (raw === null) return;
  const name = b.resolve(raw);
  const key = qualifiedKey(name);
  const view = b.views.get(key);
  if (s.eatWord("set") || s.isWord("reset")) {
    const reset = s.eatWord("reset");
    if (s.eatWord("schema")) {
      const schema = s.ident();
      if (schema !== null && view !== undefined) {
        view.name = qualified(schema, name.name);
        rekey(b.views, key, qualifiedKey(view.name), view);
      }
      return;
    }
    const options = s.group();
    const value = options === null ? undefined : securityInvokerOption(options, reset);
    if (value === undefined) return;
    if (view === undefined) b.warnUnknown("ALTER VIEW", name);
    else view.securityInvoker = value;
  } else if (s.eatWords("rename", "to")) {
    const to = s.ident();
    if (to !== null && view !== undefined) {
      view.name = qualified(name.schema, to);
      rekey(b.views, key, qualifiedKey(view.name), view);
    }
  }
}

// ---------------------------------------------------------------------------------------------------
// DROP
// ---------------------------------------------------------------------------------------------------

/** Removes views that read `key`, and the views that read those. */
function dropDependentViews(b: Builder, key: string): void {
  const doomed = [key];
  while (doomed.length > 0) {
    const gone = doomed.pop() ?? "";
    for (const [viewKey, view] of [...b.views]) {
      if (view.dependsOn.some((d) => qualifiedKey(d) === gone)) {
        b.views.delete(viewKey);
        doomed.push(viewKey);
      }
    }
  }
}

function dropRelations(b: Builder, s: Stream, kind: "table" | "view"): void {
  s.eatWords("if", "exists");
  const names = parseNameList(s);
  const cascade = s.rest().some((t) => t.kind === "word" && t.value === "cascade");
  for (const raw of names) {
    const key = qualifiedKey(b.resolve(raw));
    if (kind === "table") b.tables.delete(key);
    else b.views.delete(key);
    if (cascade) dropDependentViews(b, key);
  }
}

// ---------------------------------------------------------------------------------------------------
// Statement dispatch
// ---------------------------------------------------------------------------------------------------

/** Objects whose CREATE / ALTER / DROP never changes who can read or write table rows. */
const BENIGN_OBJECTS: Record<string, true> = {
  index: true, unique: true, function: true, procedure: true, routine: true, trigger: true, constraint: true, type: true,
  domain: true, sequence: true, extension: true, schema: true, role: true, user: true, group: true, publication: true,
  aggregate: true, operator: true, cast: true, collation: true, conversion: true, database: true, language: true,
  tablespace: true, event: true, statistics: true, text: true, transform: true, access: true, server: true,
  subscription: true, foreign: true, owned: true, system: true, large: true,
};

/** Statements that never matter to access analysis. */
const BENIGN_COMMANDS: Record<string, true> = {
  insert: true, update: true, delete: true, copy: true, select: true, do: true, comment: true, analyze: true, analyse: true,
  vacuum: true, notify: true, listen: true, unlisten: true, truncate: true, with: true, values: true, explain: true, lock: true,
  refresh: true, reindex: true, cluster: true, checkpoint: true, discard: true, prepare: true, execute: true, deallocate: true,
  declare: true, fetch: true, close: true, savepoint: true, release: true, security: true, import: true, load: true,
  merge: true, call: true, abort: true, show: true, table: true,
};

function readSearchPath(s: Stream): string | null {
  let first: string | null = null;
  while (!s.atEnd()) {
    const t = s.next();
    if (t === undefined) break;
    if (t.kind === "operator" && t.text === "$" && s.isWord("user")) {
      s.next();
      continue;
    }
    if ((isIdentToken(t) || t.kind === "string") && first === null && t.value !== "$user" && t.value !== "" && t.value !== "default") first = t.value;
  }
  return first;
}

function handleSet(b: Builder, s: Stream): void {
  s.next();
  if (!s.eatWord("local")) s.eatWord("session");
  if (!s.eatWord("search_path")) return;
  if (!s.eatWord("to") && !s.eatOperator("=")) return;
  b.schema = readSearchPath(s) ?? "public";
}

function handleCreate(b: Builder, s: Stream, text: string): void {
  s.next();
  let temp = false;
  let orReplace = false;
  let materialized = false;
  for (;;) {
    if (s.eatWords("or", "replace")) orReplace = true;
    else if (s.isWord("temp") || s.isWord("temporary")) {
      s.next();
      temp = true;
    } else if ((s.isWord("global") || s.isWord("local")) && (s.isWord("temp", 1) || s.isWord("temporary", 1))) s.next();
    else if (s.isWord("unlogged") || s.isWord("recursive")) s.next();
    else if (s.isWord("materialized")) {
      s.next();
      materialized = true;
    } else break;
  }
  const kind = s.next();
  if (kind === undefined || kind.kind !== "word") {
    b.warn(`unrecognised statement: ${snip(text)}`);
    return;
  }
  if (materialized && kind.value !== "view") {
    b.warn(`unrecognised statement: ${snip(text)}`);
    return;
  }
  switch (kind.value) {
    case "table":
      createTable(b, s, temp);
      return;
    case "view":
      createView(b, s, temp, orReplace);
      return;
    case "policy":
      createPolicy(b, s);
      return;
    case "foreign":
      if (s.isWord("table")) b.warn(`CREATE FOREIGN TABLE not modelled: ${snip(text)}`);
      return;
    default:
      if (BENIGN_OBJECTS[kind.value] !== true) b.warn(`unrecognised statement: ${snip(text)}`);
  }
}

function handleAlter(b: Builder, s: Stream, text: string): void {
  s.next();
  const kind = s.next();
  if (kind === undefined || kind.kind !== "word") {
    b.warn(`unrecognised statement: ${snip(text)}`);
    return;
  }
  switch (kind.value) {
    case "table":
      alterTable(b, s);
      return;
    case "policy":
      alterPolicy(b, s);
      return;
    case "view":
      alterView(b, s);
      return;
    case "materialized":
      if (s.eatWord("view")) alterView(b, s);
      return;
    case "default":
      if (s.eatWord("privileges")) alterDefaultPrivileges(b, s);
      return;
    default:
      if (BENIGN_OBJECTS[kind.value] !== true) b.warn(`unrecognised statement: ${snip(text)}`);
  }
}

function handleDrop(b: Builder, s: Stream, text: string): void {
  s.next();
  const kind = s.next();
  if (kind === undefined || kind.kind !== "word") {
    b.warn(`unrecognised statement: ${snip(text)}`);
    return;
  }
  switch (kind.value) {
    case "table":
      dropRelations(b, s, "table");
      return;
    case "view":
      dropRelations(b, s, "view");
      return;
    case "materialized":
      if (s.eatWord("view")) dropRelations(b, s, "view");
      return;
    case "policy":
      dropPolicy(b, s);
      return;
    default:
      if (BENIGN_OBJECTS[kind.value] !== true) b.warn(`unrecognised statement: ${snip(text)}`);
  }
}

function handleStatement(b: Builder, statement: SqlStatement): void {
  b.line = statement.line;
  const s = new Stream(tokenize(statement.text));
  const head = s.peek();
  if (head === undefined) return;
  if (head.kind === "punct" && head.text === "(") return; // a parenthesised query
  if (head.kind !== "word") {
    b.warn(`unrecognised statement: ${snip(statement.text)}`);
    return;
  }
  switch (head.value) {
    case "create":
      handleCreate(b, s, statement.text);
      return;
    case "alter":
      handleAlter(b, s, statement.text);
      return;
    case "drop":
      handleDrop(b, s, statement.text);
      return;
    case "grant":
      handleGrant(b, s, true);
      return;
    case "revoke":
      handleGrant(b, s, false);
      return;
    case "set":
      handleSet(b, s);
      return;
    case "reset":
      s.next();
      if (s.isWord("search_path") || s.isWord("all")) b.schema = "public";
      return;
    default:
      if (BENIGN_COMMANDS[head.value] !== true) b.warn(`unrecognised statement: ${snip(statement.text)}`);
  }
}

/**
 * Replays the statements of `files` in the given order and returns them with the model they build.
 * `complete` is false exactly when a size or count cap dropped input.
 */
export function parseMigrations(files: readonly SourceFile[], options: ParseOptions = {}): ParseResult {
  const b = new Builder();
  const statements: SqlStatement[] = [];
  const maxStatements = options.maxStatements ?? LIMITS.maxStatements;
  let complete = true;

  for (const file of files) {
    const split = splitStatements(file, { maxStatementBytes: options.maxStatementBytes, maxStatements: Math.max(0, maxStatements - statements.length) });
    b.file = file.path;
    b.schema = "public";
    b.warnings.push(...split.warnings);
    if (!split.complete) complete = false;
    for (const statement of split.statements) {
      statements.push(statement);
      if (statement.kind !== "sql") continue;
      try {
        handleStatement(b, statement);
      } catch {
        b.line = statement.line;
        b.warn(`could not read statement: ${snip(statement.text)}`);
      }
    }
  }

  const model: SchemaModel = {
    tables: [...b.tables.values()].map(freezeTable),
    views: [...b.views.values()].map(freezeView),
  };
  return { statements, model, warnings: b.warnings, complete };
}
