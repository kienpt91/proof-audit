import { baseTables } from "../proof/plan.js";
import type { SchemaModel, Table, View } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import type { SourceIndex, SourceSpot, SqlStatement } from "../sql/statement.js";
import { tokenize } from "../sql/tokenizer.js";
import type { RootCause } from "./rootcause.js";
import type { TraceStep } from "./records.js";

/** What the SQL reader knows about where things are declared. */
export interface SourceMap {
  readonly statements: readonly SqlStatement[];
  readonly sources: SourceIndex;
}

/** A trace into the migration SQL and the statement the record's evidence should point at. */
export interface Located {
  readonly trace: readonly TraceStep[];
  readonly anchor: SourceSpot;
  /** Empty when `anchor` is a statement that declares the object; otherwise says that it is only the first statement that names it. */
  readonly note: string;
}

/** A position, and whether it is a declaration the reader indexed (false) or the first statement that mentions the name (true). */
interface Found {
  readonly spot: SourceSpot;
  readonly fallback: boolean;
}

const declared = (spot: SourceSpot): Found => ({ spot, fallback: false });
const FALLBACK_NOTE = "The reader did not see this declared (it may come from a statement it cannot read), so the line is the first statement that names it, which need not be a CREATE.";
const noteOf = (...found: readonly Found[]): string => (found.some((f) => f.fallback) ? FALLBACK_NOTE : "");

/** Identifiers of every SQL statement, tokenised once: per statement a set of keys, and per key the statements that hold it. */
interface MentionIndex {
  readonly statements: readonly SqlStatement[];
  readonly idents: readonly (ReadonlySet<string> | null)[];
  readonly postings: ReadonlyMap<string, readonly number[]>;
}

const indexes = new WeakMap<readonly SqlStatement[], MentionIndex>();

/** Unquoted words are lower-cased by the tokenizer and match case-insensitively; a quoted identifier matches exactly. */
const wordKey = (name: string): string => `w:${name.toLowerCase()}`;
const quotedKey = (name: string): string => `q:${name}`;

function mentionIndex(statements: readonly SqlStatement[]): MentionIndex {
  const known = indexes.get(statements);
  if (known !== undefined) return known;
  const postings = new Map<string, number[]>();
  const idents = statements.map((s, i): ReadonlySet<string> | null => {
    if (s.kind !== "sql") return null;
    const keys = new Set<string>();
    for (const t of tokenize(s.text)) {
      if (t.kind === "word") keys.add(`w:${t.value}`);
      else if (t.kind === "quoted-ident") keys.add(quotedKey(t.value));
    }
    for (const key of keys) {
      const list = postings.get(key);
      if (list === undefined) postings.set(key, [i]);
      else list.push(i);
    }
    return keys;
  });
  const built = { statements, idents, postings };
  indexes.set(statements, built);
  return built;
}

/**
 * The first statement that names every one of `names` as an identifier. This is the fallback for an object the
 * reader did not see declared (created by a statement it could not read); it finds a real statement rather than
 * guessing a line. The statements are tokenised once per list and looked up by identifier, so many lookups
 * cost about one pass over the input plus the number of statements that mention the rarest name.
 */
export function findMention(statements: readonly SqlStatement[], names: readonly string[]): SourceSpot | null {
  if (names.length === 0) return null;
  const index = mentionIndex(statements);
  const hits = (name: string): readonly number[] => {
    const word: readonly number[] = index.postings.get(wordKey(name)) ?? [];
    const quoted: readonly number[] = index.postings.get(quotedKey(name)) ?? [];
    return word.length === 0 ? quoted : quoted.length === 0 ? word : [...new Set([...word, ...quoted])].sort((x, y) => x - y);
  };
  const lists = names.map(hits);
  const rarest = lists.reduce((best, list) => (list.length < best.length ? list : best));
  for (const i of rarest) {
    const keys = index.idents[i];
    if (keys !== null && keys !== undefined && names.every((n) => keys.has(wordKey(n)) || keys.has(quotedKey(n)))) {
      const s = index.statements[i];
      if (s !== undefined) return { file: s.file, line: s.line };
    }
  }
  return null;
}

function step(kind: TraceStep["kind"], found: Found, scope: string, description: string): TraceStep {
  return { kind, file: found.spot.file, line: found.spot.line, scope, description: found.fallback ? `${description} ${FALLBACK_NOTE}` : description };
}

function dedupe(steps: readonly TraceStep[]): TraceStep[] {
  const seen = new Set<string>();
  return steps.filter((s) => {
    const key = JSON.stringify(s);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Where the statement for a policy is: the reader's index, else the first statement that names both the policy and the table. */
function mention(src: SourceMap, names: readonly string[]): Found | null {
  const spot = findMention(src.statements, names);
  return spot === null ? null : { spot, fallback: true };
}

function policySpot(src: SourceMap, tableKey: string, tableName: string, policy: string): Found | null {
  const indexed = src.sources.tables.get(tableKey)?.policies.get(policy);
  if (indexed !== undefined) return declared(indexed);
  return mention(src, [policy, tableName]);
}

function createdSpot(src: SourceMap, key: string, name: string): Found | null {
  const indexed = src.sources.tables.get(key)?.created;
  if (indexed !== undefined) return declared(indexed);
  return mention(src, [name]);
}

const SINK = "The table that holds the rows the probes read and changed.";

/**
 * The trace of one table-level root cause: where access is granted (entrypoint), the statements that carry it
 * (propagation) and the table whose rows are exposed (sink). Null only when no statement of the migrations
 * can be found for the table.
 */
export function locateTableCause(src: SourceMap, table: Table, cause: RootCause | null, untested: boolean): Located | null {
  const key = qualifiedKey(table.name);
  const created = createdSpot(src, key, table.name.name);
  if (created === null) return null;
  const scope = `table ${key}`;
  const rlsSpot = src.sources.tables.get(key)?.rowSecurity ?? null;
  const rls = rlsSpot === null ? null : declared(rlsSpot);
  const sink = step("sink", created, scope, SINK);

  if (cause === null) {
    const what = untested ? "The table that could not be fully tested." : "The table the proven attacks ran against; no policy or setting the static reader found explains them.";
    return { trace: [step("sink", created, scope, what)], anchor: created.spot, note: noteOf(created) };
  }
  if (cause.kind === "rls-disabled") {
    const entry = step("entrypoint", created, scope, "CREATE TABLE exposes the table to the anon and authenticated roles through the Supabase default privileges, and row level security is not on for it.");
    const middle = rls === null ? [] : [step("propagation", rls, scope, "The last ALTER TABLE that changed row level security on this table leaves it switched off.")];
    return { trace: dedupe([entry, ...middle, sink]), anchor: created.spot, note: noteOf(created) };
  }
  if (cause.policy !== null) {
    const spot = policySpot(src, key, table.name.name, cause.policy.name);
    const located = spot ?? created;
    const note = spot === null ? " The statement that defines the policy could not be found; this is the table declaration." : "";
    const entry = step("entrypoint", located, `policy "${cause.policy.name}" on ${key}`, `${cause.text}${note}`);
    const middle = rls === null ? [] : [step("propagation", rls, scope, "Row level security is on, so policies decide access; this policy admits the rows.")];
    return { trace: dedupe([entry, ...middle, sink]), anchor: located.spot, note: noteOf(located) };
  }
  // owner-not-compared: every policy of the table is part of the cause.
  const first = rls ?? created;
  const entry = step("entrypoint", first, scope, cause.text);
  const policies = [...table.policies]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .slice(0, 10)
    .flatMap((p) => {
      const spot = policySpot(src, key, table.name.name, p.name);
      return spot === null ? [] : [step("propagation", spot, `policy "${p.name}" on ${key}`, "This policy never compares the owner column with the signed-in user.")];
    });
  return { trace: dedupe([entry, ...policies, sink]), anchor: first.spot, note: noteOf(first) };
}

/** The trace of a view that bypasses row level security: the view, then the protected tables it reads. */
export function locateViewCause(src: SourceMap, view: View, model: SchemaModel, cause: RootCause | null, untested: boolean): Located | null {
  const key = qualifiedKey(view.name);
  const indexed = src.sources.views.get(key);
  const found = indexed !== undefined ? declared(indexed) : mention(src, [view.name.name]);
  if (found === null) return null;
  const scope = `view ${key}`;
  if (cause === null) {
    const what = untested ? "The view that could not be fully tested." : "The view the proven attacks ran against; no setting the static reader found explains them.";
    return { trace: [step("sink", found, scope, what)], anchor: found.spot, note: noteOf(found) };
  }
  const entry = step("entrypoint", found, scope, cause.text);
  const bases = baseTables(view, model)
    .filter((t) => t.rlsEnabled)
    .flatMap((t) => {
      const base = createdSpot(src, qualifiedKey(t.name), t.name.name);
      return base === null ? [] : [{ t, base }];
    });
  const steps = bases.map(({ t, base }, i) => step(i === bases.length - 1 ? "sink" : "propagation", base, `table ${qualifiedKey(t.name)}`, "A table with row level security that the view reads with its owner's rights."));
  return { trace: dedupe([entry, ...steps]), anchor: found.spot, note: noteOf(found) };
}

/** The trace of a finding of the static auditor: the policy it flagged (or the table), then the table. */
export function locateStatic(src: SourceMap, table: string, policy: string | null, flagged: string): Located | null {
  const name = table.slice(table.indexOf(".") + 1);
  const created = createdSpot(src, table, name);
  if (created === null) return null;
  const scope = `table ${table}`;
  const sink = step("sink", created, scope, SINK);
  const spot = policy === null ? null : policySpot(src, table, name, policy);
  if (spot === null) return { trace: dedupe([step("entrypoint", created, scope, flagged), sink]), anchor: created.spot, note: noteOf(created) };
  return { trace: dedupe([step("entrypoint", spot, `policy "${policy}" on ${table}`, flagged), sink]), anchor: spot.spot, note: noteOf(spot) };
}
