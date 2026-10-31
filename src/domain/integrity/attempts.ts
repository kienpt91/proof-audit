import type { IntegrityKind } from "../analysis/types.js";
import { tokenize, type Token } from "../sql/tokenizer.js";
import type { SqlStatement } from "../sql/statement.js";

/**
 * Statements that touch the test environment the verdicts depend on, found by reading the migration text.
 * Legitimate migrations do not do these things: the platform (roles, `auth.*` functions, settings) is
 * provided by Supabase, and the tool's own helpers are not part of any app. The sandbox also refuses most of
 * them by privilege, so a hit is reported whether or not the database let it through.
 */
export interface TamperAttempt {
  readonly kind: IntegrityKind;
  readonly detail: string;
  readonly file: string;
  readonly line: number;
}

const PROTECTED_SCHEMAS: readonly string[] = ["auth", "proof_audit", "pg_catalog", "information_schema"];
const OBJECT_KINDS: readonly string[] = ["function", "procedure", "aggregate", "operator", "schema", "view", "table", "type", "domain", "sequence", "language", "cast"];
const PROTECTED_SETTINGS: readonly string[] = ["search_path", "session_replication_role", "session_authorization", "row_security", "role"];
const CATALOG_TABLES = /^pg_(proc|authid|auth_members|class|namespace|policy|operator|cast|language|event_trigger|db_role_setting|depend|attribute|database|roles|shadow|type|rewrite|trigger)$/;

function isName(t: Token | undefined): boolean {
  return t !== undefined && (t.kind === "word" || t.kind === "quoted-ident");
}

function flatten(source: string, depth: number): Token[] {
  const out: Token[] = [];
  for (const t of tokenize(source)) {
    out.push(t);
    if (depth < 3 && (t.kind === "dollar-string" || t.kind === "string") && /\b(alter|create|drop|update|insert|delete|set|proof_audit)\b/i.test(t.value)) {
      out.push(...flatten(t.value, depth + 1).map((inner) => ({ ...inner, line: t.line })));
    }
  }
  return out;
}

const word = (t: Token | undefined, ...values: string[]): boolean => t !== undefined && t.kind === "word" && values.includes(t.value);

function skipOptional(tokens: readonly Token[], i: number): number {
  let j = i;
  if (word(tokens[j], "if") && word(tokens[j + 1], "not") && word(tokens[j + 2], "exists")) j += 3;
  else if (word(tokens[j], "if") && word(tokens[j + 1], "exists")) j += 2;
  return j;
}

function scanStatement(statement: SqlStatement): TamperAttempt[] {
  const tokens = flatten(statement.text, 0);
  const found: TamperAttempt[] = [];
  const add = (kind: IntegrityKind, detail: string): void => {
    if (!found.some((f) => f.kind === kind && f.detail === detail)) found.push({ kind, detail, file: statement.file, line: statement.line });
  };
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t) continue;
    if (isName(t) && t.value === "proof_audit") add("targets-tool-internals", "mentions the tool's own schema proof_audit");
    if (word(t, "create", "alter", "drop") && word(tokens[i + 1], "event") && word(tokens[i + 2], "trigger")) add("event-trigger", `${t.value.toUpperCase()} EVENT TRIGGER`);
    if (word(t, "alter") && word(tokens[i + 1], "system")) add("alters-protected-setting", "ALTER SYSTEM");
    if (word(t, "alter") && word(tokens[i + 1], "extension") && isName(tokens[i + 2]) && word(tokens[i + 3], "add", "drop")) add("redefines-platform-object", `ALTER EXTENSION ${tokens[i + 2]?.value.toLowerCase()} ${tokens[i + 3]?.value.toUpperCase()}`);
    if (word(t, "alter") && word(tokens[i + 1], "database", "role", "user", "group")) {
      for (let j = i + 2; j < Math.min(tokens.length, i + 14); j++) {
        if (word(tokens[j], "set") && tokens[j + 1] && isName(tokens[j + 1]) && PROTECTED_SETTINGS.includes(tokens[j + 1]?.value.toLowerCase() ?? "")) {
          add("alters-protected-setting", `ALTER ${(tokens[i + 1]?.value ?? "").toUpperCase()} ... SET ${tokens[j + 1]?.value.toLowerCase()}`);
          break;
        }
      }
    }
    if (word(t, "set")) {
      let j = i + 1;
      if (word(tokens[j], "session", "local")) j += 1;
      const name = tokens[j];
      if (name && isName(name) && ["session_replication_role", "session_authorization"].includes(name.value.toLowerCase())) add("alters-protected-setting", `SET ${name.value.toLowerCase()}`);
    }
    if (word(t, "set_config")) {
      const arg = tokens[i + 2];
      if (arg?.kind === "string" && ["session_replication_role", "session_authorization"].includes(arg.value.toLowerCase())) add("alters-protected-setting", `set_config('${arg.value.toLowerCase()}')`);
    }
    if (word(t, "create", "alter", "drop")) {
      let j = i + 1;
      if (word(tokens[j], "or") && word(tokens[j + 1], "replace")) j += 2;
      if (word(tokens[j], "materialized")) j += 1;
      const kindToken = tokens[j];
      if (kindToken && kindToken.kind === "word" && OBJECT_KINDS.includes(kindToken.value)) {
        j = skipOptional(tokens, j + 1);
        const schema = tokens[j];
        if (isName(schema) && tokens[j + 1]?.kind === "punct" && tokens[j + 1]?.value === "." && PROTECTED_SCHEMAS.includes(schema?.value.toLowerCase() ?? "")) {
          const target = tokens[j + 2];
          add("redefines-platform-object", `${t.value.toUpperCase()} ${kindToken.value.toUpperCase()} ${schema?.value.toLowerCase()}.${target?.value ?? "?"}`);
        }
      }
    }
    if (word(t, "update", "insert", "delete")) {
      let j = i + 1;
      if (word(t, "insert") && word(tokens[j], "into")) j += 1;
      if (word(t, "delete") && word(tokens[j], "from")) j += 1;
      if (word(tokens[j], "only")) j += 1;
      let target = tokens[j];
      if (isName(target) && target?.value.toLowerCase() === "pg_catalog" && tokens[j + 1]?.value === ".") target = tokens[j + 2];
      if (isName(target) && CATALOG_TABLES.test(target?.value.toLowerCase() ?? "")) add("catalog-write", `${t.value.toUpperCase()} on pg_catalog.${target?.value.toLowerCase()}`);
    }
  }
  return found;
}

/** Scan every statement, including SQL hidden in DO blocks and EXECUTE strings (three levels deep). */
export function scanForTampering(statements: readonly SqlStatement[]): readonly TamperAttempt[] {
  return statements.filter((s) => s.kind === "sql").flatMap(scanStatement);
}
