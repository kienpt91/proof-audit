import { modelToCatalog } from "./model-sandbox.js";
import type { SqlTransport } from "../../src/infrastructure/postgres/transport.js";
import { model, notes } from "./model.js";

export interface Call {
  readonly kind: "query" | "execute";
  readonly database: string;
  readonly statements: readonly string[];
}

/** A transport with canned harness replies, for adapter tests that must not need a database. */
export class FakeTransport implements SqlTransport {
  readonly calls: Call[] = [];
  failExecute: RegExp | null = null;
  failQuery: Error | null = null;
  replyOverride: ((statement: string) => string | undefined) | null = null;

  async query(database: string, statements: readonly string[]): Promise<string[]> {
    this.calls.push({ kind: "query", database, statements });
    if (this.failQuery) throw this.failQuery;
    return statements.map((s) => this.replyOverride?.(s) ?? this.reply(s));
  }

  async execute(database: string, statements: readonly string[]): Promise<void> {
    this.calls.push({ kind: "execute", database, statements });
    for (const s of statements) if (this.failExecute?.test(s)) throw new Error(`execute failed: ${s.slice(0, 30)}`);
  }

  private reply(statement: string): string {
    if (statement.includes("proof_audit.try_exec(")) return '{"ok": true}';
    if (statement.includes("proof_audit.try_first(")) return '{"ok": true, "attempt": 0}';
    if (statement.includes("proof_audit.scalar(")) return '{"ok": true, "value": "1"}';
    if (statement.includes("proof_audit.run_probe(")) return '{"ok": true, "rows": 1}';
    if (statement.includes("proof_audit.catalog()")) return JSON.stringify(modelToCatalog(model([notes()])));
    if (statement.includes("is_superuser")) return "on";
    throw new Error(`FakeTransport does not know ${statement}`);
  }

  get executed(): string[] {
    return this.calls.filter((c) => c.kind === "execute").flatMap((c) => [...c.statements]);
  }
}
