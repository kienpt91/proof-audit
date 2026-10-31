import type { SessionSpec, SqlTransport, Step } from "../../src/infrastructure/postgres/transport.js";
import { modelToCatalog } from "./model-sandbox.js";
import { model, notes } from "./model.js";

export interface Call {
  readonly session: SessionSpec;
  readonly steps: readonly Step[];
}

/** A transport with canned replies, for adapter tests that must not need a database. */
export class FakeTransport implements SqlTransport {
  readonly calls: Call[] = [];
  /** Throw for any call that contains a step whose SQL matches. */
  failOn: RegExp | null = null;
  failAll: Error | null = null;
  /** Override the reply for a fetch step (receives the step SQL and the DO block SQL before it). */
  replyOverride: ((fetchSql: string, blockSql: string) => string | undefined) | null = null;

  async run(session: SessionSpec, steps: readonly Step[]): Promise<string[]> {
    this.calls.push({ session, steps });
    if (this.failAll) throw this.failAll;
    const out: string[] = [];
    steps.forEach((step, i) => {
      if (this.failOn?.test(step.sql)) throw new Error(`step failed: ${step.sql.slice(0, 40)}`);
      if (step.fetch) out.push(this.replyOverride?.(step.sql, steps[i - 1]?.sql ?? "") ?? this.reply(step.sql, steps[i - 1]?.sql ?? ""));
    });
    return out;
  }

  private reply(fetchSql: string, blockSql: string): string {
    if (fetchSql.includes("current_setting('proof_audit.reply'")) {
      if (blockSql.includes("jsonb_build_object('ok', true, 'rows', n)")) return '{"ok": true, "rows": 1}';
      if (blockSql.includes("'attempt'") || blockSql.includes('"attempt"')) return '{"ok": true, "attempt": 0}';
      if (blockSql.includes("'value', v")) return '{"ok": true, "value": "1"}';
      return '{"ok": true}';
    }
    if (fetchSql.includes("jsonb_agg(tj")) return JSON.stringify(modelToCatalog(model([notes()])));
    if (fetchSql.includes("'entries'")) return JSON.stringify({ entries: [{ key: "role anon", value: "super=false" }] });
    if (fetchSql.includes("is_superuser")) return "on";
    throw new Error(`FakeTransport does not know ${fetchSql.slice(0, 60)}`);
  }

  /** Every SQL string sent, in order. */
  get sent(): string[] {
    return this.calls.flatMap((c) => c.steps.map((s) => s.sql));
  }

  /** The calls made as one principal. */
  by(principal: SessionSpec["principal"]): Call[] {
    return this.calls.filter((c) => c.session.principal === principal);
  }
}
