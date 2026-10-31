import { dollarQuote, quoteLiteral } from "../../domain/sql/quote.js";
import type { Step } from "./transport.js";

/**
 * Every operation is an anonymous DO block that carries the SQL as a dollar-quoted string, followed by one SELECT that
 * reads the reply. Nothing is stored in the database for the tool to trust: there is no helper function a migration
 * could replace. Every function the blocks use is written `pg_catalog.name(...)`, no operator is used outside the SQL
 * under test, and the sessions that run them have `search_path` pinned at connection time.
 *
 * The reply travels in a custom setting, set by the block after its sub-transaction has ended, so nothing the SQL
 * under test did inside the sub-transaction (including setting that name itself) survives.
 */
const REPLY = "proof_audit.reply";

const FAIL = "pg_catalog.jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', pg_catalog.left(SQLERRM, 500))::pg_catalog.text";

const readReply: Step = { sql: `SELECT pg_catalog.current_setting('${REPLY}', true)`, fetch: true };

function block(body: string): Step {
  return { sql: `DO ${dollarQuote(body)}`, fetch: false };
}

const publish = `PERFORM pg_catalog.set_config('${REPLY}', r, false);`;

function guarded(statement: string, onSuccess: string): string {
  return `BEGIN
    EXECUTE ${dollarQuote(statement)};
    ${onSuccess}
  EXCEPTION
    WHEN query_canceled THEN r := ${FAIL};
    WHEN OTHERS THEN r := ${FAIL};
  END;`;
}

/** Run one statement, report success or its SQLSTATE and message. */
export function tryExec(statement: string): Step[] {
  return [
    block(`DECLARE r pg_catalog.text;
BEGIN
  ${guarded(statement, `r := '{"ok": true}';`)}
  ${publish}
END`),
    readReply,
  ];
}

/** Run alternatives in order until one succeeds. */
export function tryFirst(statements: readonly string[]): Step[] {
  const failedAll = `pg_catalog.jsonb_build_object('ok', false, 'sqlstate', '00000', 'message', 'no statement given')::pg_catalog.text`;
  const attempts = statements
    .map(
      (s, i) => `IF r IS NULL THEN
    BEGIN
      EXECUTE ${dollarQuote(s)};
      r := '{"ok": true, "attempt": ${i}}';
    EXCEPTION
      WHEN query_canceled THEN e := ${FAIL};
      WHEN OTHERS THEN e := ${FAIL};
    END;
  END IF;`,
    )
    .join("\n  ");
  return [
    block(`DECLARE r pg_catalog.text; e pg_catalog.text;
BEGIN
  ${attempts}
  IF r IS NULL THEN r := coalesce(e, ${failedAll}); END IF;
  ${publish}
END`),
    readReply,
  ];
}

/** Run a query that returns one value. */
export function scalar(query: string): Step[] {
  return [
    block(`DECLARE r pg_catalog.text; v pg_catalog.text;
BEGIN
  BEGIN
    EXECUTE ${dollarQuote(query)} INTO v;
    r := pg_catalog.jsonb_build_object('ok', true, 'value', v)::pg_catalog.text;
  EXCEPTION
    WHEN query_canceled THEN r := ${FAIL};
    WHEN OTHERS THEN r := ${FAIL};
  END;
  ${publish}
END`),
    readReply,
  ];
}

const CLIENT_ROLES: readonly string[] = ["anon", "authenticated"];

/**
 * Run one probe as a client role with the given JWT claims, inside a sub-transaction that is always rolled back,
 * and report the row count or the error the database raised.
 */
export function probe(role: string, claims: string, sql: string): Step[] {
  if (!CLIENT_ROLES.includes(role)) throw new Error("a probe can only run as anon or authenticated");
  return [
    block(`DECLARE n pg_catalog.int8; r pg_catalog.text;
BEGIN
  BEGIN
    PERFORM pg_catalog.set_config('request.jwt.claims', ${quoteLiteral(claims)}, true);
    SET LOCAL ROLE ${role};
    EXECUTE ${dollarQuote(sql)};
    GET DIAGNOSTICS n = ROW_COUNT;
    r := pg_catalog.jsonb_build_object('ok', true, 'rows', n)::pg_catalog.text;
    RAISE EXCEPTION USING ERRCODE = 'PA000', MESSAGE = 'probe rolled back';
  EXCEPTION
    WHEN SQLSTATE 'PA000' THEN NULL;
    WHEN query_canceled THEN r := ${FAIL};
    WHEN OTHERS THEN r := ${FAIL};
  END;
  ${publish}
END`),
    readReply,
  ];
}
