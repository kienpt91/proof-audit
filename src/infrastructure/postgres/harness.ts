import { LIMITS } from "../../domain/limits.js";

/**
 * SQL functions installed in every throwaway database (schema `proof_audit`). They let the adapters send
 * one self-contained SELECT per operation and read one JSON value back, whatever transport carries it:
 *
 * - `try_exec(stmt)`: run one statement as the database owner; an error is returned, not raised.
 * - `try_first(stmts[])`: run alternatives in order until one works.
 * - `scalar(query)`: run a query and return its single value.
 * - `run_probe(role, claims, sql)`: run one statement as a client role with the given JWT claims inside a
 *   sub-transaction that is always rolled back, and report the affected row count or the error.
 * - `catalog()`: the schema as JSON, validated on the TypeScript side.
 */
export const HARNESS_STATEMENTS: readonly string[] = [
  "CREATE SCHEMA IF NOT EXISTS proof_audit",
  `CREATE OR REPLACE FUNCTION proof_audit.try_exec(stmt text) RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE stmt;
  RESET ROLE;
  RESET SESSION AUTHORIZATION;
  RETURN jsonb_build_object('ok', true);
EXCEPTION
  WHEN query_canceled THEN
    RETURN jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
  WHEN OTHERS THEN
    RETURN jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
END
$$`,
  `CREATE OR REPLACE FUNCTION proof_audit.try_first(stmts text[]) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  i int;
  r jsonb := jsonb_build_object('ok', false, 'attempt', NULL, 'sqlstate', '00000', 'message', 'no statement given');
BEGIN
  FOR i IN 1 .. coalesce(array_length(stmts, 1), 0) LOOP
    BEGIN
      EXECUTE stmts[i];
      RESET ROLE;
      RESET SESSION AUTHORIZATION;
      RETURN jsonb_build_object('ok', true, 'attempt', i - 1);
    EXCEPTION
      WHEN query_canceled THEN
        r := jsonb_build_object('ok', false, 'attempt', NULL, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
      WHEN OTHERS THEN
        r := jsonb_build_object('ok', false, 'attempt', NULL, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
    END;
  END LOOP;
  RETURN r;
END
$$`,
  `CREATE OR REPLACE FUNCTION proof_audit.scalar(query text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
  EXECUTE query INTO v;
  RETURN jsonb_build_object('ok', true, 'value', v);
EXCEPTION
  WHEN query_canceled THEN
    RETURN jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
  WHEN OTHERS THEN
    RETURN jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
END
$$`,
  `CREATE OR REPLACE FUNCTION proof_audit.run_probe(p_role text, p_claims text, p_sql text) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  res jsonb;
BEGIN
  BEGIN
    PERFORM set_config('request.jwt.claims', p_claims, true);
    EXECUTE format('SET LOCAL ROLE %I', p_role);
    EXECUTE p_sql;
    GET DIAGNOSTICS n = ROW_COUNT;
    res := jsonb_build_object('ok', true, 'rows', n);
    RAISE EXCEPTION USING ERRCODE = 'PA000', MESSAGE = 'probe rolled back';
  EXCEPTION
    WHEN SQLSTATE 'PA000' THEN NULL;
    WHEN query_canceled THEN
      res := jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
    WHEN OTHERS THEN
      res := jsonb_build_object('ok', false, 'sqlstate', SQLSTATE, 'message', left(SQLERRM, 500));
  END;
  RETURN res;
END
$$`,
  `CREATE OR REPLACE FUNCTION proof_audit.catalog() RETURNS jsonb LANGUAGE sql AS $$
WITH rels AS (
  SELECT c.oid, n.nspname AS schema, c.relname AS name, c.relkind, c.relrowsecurity, c.relforcerowsecurity, c.reloptions
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v')
    AND NOT c.relispartition
    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'auth', 'extensions', 'proof_audit')
    AND n.nspname NOT LIKE 'pg\\_%'
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
),
cmds(cmd, priv) AS (VALUES ('select', 'SELECT'), ('insert', 'INSERT'), ('update', 'UPDATE'), ('delete', 'DELETE'))
SELECT jsonb_build_object(
  'serverVersion', current_setting('server_version'),
  'truncated', (SELECT count(*) FROM rels WHERE relkind IN ('r', 'p')) > ${LIMITS.maxTables} OR (SELECT count(*) FROM rels WHERE relkind = 'v') > ${LIMITS.maxTables},
  'tables', (
    SELECT coalesce(jsonb_agg(tj ORDER BY ord), '[]'::jsonb) FROM (
      SELECT t.schema || '.' || t.name AS ord, jsonb_build_object(
        'schema', t.schema,
        'name', t.name,
        'rls', t.relrowsecurity,
        'forceRls', t.relforcerowsecurity,
        'columns', (
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'name', a.attname,
            'type', format_type(a.atttypid, a.atttypmod),
            'notNull', a.attnotnull,
            'default', CASE WHEN a.attidentity <> '' THEN 'GENERATED AS IDENTITY' WHEN a.attgenerated <> '' THEN NULL ELSE pg_get_expr(d.adbin, d.adrelid) END,
            'generated', (a.attgenerated <> '' OR a.attidentity = 'a'),
            'enumLabels', (SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = a.atttypid)
          ) ORDER BY a.attnum), '[]'::jsonb)
          FROM pg_attribute a
          LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
          WHERE a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
        ),
        'primaryKey', (
          SELECT coalesce(jsonb_agg(a.attname ORDER BY k.ord), '[]'::jsonb)
          FROM pg_constraint c
          CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
          WHERE c.conrelid = t.oid AND c.contype = 'p'
        ),
        'unique', (
          SELECT coalesce(jsonb_agg(DISTINCT a.attname), '[]'::jsonb)
          FROM pg_index i
          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
          WHERE i.indrelid = t.oid AND i.indisunique AND i.indnatts = 1 AND i.indpred IS NULL
        ),
        'foreignKeys', (
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'columns', (SELECT jsonb_agg(a.attname ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
            'refSchema', rn.nspname,
            'refTable', rc.relname,
            'refColumns', (SELECT jsonb_agg(a.attname ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum)
          )), '[]'::jsonb)
          FROM pg_constraint c
          JOIN pg_class rc ON rc.oid = c.confrelid
          JOIN pg_namespace rn ON rn.oid = rc.relnamespace
          WHERE c.conrelid = t.oid AND c.contype = 'f'
        ),
        'checks', (SELECT coalesce(jsonb_agg(pg_get_constraintdef(c.oid) ORDER BY c.conname), '[]'::jsonb) FROM pg_constraint c WHERE c.conrelid = t.oid AND c.contype = 'c'),
        'policies', (
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'name', p.polname,
            'command', CASE p.polcmd WHEN 'r' THEN 'select' WHEN 'a' THEN 'insert' WHEN 'w' THEN 'update' WHEN 'd' THEN 'delete' ELSE 'all' END,
            'permissive', p.polpermissive,
            'roles', (SELECT coalesce(jsonb_agg(CASE WHEN r.oid = 0 THEN 'public' ELSE (SELECT rolname FROM pg_roles WHERE oid = r.oid) END), '["public"]'::jsonb) FROM unnest(p.polroles) AS r(oid)),
            'using', pg_get_expr(p.polqual, p.polrelid),
            'withCheck', pg_get_expr(p.polwithcheck, p.polrelid)
          ) ORDER BY p.polname), '[]'::jsonb)
          FROM pg_policy p WHERE p.polrelid = t.oid
        ),
        'privileges', jsonb_build_object(
          'anon', (SELECT coalesce(jsonb_agg(cmd), '[]'::jsonb) FROM cmds WHERE has_schema_privilege('anon', t.schema, 'USAGE') AND has_table_privilege('anon', t.oid, priv)),
          'authenticated', (SELECT coalesce(jsonb_agg(cmd), '[]'::jsonb) FROM cmds WHERE has_schema_privilege('authenticated', t.schema, 'USAGE') AND has_table_privilege('authenticated', t.oid, priv))
        )
      ) AS tj
      FROM rels t WHERE t.relkind IN ('r', 'p') ORDER BY t.schema, t.name LIMIT ${LIMITS.maxTables}
    ) x
  ),
  'views', (
    SELECT coalesce(jsonb_agg(vj ORDER BY ord), '[]'::jsonb) FROM (
      SELECT v.schema || '.' || v.name AS ord, jsonb_build_object(
        'schema', v.schema,
        'name', v.name,
        'columns', (SELECT coalesce(jsonb_agg(a.attname ORDER BY a.attnum), '[]'::jsonb) FROM pg_attribute a WHERE a.attrelid = v.oid AND a.attnum > 0 AND NOT a.attisdropped),
        'securityInvoker', coalesce((SELECT bool_or(o IN ('security_invoker=true', 'security_invoker=on', 'security_invoker=1', 'security_invoker=yes')) FROM unnest(v.reloptions) AS o), false),
        'definition', pg_get_viewdef(v.oid),
        'dependsOn', (
          SELECT coalesce(jsonb_agg(jsonb_build_object('schema', s.nspname, 'name', s.relname) ORDER BY s.nspname, s.relname), '[]'::jsonb)
          FROM (
            SELECT DISTINCT n2.nspname, c2.relname
            FROM pg_rewrite rw
            JOIN pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass
            JOIN pg_class c2 ON c2.oid = d.refobjid
            JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
            WHERE rw.ev_class = v.oid AND c2.oid <> v.oid AND c2.relkind IN ('r', 'p', 'v') AND n2.nspname NOT IN ('pg_catalog', 'information_schema')
          ) s
        ),
        'privileges', jsonb_build_object(
          'anon', (SELECT coalesce(jsonb_agg(cmd), '[]'::jsonb) FROM cmds WHERE has_schema_privilege('anon', v.schema, 'USAGE') AND has_table_privilege('anon', v.oid, priv)),
          'authenticated', (SELECT coalesce(jsonb_agg(cmd), '[]'::jsonb) FROM cmds WHERE has_schema_privilege('authenticated', v.schema, 'USAGE') AND has_table_privilege('authenticated', v.oid, priv))
        )
      ) AS vj
      FROM rels v WHERE v.relkind = 'v' ORDER BY v.schema, v.name LIMIT ${LIMITS.maxTables}
    ) y
  )
)
$$`,
];
