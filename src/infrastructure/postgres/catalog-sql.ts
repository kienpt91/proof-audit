import { LIMITS } from "../../domain/limits.js";
import { quoteLiteral } from "../../domain/sql/quote.js";

/**
 * Read-only queries run by the admin in a session whose search_path is pinned to pg_catalog. They contain no
 * unqualified function and nothing a migration can shadow. They are sent by the tool each time; no stored function is involved.
 */

/** Every table and view the migrations left in a schema that is not the database's own, as one JSON value. */
export const CATALOG_QUERY = `WITH rels AS (
  SELECT c.oid, n.nspname AS schema, c.relname AS name, c.relkind, c.relrowsecurity, c.relforcerowsecurity, c.reloptions
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v')
    AND NOT c.relispartition
    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
    AND n.nspname NOT LIKE 'pg\\_temp\\_%'
    AND n.nspname NOT LIKE 'pg\\_toast\\_temp\\_%'
    AND NOT (n.nspname = 'auth' AND c.relname = 'users')
),
cmds(cmd, priv) AS (VALUES ('select', 'SELECT'), ('insert', 'INSERT'), ('update', 'UPDATE'), ('delete', 'DELETE'))
SELECT pg_catalog.jsonb_build_object(
  'serverVersion', pg_catalog.current_setting('server_version'),
  'truncated', (SELECT pg_catalog.count(*) FROM rels WHERE relkind IN ('r', 'p')) > ${LIMITS.maxTables} OR (SELECT pg_catalog.count(*) FROM rels WHERE relkind = 'v') > ${LIMITS.maxTables},
  'tables', (
    SELECT coalesce(pg_catalog.jsonb_agg(tj ORDER BY ord), '[]'::pg_catalog.jsonb) FROM (
      SELECT t.schema || '.' || t.name AS ord, pg_catalog.jsonb_build_object(
        'schema', t.schema,
        'name', t.name,
        'rls', t.relrowsecurity,
        'forceRls', t.relforcerowsecurity,
        'columns', (
          SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'name', a.attname,
            'type', pg_catalog.format_type(a.atttypid, a.atttypmod),
            'notNull', a.attnotnull,
            'default', CASE WHEN a.attidentity <> '' THEN 'GENERATED AS IDENTITY' WHEN a.attgenerated <> '' THEN NULL ELSE pg_catalog.pg_get_expr(d.adbin, d.adrelid) END,
            'generated', (a.attgenerated <> '' OR a.attidentity = 'a'),
            'enumLabels', (SELECT pg_catalog.jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_catalog.pg_enum e WHERE e.enumtypid = a.atttypid)
          ) ORDER BY a.attnum), '[]'::pg_catalog.jsonb)
          FROM pg_catalog.pg_attribute a
          LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
          WHERE a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
        ),
        'primaryKey', (
          SELECT coalesce(pg_catalog.jsonb_agg(a.attname ORDER BY k.ord), '[]'::pg_catalog.jsonb)
          FROM pg_catalog.pg_constraint c
          CROSS JOIN LATERAL pg_catalog.unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
          JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
          WHERE c.conrelid = t.oid AND c.contype = 'p'
        ),
        'unique', (
          SELECT coalesce(pg_catalog.jsonb_agg(DISTINCT a.attname), '[]'::pg_catalog.jsonb)
          FROM pg_catalog.pg_index i
          JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
          WHERE i.indrelid = t.oid AND i.indisunique AND i.indnatts = 1 AND i.indpred IS NULL
        ),
        'foreignKeys', (
          SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'columns', (SELECT pg_catalog.jsonb_agg(a.attname ORDER BY k.ord) FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
            'refSchema', rn.nspname,
            'refTable', rc.relname,
            'refColumns', (SELECT pg_catalog.jsonb_agg(a.attname ORDER BY k.ord) FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord) JOIN pg_catalog.pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum)
          )), '[]'::pg_catalog.jsonb)
          FROM pg_catalog.pg_constraint c
          JOIN pg_catalog.pg_class rc ON rc.oid = c.confrelid
          JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
          WHERE c.conrelid = t.oid AND c.contype = 'f'
        ),
        'checks', (SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.pg_get_constraintdef(c.oid) ORDER BY c.conname), '[]'::pg_catalog.jsonb) FROM pg_catalog.pg_constraint c WHERE c.conrelid = t.oid AND c.contype = 'c'),
        'policies', (
          SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'name', p.polname,
            'command', CASE p.polcmd WHEN 'r' THEN 'select' WHEN 'a' THEN 'insert' WHEN 'w' THEN 'update' WHEN 'd' THEN 'delete' ELSE 'all' END,
            'permissive', p.polpermissive,
            'roles', (SELECT coalesce(pg_catalog.jsonb_agg(CASE WHEN r.oid = 0 THEN 'public' ELSE (SELECT rolname FROM pg_catalog.pg_roles WHERE oid = r.oid) END), '["public"]'::pg_catalog.jsonb) FROM pg_catalog.unnest(p.polroles) AS r(oid)),
            'using', pg_catalog.pg_get_expr(p.polqual, p.polrelid),
            'withCheck', pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)
          ) ORDER BY p.polname), '[]'::pg_catalog.jsonb)
          FROM pg_catalog.pg_policy p WHERE p.polrelid = t.oid
        ),
        'privileges', pg_catalog.jsonb_build_object(
          'anon', (SELECT coalesce(pg_catalog.jsonb_agg(cmd), '[]'::pg_catalog.jsonb) FROM cmds WHERE pg_catalog.has_schema_privilege('anon', t.schema, 'USAGE') AND pg_catalog.has_table_privilege('anon', t.oid, priv)),
          'authenticated', (SELECT coalesce(pg_catalog.jsonb_agg(cmd), '[]'::pg_catalog.jsonb) FROM cmds WHERE pg_catalog.has_schema_privilege('authenticated', t.schema, 'USAGE') AND pg_catalog.has_table_privilege('authenticated', t.oid, priv))
        )
      ) AS tj
      FROM rels t WHERE t.relkind IN ('r', 'p') ORDER BY t.schema, t.name LIMIT ${LIMITS.maxTables}
    ) x
  ),
  'views', (
    SELECT coalesce(pg_catalog.jsonb_agg(vj ORDER BY ord), '[]'::pg_catalog.jsonb) FROM (
      SELECT v.schema || '.' || v.name AS ord, pg_catalog.jsonb_build_object(
        'schema', v.schema,
        'name', v.name,
        'columns', (SELECT coalesce(pg_catalog.jsonb_agg(a.attname ORDER BY a.attnum), '[]'::pg_catalog.jsonb) FROM pg_catalog.pg_attribute a WHERE a.attrelid = v.oid AND a.attnum > 0 AND NOT a.attisdropped),
        'securityInvoker', coalesce((SELECT pg_catalog.bool_or(o IN ('security_invoker=true', 'security_invoker=on', 'security_invoker=1', 'security_invoker=yes')) FROM pg_catalog.unnest(v.reloptions) AS o), false),
        'definition', pg_catalog.pg_get_viewdef(v.oid),
        'dependsOn', (
          SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('schema', s.nspname, 'name', s.relname) ORDER BY s.nspname, s.relname), '[]'::pg_catalog.jsonb)
          FROM (
            SELECT DISTINCT n2.nspname, c2.relname
            FROM pg_catalog.pg_rewrite rw
            JOIN pg_catalog.pg_depend d ON d.objid = rw.oid AND d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
            JOIN pg_catalog.pg_class c2 ON c2.oid = d.refobjid
            JOIN pg_catalog.pg_namespace n2 ON n2.oid = c2.relnamespace
            WHERE rw.ev_class = v.oid AND c2.oid <> v.oid AND c2.relkind IN ('r', 'p', 'v') AND n2.nspname NOT IN ('pg_catalog', 'information_schema')
          ) s
        ),
        'privileges', pg_catalog.jsonb_build_object(
          'anon', (SELECT coalesce(pg_catalog.jsonb_agg(cmd), '[]'::pg_catalog.jsonb) FROM cmds WHERE pg_catalog.has_schema_privilege('anon', v.schema, 'USAGE') AND pg_catalog.has_table_privilege('anon', v.oid, priv)),
          'authenticated', (SELECT coalesce(pg_catalog.jsonb_agg(cmd), '[]'::pg_catalog.jsonb) FROM cmds WHERE pg_catalog.has_schema_privilege('authenticated', v.schema, 'USAGE') AND pg_catalog.has_table_privilege('authenticated', v.oid, priv))
        )
      ) AS vj
      FROM rels v WHERE v.relkind = 'v' ORDER BY v.schema, v.name LIMIT ${LIMITS.maxTables}
    ) y
  )
)::pg_catalog.text`;

/**
 * The platform part of the sandbox as sorted key/value pairs (see `src/domain/integrity/fingerprint.ts`): the
 * `auth` functions with owner and a hash of their body, the roles of the sandbox and their attributes and
 * memberships, per-database and per-role settings, event triggers, and the owner and ACL of the platform schemas.
 */
export function fingerprintQuery(roleNames: readonly string[]): string {
  const roles = `ARRAY[${roleNames.map(quoteLiteral).join(", ")}]::pg_catalog.text[]`;
  return `SELECT pg_catalog.jsonb_build_object('entries', coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('key', k, 'value', v) ORDER BY k), '[]'::pg_catalog.jsonb))::pg_catalog.text FROM (
  SELECT 'function auth.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS k,
    'owner=' || pg_catalog.pg_get_userbyid(p.proowner) || ';definer=' || p.prosecdef || ';lang=' || l.lanname || ';volatile=' || p.provolatile::pg_catalog.text || ';config=' || coalesce(pg_catalog.array_to_string(p.proconfig, ','), '') || ';sha=' || pg_catalog.md5(p.prosrc) AS v
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'auth'
  JOIN pg_catalog.pg_language l ON l.oid = p.prolang
  UNION ALL
  SELECT 'relation auth.users', 'owner=' || pg_catalog.pg_get_userbyid(c.relowner) || ';kind=' || c.relkind::pg_catalog.text || ';rls=' || c.relrowsecurity
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'auth' WHERE c.relname = 'users'
  UNION ALL
  SELECT 'role ' || r.rolname, 'super=' || r.rolsuper || ';bypassrls=' || r.rolbypassrls || ';login=' || r.rolcanlogin || ';inherit=' || r.rolinherit || ';createrole=' || r.rolcreaterole || ';createdb=' || r.rolcreatedb || ';replication=' || r.rolreplication
  FROM pg_catalog.pg_roles r WHERE r.rolname = ANY (${roles}) OR r.rolname IN ('anon', 'authenticated', 'service_role')
  UNION ALL
  SELECT 'membership ' || pg_catalog.pg_get_userbyid(m.member) || ' in ' || pg_catalog.pg_get_userbyid(m.roleid), 'admin=' || m.admin_option
  FROM pg_catalog.pg_auth_members m
  WHERE pg_catalog.pg_get_userbyid(m.member) = ANY (${roles}) OR pg_catalog.pg_get_userbyid(m.roleid) = ANY (${roles}) OR pg_catalog.pg_get_userbyid(m.roleid) IN ('anon', 'authenticated', 'service_role')
  UNION ALL
  SELECT 'setting database=' || CASE WHEN d.datname IS NULL THEN '-' ELSE 'current' END || ' role=' || coalesce(r.rolname, '-'), pg_catalog.array_to_string(s.setconfig, ',')
  FROM pg_catalog.pg_db_role_setting s
  LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
  LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
  WHERE (s.setdatabase = 0 OR d.datname = pg_catalog.current_database()) AND (s.setrole = 0 OR r.rolname = ANY (${roles}) OR r.rolname IN ('anon', 'authenticated', 'service_role'))
  UNION ALL
  SELECT 'event trigger ' || e.evtname, 'owner=' || pg_catalog.pg_get_userbyid(e.evtowner) || ';enabled=' || e.evtenabled::pg_catalog.text || ';function=' || e.evtfoid::pg_catalog.regproc::pg_catalog.text
  FROM pg_catalog.pg_event_trigger e
  UNION ALL
  SELECT 'schema ' || n.nspname, 'owner=' || pg_catalog.pg_get_userbyid(n.nspowner) || ';acl=' || coalesce(n.nspacl::pg_catalog.text, '')
  FROM pg_catalog.pg_namespace n WHERE n.nspname IN ('auth', 'extensions')
  UNION ALL
  SELECT 'database current', 'owner=' || pg_catalog.pg_get_userbyid(d.datdba)
  FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()
) f(k, v)`;
}
