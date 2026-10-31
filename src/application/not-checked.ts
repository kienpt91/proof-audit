/** What every run leaves unchecked. Printed in every report so a clean result is never read as "safe". */
export const NOT_CHECKED: readonly string[] = [
  "Authorization written in application code: route handlers, server actions, edge functions and anything else that runs before the database.",
  "Frontend code, and anything the browser does with the data it receives.",
  "Exposure of secrets: keys, tokens, .env files and service-role keys that ship to the client.",
  "Supabase features outside Postgres row level security: storage buckets and their policies, realtime, GraphQL, auth settings.",
  "Policies that depend on data this tool does not create: custom JWT claims other than sub, role, tenant_id and org_id, extensions other than uuid-ossp and pgcrypto.",
  "Materialized views, functions callable as RPC, column-level privileges, and tables that the migrations do not create.",
  "A CLEAN result means the listed attacks were refused for two synthetic users and an anonymous caller. It is not a penetration test and does not show the table is safe.",
];
