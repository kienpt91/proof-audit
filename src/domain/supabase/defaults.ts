import { COMMANDS, type ClientRole, type Command } from "../schema/model.js";

/** Schemas the Supabase API (PostgREST) exposes to client keys unless the project says otherwise. */
export const EXPOSED_SCHEMAS: readonly string[] = ["public"];

/**
 * Privileges a table or view created in `schema` holds for the two client roles before any explicit
 * GRANT or REVOKE. Supabase grants everything on new objects in `public` to `anon` and `authenticated`
 * (through default privileges), so without row level security anyone with the anon key can read and
 * write them. Other schemas get nothing.
 */
export function defaultPrivileges(schema: string): Record<ClientRole, readonly Command[]> {
  const granted: readonly Command[] = EXPOSED_SCHEMAS.includes(schema) ? [...COMMANDS] : [];
  return { anon: [...granted], authenticated: [...granted] };
}
