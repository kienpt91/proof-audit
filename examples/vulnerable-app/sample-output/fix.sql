-- proof-audit proposed fix: a STARTING POINT, not a finished migration.
-- Review every statement. It was derived from the schema model and checked against synthetic users only.

-- public.documents
-- Drop policy "Owners can edit documents": it does not tie every command to the row's owner.
-- Drop policy "Signed-in users can add documents": it does not tie every command to the row's owner.
-- Allow signed-in users to insert, update only rows whose owner_id is theirs.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Owners can edit documents" ON "public"."documents";
DROP POLICY IF EXISTS "Signed-in users can add documents" ON "public"."documents";
CREATE POLICY "documents_insert_own" ON "public"."documents" FOR INSERT TO authenticated WITH CHECK ("owner_id" = (select auth.uid()));
CREATE POLICY "documents_update_own" ON "public"."documents" FOR UPDATE TO authenticated USING ("owner_id" = (select auth.uid())) WITH CHECK ("owner_id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."documents" FROM anon;

-- public.invoice_summaries
-- Make the view run with the caller's rights so row level security applies to it.
-- Take every privilege away from the anon role.
ALTER VIEW "public"."invoice_summaries" SET (security_invoker = true);
REVOKE ALL ON TABLE "public"."invoice_summaries" FROM anon;

-- public.notes
-- Drop policy "Notes are viewable by everyone": it does not tie every command to the row's owner.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Notes are viewable by everyone" ON "public"."notes";
REVOKE ALL ON TABLE "public"."notes" FROM anon;

-- public.profiles
-- Turn row level security on.
-- Allow signed-in users to select, insert, update, delete only rows whose id is theirs.
-- Take every privilege away from the anon role (the public key).
ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "profiles_select_own" ON "public"."profiles" FOR SELECT TO authenticated USING ("id" = (select auth.uid()));
CREATE POLICY "profiles_insert_own" ON "public"."profiles" FOR INSERT TO authenticated WITH CHECK ("id" = (select auth.uid()));
CREATE POLICY "profiles_update_own" ON "public"."profiles" FOR UPDATE TO authenticated USING ("id" = (select auth.uid())) WITH CHECK ("id" = (select auth.uid()));
CREATE POLICY "profiles_delete_own" ON "public"."profiles" FOR DELETE TO authenticated USING ("id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."profiles" FROM anon;

-- public.projects
-- Drop policy "Projects follow the customer": it does not tie every command to the row's owner.
-- Allow signed-in users to select, insert, update, delete only rows whose owner_id is theirs.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Projects follow the customer" ON "public"."projects";
CREATE POLICY "projects_select_own" ON "public"."projects" FOR SELECT TO authenticated USING ("owner_id" = (select auth.uid()));
CREATE POLICY "projects_insert_own" ON "public"."projects" FOR INSERT TO authenticated WITH CHECK ("owner_id" = (select auth.uid()));
CREATE POLICY "projects_update_own" ON "public"."projects" FOR UPDATE TO authenticated USING ("owner_id" = (select auth.uid())) WITH CHECK ("owner_id" = (select auth.uid()));
CREATE POLICY "projects_delete_own" ON "public"."projects" FOR DELETE TO authenticated USING ("owner_id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."projects" FROM anon;

-- public.tickets
-- Drop policy "Anyone can use tickets": it does not tie every command to the row's owner.
-- Allow signed-in users to select, insert, update, delete only rows whose user_id is theirs.
-- Take every privilege away from the anon role (the public key).
DROP POLICY IF EXISTS "Anyone can use tickets" ON "public"."tickets";
CREATE POLICY "tickets_select_own" ON "public"."tickets" FOR SELECT TO authenticated USING ("user_id" = (select auth.uid()));
CREATE POLICY "tickets_insert_own" ON "public"."tickets" FOR INSERT TO authenticated WITH CHECK ("user_id" = (select auth.uid()));
CREATE POLICY "tickets_update_own" ON "public"."tickets" FOR UPDATE TO authenticated USING ("user_id" = (select auth.uid())) WITH CHECK ("user_id" = (select auth.uid()));
CREATE POLICY "tickets_delete_own" ON "public"."tickets" FOR DELETE TO authenticated USING ("user_id" = (select auth.uid()));
REVOKE ALL ON TABLE "public"."tickets" FROM anon;
