-- Notes + invoices app, reviewed version: the same tables as examples/vulnerable-app
-- with every access-control mistake corrected. Policies use (select auth.uid()) so
-- Postgres evaluates it once per statement, and nothing is granted to anon.

create extension if not exists "pgcrypto" with schema extensions;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null,
  avatar_url text,
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
create policy "Users manage their own profile" on public.profiles
  for all to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));
revoke all on public.profiles from anon;

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text,
  created_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create policy "Users manage their own notes" on public.notes
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));
revoke all on public.notes from anon;

-- Visitors file tickets through the server (service role); nobody reads the table directly.
create table public.tickets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id),
  subject text not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);
alter table public.tickets enable row level security;
create policy "Users manage their own tickets" on public.tickets
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));
revoke all on public.tickets from anon;

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text
);
alter table public.documents enable row level security;
create policy "Owners manage documents" on public.documents
  for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
revoke all on public.documents from anon;

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  customer_id uuid not null references auth.users (id) on delete cascade,
  name text not null
);
alter table public.projects enable row level security;
create policy "Owners manage projects" on public.projects
  for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
revoke all on public.projects from anon;

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  total_cents integer not null check (total_cents >= 0),
  status text not null default 'open' check (status in ('open', 'paid', 'void')),
  created_at timestamptz not null default now()
);
alter table public.invoices enable row level security;
create policy "Owners manage invoices" on public.invoices
  for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
revoke all on public.invoices from anon;

-- security_invoker makes the view run with the caller's rights, so the policies on invoices apply.
create view public.invoice_summaries with (security_invoker = true) as
  select id, owner_id, total_cents, status from public.invoices;
revoke all on public.invoice_summaries from anon;
