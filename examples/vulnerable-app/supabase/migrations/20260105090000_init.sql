-- Notes + invoices app, first version. Written fast and shipped without a review.
-- Every table below has at least one access-control mistake of the kind that
-- shows up again and again in apps built quickly with coding assistants.

create extension if not exists "pgcrypto" with schema extensions;

-- Mistake 1: row level security is never switched on for profiles.
-- With Supabase's default grants anyone holding the public anon key can read
-- and edit every profile.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null,
  avatar_url text,
  created_at timestamptz not null default now()
);

-- Mistake 2: a "public read" policy was added while debugging and never removed.
-- `using (true)` makes every note readable by everyone, signed in or not.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text,
  created_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create policy "Notes are viewable by everyone" on public.notes
  for select using (true);
create policy "Users can manage their own notes" on public.notes
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Mistake 3: a support form was made to work for visitors by opening the whole
-- table to the anon role, reads and writes included.
create table public.tickets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id),
  subject text not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);
alter table public.tickets enable row level security;
create policy "Anyone can use tickets" on public.tickets
  for all using (true) with check (true);
grant all on public.tickets to anon;

-- Mistake 4: reads are scoped to the owner, but inserts only check that the
-- caller is signed in and updates have `with check (true)`. Any signed-in user
-- can create documents in someone else's name or hand their own to someone else.
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text
);
alter table public.documents enable row level security;
create policy "Owners can read documents" on public.documents
  for select to authenticated using (auth.uid() = owner_id);
create policy "Signed-in users can add documents" on public.documents
  for insert to authenticated with check (auth.role() = 'authenticated');
create policy "Owners can edit documents" on public.documents
  for update to authenticated using (auth.uid() = owner_id) with check (true);
create policy "Owners can delete documents" on public.documents
  for delete to authenticated using (auth.uid() = owner_id);

-- Mistake 5: the policy compares the caller with customer_id, not with the
-- column that says who owns the project (owner_id). Rows can be planted in
-- another owner's name and handed over, because customer_id is free to choose.
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  customer_id uuid not null references auth.users (id) on delete cascade,
  name text not null
);
alter table public.projects enable row level security;
create policy "Projects follow the customer" on public.projects
  for all to authenticated
  using (auth.uid() = customer_id)
  with check (auth.uid() = customer_id);

-- Mistake 6: invoices are protected correctly, then a summary view is added.
-- The view runs with its owner's rights, so row level security on invoices is
-- skipped and everyone who may read the view sees every customer's invoices.
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

create view public.invoice_summaries as
  select id, owner_id, total_cents, status from public.invoices;
