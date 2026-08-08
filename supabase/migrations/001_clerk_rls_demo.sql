-- Clerk + Supabase native third-party auth demo
--
-- This migration intentionally uses Clerk session tokens directly. It does not
-- use a Clerk JWT template, a shared Supabase JWT secret, or auth.uid().
--
-- Security/performance invariants:
--   * Clerk user identity comes from JWT sub.
--   * Active Clerk organization context comes from JWT o.id.
--   * Personal accounts use a deterministic synthetic organization key.
--   * RLS policies never query the table whose policy they are evaluating.
--   * Membership reads are isolated behind SECURITY DEFINER closures with RLS
--     disabled inside the function to avoid recursive policy chains.
--   * JWT scalars are invoked as `(select function())` so PostgreSQL can hoist
--     them once per statement instead of evaluating them once per row.
--   * SELECT and write policies are split rather than hidden behind FOR ALL.

begin;

create extension if not exists pgcrypto;

-- The application owns organization and membership mirrors keyed by Clerk's
-- string IDs. Personal accounts use org_<sub>; Clerk organizations use o.id.
-- Projects and documents carry organization_id directly so every tenant-owned
-- row has an obvious RLS predicate and supporting index.
create table if not exists public.demo_organizations (
  id text primary key,
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.demo_memberships (
  organization_id text not null references public.demo_organizations(id) on delete cascade,
  user_id text not null,
  role text not null check (role in ('admin', 'member')),
  created_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);

create table if not exists public.demo_projects (
  id uuid primary key default gen_random_uuid(),
  organization_id text not null references public.demo_organizations(id) on delete cascade,
  name text not null,
  created_by text not null,
  created_at timestamptz not null default now()
);

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'demo_projects_id_organization_key'
      and conrelid = 'public.demo_projects'::regclass
  ) then
    alter table public.demo_projects
      add constraint demo_projects_id_organization_key unique (id, organization_id);
  end if;
end;
$$;

create table if not exists public.demo_documents (
  id uuid primary key default gen_random_uuid(),
  organization_id text not null references public.demo_organizations(id) on delete cascade,
  project_id uuid not null,
  body text not null,
  created_by text not null,
  created_at timestamptz not null default now()
);

alter table public.demo_documents
  drop constraint if exists demo_documents_project_id_fkey;

alter table public.demo_documents
  drop constraint if exists demo_documents_project_tenant_check;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'demo_documents_project_tenant_fkey'
      and conrelid = 'public.demo_documents'::regclass
  ) then
    alter table public.demo_documents
      add constraint demo_documents_project_tenant_fkey
      foreign key (project_id, organization_id)
      references public.demo_projects(id, organization_id)
      on delete cascade;
  end if;
end;
$$;

create index if not exists demo_memberships_user_org_idx
  on public.demo_memberships (user_id, organization_id);

drop index if exists public.demo_memberships_org_user_idx;

create index if not exists demo_projects_org_idx
  on public.demo_projects (organization_id);

create index if not exists demo_documents_org_idx
  on public.demo_documents (organization_id);

create index if not exists demo_documents_project_org_idx
  on public.demo_documents (project_id, organization_id);

-- --------------------------------------------------------------------------
-- Native Clerk JWT helpers
-- --------------------------------------------------------------------------

create or replace function public.demo_requesting_user_id()
returns text
language sql
stable
security invoker
set search_path = public
as $$
  select nullif(auth.jwt()->>'sub', '');
$$;

create or replace function public.demo_requesting_organization_id()
returns text
language sql
stable
security invoker
set search_path = public
as $$
  select case
    when nullif(auth.jwt()->>'sub', '') is null then null
    else coalesce(
      nullif(auth.jwt()->'o'->>'id', ''),
      'org_' || (auth.jwt()->>'sub')
    )
  end;
$$;

create or replace function public.demo_requesting_organization_role()
returns text
language sql
stable
security invoker
set search_path = public
as $$
  select nullif(auth.jwt()->'o'->>'rol', '');
$$;

create or replace function public.demo_requesting_is_organization_admin()
returns boolean
language sql
stable
security invoker
set search_path = public
as $$
  select (
    nullif(auth.jwt()->'o'->>'id', '') is null
    or (select public.demo_requesting_organization_role()) = 'admin'
  );
$$;

-- --------------------------------------------------------------------------
-- Access closures
-- --------------------------------------------------------------------------
--
-- This is the key anti-recursion pattern. Policies on organizations,
-- memberships, projects, and documents all need membership information. If
-- those policies directly queried demo_memberships, PostgreSQL could re-enter
-- demo_memberships RLS while evaluating another policy. This closure executes
-- as a tightly scoped definer function with row_security disabled, and returns
-- only the organization IDs authorized for the verified request context.

create or replace function public.demo_accessible_organization_ids()
returns setof text
language sql
stable
security definer
set search_path = ''
set row_security = off
as $$
  select m.organization_id
  from public.demo_memberships as m
  where m.user_id = (select public.demo_requesting_user_id())
    and m.organization_id = (select public.demo_requesting_organization_id())
    and m.role in ('admin', 'member');
$$;

create or replace function public.demo_current_user_is_member(p_organization_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
set row_security = off
as $$
  select exists (
    select 1
    from public.demo_memberships as m
    where m.organization_id = p_organization_id
      and m.user_id = (select public.demo_requesting_user_id())
      and m.role in ('admin', 'member')
  );
$$;

create or replace function public.demo_accessible_project_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
set row_security = off
as $$
  select p.id
  from public.demo_projects as p
  where p.organization_id in (
    select public.demo_accessible_organization_ids()
  );
$$;

-- --------------------------------------------------------------------------
-- Authenticated bootstrap
-- --------------------------------------------------------------------------
--
-- The browser calls this once after Clerk has authenticated the user. The
-- server derives both user and organization identity from the verified JWT;
-- no organization ID is accepted from the request body.

create or replace function public.demo_bootstrap_current_context()
returns text
language plpgsql
volatile
security definer
set search_path = ''
set row_security = off
as $$
declare
  v_user_id text := public.demo_requesting_user_id();
  v_organization_id text := public.demo_requesting_organization_id();
  v_role text := case
    when nullif(auth.jwt()->'o'->>'id', '') is null then 'admin'
    when public.demo_requesting_organization_role() = 'admin' then 'admin'
    else 'member'
  end;
  v_name text := coalesce(
    nullif(auth.jwt()->'o'->>'slg', ''),
    nullif(auth.jwt()->>'org_name', ''),
    v_organization_id
  );
begin
  if v_user_id is null or v_organization_id is null then
    raise exception 'authenticated Clerk user context is required';
  end if;

  insert into public.demo_organizations (id, name)
  values (v_organization_id, v_name)
  on conflict (id) do update set name = excluded.name;

  insert into public.demo_memberships (organization_id, user_id, role)
  values (v_organization_id, v_user_id, v_role)
  on conflict (organization_id, user_id)
  do update set role = excluded.role;

  return v_organization_id;
end;
$$;

create or replace function public.demo_protect_created_by()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := public.demo_requesting_user_id();
  elsif new.created_by is distinct from old.created_by then
    raise exception 'created_by is immutable'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

drop trigger if exists demo_projects_protect_created_by on public.demo_projects;
create trigger demo_projects_protect_created_by
before insert or update on public.demo_projects
for each row execute function public.demo_protect_created_by();

drop trigger if exists demo_documents_protect_created_by on public.demo_documents;
create trigger demo_documents_protect_created_by
before insert or update on public.demo_documents
for each row execute function public.demo_protect_created_by();

-- --------------------------------------------------------------------------
-- RLS policies
-- --------------------------------------------------------------------------

-- Access matrix:
--   * authenticated members: read organizations, memberships, projects, and
--     documents; create projects and documents for the verified tenant.
--     Document update/delete are also member-scoped in this intentionally
--     simple example.
--   * organization admins: additionally update/delete projects.
--   * direct organization/membership inserts and organization deletes remain
--     denied. Organization and membership mirrors are read-only through the
--     Data API; the SECURITY DEFINER bootstrap RPC is the controlled write path.

alter table public.demo_organizations enable row level security;
alter table public.demo_memberships enable row level security;
alter table public.demo_projects enable row level security;
alter table public.demo_documents enable row level security;

drop policy if exists demo_organizations_select on public.demo_organizations;
create policy demo_organizations_select
on public.demo_organizations
for select to authenticated
using (
  id in (select public.demo_accessible_organization_ids())
);

drop policy if exists demo_organizations_insert on public.demo_organizations;
create policy demo_organizations_insert
on public.demo_organizations
for insert to authenticated
with check (false);

drop policy if exists demo_organizations_update on public.demo_organizations;
create policy demo_organizations_update
on public.demo_organizations
for update to authenticated
using (false)
with check (false);

drop policy if exists demo_organizations_delete on public.demo_organizations;
create policy demo_organizations_delete
on public.demo_organizations
for delete to authenticated
using (false);

drop policy if exists demo_memberships_select on public.demo_memberships;
create policy demo_memberships_select
on public.demo_memberships
for select to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
);

drop policy if exists demo_memberships_insert on public.demo_memberships;
create policy demo_memberships_insert
on public.demo_memberships
for insert to authenticated
with check (false);

drop policy if exists demo_memberships_update on public.demo_memberships;
create policy demo_memberships_update
on public.demo_memberships
for update to authenticated
using (false)
with check (false);

drop policy if exists demo_memberships_delete on public.demo_memberships;
create policy demo_memberships_delete
on public.demo_memberships
for delete to authenticated
using (false);

drop policy if exists demo_projects_select on public.demo_projects;
create policy demo_projects_select
on public.demo_projects
for select to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
);

drop policy if exists demo_projects_insert on public.demo_projects;
create policy demo_projects_insert
on public.demo_projects
for insert to authenticated
with check (
  organization_id = (select public.demo_requesting_organization_id())
  and organization_id in (select public.demo_accessible_organization_ids())
  and created_by = (select public.demo_requesting_user_id())
);

drop policy if exists demo_projects_update on public.demo_projects;
create policy demo_projects_update
on public.demo_projects
for update to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
  and (select public.demo_requesting_is_organization_admin())
)
with check (
  organization_id = (select public.demo_requesting_organization_id())
  and organization_id in (select public.demo_accessible_organization_ids())
);

drop policy if exists demo_projects_delete on public.demo_projects;
create policy demo_projects_delete
on public.demo_projects
for delete to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
  and (select public.demo_requesting_is_organization_admin())
);

drop policy if exists demo_documents_select on public.demo_documents;
create policy demo_documents_select
on public.demo_documents
for select to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
);

drop policy if exists demo_documents_insert on public.demo_documents;
create policy demo_documents_insert
on public.demo_documents
for insert to authenticated
with check (
  organization_id = (select public.demo_requesting_organization_id())
  and organization_id in (select public.demo_accessible_organization_ids())
  and created_by = (select public.demo_requesting_user_id())
  and project_id in (select public.demo_accessible_project_ids())
);

drop policy if exists demo_documents_update on public.demo_documents;
create policy demo_documents_update
on public.demo_documents
for update to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
)
with check (
  organization_id = (select public.demo_requesting_organization_id())
  and organization_id in (select public.demo_accessible_organization_ids())
  and project_id in (select public.demo_accessible_project_ids())
);

drop policy if exists demo_documents_delete on public.demo_documents;
create policy demo_documents_delete
on public.demo_documents
for delete to authenticated
using (
  organization_id in (select public.demo_accessible_organization_ids())
);

revoke all on public.demo_organizations from anon, public;
revoke all on public.demo_memberships from anon, public;
revoke all on public.demo_projects from anon, public;
revoke all on public.demo_documents from anon, public;
revoke all on public.demo_organizations from authenticated;
revoke all on public.demo_memberships from authenticated;
revoke all on public.demo_projects from authenticated;
revoke all on public.demo_documents from authenticated;

grant select on public.demo_organizations to authenticated;
grant select on public.demo_memberships to authenticated;
grant select, insert, update, delete on public.demo_projects to authenticated;
grant select, insert, update, delete on public.demo_documents to authenticated;

revoke all on function public.demo_requesting_user_id() from anon, public;
revoke all on function public.demo_requesting_organization_id() from anon, public;
revoke all on function public.demo_requesting_organization_role() from anon, public;
revoke all on function public.demo_requesting_is_organization_admin() from anon, public;
revoke all on function public.demo_accessible_organization_ids() from anon, public;
revoke all on function public.demo_current_user_is_member(text) from anon, public;
revoke all on function public.demo_accessible_project_ids() from anon, public;
revoke all on function public.demo_bootstrap_current_context() from anon, public;
revoke all on function public.demo_protect_created_by() from anon, public;

grant execute on function public.demo_requesting_user_id() to authenticated;
grant execute on function public.demo_requesting_organization_id() to authenticated;
grant execute on function public.demo_requesting_organization_role() to authenticated;
grant execute on function public.demo_requesting_is_organization_admin() to authenticated;
grant execute on function public.demo_accessible_organization_ids() to authenticated;
grant execute on function public.demo_current_user_is_member(text) to authenticated;
grant execute on function public.demo_accessible_project_ids() to authenticated;
grant execute on function public.demo_bootstrap_current_context() to authenticated;

notify pgrst, 'reload schema';

commit;
