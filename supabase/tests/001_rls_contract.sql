-- Catalog-level contract checks for the demo RLS design.
-- Run with: ./run_sql.sh -f supabase/tests/001_rls_contract.sql
--
-- These checks inspect database configuration rather than impersonating a
-- user. See 002_rls_behavior.sql for rollback-safe claim-based tests, and the
-- browser demo for real Clerk session-token coverage.

do $$
declare
  actual_policy_count integer;
  missing_policy_count integer;
  extra_policy_count integer;
  protected_function regprocedure;
  protected_functions regprocedure[] := array[
    'public.demo_requesting_user_id()'::regprocedure,
    'public.demo_requesting_organization_id()'::regprocedure,
    'public.demo_requesting_organization_role()'::regprocedure,
    'public.demo_requesting_is_organization_admin()'::regprocedure,
    'public.demo_accessible_organization_ids()'::regprocedure,
    'public.demo_current_user_is_member(text)'::regprocedure,
    'public.demo_accessible_project_ids()'::regprocedure,
    'public.demo_bootstrap_current_context()'::regprocedure,
    'public.demo_protect_created_by()'::regprocedure
  ];
begin
  with expected(tablename, policyname, cmd) as (
    values
      ('demo_organizations', 'demo_organizations_select', 'SELECT'),
      ('demo_organizations', 'demo_organizations_insert', 'INSERT'),
      ('demo_organizations', 'demo_organizations_update', 'UPDATE'),
      ('demo_organizations', 'demo_organizations_delete', 'DELETE'),
      ('demo_memberships', 'demo_memberships_select', 'SELECT'),
      ('demo_memberships', 'demo_memberships_insert', 'INSERT'),
      ('demo_memberships', 'demo_memberships_update', 'UPDATE'),
      ('demo_memberships', 'demo_memberships_delete', 'DELETE'),
      ('demo_projects', 'demo_projects_select', 'SELECT'),
      ('demo_projects', 'demo_projects_insert', 'INSERT'),
      ('demo_projects', 'demo_projects_update', 'UPDATE'),
      ('demo_projects', 'demo_projects_delete', 'DELETE'),
      ('demo_documents', 'demo_documents_select', 'SELECT'),
      ('demo_documents', 'demo_documents_insert', 'INSERT'),
      ('demo_documents', 'demo_documents_update', 'UPDATE'),
      ('demo_documents', 'demo_documents_delete', 'DELETE')
  ), actual as (
    select tablename, policyname, cmd
    from pg_policies
    where schemaname = 'public'
      and tablename in ('demo_organizations', 'demo_memberships', 'demo_projects', 'demo_documents')
  )
  select count(*) into missing_policy_count
  from expected e
  left join actual a using (tablename, policyname, cmd)
  where a.policyname is null;

  with expected(tablename, policyname, cmd) as (
    values
      ('demo_organizations', 'demo_organizations_select', 'SELECT'),
      ('demo_organizations', 'demo_organizations_insert', 'INSERT'),
      ('demo_organizations', 'demo_organizations_update', 'UPDATE'),
      ('demo_organizations', 'demo_organizations_delete', 'DELETE'),
      ('demo_memberships', 'demo_memberships_select', 'SELECT'),
      ('demo_memberships', 'demo_memberships_insert', 'INSERT'),
      ('demo_memberships', 'demo_memberships_update', 'UPDATE'),
      ('demo_memberships', 'demo_memberships_delete', 'DELETE'),
      ('demo_projects', 'demo_projects_select', 'SELECT'),
      ('demo_projects', 'demo_projects_insert', 'INSERT'),
      ('demo_projects', 'demo_projects_update', 'UPDATE'),
      ('demo_projects', 'demo_projects_delete', 'DELETE'),
      ('demo_documents', 'demo_documents_select', 'SELECT'),
      ('demo_documents', 'demo_documents_insert', 'INSERT'),
      ('demo_documents', 'demo_documents_update', 'UPDATE'),
      ('demo_documents', 'demo_documents_delete', 'DELETE')
  ), actual as (
    select tablename, policyname, cmd
    from pg_policies
    where schemaname = 'public'
      and tablename in ('demo_organizations', 'demo_memberships', 'demo_projects', 'demo_documents')
  )
  select count(*) into extra_policy_count
  from actual a
  left join expected e using (tablename, policyname, cmd)
  where e.policyname is null;

  select count(*) into actual_policy_count
  from pg_policies
  where schemaname = 'public'
    and tablename in ('demo_organizations', 'demo_memberships', 'demo_projects', 'demo_documents');

  if missing_policy_count <> 0 or extra_policy_count <> 0 or actual_policy_count <> 16 then
    raise exception 'expected exactly 16 named CRUD policies; found %, missing %, extra %',
      actual_policy_count, missing_policy_count, extra_policy_count;
  end if;

  if exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename in ('demo_organizations', 'demo_memberships', 'demo_projects', 'demo_documents')
      and cmd = 'ALL'
  ) then
    raise exception 'broad FOR ALL policy found; split read and write policies are required';
  end if;

  if (select count(*) from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
        and c.relname in ('demo_organizations', 'demo_memberships', 'demo_projects', 'demo_documents')
        and c.relrowsecurity) <> 4 then
    raise exception 'RLS must be enabled on all four tenant-owned tables';
  end if;

  if (select count(*) from pg_proc
      where pronamespace = 'public'::regnamespace
        and proname in ('demo_accessible_organization_ids', 'demo_current_user_is_member', 'demo_accessible_project_ids', 'demo_bootstrap_current_context')
        and prosecdef
        and proconfig @> array['search_path=""', 'row_security=off']::text[]) <> 4 then
    raise exception 'all SECURITY DEFINER functions must use empty search_path and row_security=off';
  end if;

  foreach protected_function in array protected_functions loop
    if exists (
      select 1
      from pg_proc p
      cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) privilege
      where p.oid = protected_function
        and privilege.grantee in (0::oid, 'anon'::regrole)
        and privilege.privilege_type = 'EXECUTE'
    ) then
      raise exception 'protected function % must not be executable by PUBLIC or anon', protected_function;
    end if;
  end loop;

  if has_table_privilege('authenticated', 'public.demo_organizations', 'INSERT')
     or has_table_privilege('authenticated', 'public.demo_organizations', 'UPDATE')
     or has_table_privilege('authenticated', 'public.demo_organizations', 'DELETE')
     or has_table_privilege('authenticated', 'public.demo_memberships', 'INSERT')
     or has_table_privilege('authenticated', 'public.demo_memberships', 'UPDATE')
     or has_table_privilege('authenticated', 'public.demo_memberships', 'DELETE') then
    raise exception 'organization and membership mirrors must be read-only through the Data API';
  end if;

  if not exists (
    select 1 from pg_constraint c
    where c.conname = 'demo_documents_project_tenant_fkey'
      and c.conrelid = 'public.demo_documents'::regclass
      and c.confrelid = 'public.demo_projects'::regclass
      and c.conkey = array[
        (select attnum from pg_attribute where attrelid = c.conrelid and attname = 'project_id'),
        (select attnum from pg_attribute where attrelid = c.conrelid and attname = 'organization_id')
      ]
      and c.confkey = array[
        (select attnum from pg_attribute where attrelid = c.confrelid and attname = 'id'),
        (select attnum from pg_attribute where attrelid = c.confrelid and attname = 'organization_id')
      ]
  ) then
    raise exception 'documents require the exact composite project/organization foreign key';
  end if;

  if (select count(*) from pg_trigger
      where tgrelid in ('public.demo_projects'::regclass, 'public.demo_documents'::regclass)
        and tgname in ('demo_projects_protect_created_by', 'demo_documents_protect_created_by')
        and not tgisinternal) <> 2 then
    raise exception 'both project and document audit triggers are required';
  end if;

  raise notice 'RLS contract checks passed: exact policies, grants, definer settings, constraints, and audit triggers verified';
end;
$$;
