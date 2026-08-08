-- Behavioral RLS tests using simulated native Clerk claims.
-- Run with: ./run_sql.sh -f supabase/tests/002_rls_behavior.sql
--
-- This validates policy behavior, not Clerk token signatures. Every change is
-- rolled back. The browser test remains the integration test for a real Clerk
-- session. Error handlers intentionally catch only the SQLSTATE being tested;
-- unrelated errors must fail this test.

begin;
set local role authenticated;

-- Create two real tenants so a cross-tenant denial cannot be confused with a
-- missing-organization foreign-key failure.
select set_config(
  'request.jwt.claims',
  '{"sub":"user_sql_admin","role":"authenticated","o":{"id":"org_sql_rls_test","rol":"admin"}}',
  true
);
select public.demo_bootstrap_current_context();

-- Repeating the exact same context is idempotent: one organization and one
-- membership mirror row remain.
select public.demo_bootstrap_current_context();
do $$
begin
  if (select count(*) from public.demo_organizations where id = 'org_sql_rls_test') <> 1
     or (select count(*) from public.demo_memberships
         where organization_id = 'org_sql_rls_test' and user_id = 'user_sql_admin') <> 1 then
    raise exception 'repeated bootstrap created duplicate mirror rows';
  end if;
end;
$$;

insert into public.demo_projects (organization_id, name, created_by)
values ('org_sql_rls_test', 'Admin project', 'forged_user');

do $$
declare
  v_row_count bigint;
  v_created_by text;
begin
  update public.demo_projects
  set name = 'Admin-updated project'
  where organization_id = 'org_sql_rls_test';
  get diagnostics v_row_count = row_count;
  if v_row_count <> 1 then
    raise exception 'admin update affected %, expected 1', v_row_count;
  end if;

  select created_by into v_created_by
  from public.demo_projects
  where organization_id = 'org_sql_rls_test';
  if v_created_by <> 'user_sql_admin' then
    raise exception 'created_by was not derived from JWT subject';
  end if;
end;
$$;

select set_config(
  'request.jwt.claims',
  '{"sub":"user_other_admin","role":"authenticated","o":{"id":"org_other_tenant","rol":"admin"}}',
  true
);
select public.demo_bootstrap_current_context();

insert into public.demo_projects (organization_id, name)
values ('org_other_tenant', 'Other tenant project');

select set_config(
  'demo.other_project_id',
  (select id::text from public.demo_projects where organization_id = 'org_other_tenant'),
  true
);

do $$
begin
  if nullif(current_setting('demo.other_project_id', true), '') is null then
    raise exception 'test fixture did not capture the other tenant project UUID';
  end if;
end;
$$;

-- Return to the first tenant. The other tenant and its project now exist.
select set_config(
  'request.jwt.claims',
  '{"sub":"user_sql_admin","role":"authenticated","o":{"id":"org_sql_rls_test","rol":"admin"}}',
  true
);

-- A valid same-tenant document is the positive control for the negative test.
insert into public.demo_documents (organization_id, project_id, body)
select 'org_sql_rls_test', id, 'Valid same-tenant document'
from public.demo_projects
where organization_id = 'org_sql_rls_test';

do $$
begin
  if (select count(*) from public.demo_projects where organization_id = 'org_other_tenant') <> 0 then
    raise exception 'cross-tenant read returned rows';
  end if;

  begin
    insert into public.demo_projects (organization_id, name)
    values ('org_other_tenant', 'Forged project');
    raise exception 'cross-tenant insert unexpectedly succeeded';
  exception
    when insufficient_privilege then
      null;
  end;

  begin
    update public.demo_projects
    set created_by = 'forged_user'
    where organization_id = 'org_sql_rls_test';
    raise exception 'created_by mutation unexpectedly succeeded';
  exception
    when insufficient_privilege then
      null;
  end;
end;
$$;

-- Organization member: can read and create, but cannot update or delete.
select set_config(
  'request.jwt.claims',
  '{"sub":"user_sql_member","role":"authenticated","o":{"id":"org_sql_rls_test","rol":"member"}}',
  true
);
select public.demo_bootstrap_current_context();

do $$
begin
  if (select role from public.demo_memberships
      where organization_id = 'org_sql_rls_test'
        and user_id = 'user_sql_member') <> 'member' then
    raise exception 'bootstrap did not mirror member role';
  end if;
end;
$$;

-- Bootstrap is idempotent and mirrors a role change from verified claims.
select set_config(
  'request.jwt.claims',
  '{"sub":"user_sql_member","role":"authenticated","o":{"id":"org_sql_rls_test","rol":"admin"}}',
  true
);
select public.demo_bootstrap_current_context();

do $$
begin
  if (select role from public.demo_memberships
      where organization_id = 'org_sql_rls_test'
        and user_id = 'user_sql_member') <> 'admin' then
    raise exception 'bootstrap did not mirror admin role change';
  end if;
end;
$$;

select set_config(
  'request.jwt.claims',
  '{"sub":"user_sql_member","role":"authenticated","o":{"id":"org_sql_rls_test","rol":"member"}}',
  true
);
select public.demo_bootstrap_current_context();

do $$
declare
  v_row_count bigint;
begin
  if (select count(*) from public.demo_projects where organization_id = 'org_sql_rls_test') <> 1 then
    raise exception 'member could not read the organization project';
  end if;

  insert into public.demo_projects (organization_id, name)
  values ('org_sql_rls_test', 'Member project');

  update public.demo_projects
  set name = 'Member must not update'
  where organization_id = 'org_sql_rls_test';
  get diagnostics v_row_count = row_count;
  if v_row_count <> 0 then
    raise exception 'member update affected %, expected 0', v_row_count;
  end if;

  delete from public.demo_projects
  where organization_id = 'org_sql_rls_test';
  get diagnostics v_row_count = row_count;
  if v_row_count <> 0 then
    raise exception 'member delete affected %, expected 0', v_row_count;
  end if;
end;
$$;

-- A document cannot point at the captured, valid project belonging to another
-- valid tenant. The UUID was captured while that tenant's claims were active.
do $$
begin
  if nullif(current_setting('demo.other_project_id', true), '') is null then
    raise exception 'cross-tenant document test has no project UUID fixture';
  end if;

  begin
    insert into public.demo_documents (organization_id, project_id, body)
    values (
      'org_sql_rls_test',
      current_setting('demo.other_project_id')::uuid,
      'Forged cross-tenant document'
    );
    raise exception 'cross-tenant document insert unexpectedly succeeded';
  exception
    when insufficient_privilege then
      null;
  end;
end;
$$;

-- Return to the admin and verify exactly one project can be deleted.
select set_config(
  'request.jwt.claims',
  '{"sub":"user_sql_admin","role":"authenticated","o":{"id":"org_sql_rls_test","rol":"admin"}}',
  true
);

do $$
declare
  v_row_count bigint;
begin
  delete from public.demo_projects
  where organization_id = 'org_sql_rls_test'
    and name = 'Admin-updated project';
  get diagnostics v_row_count = row_count;
  if v_row_count <> 1 then
    raise exception 'admin delete affected %, expected 1', v_row_count;
  end if;
end;
$$;

do $$
begin
  raise notice 'Behavioral RLS checks passed: tenant isolation, roles, audit identity, and document integrity enforced';
end;
$$;

rollback;
