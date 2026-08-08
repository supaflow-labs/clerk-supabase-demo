# RLS design notes

This demo intentionally follows the efficient RLS pattern used in Supaflow's recent authorization-closure refactor.

## Avoiding recursion

Policies must not query the table whose policy is being evaluated. For example, a policy on `demo_projects` should not query `demo_projects` again to decide whether the current row is visible. That creates recursive policy chains and can fail with an infinite-recursion error or produce difficult-to-audit behavior.

Membership-dependent checks use `SECURITY DEFINER` access closures. The closure runs with a fixed `search_path` and `row_security = off`, reads the membership table once, and returns only the caller's authorized organization IDs. The public policy consumes that result without re-entering membership RLS.

## Avoiding per-row JWT and membership work

JWT helpers are `STABLE` SQL functions and are called as:

```sql
(select demo_requesting_user_id())
(select demo_requesting_organization_id())
```

The scalar subquery gives PostgreSQL an init-plan shape that can be evaluated once per statement. Policies use set-returning closures through `IN (SELECT ...)`, which PostgreSQL can materialize as a hashed subplan. Policy columns and closure join columns are indexed.

## Splitting read and write policies

The demo uses separate `SELECT`, `INSERT`, `UPDATE`, and `DELETE` policies. A broad `FOR ALL` policy can unintentionally run its write-oriented predicate during reads and makes query-plan review harder.

## RLS versus relational integrity

RLS answers whether the current caller may access a row. Foreign keys answer whether rows may form a valid relationship, even during owner-level maintenance or service-side work. `demo_documents` therefore uses a composite `(project_id, organization_id)` foreign key so a document cannot reference a project from another tenant.

## Audit identity

`created_by` is assigned from the verified JWT subject by a database trigger and is immutable afterward. The browser may send ordinary row fields such as `name` and `organization_id`, but it does not author the audit identity. RLS still validates the tenant independently.

## Read-only identity mirrors

The Data API grants `authenticated` only `SELECT` on organizations and memberships. Clerk remains the organization and membership authority; `demo_bootstrap_current_context()` is the controlled `SECURITY DEFINER` synchronization path. Direct update and delete policies are explicit denies so the policy model remains clear.

## Security-definer checklist

Every definer function should:

- Use a fixed, explicit `search_path`.
- Prefer `set search_path = ''` in portable examples and schema-qualify every relation and function.
- Use `row_security = off` as a fail-loud guard for the definer's internal reads; it is not a substitute for authorization.
- Use schema-qualified table and function names.
- Accept only verified JWT-derived identity or row values.
- Return the narrowest useful result.
- Be executable only by the intended database role.
- Have a regression test for both allowed and denied paths.
