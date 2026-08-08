# Manual security test matrix

The browser demo uses real Clerk sessions and Supabase RLS. Run these cases with the demo running locally.

## Accounts and organization setup

Create:

1. A personal Clerk user with no active organization.
2. Organization A with an admin and a member.
3. Organization B with a separate admin or member.

The first authenticated request calls `demo_bootstrap_current_context()`. This creates the local organization and membership record from the verified Clerk session claims; it does not accept an organization ID from the browser request.

## Expected results

| Case | Expected result |
| --- | --- |
| Signed-out visitor | No protected data or write controls are available. |
| Personal user | Sees only their personal organization, identified by the system-generated ID `org_<user_id>`. |
| Organization A admin | Sees and can create projects in Organization A. |
| Organization A member | Sees Organization A projects and can create project rows, but cannot update or delete them. |
| Organization A admin | Can update and delete projects in Organization A. |
| Project controls in the browser | Admin sees the delete control; member does not. The database policy remains authoritative. |
| Organization A document member | Can read, create, update, and delete documents within Organization A; cross-tenant project references remain rejected. |
| Switch A → B | The visible project list changes to B after the Clerk session updates. |
| Insert with another organization ID | Rejected by `WITH CHECK`. |
| Insert with another user as `created_by` | Overwritten with the verified JWT `sub`; later changes are rejected with `42501`. |
| Document referencing another tenant's project | Rejected by the accessible-project closure. |
| Direct organization or membership mutation | Rejected by grants and explicit-deny policies; bootstrap remains the mutation path. |
| Forged `created_by` | Database replaces it with the JWT subject on insert and rejects later changes. |
| Direct table access as `anon` | Rejected by grants and RLS. |

## Claim inspection

The demo displays values returned by database helper functions, not a client-decoded token. The important native Clerk claims are:

```text
sub       Clerk user ID
role      Supabase database role, normally authenticated
o.id      active Clerk organization ID, when present
o.rol     active Clerk organization role, such as admin
aud       Optional JWT audience metadata; unused by this authorization model
```

## SQL behavior test

Run the rollback-safe SQL harness:

```bash
./run_sql.sh -f supabase/tests/002_rls_behavior.sql
```

It simulates native Clerk claims with `request.jwt.claims` and verifies that admins can update/delete projects, members can read/create but not update/delete, and even an admin cannot insert into another organization. Because the claims are simulated, this tests policy behavior only; use the browser matrix to test real Clerk session tokens.
