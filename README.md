# Clerk + Supabase RLS Demo

This repository demonstrates the native, non-template Clerk integration with Supabase third-party authentication and efficient Postgres Row-Level Security (RLS). The canonical tutorial is published on the [Supaflow blog](https://www.supa-flow.io/docs/blog/clerk-supabase-rls-tenant-isolation).

It covers user identity, active Clerk organizations, personal-account tenant isolation, RLS recursion avoidance, hoisted access closures, and adversarial cross-tenant checks.

## Prerequisites

- Node.js 20 or newer
- npm
- `psql` (only needed to apply SQL or run the SQL tests)
- A Clerk development instance
- A disposable Supabase project with Clerk enabled under Authentication → Sign In / Up → Third-party Auth

Before using this repository, complete the native Clerk–Supabase integration in both dashboards:

1. In Clerk, open the [Supabase integration setup](https://dashboard.clerk.com/setup/supabase) and follow Clerk’s [Supabase integration guide](https://clerk.com/docs/guides/development/integrations/databases/supabase).
2. In Supabase, open Authentication → Third-party Auth, or the [Third-party Auth settings](https://supabase.com/dashboard/project/_/auth/third-party), and enable Clerk for the project.

This demo assumes the integration is enabled and uses the native Clerk session token. It does not use a Clerk JWT template, Supabase JWT secret, or `auth.uid()`.

## Local configuration

Create the gitignored environment file:

```bash
cp .env.example clerk-supabase-demo.env
```

Populate it with:

```env
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=

# Required by Clerk's Next.js server middleware; never expose as NEXT_PUBLIC_.
CLERK_SECRET_KEY=

# Used only by the local SQL wrapper for this disposable database.
SUPABASE_PROJECT_REF=
SUPABASE_DB_PASSWORD=

# Supabase Dashboard → Connect → Transaction pooler
host=
port=6543
database=postgres
user=
```

Get the Clerk publishable key from the Clerk dashboard’s API keys page. Get the Supabase URL and publishable key from the Supabase project’s API settings. Get the database host, port, database, and user from Supabase’s Connect dialog, and enter the disposable database password separately. `SUPABASE_PROJECT_REF` is retained for project identification but is not required by `run_sql.sh`.

`NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` is safe for browser use. `CLERK_SECRET_KEY` is required by Clerk's Next.js server middleware and must never be exposed through a `NEXT_PUBLIC_` variable. Never commit `clerk-supabase-demo.env`, a service-role key, a Supabase JWT signing secret, or a Clerk JWT template.

## Run the demo

Install dependencies with lifecycle scripts disabled:

```bash
npm install --ignore-scripts
```

Run the local checks:

```bash
npm run lint
npm run typecheck
set -a; source clerk-supabase-demo.env; set +a; npm run build
```

Start the development server with the same env file:

```bash
set -a; source clerk-supabase-demo.env; set +a; npm run dev
```

Open `http://localhost:3000`, sign in with Clerk, and use the organization switcher to change the active organization. The app calls `session.getToken()` through Supabase's `accessToken` callback; it never requests a JWT template.

Clerk profile fields such as name, username, and primary email are display data owned by Clerk. The demo reads them with Clerk's `useUser()` hook but does not copy them into Supabase because RLS only needs the stable user ID from the JWT `sub` claim. Persist profile fields in your own tables only when your product needs to query or retain them, and synchronize them through a controlled server-side flow or Clerk webhooks.

## Apply the SQL and run tests

This repository intentionally does not link Git to Supabase. Apply the migration directly to the disposable project:

```bash
./run_sql.sh -f supabase/migrations/001_clerk_rls_demo.sql
./run_sql.sh -f supabase/tests/001_rls_contract.sql
./run_sql.sh -f supabase/tests/002_rls_behavior.sql
```

The wrapper uses the database connection values from `clerk-supabase-demo.env` and keeps the password out of process arguments. It does not update a Supabase migration ledger, so use it only for this throwaway demo or apply the migration once and keep the numbered files as the source of truth.

`002_rls_behavior.sql` uses `request.jwt.claims` to simulate native Clerk claims inside a rollback-only transaction. It tests the RLS policies, not Clerk token verification; the browser demo is still required to test the complete Clerk-to-Supabase request path.

The tests have two layers:

- `001_rls_contract.sql` checks database structure: RLS is split by command, no broad `FOR ALL` policies exist, and access closures are `SECURITY DEFINER`.
- `002_rls_behavior.sql` runs inside a transaction and rolls back. It simulates Clerk claims, verifies admin/member project permissions, and checks cross-tenant rejection.

The schema also protects two separate invariants: RLS authorizes the caller, while the composite project/organization foreign key protects document relationships even during owner-level maintenance. Database triggers derive and freeze `created_by` from the verified JWT subject.

## Run the browser demo

Start the app:

```bash
set -a; source clerk-supabase-demo.env; set +a
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), create or sign in to a Clerk user, and exercise these cases:

1. Create a personal project. It is stored in your personal organization under its system-generated ID, `org_<clerk_user_id>`.
2. Create an organization from the organization switcher.
3. Create an organization project and confirm its tenant key is the Clerk `org_...` ID.
4. Switch back to the personal account and confirm the organization project is not visible.
5. With an admin session, confirm the Delete control is present. A member can read/create but does not receive that control; the database policy remains authoritative.

See [`docs/manual-test-matrix.md`](docs/manual-test-matrix.md) for the complete security matrix.

## Coverage

- Personal users without an active organization
- Organization admins and members
- Multiple-organization isolation
- Native Clerk session tokens
- Supabase RLS policies based on verified JWT claims
- Project role access: members can read/create, admins can update/delete
- Rejected cross-tenant reads and forged inserts

## Repository map

- `supabase/migrations/` — schema, native Clerk claim helpers, access closures, and split RLS policies.
- `supabase/tests/` — catalog-level and rollback-safe behavioral RLS checks.
- `docs/rls-design.md` — recursion, `SECURITY DEFINER`, hoisting, indexing, and policy-splitting notes.
- `docs/manual-test-matrix.md` — browser test cases for personal accounts and organizations.
- The [published tutorial](https://www.supa-flow.io/docs/blog/clerk-supabase-rls-tenant-isolation) — the conceptual walkthrough; this repository contains the runnable implementation.
- The [GitHub repository](https://github.com/supaflow-labs/clerk-supabase-demo) — the source code, migration, tests, and setup instructions.
