'use client';

import {
  OrganizationSwitcher,
  SignInButton,
  SignUpButton,
  UserButton,
  useAuth,
  useSession,
  useUser,
} from '@clerk/nextjs';
import { useEffect, useMemo, useRef, useState } from 'react';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

type Project = {
  id: string;
  organization_id: string;
  name: string;
  created_by: string;
  created_at: string;
};

function DemoPanel() {
  const { isLoaded, isSignedIn, userId, orgId } = useAuth();
  const { user } = useUser();
  const { session } = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(null);
  const [organizationRole, setOrganizationRole] = useState<string | null>(null);
  const [databaseUserId, setDatabaseUserId] = useState<string | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectName, setProjectName] = useState('My first protected project');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const requestGeneration = useRef(0);
  const displayName = user?.fullName || user?.username || user?.primaryEmailAddress?.emailAddress || 'Clerk user';

  const supabase = useMemo<SupabaseClient | null>(() => {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
    if (!url || !key || !session) return null;

    return createClient(url, key, {
      accessToken: async () => session.getToken() ?? null,
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    });
  }, [session]);

  async function loadContext(client: SupabaseClient): Promise<boolean> {
    const requestId = ++requestGeneration.current;
    setLoading(true);
    setError(null);
    try {
      const { data: bootstrappedOrg, error: bootstrapError } = await client.rpc(
        'demo_bootstrap_current_context',
      );
      if (bootstrapError) throw bootstrapError;

      const [userResult, orgResult, roleResult] = await Promise.all([
        client.rpc('demo_requesting_user_id'),
        client.rpc('demo_requesting_organization_id'),
        client.rpc('demo_requesting_organization_role'),
      ]);

      if (userResult.error) throw userResult.error;
      if (orgResult.error) throw orgResult.error;
      if (roleResult.error) throw roleResult.error;

      const currentOrganizationId = (orgResult.data as string | null) ?? (bootstrappedOrg as string | null);
      if (!currentOrganizationId) throw new Error('Postgres did not return an organization context');

      const projectsResult = await client
        .from('demo_projects')
        .select('*')
        .eq('organization_id', currentOrganizationId)
        .order('created_at', { ascending: false });
      if (projectsResult.error) throw projectsResult.error;
      if (requestId !== requestGeneration.current) return false;

      setDatabaseUserId((userResult.data as string | null) ?? null);
      setOrganizationId(currentOrganizationId);
      setOrganizationRole((roleResult.data as string | null) ?? 'personal-admin');
      setProjects((projectsResult.data as Project[]) ?? []);
      return true;
    } catch (loadError: unknown) {
      if (requestId === requestGeneration.current) {
        setError(loadError instanceof Error ? loadError.message : 'Could not load protected data');
      }
      return false;
    } finally {
      if (requestId === requestGeneration.current) setLoading(false);
    }
  }

  useEffect(() => {
    if (!isSignedIn || !supabase) return;
    let active = true;
    void Promise.resolve().then(() => {
      if (!active) return;
      setLoading(true);
      setError(null);
      setDatabaseUserId(null);
      setOrganizationId(null);
      setOrganizationRole(null);
      setProjects([]);
      return loadContext(supabase);
    });
    return () => {
      active = false;
    };
  }, [isSignedIn, supabase, orgId]);

  async function createProject() {
    if (!supabase || !projectName.trim() || loading || !organizationId || !userId) return;
    const actionGeneration = requestGeneration.current;
    setLoading(true);
    setError(null);
    try {
      const { error: insertError } = await supabase.from('demo_projects').insert({
        name: projectName.trim(),
        organization_id: organizationId,
      });
      if (insertError) throw insertError;
      if (actionGeneration !== requestGeneration.current) return;
      if (await loadContext(supabase)) setProjectName('');
    } catch (createError: unknown) {
      if (actionGeneration === requestGeneration.current) {
        setError(createError instanceof Error ? createError.message : 'Could not create project');
      }
    } finally {
      if (actionGeneration === requestGeneration.current) setLoading(false);
    }
  }

  async function deleteProject(projectId: string) {
    if (!supabase || loading || !organizationId || !userId) return;
    const actionGeneration = requestGeneration.current;
    setLoading(true);
    setError(null);
    try {
      const { error: deleteError } = await supabase.from('demo_projects').delete().eq('id', projectId);
      if (deleteError) throw deleteError;
      if (actionGeneration !== requestGeneration.current) return;
      await loadContext(supabase);
    } catch (deleteError: unknown) {
      if (actionGeneration === requestGeneration.current) {
        setError(deleteError instanceof Error ? deleteError.message : 'Could not delete project');
      }
    } finally {
      if (actionGeneration === requestGeneration.current) setLoading(false);
    }
  }

  if (!isLoaded) return <p>Loading Clerk…</p>;
  if (!isSignedIn) {
    return (
      <div className="card">
        <h2>Sign in to exercise RLS</h2>
        <p>The demo only exposes data through an authenticated Clerk session.</p>
        <div className="actions"><SignInButton mode="modal"><button>Sign in</button></SignInButton><SignUpButton mode="modal"><button className="secondary">Create account</button></SignUpButton></div>
      </div>
    );
  }

  return (
    <div className="grid">
      <section className="card">
        <h2>Signed-in context</h2>
        <p className="muted">Your profile is managed by Clerk. Postgres uses the verified claims for authorization.</p>
        <div className="claim"><span>Signed in as</span><span>{displayName}</span></div>
        <div className="claim"><span>Tenant key</span><code>{organizationId ?? 'none'}</code></div>
        <div className="claim"><span>Organization role</span><code>{organizationRole ?? 'none'}</code></div>
        <details className="technical">
          <summary>Show technical RLS identity</summary>
          <div className="claim"><span>Clerk user ID</span><code>{userId}</code></div>
          <div className="claim"><span>Postgres JWT subject</span><code>{databaseUserId ?? 'none'}</code></div>
        </details>
        <p className="muted">You are using a personal organization. Its organization ID is system-generated: <code>org_&lt;user_id&gt;</code>.</p>
      </section>

      <section className="card">
        <h2>Switch organization</h2>
        <p>Changing the active organization changes the Clerk session claims and therefore the RLS-visible tenant.</p>
        <OrganizationSwitcher hidePersonal={false} />
      </section>

      <section className="card wide">
        <h2>RLS-protected projects</h2>
        <p>Members can read and create projects. Admins can also delete them. Every action is enforced by RLS.</p>
        <div className="form"><input value={projectName} onChange={(event) => setProjectName(event.target.value)} placeholder="Project name" /><button disabled={loading || !organizationId || !userId} onClick={() => void createProject()}>Create project</button></div>
        {error && <p className="error">{error}</p>}
        {loading && <p className="muted">Loading…</p>}
        {!loading && projects.length === 0 && <p className="muted">No projects visible for this tenant.</p>}
        {projects.map((project) => <div className="project" key={project.id}><div><strong>{project.name}</strong><div className="muted">{project.created_by === userId ? `Created by ${displayName}` : 'Created by another Clerk user'}</div><details className="technical project-details"><summary>Show tenant and audit IDs</summary><div><code>{project.organization_id}</code> · created by <code>{project.created_by}</code></div></details></div>{organizationRole === 'admin' || organizationRole === 'personal-admin' ? <button className="secondary" disabled={loading || !organizationId || !userId} onClick={() => void deleteProject(project.id)}>Delete</button> : null}</div>)}
      </section>
    </div>
  );
}

export default function HomePage() {
  return (
    <main className="shell">
      <header className="topbar"><div className="brand">Clerk × Supabase RLS</div><div className="actions"><UserButton /></div></header>
      <section className="hero"><div className="eyebrow">Native third-party auth</div><h1>Tenant isolation from verified Clerk claims.</h1><p>This small demo shows how Supabase Postgres can authorize Clerk users without <code>auth.uid()</code>, JWT templates, or client-supplied tenant trust.</p></section>
      <DemoPanel />
    </main>
  );
}
