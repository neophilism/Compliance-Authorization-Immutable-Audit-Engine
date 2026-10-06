import type { Pool } from "pg";

export async function runMigrations(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const applied = await pool.query<{ version: string }>("SELECT version FROM schema_migrations");
  const versions = new Set(applied.rows.map((row) => row.version));

  if (!versions.has("0001_core_domain")) {
    await pool.query("BEGIN");
    try {
      await pool.query(CORE_DOMAIN_SQL);
      await pool.query("INSERT INTO schema_migrations(version) VALUES ($1)", ["0001_core_domain"]);
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }
}

const CORE_DOMAIN_SQL = `
CREATE TABLE organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  status text NOT NULL CHECK (status IN ('active', 'inactive')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE principals (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  kind text NOT NULL CHECK (kind IN ('user', 'service')),
  display_name text NOT NULL,
  external_ref text,
  status text NOT NULL CHECK (status IN ('active', 'inactive')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE resources (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_type text NOT NULL,
  name text NOT NULL,
  external_ref text,
  status text NOT NULL CHECK (status IN ('active', 'inactive', 'archived')),
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX resources_org_type_idx ON resources(organization_id, resource_type);

CREATE TABLE policies (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  key text NOT NULL,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  status text NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, key)
);

CREATE TABLE rule_sets (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  policy_id uuid NOT NULL REFERENCES policies(id),
  key text NOT NULL,
  version text NOT NULL,
  status text NOT NULL CHECK (status IN ('draft', 'active', 'superseded', 'retired')),
  effective_from timestamptz,
  effective_to timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, key, version)
);

CREATE TABLE rules (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  rule_set_id uuid NOT NULL REFERENCES rule_sets(id),
  key text NOT NULL,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  definition jsonb NOT NULL DEFAULT '{}'::jsonb,
  enabled boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (rule_set_id, key)
);

CREATE TABLE obligations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  rule_id uuid REFERENCES rules(id),
  key text NOT NULL,
  title text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'satisfied', 'waived', 'overdue', 'cancelled')),
  due_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE authorizations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  authorization_type text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
  requested_by_principal_id uuid REFERENCES principals(id),
  decided_by_principal_id uuid REFERENCES principals(id),
  requested_at timestamptz NOT NULL,
  decided_at timestamptz,
  valid_from timestamptz,
  valid_until timestamptz,
  conditions jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE exceptions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  rule_id uuid REFERENCES rules(id),
  status text NOT NULL CHECK (status IN ('requested', 'approved', 'denied', 'expired', 'revoked')),
  justification text NOT NULL,
  valid_from timestamptz,
  valid_until timestamptz,
  conditions jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  evidence_type text NOT NULL,
  title text NOT NULL,
  source text,
  uri text,
  checksum text,
  captured_at timestamptz,
  valid_until timestamptz,
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE checks (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  rule_set_id uuid REFERENCES rule_sets(id),
  status text NOT NULL CHECK (status IN ('pending', 'running', 'passed', 'failed', 'unknown', 'error')),
  started_at timestamptz,
  completed_at timestamptz,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE findings (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  check_id uuid REFERENCES checks(id),
  rule_id uuid REFERENCES rules(id),
  severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status text NOT NULL CHECK (status IN ('open', 'acknowledged', 'remediating', 'resolved', 'closed')),
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  finding_id uuid NOT NULL REFERENCES findings(id),
  owner_principal_id uuid REFERENCES principals(id),
  status text NOT NULL CHECK (status IN ('planned', 'in_progress', 'ready_for_verification', 'verified', 'rejected', 'cancelled')),
  plan text NOT NULL,
  due_at timestamptz,
  completed_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE certifications (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid NOT NULL REFERENCES resources(id),
  certification_type text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'revoked', 'expired')),
  issued_at timestamptz,
  valid_until timestamptz,
  conditions jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE deadlines (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid REFERENCES resources(id),
  subject_type text NOT NULL,
  subject_id uuid NOT NULL,
  deadline_type text NOT NULL,
  status text NOT NULL CHECK (status IN ('scheduled', 'warning', 'due', 'overdue', 'satisfied', 'cancelled')),
  due_at timestamptz NOT NULL,
  satisfied_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  event_type text NOT NULL,
  actor_principal_id uuid REFERENCES principals(id),
  occurred_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  correlation_id text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  previous_event_hash text,
  event_hash text
);
CREATE INDEX audit_events_aggregate_idx
  ON audit_events(organization_id, aggregate_type, aggregate_id, recorded_at);
`;
