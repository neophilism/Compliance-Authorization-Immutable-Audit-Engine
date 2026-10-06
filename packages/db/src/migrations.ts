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

  if (!versions.has("0002_tamper_evident_audit")) {
    await pool.query("BEGIN");
    try {
      await pool.query(TAMPER_EVIDENT_AUDIT_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0002_tamper_evident_audit"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0003_authorization_engine")) {
    await pool.query("BEGIN");
    try {
      await pool.query(AUTHORIZATION_ENGINE_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0003_authorization_engine"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0004_exceptions_waivers")) {
    await pool.query("BEGIN");
    try {
      await pool.query(EXCEPTIONS_WAIVERS_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0004_exceptions_waivers"],
      );
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


const TAMPER_EVIDENT_AUDIT_SQL = `
ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS sequence_number bigint;

WITH ranked AS (
  SELECT
    id,
    row_number() OVER (
      PARTITION BY organization_id, aggregate_type, aggregate_id
      ORDER BY recorded_at ASC, id ASC
    ) AS sequence_number
  FROM audit_events
  WHERE sequence_number IS NULL
)
UPDATE audit_events AS events
SET sequence_number = ranked.sequence_number
FROM ranked
WHERE events.id = ranked.id;

ALTER TABLE audit_events
  ALTER COLUMN sequence_number SET NOT NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM audit_events WHERE event_hash IS NULL) THEN
    RAISE EXCEPTION
      'Existing audit_events without event_hash must be repaired before enabling tamper-evident audit';
  END IF;
END
$$;

ALTER TABLE audit_events
  ALTER COLUMN event_hash SET NOT NULL;

ALTER TABLE audit_events
  DROP CONSTRAINT IF EXISTS audit_events_event_hash_format;

ALTER TABLE audit_events
  ADD CONSTRAINT audit_events_event_hash_format
  CHECK (event_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE audit_events
  DROP CONSTRAINT IF EXISTS audit_events_previous_hash_format;

ALTER TABLE audit_events
  ADD CONSTRAINT audit_events_previous_hash_format
  CHECK (
    previous_event_hash IS NULL
    OR previous_event_hash ~ '^[0-9a-f]{64}$'
  );

CREATE UNIQUE INDEX IF NOT EXISTS audit_events_chain_sequence_uidx
  ON audit_events(
    organization_id,
    aggregate_type,
    aggregate_id,
    sequence_number
  );

CREATE INDEX IF NOT EXISTS audit_events_chain_hash_idx
  ON audit_events(
    organization_id,
    aggregate_type,
    aggregate_id,
    event_hash
  );

CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION
    'audit_events is append-only; % is not permitted',
    TG_OP
    USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION reject_audit_event_mutation();
`;


const AUTHORIZATION_ENGINE_SQL = `
ALTER TABLE authorizations
  ADD COLUMN IF NOT EXISTS scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS approval_quorum integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS approval_authority text,
  ADD COLUMN IF NOT EXISTS emergency boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS emergency_review_due_at timestamptz,
  ADD COLUMN IF NOT EXISTS emergency_reviewed_at timestamptz;

ALTER TABLE authorizations
  DROP CONSTRAINT IF EXISTS authorizations_approval_quorum_positive;

ALTER TABLE authorizations
  ADD CONSTRAINT authorizations_approval_quorum_positive
  CHECK (approval_quorum > 0);

ALTER TABLE authorizations
  DROP CONSTRAINT IF EXISTS authorizations_valid_window;

ALTER TABLE authorizations
  ADD CONSTRAINT authorizations_valid_window
  CHECK (
    valid_from IS NULL
    OR valid_until IS NULL
    OR valid_until > valid_from
  );

ALTER TABLE authorizations
  DROP CONSTRAINT IF EXISTS authorizations_emergency_review_requirement;

ALTER TABLE authorizations
  ADD CONSTRAINT authorizations_emergency_review_requirement
  CHECK (
    emergency = false
    OR emergency_review_due_at IS NOT NULL
  );

CREATE TABLE IF NOT EXISTS authorization_decisions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  authorization_id uuid NOT NULL REFERENCES authorizations(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  decision text NOT NULL CHECK (decision IN ('approve', 'deny')),
  rationale text NOT NULL DEFAULT '',
  decided_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (authorization_id, principal_id)
);

CREATE TABLE IF NOT EXISTS authorization_eligible_approvers (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  authorization_id uuid NOT NULL REFERENCES authorizations(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (authorization_id, principal_id)
);

CREATE INDEX IF NOT EXISTS authorization_decisions_authorization_idx
  ON authorization_decisions(authorization_id, decided_at);

CREATE INDEX IF NOT EXISTS authorizations_expiration_idx
  ON authorizations(status, valid_until)
  WHERE status = 'approved' AND valid_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS authorizations_emergency_review_idx
  ON authorizations(emergency_review_due_at)
  WHERE emergency = true
    AND status = 'approved'
    AND emergency_reviewed_at IS NULL;
`;


const EXCEPTIONS_WAIVERS_SQL = `
ALTER TABLE exceptions
  ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'exception',
  ADD COLUMN IF NOT EXISTS requested_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS decided_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS requested_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS decided_at timestamptz,
  ADD COLUMN IF NOT EXISTS scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS approval_quorum integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS approval_authority text;

ALTER TABLE exceptions
  DROP CONSTRAINT IF EXISTS exceptions_kind_valid;

ALTER TABLE exceptions
  ADD CONSTRAINT exceptions_kind_valid
  CHECK (kind IN ('exception', 'waiver'));

ALTER TABLE exceptions
  DROP CONSTRAINT IF EXISTS exceptions_approval_quorum_positive;

ALTER TABLE exceptions
  ADD CONSTRAINT exceptions_approval_quorum_positive
  CHECK (approval_quorum > 0);

ALTER TABLE exceptions
  DROP CONSTRAINT IF EXISTS exceptions_validity_bounded;

ALTER TABLE exceptions
  ADD CONSTRAINT exceptions_validity_bounded
  CHECK (
    valid_until IS NOT NULL
    AND valid_until > COALESCE(valid_from, requested_at)
  );

CREATE TABLE IF NOT EXISTS exception_decisions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  exception_id uuid NOT NULL REFERENCES exceptions(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  decision text NOT NULL CHECK (decision IN ('approve', 'deny')),
  rationale text NOT NULL DEFAULT '',
  decided_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (exception_id, principal_id)
);

CREATE TABLE IF NOT EXISTS exception_eligible_approvers (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  exception_id uuid NOT NULL REFERENCES exceptions(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (exception_id, principal_id)
);

CREATE INDEX IF NOT EXISTS exception_decisions_exception_idx
  ON exception_decisions(exception_id, decided_at);

CREATE INDEX IF NOT EXISTS exceptions_expiration_idx
  ON exceptions(status, valid_until)
  WHERE status IN ('requested', 'approved');
`;
