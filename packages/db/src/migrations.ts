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

  if (!versions.has("0005_evidence_attestations")) {
    await pool.query("BEGIN");
    try {
      await pool.query(EVIDENCE_ATTESTATIONS_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0005_evidence_attestations"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0006_deadline_clock_engine")) {
    await pool.query("BEGIN");
    try {
      await pool.query(DEADLINE_CLOCK_ENGINE_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0006_deadline_clock_engine"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0007_automated_compliance_evaluations")) {
    await pool.query("BEGIN");
    try {
      await pool.query(AUTOMATED_COMPLIANCE_EVALUATIONS_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0007_automated_compliance_evaluations"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0008_findings_remediation_lifecycle")) {
    await pool.query("BEGIN");
    try {
      await pool.query(FINDINGS_REMEDIATION_LIFECYCLE_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0008_findings_remediation_lifecycle"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0009_certification_engine")) {
    await pool.query("BEGIN");
    try {
      await pool.query(CERTIFICATION_ENGINE_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0009_certification_engine"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0010_api_integration_layer")) {
    await pool.query("BEGIN");
    try {
      await pool.query(API_INTEGRATION_LAYER_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0010_api_integration_layer"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }

  if (!versions.has("0011_publication_controls")) {
    await pool.query("BEGIN");
    try {
      await pool.query(PUBLICATION_CONTROLS_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0011_publication_controls"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  }
}

  if (!versions.has("0012_security_permission_hardening")) {
    await pool.query("BEGIN");
    try {
      await pool.query(SECURITY_PERMISSION_HARDENING_SQL);
      await pool.query(
        "INSERT INTO schema_migrations(version) VALUES ($1)",
        ["0012_security_permission_hardening"],
      );
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
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


const EVIDENCE_ATTESTATIONS_SQL = `
ALTER TABLE evidence
  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS submitted_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS media_type text,
  ADD COLUMN IF NOT EXISTS file_name text,
  ADD COLUMN IF NOT EXISTS checksum_algorithm text,
  ADD COLUMN IF NOT EXISTS valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS supersedes_evidence_id uuid REFERENCES evidence(id),
  ADD COLUMN IF NOT EXISTS superseded_at timestamptz;

ALTER TABLE evidence
  DROP CONSTRAINT IF EXISTS evidence_status_valid;

ALTER TABLE evidence
  ADD CONSTRAINT evidence_status_valid
  CHECK (status IN ('active', 'superseded', 'revoked'));

ALTER TABLE evidence
  DROP CONSTRAINT IF EXISTS evidence_validity_window;

ALTER TABLE evidence
  ADD CONSTRAINT evidence_validity_window
  CHECK (
    valid_until IS NULL
    OR valid_from IS NULL
    OR valid_until > valid_from
  );

CREATE INDEX IF NOT EXISTS evidence_resource_type_status_idx
  ON evidence(organization_id, resource_id, evidence_type, status);

CREATE INDEX IF NOT EXISTS evidence_validity_idx
  ON evidence(resource_id, valid_from, valid_until)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS evidence_attestations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  evidence_id uuid NOT NULL REFERENCES evidence(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  attestation_type text NOT NULL,
  statement text NOT NULL,
  claims jsonb NOT NULL DEFAULT '{}'::jsonb,
  attested_at timestamptz NOT NULL,
  valid_until timestamptz,
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS evidence_attestations_evidence_idx
  ON evidence_attestations(evidence_id, attested_at);

CREATE INDEX IF NOT EXISTS evidence_attestations_validity_idx
  ON evidence_attestations(evidence_id, valid_until, revoked_at);
`;


const DEADLINE_CLOCK_ENGINE_SQL = `
ALTER TABLE deadlines
  ADD COLUMN IF NOT EXISTS created_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS anchor_at timestamptz,
  ADD COLUMN IF NOT EXISTS due_offset_seconds bigint,
  ADD COLUMN IF NOT EXISTS warning_window_seconds bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS grace_period_seconds bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS recurrence_interval_seconds bigint,
  ADD COLUMN IF NOT EXISTS recurrence_end_at timestamptz,
  ADD COLUMN IF NOT EXISTS max_occurrences integer,
  ADD COLUMN IF NOT EXISTS cycle_number integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS escalation_after_seconds jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS escalation_level integer NOT NULL DEFAULT 0;

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_warning_nonnegative;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_warning_nonnegative
  CHECK (warning_window_seconds >= 0);

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_grace_nonnegative;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_grace_nonnegative
  CHECK (grace_period_seconds >= 0);

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_due_offset_positive;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_due_offset_positive
  CHECK (due_offset_seconds IS NULL OR due_offset_seconds > 0);

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_recurrence_positive;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_recurrence_positive
  CHECK (
    recurrence_interval_seconds IS NULL
    OR recurrence_interval_seconds > 0
  );

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_max_occurrences_positive;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_max_occurrences_positive
  CHECK (max_occurrences IS NULL OR max_occurrences > 0);

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_cycle_positive;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_cycle_positive
  CHECK (cycle_number > 0);

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_escalation_level_nonnegative;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_escalation_level_nonnegative
  CHECK (escalation_level >= 0);

ALTER TABLE deadlines
  DROP CONSTRAINT IF EXISTS deadlines_relative_pair;
ALTER TABLE deadlines
  ADD CONSTRAINT deadlines_relative_pair
  CHECK (
    (anchor_at IS NULL AND due_offset_seconds IS NULL)
    OR (anchor_at IS NOT NULL AND due_offset_seconds IS NOT NULL)
  );

CREATE TABLE IF NOT EXISTS deadline_occurrences (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  deadline_id uuid NOT NULL REFERENCES deadlines(id),
  cycle_number integer NOT NULL CHECK (cycle_number > 0),
  due_at timestamptz NOT NULL,
  satisfied_at timestamptz NOT NULL,
  satisfied_by_principal_id uuid NOT NULL REFERENCES principals(id),
  outcome text NOT NULL CHECK (outcome IN ('on_time', 'late')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (deadline_id, cycle_number)
);

CREATE INDEX IF NOT EXISTS deadlines_active_due_idx
  ON deadlines(due_at, status)
  WHERE status NOT IN ('satisfied', 'cancelled');

CREATE INDEX IF NOT EXISTS deadlines_subject_idx
  ON deadlines(organization_id, subject_type, subject_id);

CREATE INDEX IF NOT EXISTS deadline_occurrences_deadline_idx
  ON deadline_occurrences(deadline_id, cycle_number);
`;


const AUTOMATED_COMPLIANCE_EVALUATIONS_SQL = `
CREATE TABLE IF NOT EXISTS evaluation_schedules (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  resource_id uuid REFERENCES resources(id),
  resource_type text,
  created_by_principal_id uuid REFERENCES principals(id),
  rule_set_snapshot jsonb NOT NULL,
  facts jsonb NOT NULL DEFAULT '{}'::jsonb,
  interval_seconds bigint NOT NULL CHECK (interval_seconds > 0),
  next_run_at timestamptz NOT NULL,
  last_run_at timestamptz,
  active boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (resource_id IS NOT NULL AND resource_type IS NULL)
    OR (resource_id IS NULL AND resource_type IS NOT NULL)
  )
);

ALTER TABLE checks
  ADD COLUMN IF NOT EXISTS schedule_id uuid REFERENCES evaluation_schedules(id),
  ADD COLUMN IF NOT EXISTS trigger text NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS trigger_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS requested_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS scheduled_for timestamptz,
  ADD COLUMN IF NOT EXISTS evaluated_at timestamptz,
  ADD COLUMN IF NOT EXISTS rule_set_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS context_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS evidence_trace jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS error_message text;

ALTER TABLE checks
  DROP CONSTRAINT IF EXISTS checks_trigger_valid;
ALTER TABLE checks
  ADD CONSTRAINT checks_trigger_valid
  CHECK (trigger IN ('manual', 'event', 'scheduled'));

CREATE INDEX IF NOT EXISTS checks_resource_completed_idx
  ON checks(organization_id, resource_id, completed_at DESC);

CREATE INDEX IF NOT EXISTS checks_schedule_idx
  ON checks(schedule_id, scheduled_for);

CREATE INDEX IF NOT EXISTS evaluation_schedules_due_idx
  ON evaluation_schedules(next_run_at)
  WHERE active = true;

CREATE INDEX IF NOT EXISTS evaluation_schedules_resource_type_idx
  ON evaluation_schedules(organization_id, resource_type)
  WHERE active = true AND resource_type IS NOT NULL;
`;


const FINDINGS_REMEDIATION_LIFECYCLE_SQL = `
ALTER TABLE findings
  DROP CONSTRAINT IF EXISTS findings_status_check;

ALTER TABLE findings
  ADD CONSTRAINT findings_status_check
  CHECK (
    status IN (
      'open',
      'acknowledged',
      'disputed',
      'remediating',
      'resolved',
      'closed'
    )
  );

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS rule_key text,
  ADD COLUMN IF NOT EXISTS rule_set_key text,
  ADD COLUMN IF NOT EXISTS rule_set_version text,
  ADD COLUMN IF NOT EXISTS owner_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS rule_result jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS opened_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz,
  ADD COLUMN IF NOT EXISTS acknowledged_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS disputed_at timestamptz,
  ADD COLUMN IF NOT EXISTS disputed_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS dispute_reason text,
  ADD COLUMN IF NOT EXISTS resolved_at timestamptz,
  ADD COLUMN IF NOT EXISTS closed_at timestamptz,
  ADD COLUMN IF NOT EXISTS reopened_at timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS findings_check_rule_key_unique_idx
  ON findings(check_id, rule_key)
  WHERE check_id IS NOT NULL AND rule_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS findings_resource_status_idx
  ON findings(organization_id, resource_id, status);

ALTER TABLE remediations
  ADD COLUMN IF NOT EXISTS deadline_id uuid REFERENCES deadlines(id),
  ADD COLUMN IF NOT EXISTS created_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS started_at timestamptz,
  ADD COLUMN IF NOT EXISTS verified_at timestamptz,
  ADD COLUMN IF NOT EXISTS verified_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS verification_note text,
  ADD COLUMN IF NOT EXISTS rejected_at timestamptz,
  ADD COLUMN IF NOT EXISTS rejected_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS rejection_reason text,
  ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;

UPDATE remediations
SET created_by_principal_id = owner_principal_id
WHERE created_by_principal_id IS NULL
  AND owner_principal_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS remediations_finding_status_idx
  ON remediations(finding_id, status, created_at);
`;


const CERTIFICATION_ENGINE_SQL = `
ALTER TABLE certifications
  DROP CONSTRAINT IF EXISTS certifications_status_check;

ALTER TABLE certifications
  ADD CONSTRAINT certifications_status_check
  CHECK (
    status IN (
      'pending',
      'active',
      'suspended',
      'revoked',
      'expired',
      'superseded'
    )
  );

ALTER TABLE certifications
  ADD COLUMN IF NOT EXISTS supporting_check_id uuid REFERENCES checks(id),
  ADD COLUMN IF NOT EXISTS certificate_number text,
  ADD COLUMN IF NOT EXISTS verification_code text,
  ADD COLUMN IF NOT EXISTS issued_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS criteria jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS artifact jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS public_artifact jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS suspended_at timestamptz,
  ADD COLUMN IF NOT EXISTS suspended_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS suspension_reason text,
  ADD COLUMN IF NOT EXISTS suspension_check_id uuid REFERENCES checks(id),
  ADD COLUMN IF NOT EXISTS reinstated_at timestamptz,
  ADD COLUMN IF NOT EXISTS reinstated_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS reinstatement_check_id uuid REFERENCES checks(id),
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz,
  ADD COLUMN IF NOT EXISTS revoked_by_principal_id uuid REFERENCES principals(id),
  ADD COLUMN IF NOT EXISTS revocation_reason text,
  ADD COLUMN IF NOT EXISTS renewed_from_certification_id uuid REFERENCES certifications(id),
  ADD COLUMN IF NOT EXISTS superseded_at timestamptz,
  ADD COLUMN IF NOT EXISTS superseded_by_certification_id uuid REFERENCES certifications(id);

CREATE UNIQUE INDEX IF NOT EXISTS certifications_certificate_number_unique_idx
  ON certifications(certificate_number)
  WHERE certificate_number IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS certifications_verification_code_unique_idx
  ON certifications(verification_code)
  WHERE verification_code IS NOT NULL;

CREATE INDEX IF NOT EXISTS certifications_resource_status_idx
  ON certifications(organization_id, resource_id, status);

CREATE INDEX IF NOT EXISTS certifications_valid_until_idx
  ON certifications(valid_until, status)
  WHERE status IN ('pending', 'active', 'suspended');

CREATE INDEX IF NOT EXISTS certifications_supporting_check_idx
  ON certifications(supporting_check_id);

CREATE INDEX IF NOT EXISTS certifications_renewed_from_idx
  ON certifications(renewed_from_certification_id);
`;


const API_INTEGRATION_LAYER_SQL = `
CREATE TABLE IF NOT EXISTS api_credentials (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  name text NOT NULL,
  token_prefix text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'revoked')),
  expires_at timestamptz,
  last_used_at timestamptz,
  created_by_principal_id uuid REFERENCES principals(id),
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS api_credentials_principal_idx
  ON api_credentials(organization_id, principal_id, status);

CREATE TABLE IF NOT EXISTS idempotency_records (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  credential_id uuid NOT NULL REFERENCES api_credentials(id),
  idempotency_key text NOT NULL,
  method text NOT NULL,
  route text NOT NULL,
  request_hash text NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'completed')),
  response_status integer,
  response_body jsonb,
  content_type text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  expires_at timestamptz NOT NULL,
  UNIQUE (credential_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idempotency_records_expiry_idx
  ON idempotency_records(expires_at);

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  url text NOT NULL,
  event_types jsonb NOT NULL DEFAULT '["*"]'::jsonb,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'inactive')),
  created_by_principal_id uuid REFERENCES principals(id),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS integration_events (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  audit_event_id uuid NOT NULL UNIQUE REFERENCES audit_events(id),
  event_type text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS integration_events_org_created_idx
  ON integration_events(organization_id, created_at, id);

CREATE INDEX IF NOT EXISTS integration_events_org_type_idx
  ON integration_events(organization_id, event_type, created_at, id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  subscription_id uuid NOT NULL REFERENCES webhook_subscriptions(id),
  event_id uuid NOT NULL REFERENCES integration_events(id),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'succeeded', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_attempt_at timestamptz,
  delivered_at timestamptz,
  response_status integer,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subscription_id, event_id)
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
  ON webhook_deliveries(next_attempt_at, status)
  WHERE status IN ('pending', 'failed');

CREATE TABLE IF NOT EXISTS integration_import_records (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  source text NOT NULL,
  entity_type text NOT NULL,
  external_id text NOT NULL,
  entity_id uuid NOT NULL,
  payload_hash text NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (
    organization_id,
    source,
    entity_type,
    external_id
  )
);

CREATE OR REPLACE FUNCTION fanout_audit_event_to_integrations()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  new_event_id uuid;
BEGIN
  new_event_id := gen_random_uuid();

  INSERT INTO integration_events(
    id,
    organization_id,
    audit_event_id,
    event_type,
    aggregate_type,
    aggregate_id,
    payload,
    occurred_at
  ) VALUES (
    new_event_id,
    NEW.organization_id,
    NEW.id,
    NEW.event_type,
    NEW.aggregate_type,
    NEW.aggregate_id,
    jsonb_build_object(
      'auditEventId', NEW.id,
      'sequenceNumber', NEW.sequence_number,
      'actorPrincipalId', NEW.actor_principal_id,
      'correlationId', NEW.correlation_id,
      'payload', NEW.payload,
      'eventHash', NEW.event_hash
    ),
    NEW.occurred_at
  );

  INSERT INTO webhook_deliveries(
    id,
    organization_id,
    subscription_id,
    event_id
  )
  SELECT
    gen_random_uuid(),
    subscriptions.organization_id,
    subscriptions.id,
    new_event_id
  FROM webhook_subscriptions AS subscriptions
  WHERE subscriptions.organization_id = NEW.organization_id
    AND subscriptions.status = 'active'
    AND (
      subscriptions.event_types ? '*'
      OR subscriptions.event_types ? NEW.event_type
    );

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS audit_events_integration_fanout
  ON audit_events;

CREATE TRIGGER audit_events_integration_fanout
AFTER INSERT ON audit_events
FOR EACH ROW
EXECUTE FUNCTION fanout_audit_event_to_integrations();
`;


const PUBLICATION_CONTROLS_SQL = `
CREATE TABLE IF NOT EXISTS publication_controls (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  subject_type text NOT NULL,
  subject_id uuid NOT NULL,
  projection_type text NOT NULL,
  state text NOT NULL DEFAULT 'private'
    CHECK (state IN ('private', 'published')),
  revision integer NOT NULL DEFAULT 1
    CHECK (revision >= 1),
  projection jsonb NOT NULL DEFAULT '{}'::jsonb,
  projection_hash text NOT NULL,
  policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  published_at timestamptz,
  published_by_principal_id uuid REFERENCES principals(id),
  unpublished_at timestamptz,
  unpublished_by_principal_id uuid REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (
    organization_id,
    subject_type,
    subject_id,
    projection_type
  ),
  CHECK (
    projection_hash ~ '^[0-9a-f]{64}$'
  ),
  CHECK (
    state <> 'published'
    OR (
      published_at IS NOT NULL
      AND published_by_principal_id IS NOT NULL
    )
  )
);

CREATE INDEX IF NOT EXISTS publication_controls_public_idx
  ON publication_controls(
    organization_id,
    subject_type,
    projection_type,
    subject_id
  )
  WHERE state = 'published';

CREATE INDEX IF NOT EXISTS publication_controls_subject_idx
  ON publication_controls(
    organization_id,
    subject_type,
    subject_id
  );
`;


const SECURITY_PERMISSION_HARDENING_SQL = `
CREATE TABLE IF NOT EXISTS security_roles (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  key text NOT NULL,
  name text NOT NULL,
  permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
  system boolean NOT NULL DEFAULT false,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, key),
  CHECK (jsonb_typeof(permissions) = 'array')
);

CREATE TABLE IF NOT EXISTS principal_role_assignments (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  role_id uuid NOT NULL REFERENCES security_roles(id),
  assigned_by_principal_id uuid REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (
    organization_id,
    principal_id,
    role_id
  )
);

CREATE INDEX IF NOT EXISTS principal_role_assignments_principal_idx
  ON principal_role_assignments(
    organization_id,
    principal_id
  );

CREATE TABLE IF NOT EXISTS operator_credentials (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  name text NOT NULL,
  token_prefix text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'revoked')),
  expires_at timestamptz,
  last_used_at timestamptz,
  created_by_principal_id uuid REFERENCES principals(id),
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS operator_credentials_principal_idx
  ON operator_credentials(
    organization_id,
    principal_id,
    status
  );

CREATE INDEX IF NOT EXISTS operator_credentials_active_expiry_idx
  ON operator_credentials(expires_at)
  WHERE status = 'active';
`;
