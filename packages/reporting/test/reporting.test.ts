import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  ReportingError,
  ReportingService,
  renderCsv,
  renderHumanReadable,
  renderJson,
} from "../src/index.js";

const AS_OF = "2026-10-05T12:00:00.000Z";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceA = randomUUID();
  const resourceB = randomUUID();
  const principalId = randomUUID();
  const checkA = randomUUID();
  const checkB = randomUUID();
  const exceptionId = randomUUID();
  const deadlineId = randomUUID();
  const findingId = randomUUID();
  const remediationId = randomUUID();
  const certificationId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Reporting Test Organization', $2, 'active'
     )`,
    [
      organizationId,
      `reporting-test-${organizationId}`,
    ],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       external_ref,
       attributes
     ) VALUES
       ($1, $3, 'system', 'Alpha System', 'active', 'alpha', '{}'::jsonb),
       ($2, $3, 'system', 'Beta System', 'inactive', 'beta', '{}'::jsonb)`,
    [resourceA, resourceB, organizationId],
  );

  await pool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES (
       $1, $2, 'user', 'Report Operator', 'active'
     )`,
    [principalId, organizationId],
  );

  await pool.query(
    `INSERT INTO checks(
       id,
       organization_id,
       resource_id,
       status,
       trigger,
       requested_by_principal_id,
       evaluated_at,
       completed_at,
       rule_set_snapshot,
       context_snapshot,
       evidence_trace,
       result,
       metadata
     ) VALUES
       (
         $1, $3, $4, 'passed', 'manual', $5,
         '2026-10-05T09:00:00Z',
         '2026-10-05T09:00:01Z',
         '{"id":"baseline","version":"1"}'::jsonb,
         '{}'::jsonb,
         '[]'::jsonb,
         '{"counts":{"pass":2,"fail":0,"unknown":0,"notApplicable":0}}'::jsonb,
         '{}'::jsonb
       ),
       (
         $2, $3, $6, 'failed', 'scheduled', $5,
         '2026-10-05T08:00:00Z',
         '2026-10-05T08:00:01Z',
         '{"id":"baseline","version":"1"}'::jsonb,
         '{}'::jsonb,
         '[]'::jsonb,
         '{"counts":{"pass":1,"fail":1,"unknown":0,"notApplicable":0}}'::jsonb,
         '{}'::jsonb
       )`,
    [
      checkA,
      checkB,
      organizationId,
      resourceA,
      principalId,
      resourceB,
    ],
  );

  await pool.query(
    `INSERT INTO exceptions(
       id,
       organization_id,
       resource_id,
       kind,
       status,
       justification,
       requested_by_principal_id,
       decided_by_principal_id,
       requested_at,
       decided_at,
       valid_from,
       valid_until,
       approval_quorum,
       conditions,
       scope,
       metadata
     ) VALUES (
       $1, $2, $3, 'waiver', 'approved',
       'Temporary migration allowance',
       $4, $4,
       '2026-10-01T10:00:00Z',
       '2026-10-01T11:00:00Z',
       '2026-10-01T11:00:00Z',
       '2026-10-10T11:00:00Z',
       1,
       '{}'::jsonb,
       '{}'::jsonb,
       '{}'::jsonb
     )`,
    [
      exceptionId,
      organizationId,
      resourceA,
      principalId,
    ],
  );

  await pool.query(
    `INSERT INTO deadlines(
       id,
       organization_id,
       resource_id,
       subject_type,
       subject_id,
       deadline_type,
       status,
       created_by_principal_id,
       due_at,
       warning_window_seconds,
       grace_period_seconds,
       cycle_number,
       escalation_after_seconds,
       escalation_level,
       metadata
     ) VALUES (
       $1, $2, $3, 'remediation', $4,
       'remediation-completion',
       'scheduled', $5,
       '2026-10-05T10:00:00Z',
       3600, 0, 1, '[0,900]'::jsonb, 0,
       '{}'::jsonb
     )`,
    [
      deadlineId,
      organizationId,
      resourceA,
      remediationId,
      principalId,
    ],
  );

  await pool.query(
    `INSERT INTO findings(
       id,
       organization_id,
       resource_id,
       check_id,
       rule_key,
       rule_set_key,
       rule_set_version,
       severity,
       status,
       owner_principal_id,
       title,
       description,
       rule_result,
       opened_at,
       metadata
     ) VALUES (
       $1, $2, $3, $4,
       'control-enabled',
       'baseline',
       '1',
       'high',
       'remediating',
       $5,
       'Encryption, control disabled',
       'A high-severity test finding.',
       '{}'::jsonb,
       '2026-10-05T08:00:02Z',
       '{}'::jsonb
     )`,
    [
      findingId,
      organizationId,
      resourceA,
      checkA,
      principalId,
    ],
  );

  await pool.query(
    `INSERT INTO remediations(
       id,
       organization_id,
       finding_id,
       deadline_id,
       created_by_principal_id,
       owner_principal_id,
       status,
       plan,
       due_at,
       started_at,
       metadata
     ) VALUES (
       $1, $2, $3, $4, $5, $5,
       'in_progress',
       'Enable the control and verify configuration.',
       '2026-10-05T10:00:00Z',
       '2026-10-05T08:30:00Z',
       '{}'::jsonb
     )`,
    [
      remediationId,
      organizationId,
      findingId,
      deadlineId,
      principalId,
    ],
  );

  await pool.query(
    `INSERT INTO certifications(
       id,
       organization_id,
       resource_id,
       supporting_check_id,
       certification_type,
       status,
       certificate_number,
       verification_code,
       issued_by_principal_id,
       issued_at,
       valid_from,
       valid_until,
       criteria,
       conditions,
       artifact,
       public_artifact,
       metadata
     ) VALUES (
       $1, $2, $3, $4,
       'baseline-compliance',
       'pending',
       'CERT-REPORTINGTEST1',
       'reporting-verification-code',
       $5,
       '2026-10-01T12:00:00Z',
       '2026-10-02T12:00:00Z',
       '2026-11-01T12:00:00Z',
       '{}'::jsonb,
       '{}'::jsonb,
       '{}'::jsonb,
       '{}'::jsonb,
       '{}'::jsonb
     )`,
    [
      certificationId,
      organizationId,
      resourceA,
      checkA,
      principalId,
    ],
  );

  const ledger = new AuditLedger(pool);

  for (const [aggregateType, aggregateId, eventType] of [
    ["resource", resourceA, "resource.created"],
    ["resource", resourceB, "resource.created"],
    ["check", checkA, "check.completed"],
    ["check", checkB, "check.completed"],
    ["exception", exceptionId, "exception.approved"],
    ["deadline", deadlineId, "deadline.created"],
    ["finding", findingId, "finding.opened"],
    ["remediation", remediationId, "remediation.started"],
    ["certification", certificationId, "certification.issued"],
  ]) {
    await ledger.append({
      organizationId,
      aggregateType,
      aggregateId,
      eventType,
      actorPrincipalId: principalId,
      occurredAt: AS_OF,
      payload: {},
    });
  }

  return {
    pool,
    service: new ReportingService(pool),
    organizationId,
    resourceA,
    resourceB,
    checkA,
    checkB,
  };
}

test("organization report compiles all compliance sections and derives worker-independent status", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    const report = await f.service.generate({
      organizationId: f.organizationId,
      asOf: AS_OF,
    });

    assert.equal(report.scope.resourceId, null);
    assert.equal(report.resources.length, 2);
    assert.equal(report.summary.resources.total, 2);

    assert.deepEqual(
      report.summary.checks.byStatus,
      {
        failed: 1,
        passed: 1,
      },
    );

    assert.equal(
      report.summary.exceptions.active,
      1,
    );
    assert.equal(
      report.exceptions[0]?.effectiveStatus,
      "approved",
    );

    assert.equal(
      report.summary.deadlines.overdue,
      1,
    );
    assert.equal(
      report.deadlines[0]?.storedStatus,
      "scheduled",
    );
    assert.equal(
      report.deadlines[0]?.effectiveStatus,
      "overdue",
    );

    assert.equal(
      report.summary.findings.unresolved,
      1,
    );
    assert.equal(
      report.summary.findings.unresolvedHighCritical,
      1,
    );
    assert.equal(
      report.summary.remediations.overdue,
      1,
    );

    assert.equal(
      report.certifications[0]?.storedStatus,
      "pending",
    );
    assert.equal(
      report.certifications[0]?.effectiveStatus,
      "active",
    );
    assert.equal(
      report.summary.certifications.valid,
      1,
    );

    assert.equal(
      report.summary.audit.eventCount,
      9,
    );
    assert.equal(
      report.summary.audit.chainCount,
      9,
    );
    assert.equal(
      report.summary.audit.invalidChainCount,
      0,
    );
    assert.equal(
      report.summary.audit.allChainsValid,
      true,
    );
  } finally {
    await f.pool.end();
  }
});

test("resource report limits records and audit chains to the selected resource", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    const report = await f.service.generate({
      organizationId: f.organizationId,
      resourceId: f.resourceA,
      asOf: AS_OF,
    });

    assert.equal(
      report.resource?.id,
      f.resourceA,
    );
    assert.equal(report.resources.length, 1);
    assert.equal(report.checks.length, 1);
    assert.equal(
      report.checks[0]?.id,
      f.checkA,
    );
    assert.equal(
      report.auditEvents.some(
        (event) =>
          event.aggregateId ===
          f.checkB,
      ),
      false,
    );
    assert.equal(
      report.auditEvents.some(
        (event) =>
          event.aggregateId ===
          f.resourceB,
      ),
      false,
    );
    assert.equal(
      report.summary.audit.allChainsValid,
      true,
    );
  } finally {
    await f.pool.end();
  }
});

test("JSON CSV and human-readable renderers share the same canonical report", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    const report = await f.service.generate({
      organizationId: f.organizationId,
      resourceId: f.resourceA,
      asOf: AS_OF,
    });

    const json = renderJson(report);
    const parsed = JSON.parse(json);
    assert.equal(
      parsed.summary.deadlines.overdue,
      1,
    );

    const csv = renderCsv(report);
    assert.match(
      csv,
      /^section,resource_id,entity_type,/,
    );
    assert.match(
      csv,
      /"Encryption, control disabled"/,
    );
    assert.match(
      csv,
      /certifications/,
    );
    assert.match(csv, /audit/);

    const text =
      renderHumanReadable(report);
    assert.match(
      text,
      /# Compliance Report/,
    );
    assert.match(
      text,
      /## Executive Summary/,
    );
    assert.match(
      text,
      /## Deadlines/,
    );
    assert.match(
      text,
      /## Audit Integrity/,
    );
    assert.match(
      text,
      /Audit integrity: valid/,
    );
  } finally {
    await f.pool.end();
  }
});

test("reporting rejects invalid timestamps and missing scopes", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    await assert.rejects(
      f.service.generate({
        organizationId: f.organizationId,
        asOf: "not-a-date",
      }),
      (error: unknown) =>
        error instanceof ReportingError &&
        error.code === "validation",
    );

    await assert.rejects(
      f.service.generate({
        organizationId:
          randomUUID(),
      }),
      (error: unknown) =>
        error instanceof ReportingError &&
        error.code === "not_found",
    );

    await assert.rejects(
      f.service.generate({
        organizationId: f.organizationId,
        resourceId: randomUUID(),
      }),
      (error: unknown) =>
        error instanceof ReportingError &&
        error.code === "not_found",
    );
  } finally {
    await f.pool.end();
  }
});
