import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import { EvidenceService } from "@caiae/evidence";
import { EvaluationService } from "../src/index.js";

const PASSING_RULESET = {
  schemaVersion: "1",
  id: "baseline-encryption",
  version: "1.0.0",
  title: "Baseline Encryption",
  rules: [
    {
      id: "encryption-enabled",
      title: "Encryption is enabled",
      severity: "high",
      require: {
        field: "resource.attributes.encryptionEnabled",
        operator: "equals",
        value: true,
      },
      requiredEvidenceTypes: [
        "encryption-configuration",
      ],
    },
  ],
} as const;

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const failingResourceId = randomUUID();
  const principalId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Evaluation Test Organization', $2, 'active')`,
    [organizationId, `evaluation-test-${organizationId}`],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       attributes
     ) VALUES
       ($1, $3, 'information-system', 'Passing System', 'active',
        '{"encryptionEnabled":true}'::jsonb),
       ($2, $3, 'information-system', 'Failing System', 'active',
        '{"encryptionEnabled":false}'::jsonb)`,
    [resourceId, failingResourceId, organizationId],
  );

  await pool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES ($1, $2, 'user', 'Evaluator', 'active')`,
    [principalId, organizationId],
  );

  const evidence = new EvidenceService(pool);

  await evidence.create({
    organizationId,
    resourceId,
    evidenceType: "encryption-configuration",
    title: "Encryption Configuration",
    submittedByPrincipalId: principalId,
    checksumAlgorithm: "sha256",
    checksum: "abc123",
    source: "configuration-export",
    uri: "urn:test:encryption-config",
  });

  await evidence.create({
    organizationId,
    resourceId: failingResourceId,
    evidenceType: "encryption-configuration",
    title: "Encryption Configuration",
    submittedByPrincipalId: principalId,
    checksumAlgorithm: "sha256",
    checksum: "def456",
  });

  return {
    pool,
    service: new EvaluationService(pool),
    organizationId,
    resourceId,
    failingResourceId,
    principalId,
  };
}

test("manual evaluation persists normalized ruleset, context, evidence trace, and result", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const result = await f.service.run({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      ruleSet: PASSING_RULESET,
      requestedByPrincipalId: f.principalId,
      facts: {
        environment: "production",
      },
    });

    assert.equal(result.check.trigger, "manual");
    assert.equal(result.check.status, "passed");
    assert.equal(result.evaluation?.status, "pass");
    assert.equal(
      result.check.ruleSetSnapshot.version,
      "1.0.0",
    );
    assert.equal(
      result.check.contextSnapshot.resource.attributes
        .encryptionEnabled,
      true,
    );
    assert.equal(result.check.evidenceTrace.length, 1);
    assert.equal(
      result.check.evidenceTrace[0]?.evidenceType,
      "encryption-configuration",
    );
    assert.equal(
      result.check.evidenceTrace[0]?.checksum,
      "abc123",
    );

    const ledger = new AuditLedger(f.pool);
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "check",
        result.check.id,
      ),
      { valid: true, checked: 3 },
    );
  } finally {
    await f.pool.end();
  }
});

test("historical check snapshots remain unchanged after resource and evidence changes", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const first = await f.service.run({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      ruleSet: PASSING_RULESET,
      requestedByPrincipalId: f.principalId,
    });

    await f.pool.query(
      `UPDATE resources
       SET attributes = '{"encryptionEnabled":false}'::jsonb
       WHERE id = $1`,
      [f.resourceId],
    );

    const evidence = new EvidenceService(f.pool);
    const current = await evidence.validEvidenceForResource(
      f.organizationId,
      f.resourceId,
    );

    await evidence.revoke({
      evidenceId: current[0]!.id,
      principalId: f.principalId,
      reason: "Configuration replaced",
    });

    const reread = await f.service.get(first.check.id);

    assert.equal(reread.check.status, "passed");
    assert.equal(
      reread.check.contextSnapshot.resource.attributes
        .encryptionEnabled,
      true,
    );
    assert.equal(
      reread.check.evidenceTrace[0]?.checksum,
      "abc123",
    );
    assert.equal(
      reread.check.ruleSetSnapshot.version,
      "1.0.0",
    );

    const second = await f.service.run({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      ruleSet: PASSING_RULESET,
      requestedByPrincipalId: f.principalId,
    });

    assert.equal(second.check.status, "failed");
  } finally {
    await f.pool.end();
  }
});

test("event-triggered evaluation uses the same evaluator and preserves event details", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const result = await f.service.runEvent({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      ruleSet: PASSING_RULESET,
      requestedByPrincipalId: f.principalId,
      eventType: "resource.configuration_changed",
      event: {
        changeId: "chg-123",
      },
    });

    assert.equal(result.check.trigger, "event");
    assert.equal(result.check.status, "passed");
    assert.equal(
      result.check.triggerDetail.eventType,
      "resource.configuration_changed",
    );
    assert.equal(
      result.check.triggerDetail.event.changeId,
      "chg-123",
    );
  } finally {
    await f.pool.end();
  }
});

test("batch evaluation produces independent reproducible checks per resource", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const results = await f.service.runBatch({
      organizationId: f.organizationId,
      resourceIds: [
        f.resourceId,
        f.failingResourceId,
      ],
      ruleSet: PASSING_RULESET,
      requestedByPrincipalId: f.principalId,
    });

    assert.equal(results.length, 2);
    assert.deepEqual(
      results.map((item) => item.check.status),
      ["passed", "failed"],
    );
    assert.notEqual(
      results[0]?.check.id,
      results[1]?.check.id,
    );
  } finally {
    await f.pool.end();
  }
});

test("scheduled resource-type evaluation creates checks and advances schedule without drift", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const firstDue = new Date(
      Date.now() - 1_000,
    );
    const schedule = await f.service.createSchedule({
      organizationId: f.organizationId,
      resourceType: "information-system",
      ruleSet: PASSING_RULESET,
      createdByPrincipalId: f.principalId,
      intervalSeconds: 3_600,
      nextRunAt: firstDue.toISOString(),
    });

    const sweepAt = new Date();

    const sweep = await f.service.runDueSchedules(sweepAt);

    assert.equal(sweep.schedulesClaimed, 1);
    assert.equal(sweep.checksCreated, 2);
    assert.equal(sweep.errors, 0);

    const after = await f.service.getSchedule(
      schedule.schedule.id,
    );

    assert.equal(
      after.schedule.lastRunAt,
      sweepAt.toISOString(),
    );
    assert.ok(
      new Date(after.schedule.nextRunAt).getTime() >
        sweepAt.getTime(),
    );

    const passingChecks =
      await f.service.listForResource(
        f.organizationId,
        f.resourceId,
      );

    const scheduledCheck = passingChecks.find(
      (check) =>
        check.scheduleId === schedule.schedule.id,
    );

    assert.equal(scheduledCheck?.trigger, "scheduled");
    assert.equal(
      scheduledCheck?.scheduledFor,
      firstDue.toISOString(),
    );
  } finally {
    await f.pool.end();
  }
});

test("schedule claiming prevents a second sweep from duplicating the same occurrence", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    await f.service.createSchedule({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      ruleSet: PASSING_RULESET,
      intervalSeconds: 3_600,
      nextRunAt: new Date(
        Date.now() - 1_000,
      ).toISOString(),
    });

    const at = new Date();

    const first = await f.service.runDueSchedules(at);
    const second = await f.service.runDueSchedules(at);

    assert.equal(first.checksCreated, 1);
    assert.equal(second.checksCreated, 0);

    const checks = await f.service.listForResource(
      f.organizationId,
      f.resourceId,
    );

    assert.equal(
      checks.filter(
        (check) => check.trigger === "scheduled",
      ).length,
      1,
    );
  } finally {
    await f.pool.end();
  }
});
