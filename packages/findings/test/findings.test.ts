import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import { DeadlineService } from "@caiae/deadlines";
import {
  FindingError,
  FindingService,
} from "../src/index.js";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const actorId = randomUUID();
  const ownerId = randomUUID();
  const checkId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Finding Test Organization', $2, 'active')`,
    [organizationId, `finding-test-${organizationId}`],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       attributes
     ) VALUES (
       $1, $2, 'system', 'Finding Test System', 'active',
       '{"controlEnabled":false}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [actorId, "Finding Actor"],
    [ownerId, "Finding Owner"],
  ]) {
    await pool.query(
      `INSERT INTO principals(
         id,
         organization_id,
         kind,
         display_name,
         status
       ) VALUES ($1, $2, 'user', $3, 'active')`,
      [id, organizationId, name],
    );
  }

  const ruleSetSnapshot = {
    schemaVersion: "1",
    id: "test-controls",
    version: "2.4.0",
    title: "Test Controls",
    rules: [
      {
        id: "control-enabled",
        title: "Control must be enabled",
        description: "The test control must be enabled.",
        severity: "high",
        require: {
          field: "resource.attributes.controlEnabled",
          operator: "equals",
          value: true,
        },
      },
      {
        id: "other-rule",
        title: "Other rule",
        severity: "low",
        require: {
          field: "resource.status",
          operator: "equals",
          value: "active",
        },
      },
    ],
  };

  const result = {
    ruleSetId: "test-controls",
    version: "2.4.0",
    status: "fail",
    counts: {
      pass: 1,
      fail: 1,
      unknown: 0,
      notApplicable: 0,
    },
    rules: [
      {
        ruleId: "control-enabled",
        title: "Control must be enabled",
        severity: "high",
        applicable: true,
        requirement: false,
        status: "fail",
        requiredEvidenceTypes: [],
        missingEvidenceTypes: [],
      },
      {
        ruleId: "other-rule",
        title: "Other rule",
        severity: "low",
        applicable: true,
        requirement: true,
        status: "pass",
        requiredEvidenceTypes: [],
        missingEvidenceTypes: [],
      },
    ],
  };

  await pool.query(
    `INSERT INTO checks(
       id,
       organization_id,
       resource_id,
       status,
       trigger,
       rule_set_snapshot,
       context_snapshot,
       result,
       completed_at,
       evaluated_at,
       metadata
     ) VALUES (
       $1, $2, $3, 'failed', 'manual',
       $4::jsonb, '{}'::jsonb, $5::jsonb,
       now(), now(), '{}'::jsonb
     )`,
    [
      checkId,
      organizationId,
      resourceId,
      JSON.stringify(ruleSetSnapshot),
      JSON.stringify(result),
    ],
  );

  return {
    pool,
    service: new FindingService(pool),
    organizationId,
    resourceId,
    actorId,
    ownerId,
    checkId,
  };
}

test("failed check synchronization creates one finding per failed rule and is idempotent", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const first = await f.service.syncFailedCheck(
      f.checkId,
    );

    assert.equal(first.length, 1);
    assert.equal(
      first[0]?.ruleKey,
      "control-enabled",
    );
    assert.equal(first[0]?.ruleSetKey, "test-controls");
    assert.equal(first[0]?.ruleSetVersion, "2.4.0");
    assert.equal(first[0]?.severity, "high");
    assert.equal(first[0]?.status, "open");
    assert.equal(
      first[0]?.description,
      "The test control must be enabled.",
    );

    const second = await f.service.syncFailedCheck(
      f.checkId,
    );
    assert.equal(second.length, 1);
    assert.equal(second[0]?.id, first[0]?.id);

    const ledger = new AuditLedger(f.pool);
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "finding",
        first[0]!.id,
      ),
      { valid: true, checked: 1 },
    );
  } finally {
    await f.pool.end();
  }
});

test("acknowledgement, owner assignment, dispute, and upheld dispute preserve lifecycle history", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const [finding] =
      await f.service.syncFailedCheck(f.checkId);

    const acknowledged = await f.service.acknowledge({
      findingId: finding!.id,
      principalId: f.actorId,
    });
    assert.equal(
      acknowledged.finding.status,
      "acknowledged",
    );
    assert.equal(
      acknowledged.finding.acknowledgedByPrincipalId,
      f.actorId,
    );

    const assigned = await f.service.assignOwner({
      findingId: finding!.id,
      principalId: f.actorId,
      ownerPrincipalId: f.ownerId,
    });
    assert.equal(
      assigned.finding.ownerPrincipalId,
      f.ownerId,
    );

    const disputed = await f.service.dispute({
      findingId: finding!.id,
      principalId: f.ownerId,
      reason: "The source configuration is contested.",
    });
    assert.equal(disputed.finding.status, "disputed");
    assert.equal(
      disputed.finding.disputeReason,
      "The source configuration is contested.",
    );

    const upheld = await f.service.resolveDispute({
      findingId: finding!.id,
      principalId: f.actorId,
      outcome: "uphold",
      rationale: "The failed control was independently confirmed.",
    });
    assert.equal(
      upheld.finding.status,
      "acknowledged",
    );

    const ledger = new AuditLedger(f.pool);
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "finding",
        finding!.id,
      ),
      { valid: true, checked: 5 },
    );
  } finally {
    await f.pool.end();
  }
});

test("dismissed dispute closes the finding without remediation", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const [finding] =
      await f.service.syncFailedCheck(f.checkId);

    await f.service.dispute({
      findingId: finding!.id,
      principalId: f.actorId,
      reason: "The check used an invalid source fact.",
    });

    const dismissed =
      await f.service.resolveDispute({
        findingId: finding!.id,
        principalId: f.actorId,
        outcome: "dismiss",
        rationale:
          "The underlying source fact was invalid.",
      });

    assert.equal(dismissed.finding.status, "closed");
    assert.notEqual(
      dismissed.finding.closedAt,
      null,
    );
    assert.equal(dismissed.remediations.length, 0);
  } finally {
    await f.pool.end();
  }
});

test("verified remediation resolves the finding and satisfies its deadline", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const [finding] =
      await f.service.syncFailedCheck(f.checkId);
    const dueAt = new Date(
      Date.now() + 3_600_000,
    ).toISOString();

    const created =
      await f.service.createRemediation({
        findingId: finding!.id,
        createdByPrincipalId: f.actorId,
        ownerPrincipalId: f.ownerId,
        plan: "Enable the required control and verify configuration.",
        dueAt,
        warningWindowSeconds: 600,
        gracePeriodSeconds: 300,
        escalationAfterSeconds: [0, 900],
      });

    assert.equal(
      created.finding.status,
      "remediating",
    );
    assert.equal(created.remediations.length, 1);
    const remediation = created.remediations[0]!;
    assert.equal(remediation.status, "planned");
    assert.notEqual(remediation.deadlineId, null);

    const deadlines = new DeadlineService(f.pool);
    const deadline = await deadlines.get(
      remediation.deadlineId!,
    );
    assert.equal(
      deadline.deadline.subjectType,
      "remediation",
    );
    assert.equal(
      deadline.deadline.subjectId,
      remediation.id,
    );
    assert.equal(deadline.deadline.dueAt, dueAt);

    const started =
      await f.service.startRemediation({
        remediationId: remediation.id,
        principalId: f.ownerId,
      });
    assert.equal(
      started.remediations[0]?.status,
      "in_progress",
    );

    const submitted =
      await f.service.submitForVerification({
        remediationId: remediation.id,
        principalId: f.ownerId,
      });
    assert.equal(
      submitted.remediations[0]?.status,
      "ready_for_verification",
    );

    const verified =
      await f.service.verifyRemediation({
        remediationId: remediation.id,
        principalId: f.actorId,
        note: "Configuration evidence confirms the control is enabled.",
      });
    assert.equal(
      verified.remediations[0]?.status,
      "verified",
    );
    assert.equal(
      verified.finding.status,
      "resolved",
    );

    const satisfiedDeadline =
      await deadlines.get(remediation.deadlineId!);
    assert.equal(
      satisfiedDeadline.deadline.status,
      "satisfied",
    );

    const closed = await f.service.close({
      findingId: finding!.id,
      principalId: f.actorId,
    });
    assert.equal(closed.finding.status, "closed");

    const reopened = await f.service.reopen({
      findingId: finding!.id,
      principalId: f.actorId,
    });
    assert.equal(reopened.finding.status, "open");
    assert.equal(reopened.finding.resolvedAt, null);
    assert.equal(reopened.finding.closedAt, null);
  } finally {
    await f.pool.end();
  }
});

test("rejected remediation cancels its deadline and permits a replacement plan", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const [finding] =
      await f.service.syncFailedCheck(f.checkId);

    const first =
      await f.service.createRemediation({
        findingId: finding!.id,
        createdByPrincipalId: f.actorId,
        ownerPrincipalId: f.ownerId,
        plan: "First corrective action.",
        dueAt: new Date(
          Date.now() + 3_600_000,
        ).toISOString(),
      });

    const remediation = first.remediations[0]!;

    await f.service.startRemediation({
      remediationId: remediation.id,
      principalId: f.ownerId,
    });
    await f.service.submitForVerification({
      remediationId: remediation.id,
      principalId: f.ownerId,
    });

    const rejected =
      await f.service.rejectRemediation({
        remediationId: remediation.id,
        principalId: f.actorId,
        reason: "The control remains disabled.",
      });

    assert.equal(
      rejected.remediations[0]?.status,
      "rejected",
    );
    assert.equal(
      rejected.finding.status,
      "remediating",
    );

    const deadlines = new DeadlineService(f.pool);
    const cancelledDeadline =
      await deadlines.get(remediation.deadlineId!);
    assert.equal(
      cancelledDeadline.deadline.status,
      "cancelled",
    );

    const replacement =
      await f.service.createRemediation({
        findingId: finding!.id,
        createdByPrincipalId: f.actorId,
        ownerPrincipalId: f.ownerId,
        plan: "Replacement corrective action.",
      });

    assert.equal(replacement.remediations.length, 2);
    assert.equal(
      replacement.remediations[1]?.status,
      "planned",
    );
  } finally {
    await f.pool.end();
  }
});

test("invalid lifecycle transitions are rejected", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const [finding] =
      await f.service.syncFailedCheck(f.checkId);

    await assert.rejects(
      f.service.close({
        findingId: finding!.id,
        principalId: f.actorId,
      }),
      (error: unknown) =>
        error instanceof FindingError &&
        error.code === "invalid_state",
    );

    await f.service.dispute({
      findingId: finding!.id,
      principalId: f.actorId,
      reason: "Contested.",
    });

    await assert.rejects(
      f.service.createRemediation({
        findingId: finding!.id,
        createdByPrincipalId: f.actorId,
        plan: "Should not be allowed while disputed.",
      }),
      (error: unknown) =>
        error instanceof FindingError &&
        error.code === "invalid_state",
    );
  } finally {
    await f.pool.end();
  }
});
