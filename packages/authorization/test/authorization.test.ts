import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  AuthorizationError,
  AuthorizationService,
} from "../src/index.js";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const requesterId = randomUUID();
  const approver1Id = randomUUID();
  const approver2Id = randomUUID();
  const outsiderId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, $2, $3, 'active')`,
    [
      organizationId,
      "Authorization Test Organization",
      `authorization-test-${organizationId}`,
    ],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status
     ) VALUES ($1, $2, 'test-resource', 'Test Resource', 'active')`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [requesterId, "Requester"],
    [approver1Id, "Approver One"],
    [approver2Id, "Approver Two"],
    [outsiderId, "Outsider"],
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

  return {
    pool,
    service: new AuthorizationService(pool),
    organizationId,
    resourceId,
    requesterId,
    approver1Id,
    approver2Id,
    outsiderId,
  };
}

test("two-person quorum keeps request pending until quorum is reached", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const requested = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "controlled-operation",
      requestedByPrincipalId: f.requesterId,
      approvalQuorum: 2,
      approvalAuthority: "designated-review-board",
      eligibleApproverPrincipalIds: [
        f.approver1Id,
        f.approver2Id,
      ],
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
      scope: { operation: "demo" },
      conditions: { supervised: true },
    });

    assert.equal(requested.authorization.status, "pending");
    assert.deepEqual(requested.authorization.scope, {
      operation: "demo",
    });
    assert.deepEqual(requested.authorization.conditions, {
      supervised: true,
    });
    assert.equal(
      (await f.service.effectiveness(requested.authorization.id)).effective,
      false,
    );

    const afterFirst = await f.service.recordDecision({
      authorizationId: requested.authorization.id,
      principalId: f.approver1Id,
      decision: "approve",
      rationale: "first review complete",
    });

    assert.equal(afterFirst.authorization.status, "pending");
    assert.equal(afterFirst.approvalCount, 1);

    const afterSecond = await f.service.recordDecision({
      authorizationId: requested.authorization.id,
      principalId: f.approver2Id,
      decision: "approve",
      rationale: "second review complete",
    });

    assert.equal(afterSecond.authorization.status, "approved");
    assert.equal(afterSecond.approvalCount, 2);
    assert.equal(
      (await f.service.effectiveness(requested.authorization.id)).effective,
      true,
    );

    const ledger = new AuditLedger(f.pool);
    const verification = await ledger.verify(
      f.organizationId,
      "authorization",
      requested.authorization.id,
    );
    assert.deepEqual(verification, { valid: true, checked: 4 });

    const events = await ledger.list(
      f.organizationId,
      "authorization",
      requested.authorization.id,
    );
    assert.deepEqual(
      events.map((event) => event.eventType),
      [
        "authorization.requested",
        "authorization.decision_recorded",
        "authorization.decision_recorded",
        "authorization.approved",
      ],
    );
  } finally {
    await f.pool.end();
  }
});

test("configured eligible approvers are enforced", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "restricted-access",
      requestedByPrincipalId: f.requesterId,
      eligibleApproverPrincipalIds: [f.approver1Id],
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
    });

    await assert.rejects(
      f.service.recordDecision({
        authorizationId: record.authorization.id,
        principalId: f.outsiderId,
        decision: "approve",
      }),
      (error: unknown) =>
        error instanceof AuthorizationError &&
        error.code === "forbidden_approver",
    );
  } finally {
    await f.pool.end();
  }
});

test("a denial terminates a pending authorization", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "restricted-access",
      requestedByPrincipalId: f.requesterId,
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    const denied = await f.service.recordDecision({
      authorizationId: record.authorization.id,
      principalId: f.approver1Id,
      decision: "deny",
      rationale: "requirements not satisfied",
    });

    assert.equal(denied.authorization.status, "denied");
    assert.deepEqual(
      await f.service.effectiveness(record.authorization.id),
      { effective: false, reason: "denied" },
    );
  } finally {
    await f.pool.end();
  }
});

test("one principal cannot submit two decisions on the same request", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "two-person-review",
      requestedByPrincipalId: f.requesterId,
      approvalQuorum: 2,
      eligibleApproverPrincipalIds: [
        f.approver1Id,
        f.approver2Id,
      ],
    });

    await f.service.recordDecision({
      authorizationId: record.authorization.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    await assert.rejects(
      f.service.recordDecision({
        authorizationId: record.authorization.id,
        principalId: f.approver1Id,
        decision: "approve",
      }),
      (error: unknown) =>
        error instanceof AuthorizationError &&
        error.code === "duplicate_decision",
    );
  } finally {
    await f.pool.end();
  }
});

test("emergency authorization is temporary and revoked when review is overdue", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const now = Date.now();
    const reviewDue = new Date(now + 60_000);
    const validUntil = new Date(now + 120_000);

    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "emergency-action",
      requestedByPrincipalId: f.requesterId,
      emergency: true,
      emergencyReviewDueAt: reviewDue.toISOString(),
      validUntil: validUntil.toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    assert.equal(record.authorization.status, "approved");
    assert.deepEqual(
      await f.service.effectiveness(
        record.authorization.id,
        new Date(now + 30_000),
      ),
      { effective: true, reason: "approved" },
    );

    assert.deepEqual(
      await f.service.effectiveness(
        record.authorization.id,
        new Date(now + 61_000),
      ),
      {
        effective: false,
        reason: "emergency_review_overdue",
      },
    );

    const result = await f.service.expireDue(
      new Date(now + 61_000),
    );
    assert.deepEqual(result, {
      expired: 0,
      emergencyRevoked: 1,
    });

    const after = await f.service.get(record.authorization.id);
    assert.equal(after.authorization.status, "revoked");
  } finally {
    await f.pool.end();
  }
});

test("approved emergency review preserves authority through the validity window", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const now = Date.now();
    const reviewDue = new Date(now + 60_000);
    const validUntil = new Date(now + 120_000);

    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "emergency-action",
      requestedByPrincipalId: f.requesterId,
      emergency: true,
      emergencyReviewDueAt: reviewDue.toISOString(),
      validUntil: validUntil.toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    const reviewed = await f.service.recordDecision({
      authorizationId: record.authorization.id,
      principalId: f.approver1Id,
      decision: "approve",
      rationale: "emergency use affirmed",
    });

    assert.notEqual(
      reviewed.authorization.emergencyReviewedAt,
      null,
    );

    assert.deepEqual(
      await f.service.effectiveness(
        record.authorization.id,
        new Date(now + 90_000),
      ),
      { effective: true, reason: "approved" },
    );
  } finally {
    await f.pool.end();
  }
});

test("approved authorization expires automatically after validUntil", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const now = Date.now();
    const validUntil = new Date(now + 60_000);

    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "time-bound-action",
      requestedByPrincipalId: f.requesterId,
      validUntil: validUntil.toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    await f.service.recordDecision({
      authorizationId: record.authorization.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    const result = await f.service.expireDue(
      new Date(now + 61_000),
    );
    assert.deepEqual(result, {
      expired: 1,
      emergencyRevoked: 0,
    });

    const expired = await f.service.get(record.authorization.id);
    assert.equal(expired.authorization.status, "expired");
  } finally {
    await f.pool.end();
  }
});

test("approved authorization can be explicitly revoked", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "revocable-action",
      requestedByPrincipalId: f.requesterId,
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    await f.service.recordDecision({
      authorizationId: record.authorization.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    const revoked = await f.service.revoke({
      authorizationId: record.authorization.id,
      principalId: f.requesterId,
      reason: "operational need ended",
    });

    assert.equal(revoked.authorization.status, "revoked");
  } finally {
    await f.pool.end();
  }
});

test("emergency path requires a bounded validity and review window", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    await assert.rejects(
      f.service.request({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        authorizationType: "unbounded-emergency",
        requestedByPrincipalId: f.requesterId,
        emergency: true,
      }),
      (error: unknown) =>
        error instanceof AuthorizationError &&
        error.code === "validation",
    );

    await assert.rejects(
      f.service.request({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        authorizationType: "impossible-quorum",
        requestedByPrincipalId: f.requesterId,
        approvalQuorum: 2,
        eligibleApproverPrincipalIds: [f.approver1Id],
      }),
      (error: unknown) =>
        error instanceof AuthorizationError &&
        error.code === "validation",
    );
  } finally {
    await f.pool.end();
  }
});
