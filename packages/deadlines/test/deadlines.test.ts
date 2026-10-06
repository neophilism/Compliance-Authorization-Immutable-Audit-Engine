import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { AuthorizationService } from "@caiae/authorization";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  DeadlineError,
  DeadlineService,
} from "../src/index.js";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const requesterId = randomUUID();
  const approverId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Deadline Test Organization', $2, 'active')`,
    [organizationId, `deadline-test-${organizationId}`],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status
     ) VALUES ($1, $2, 'system', 'Deadline Test System', 'active')`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [requesterId, "Requester"],
    [approverId, "Approver"],
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
    service: new DeadlineService(pool),
    organizationId,
    resourceId,
    requesterId,
    approverId,
  };
}

test("relative deadlines preserve anchor and offset while resolving an absolute due time", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const anchor = new Date(
      Date.now() + 600_000,
    );

    const record = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      subjectType: "resource",
      subjectId: f.resourceId,
      deadlineType: "relative-review",
      createdByPrincipalId: f.requesterId,
      anchorAt: anchor.toISOString(),
      dueAfterSeconds: 3_600,
    });

    assert.equal(
      record.deadline.anchorAt,
      anchor.toISOString(),
    );
    assert.equal(
      record.deadline.dueOffsetSeconds,
      3_600,
    );
    assert.equal(
      record.deadline.dueAt,
      new Date(
        anchor.getTime() + 3_600_000,
      ).toISOString(),
    );
  } finally {
    await f.pool.end();
  }
});

test("clock calculation advances scheduled to warning to due to overdue with escalation", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const due = new Date(
      Date.now() + 600_000,
    );

    const record = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      subjectType: "resource",
      subjectId: f.resourceId,
      deadlineType: "clock-progression",
      dueAt: due.toISOString(),
      warningWindowSeconds: 60,
      gracePeriodSeconds: 30,
      escalationAfterSeconds: [0, 60],
    });

    assert.equal(
      (
        await f.service.statusAt(
          record.deadline.id,
          new Date(due.getTime() - 120_000),
        )
      ).status,
      "scheduled",
    );

    assert.equal(
      (
        await f.service.statusAt(
          record.deadline.id,
          new Date(due.getTime() - 30_000),
        )
      ).status,
      "warning",
    );

    assert.equal(
      (
        await f.service.statusAt(
          record.deadline.id,
          new Date(due.getTime() + 10_000),
        )
      ).status,
      "due",
    );

    assert.deepEqual(
      await f.service.statusAt(
        record.deadline.id,
        new Date(due.getTime() + 31_000),
      ),
      {
        status: "overdue",
        escalationLevel: 1,
        warningAt: new Date(
          due.getTime() - 60_000,
        ).toISOString(),
        dueAt: due.toISOString(),
        overdueAt: new Date(
          due.getTime() + 30_000,
        ).toISOString(),
      },
    );

    assert.equal(
      (
        await f.service.statusAt(
          record.deadline.id,
          new Date(due.getTime() + 91_000),
        )
      ).escalationLevel,
      2,
    );
  } finally {
    await f.pool.end();
  }
});

test("a late sweep records every crossed clock threshold in the audit chain", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const due = new Date(
      Date.now() + 600_000,
    );

    const record = await f.service.create({
      organizationId: f.organizationId,
      subjectType: "case",
      subjectId: randomUUID(),
      deadlineType: "statutory-response",
      dueAt: due.toISOString(),
      warningWindowSeconds: 60,
      gracePeriodSeconds: 30,
      escalationAfterSeconds: [0, 60],
    });

    const sweep = await f.service.sweep(
      new Date(due.getTime() + 91_000),
    );

    assert.equal(sweep.statusTransitions, 3);
    assert.equal(sweep.escalations, 2);

    const after = await f.service.get(
      record.deadline.id,
    );
    assert.equal(after.deadline.status, "overdue");
    assert.equal(after.deadline.escalationLevel, 2);

    const ledger = new AuditLedger(f.pool);
    const events = await ledger.list(
      f.organizationId,
      "deadline",
      record.deadline.id,
    );

    assert.deepEqual(
      events.map((event) => event.eventType),
      [
        "deadline.created",
        "deadline.warning",
        "deadline.due",
        "deadline.overdue",
        "deadline.escalated",
        "deadline.escalated",
      ],
    );

    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "deadline",
        record.deadline.id,
      ),
      { valid: true, checked: 6 },
    );
  } finally {
    await f.pool.end();
  }
});

test("recurring deadlines preserve occurrence history and advance from the prior due date", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const firstDue = new Date(
      Date.now() + 600_000,
    );
    const interval = 86_400;

    const record = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      subjectType: "resource",
      subjectId: f.resourceId,
      deadlineType: "annual-review",
      dueAt: firstDue.toISOString(),
      gracePeriodSeconds: 60,
      recurrenceIntervalSeconds: interval,
      maxOccurrences: 2,
    });

    const firstSatisfied = await f.service.satisfy({
      deadlineId: record.deadline.id,
      principalId: f.requesterId,
      satisfiedAt: new Date(
        firstDue.getTime() - 10_000,
      ).toISOString(),
    });

    assert.equal(
      firstSatisfied.deadline.cycleNumber,
      2,
    );
    assert.equal(
      firstSatisfied.deadline.dueAt,
      new Date(
        firstDue.getTime() + interval * 1_000,
      ).toISOString(),
    );
    assert.equal(
      firstSatisfied.occurrences.length,
      1,
    );
    assert.equal(
      firstSatisfied.occurrences[0]?.outcome,
      "on_time",
    );

    const secondDue = new Date(
      firstSatisfied.deadline.dueAt,
    );

    const secondSatisfied = await f.service.satisfy({
      deadlineId: record.deadline.id,
      principalId: f.requesterId,
      satisfiedAt: new Date(
        secondDue.getTime() + 1_000,
      ).toISOString(),
    });

    assert.equal(
      secondSatisfied.deadline.status,
      "satisfied",
    );
    assert.equal(
      secondSatisfied.occurrences.length,
      2,
    );
  } finally {
    await f.pool.end();
  }
});

test("completion at or after overdueAt is recorded as late", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const due = new Date(
      Date.now() + 600_000,
    );

    const record = await f.service.create({
      organizationId: f.organizationId,
      subjectType: "report",
      subjectId: randomUUID(),
      deadlineType: "filing",
      dueAt: due.toISOString(),
      gracePeriodSeconds: 30,
    });

    const satisfied = await f.service.satisfy({
      deadlineId: record.deadline.id,
      principalId: f.requesterId,
      satisfiedAt: new Date(
        due.getTime() + 30_000,
      ).toISOString(),
    });

    assert.equal(
      satisfied.occurrences[0]?.outcome,
      "late",
    );
  } finally {
    await f.pool.end();
  }
});

test("invalid schedule combinations are rejected", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    await assert.rejects(
      f.service.create({
        organizationId: f.organizationId,
        subjectType: "resource",
        subjectId: f.resourceId,
        deadlineType: "ambiguous",
        dueAt: new Date(
          Date.now() + 600_000,
        ).toISOString(),
        dueAfterSeconds: 60,
      }),
      (error: unknown) =>
        error instanceof DeadlineError &&
        error.code === "validation",
    );

    await assert.rejects(
      f.service.create({
        organizationId: f.organizationId,
        subjectType: "resource",
        subjectId: f.resourceId,
        deadlineType: "bad-recurrence",
        dueAt: new Date(
          Date.now() + 600_000,
        ).toISOString(),
        recurrenceEndAt: new Date(
          Date.now() + 1_200_000,
        ).toISOString(),
      }),
      (error: unknown) =>
        error instanceof DeadlineError &&
        error.code === "validation",
    );

    await assert.rejects(
      f.service.create({
        organizationId: f.organizationId,
        subjectType: "resource",
        subjectId: f.resourceId,
        deadlineType: "duplicate-escalation",
        dueAt: new Date(
          Date.now() + 600_000,
        ).toISOString(),
        escalationAfterSeconds: [0, 0],
      }),
      (error: unknown) =>
        error instanceof DeadlineError &&
        error.code === "validation",
    );
  } finally {
    await f.pool.end();
  }
});

test("deadlines can be cancelled with a durable audit event", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.create({
      organizationId: f.organizationId,
      subjectType: "case",
      subjectId: randomUUID(),
      deadlineType: "cancel-test",
      dueAt: new Date(
        Date.now() + 600_000,
      ).toISOString(),
    });

    const cancelled = await f.service.cancel({
      deadlineId: record.deadline.id,
      principalId: f.requesterId,
      reason: "Underlying obligation withdrawn",
    });

    assert.equal(
      cancelled.deadline.status,
      "cancelled",
    );

    const ledger = new AuditLedger(f.pool);
    const events = await ledger.list(
      f.organizationId,
      "deadline",
      record.deadline.id,
    );

    assert.equal(
      events.at(-1)?.eventType,
      "deadline.cancelled",
    );
  } finally {
    await f.pool.end();
  }
});

test("authorization clock progresses warning to due to overdue before authorization expiration", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const base = Date.now();
    const authorizationService =
      new AuthorizationService(f.pool);

    const authorization = await authorizationService.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      authorizationType: "time-bound-operation",
      requestedByPrincipalId: f.requesterId,
      eligibleApproverPrincipalIds: [f.approverId],
      validUntil: new Date(
        base + 1_200_000,
      ).toISOString(),
    });

    const approved = await authorizationService.recordDecision({
      authorizationId: authorization.authorization.id,
      principalId: f.approverId,
      decision: "approve",
    });

    assert.equal(
      approved.authorization.status,
      "approved",
    );

    const deadline = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      subjectType: "authorization",
      subjectId: approved.authorization.id,
      deadlineType: "authorization-review",
      dueAt: new Date(
        base + 600_000,
      ).toISOString(),
      warningWindowSeconds: 300,
      gracePeriodSeconds: 300,
    });

    await f.service.sweep(
      new Date(base + 400_000),
    );
    assert.equal(
      (await f.service.get(deadline.deadline.id))
        .deadline.status,
      "warning",
    );

    await f.service.sweep(
      new Date(base + 600_000),
    );
    assert.equal(
      (await f.service.get(deadline.deadline.id))
        .deadline.status,
      "due",
    );

    await f.service.sweep(
      new Date(base + 901_000),
    );
    assert.equal(
      (await f.service.get(deadline.deadline.id))
        .deadline.status,
      "overdue",
    );

    assert.deepEqual(
      await authorizationService.effectiveness(
        approved.authorization.id,
        new Date(base + 901_000),
      ),
      { effective: true, reason: "approved" },
    );

    await authorizationService.expireDue(
      new Date(base + 1_201_000),
    );

    assert.equal(
      (
        await authorizationService.get(
          approved.authorization.id,
        )
      ).authorization.status,
      "expired",
    );
  } finally {
    await f.pool.end();
  }
});
