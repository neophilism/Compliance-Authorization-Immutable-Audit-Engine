import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  ExceptionError,
  ExceptionService,
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
      "Exception Test Organization",
      `exception-test-${organizationId}`,
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
    service: new ExceptionService(pool),
    organizationId,
    resourceId,
    requesterId,
    approver1Id,
    approver2Id,
    outsiderId,
  };
}

async function createRule(
  pool: ReturnType<typeof createPool>,
  organizationId: string,
): Promise<string> {
  const policyId = randomUUID();
  const ruleSetId = randomUUID();
  const ruleId = randomUUID();

  await pool.query(
    `INSERT INTO policies(
       id,
       organization_id,
       key,
       title,
       status
     ) VALUES ($1, $2, $3, 'Test Policy', 'active')`,
    [policyId, organizationId, `policy-${policyId}`],
  );

  await pool.query(
    `INSERT INTO rule_sets(
       id,
       organization_id,
       policy_id,
       key,
       version,
       status
     ) VALUES ($1, $2, $3, $4, '1', 'active')`,
    [
      ruleSetId,
      organizationId,
      policyId,
      `ruleset-${ruleSetId}`,
    ],
  );

  await pool.query(
    `INSERT INTO rules(
       id,
       organization_id,
       rule_set_id,
       key,
       title,
       severity,
       enabled
     ) VALUES ($1, $2, $3, $4, 'Test Rule', 'high', true)`,
    [
      ruleId,
      organizationId,
      ruleSetId,
      `rule-${ruleId}`,
    ],
  );

  return ruleId;
}

test("two-person exception quorum remains requested until approvals are complete", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const validUntil = new Date(
      Date.now() + 3_600_000,
    ).toISOString();

    const requested = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "exception",
      requestedByPrincipalId: f.requesterId,
      justification: "Temporary operational incompatibility",
      validUntil,
      approvalQuorum: 2,
      eligibleApproverPrincipalIds: [
        f.approver1Id,
        f.approver2Id,
      ],
      scope: { subsystem: "demo" },
      conditions: { compensatingControl: true },
    });

    assert.equal(requested.exception.status, "requested");
    assert.deepEqual(requested.exception.scope, {
      subsystem: "demo",
    });

    const first = await f.service.recordDecision({
      exceptionId: requested.exception.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    assert.equal(first.exception.status, "requested");
    assert.equal(first.approvalCount, 1);

    const second = await f.service.recordDecision({
      exceptionId: requested.exception.id,
      principalId: f.approver2Id,
      decision: "approve",
    });

    assert.equal(second.exception.status, "approved");
    assert.equal(second.approvalCount, 2);
    assert.deepEqual(
      await f.service.effectiveness(requested.exception.id),
      { effective: true, reason: "approved" },
    );

    const ledger = new AuditLedger(f.pool);
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "exception",
        requested.exception.id,
      ),
      { valid: true, checked: 4 },
    );
  } finally {
    await f.pool.end();
  }
});

test("waivers use the same bounded approval lifecycle", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const requested = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "waiver",
      requestedByPrincipalId: f.requesterId,
      justification: "Temporary waiver for migration window",
      validUntil: new Date(
        Date.now() + 3_600_000,
      ).toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    const approved = await f.service.recordDecision({
      exceptionId: requested.exception.id,
      principalId: f.approver1Id,
      decision: "approve",
      rationale: "bounded migration period accepted",
    });

    assert.equal(approved.exception.kind, "waiver");
    assert.equal(approved.exception.status, "approved");

    const ledger = new AuditLedger(f.pool);
    const events = await ledger.list(
      f.organizationId,
      "exception",
      requested.exception.id,
    );

    assert.deepEqual(
      events.map((event) => event.eventType),
      [
        "waiver.requested",
        "waiver.decision_recorded",
        "waiver.approved",
      ],
    );
  } finally {
    await f.pool.end();
  }
});

test("rule-targeted exception requires an enabled rule in the same organization", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const ruleId = await createRule(
      f.pool,
      f.organizationId,
    );

    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      ruleId,
      kind: "exception",
      requestedByPrincipalId: f.requesterId,
      justification: "Rule-specific deviation",
      validUntil: new Date(
        Date.now() + 3_600_000,
      ).toISOString(),
    });

    assert.equal(record.exception.ruleId, ruleId);

    await assert.rejects(
      f.service.request({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        ruleId: randomUUID(),
        kind: "exception",
        requestedByPrincipalId: f.requesterId,
        justification: "Invalid rule",
        validUntil: new Date(
          Date.now() + 3_600_000,
        ).toISOString(),
      }),
      (error: unknown) =>
        error instanceof ExceptionError &&
        error.code === "not_found",
    );
  } finally {
    await f.pool.end();
  }
});

test("eligible approver restriction and duplicate decision protection are enforced", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "exception",
      requestedByPrincipalId: f.requesterId,
      justification: "Approval controls test",
      validUntil: new Date(
        Date.now() + 3_600_000,
      ).toISOString(),
      approvalQuorum: 2,
      eligibleApproverPrincipalIds: [
        f.approver1Id,
        f.approver2Id,
      ],
    });

    await assert.rejects(
      f.service.recordDecision({
        exceptionId: record.exception.id,
        principalId: f.outsiderId,
        decision: "approve",
      }),
      (error: unknown) =>
        error instanceof ExceptionError &&
        error.code === "forbidden_approver",
    );

    await f.service.recordDecision({
      exceptionId: record.exception.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    await assert.rejects(
      f.service.recordDecision({
        exceptionId: record.exception.id,
        principalId: f.approver1Id,
        decision: "approve",
      }),
      (error: unknown) =>
        error instanceof ExceptionError &&
        error.code === "duplicate_decision",
    );
  } finally {
    await f.pool.end();
  }
});

test("denial is terminal and approved records can be revoked", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const deniedRequest = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "exception",
      requestedByPrincipalId: f.requesterId,
      justification: "Denial test",
      validUntil: new Date(
        Date.now() + 3_600_000,
      ).toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    const denied = await f.service.recordDecision({
      exceptionId: deniedRequest.exception.id,
      principalId: f.approver1Id,
      decision: "deny",
      rationale: "Deviation not justified",
    });

    assert.equal(denied.exception.status, "denied");

    const approvedRequest = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "waiver",
      requestedByPrincipalId: f.requesterId,
      justification: "Revocation test",
      validUntil: new Date(
        Date.now() + 3_600_000,
      ).toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    await f.service.recordDecision({
      exceptionId: approvedRequest.exception.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    const revoked = await f.service.revoke({
      exceptionId: approvedRequest.exception.id,
      principalId: f.approver1Id,
      reason: "Underlying condition resolved",
    });

    assert.equal(revoked.exception.status, "revoked");
  } finally {
    await f.pool.end();
  }
});

test("requests must be time-bounded and expire automatically", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    await assert.rejects(
      f.service.request({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        kind: "exception",
        requestedByPrincipalId: f.requesterId,
        justification: "Unbounded request",
        validUntil: "",
      }),
      (error: unknown) =>
        error instanceof ExceptionError &&
        error.code === "validation",
    );

    const now = Date.now();
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "exception",
      requestedByPrincipalId: f.requesterId,
      justification: "Short request",
      validUntil: new Date(now + 60_000).toISOString(),
    });

    assert.deepEqual(
      await f.service.effectiveness(
        record.exception.id,
        new Date(now + 61_000),
      ),
      { effective: false, reason: "requested" },
    );

    assert.deepEqual(
      await f.service.expireDue(new Date(now + 61_000)),
      { expired: 1 },
    );

    const expired = await f.service.get(record.exception.id);
    assert.equal(expired.exception.status, "expired");
  } finally {
    await f.pool.end();
  }
});

test("approval after the validity window records expiration instead of creating authority", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.request({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      kind: "exception",
      requestedByPrincipalId: f.requesterId,
      justification: "Late approval test",
      validUntil: new Date(
        Date.now() + 60_000,
      ).toISOString(),
      eligibleApproverPrincipalIds: [f.approver1Id],
    });

    await f.pool.query(
      `UPDATE exceptions
       SET valid_until = $2
       WHERE id = $1`,
      [
        record.exception.id,
        new Date(Date.now() - 1_000).toISOString(),
      ],
    );

    const after = await f.service.recordDecision({
      exceptionId: record.exception.id,
      principalId: f.approver1Id,
      decision: "approve",
    });

    assert.equal(after.exception.status, "expired");
  } finally {
    await f.pool.end();
  }
});
