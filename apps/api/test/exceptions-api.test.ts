import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { buildApp } from "../src/app.js";

test("waiver API remains ineffective until its approval quorum is reached", async () => {
  if (!process.env.DATABASE_URL) return;

  const seedPool = createPool();
  await runMigrations(seedPool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const requesterId = randomUUID();
  const approver1Id = randomUUID();
  const approver2Id = randomUUID();

  await seedPool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'API Exception Test', $2, 'active')`,
    [organizationId, `api-exception-${organizationId}`],
  );

  await seedPool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status
     ) VALUES ($1, $2, 'system', 'API System', 'active')`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [requesterId, "Requester"],
    [approver1Id, "Approver One"],
    [approver2Id, "Approver Two"],
  ]) {
    await seedPool.query(
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

  const app = await buildApp();

  try {
    const createResponse = await app.inject({
      method: "POST",
      url: "/v1/exceptions",
      payload: {
        organizationId,
        resourceId,
        kind: "waiver",
        requestedByPrincipalId: requesterId,
        justification: "Temporary migration waiver",
        validUntil: new Date(
          Date.now() + 3_600_000,
        ).toISOString(),
        approvalQuorum: 2,
        eligibleApproverPrincipalIds: [
          approver1Id,
          approver2Id,
        ],
        scope: {
          subsystem: "migration-target",
        },
      },
    });

    assert.equal(createResponse.statusCode, 201);
    const created = createResponse.json();
    const exceptionId = created.exception.id;
    assert.equal(created.exception.status, "requested");

    const first = await app.inject({
      method: "POST",
      url: `/v1/exceptions/${exceptionId}/decisions`,
      payload: {
        principalId: approver1Id,
        decision: "approve",
      },
    });

    assert.equal(first.statusCode, 200);
    assert.equal(first.json().exception.status, "requested");

    const beforeQuorum = await app.inject({
      method: "GET",
      url: `/v1/exceptions/${exceptionId}/effectiveness`,
    });

    assert.deepEqual(beforeQuorum.json(), {
      effective: false,
      reason: "requested",
    });

    const second = await app.inject({
      method: "POST",
      url: `/v1/exceptions/${exceptionId}/decisions`,
      payload: {
        principalId: approver2Id,
        decision: "approve",
      },
    });

    assert.equal(second.statusCode, 200);
    assert.equal(second.json().exception.status, "approved");

    const effective = await app.inject({
      method: "GET",
      url: `/v1/exceptions/${exceptionId}/effectiveness`,
    });

    assert.deepEqual(effective.json(), {
      effective: true,
      reason: "approved",
    });
  } finally {
    await app.close();
    await seedPool.end();
  }
});
