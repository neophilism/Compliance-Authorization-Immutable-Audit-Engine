import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { buildApp } from "../src/app.js";

test("authorization API enforces quorum before becoming effective", async () => {
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
     VALUES ($1, 'API Authorization Test', $2, 'active')`,
    [organizationId, `api-auth-${organizationId}`],
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
      url: "/v1/authorizations",
      payload: {
        organizationId,
        resourceId,
        authorizationType: "api-controlled-action",
        requestedByPrincipalId: requesterId,
        approvalQuorum: 2,
        eligibleApproverPrincipalIds: [
          approver1Id,
          approver2Id,
        ],
        validUntil: new Date(
          Date.now() + 3_600_000,
        ).toISOString(),
      },
    });

    assert.equal(createResponse.statusCode, 201);
    const created = createResponse.json();
    const authorizationId = created.authorization.id;
    assert.equal(created.authorization.status, "pending");

    const firstDecision = await app.inject({
      method: "POST",
      url: `/v1/authorizations/${authorizationId}/decisions`,
      payload: {
        principalId: approver1Id,
        decision: "approve",
      },
    });

    assert.equal(firstDecision.statusCode, 200);
    assert.equal(firstDecision.json().authorization.status, "pending");

    const pendingEffectiveness = await app.inject({
      method: "GET",
      url: `/v1/authorizations/${authorizationId}/effectiveness`,
    });

    assert.equal(pendingEffectiveness.statusCode, 200);
    assert.deepEqual(pendingEffectiveness.json(), {
      effective: false,
      reason: "pending",
    });

    const secondDecision = await app.inject({
      method: "POST",
      url: `/v1/authorizations/${authorizationId}/decisions`,
      payload: {
        principalId: approver2Id,
        decision: "approve",
      },
    });

    assert.equal(secondDecision.statusCode, 200);
    assert.equal(
      secondDecision.json().authorization.status,
      "approved",
    );

    const approvedEffectiveness = await app.inject({
      method: "GET",
      url: `/v1/authorizations/${authorizationId}/effectiveness`,
    });

    assert.equal(approvedEffectiveness.statusCode, 200);
    assert.deepEqual(approvedEffectiveness.json(), {
      effective: true,
      reason: "approved",
    });
  } finally {
    await app.close();
    await seedPool.end();
  }
});
