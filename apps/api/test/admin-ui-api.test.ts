import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import { buildApp } from "../src/app.js";

test("admin read endpoints expose active principals and authorization queues with filters", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const requesterId = randomUUID();
  const approverId = randomUUID();
  const inactiveId = randomUUID();
  const resourceId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Admin UI Test', $2, 'active'
     )`,
    [
      organizationId,
      `admin-ui-${organizationId}`,
    ],
  );

  for (const [id, name, status] of [
    [requesterId, "Requester", "active"],
    [approverId, "Approver", "active"],
    [inactiveId, "Inactive", "inactive"],
  ]) {
    await pool.query(
      `INSERT INTO principals(
         id,
         organization_id,
         kind,
         display_name,
         status
       ) VALUES (
         $1, $2, 'user', $3, $4
       )`,
      [
        id,
        organizationId,
        name,
        status,
      ],
    );
  }

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       attributes
     ) VALUES (
       $1, $2, 'system',
       'Admin UI System',
       'active',
       '{}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  const app = await buildApp();

  try {
    const principals = await app.inject({
      method: "GET",
      url:
        `/v1/organizations/${organizationId}/principals?status=active&kind=user`,
    });

    assert.equal(
      principals.statusCode,
      200,
    );
    assert.deepEqual(
      principals
        .json()
        .map(
          (principal: any) =>
            principal.displayName,
        )
        .sort(),
      ["Approver", "Requester"],
    );

    const created = await app.inject({
      method: "POST",
      url: "/v1/authorizations",
      payload: {
        organizationId,
        resourceId,
        authorizationType:
          "deployment-approval",
        requestedByPrincipalId:
          requesterId,
        approvalQuorum: 1,
        eligibleApproverPrincipalIds: [
          approverId,
        ],
      },
    });

    assert.equal(
      created.statusCode,
      201,
    );
    const authorizationId =
      created.json().authorization.id;

    const queue = await app.inject({
      method: "GET",
      url:
        `/v1/organizations/${organizationId}/authorizations?status=pending&resourceId=${resourceId}`,
    });

    assert.equal(queue.statusCode, 200);
    assert.equal(queue.json().length, 1);
    assert.equal(
      queue.json()[0].id,
      authorizationId,
    );
    assert.equal(
      queue.json()[0].approvalCount,
      0,
    );
    assert.equal(
      queue.json()[0]
        .eligibleApproverCount,
      1,
    );

    const decision = await app.inject({
      method: "POST",
      url:
        `/v1/authorizations/${authorizationId}/decisions`,
      payload: {
        principalId: approverId,
        decision: "approve",
        rationale:
          "Reference console approval",
      },
    });

    assert.equal(decision.statusCode, 200);

    const approved = await app.inject({
      method: "GET",
      url:
        `/v1/organizations/${organizationId}/authorizations?status=approved`,
    });

    assert.equal(
      approved.statusCode,
      200,
    );
    assert.equal(
      approved.json()[0]
        .approvalCount,
      1,
    );

    const openapi = await app.inject({
      method: "GET",
      url: "/openapi.json",
    });

    assert.ok(
      openapi.json().paths[
        "/v1/organizations/{organizationId}/principals"
      ],
    );
    assert.ok(
      openapi.json().paths[
        "/v1/organizations/{organizationId}/authorizations"
      ],
    );
  } finally {
    await app.close();
    await pool.end();
  }
});
