import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { buildApp } from "../src/app.js";

const FAILING_RULESET = {
  schemaVersion: "1",
  id: "api-finding-rules",
  version: "1",
  title: "API Finding Rules",
  rules: [
    {
      id: "control-enabled",
      title: "Control must be enabled",
      description: "The API test control must be enabled.",
      severity: "high",
      require: {
        field: "resource.attributes.controlEnabled",
        operator: "equals",
        value: true,
      },
    },
  ],
};

test("failed API check automatically opens a finding that can be remediated, closed, and reopened", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const actorId = randomUUID();
  const ownerId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Finding API Test', $2, 'active')`,
    [organizationId, `finding-api-${organizationId}`],
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
       $1, $2, 'system', 'Finding API System', 'active',
       '{"controlEnabled":false}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [actorId, "Finding API Actor"],
    [ownerId, "Finding API Owner"],
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

  const app = await buildApp();

  try {
    const check = await app.inject({
      method: "POST",
      url: "/v1/checks/run",
      payload: {
        organizationId,
        resourceId,
        requestedByPrincipalId: actorId,
        ruleSet: FAILING_RULESET,
      },
    });

    assert.equal(check.statusCode, 201);
    assert.equal(check.json().check.status, "failed");

    const list = await app.inject({
      method: "GET",
      url:
        `/v1/organizations/${organizationId}/resources/${resourceId}/findings`,
    });

    assert.equal(list.statusCode, 200);
    assert.equal(list.json().length, 1);
    const findingId = list.json()[0].id;

    const acknowledge = await app.inject({
      method: "POST",
      url: `/v1/findings/${findingId}/acknowledge`,
      payload: {
        principalId: actorId,
      },
    });
    assert.equal(acknowledge.statusCode, 200);
    assert.equal(
      acknowledge.json().finding.status,
      "acknowledged",
    );

    const assign = await app.inject({
      method: "POST",
      url: `/v1/findings/${findingId}/owner`,
      payload: {
        principalId: actorId,
        ownerPrincipalId: ownerId,
      },
    });
    assert.equal(assign.statusCode, 200);
    assert.equal(
      assign.json().finding.ownerPrincipalId,
      ownerId,
    );

    const remediationResponse = await app.inject({
      method: "POST",
      url:
        `/v1/findings/${findingId}/remediations`,
      payload: {
        createdByPrincipalId: actorId,
        ownerPrincipalId: ownerId,
        plan: "Enable and verify the failed control.",
        dueAt: new Date(
          Date.now() + 3_600_000,
        ).toISOString(),
        warningWindowSeconds: 600,
      },
    });

    assert.equal(remediationResponse.statusCode, 201);
    const remediationId =
      remediationResponse.json().remediations[0].id;
    assert.ok(
      remediationResponse.json().remediations[0].deadlineId,
    );

    for (const [path, principalId] of [
      ["start", ownerId],
      ["submit", ownerId],
    ]) {
      const response = await app.inject({
        method: "POST",
        url: `/v1/remediations/${remediationId}/${path}`,
        payload: { principalId },
      });
      assert.equal(response.statusCode, 200);
    }

    const verify = await app.inject({
      method: "POST",
      url:
        `/v1/remediations/${remediationId}/verify`,
      payload: {
        principalId: actorId,
        note: "Verified by API test.",
      },
    });
    assert.equal(verify.statusCode, 200);
    assert.equal(
      verify.json().finding.status,
      "resolved",
    );

    const close = await app.inject({
      method: "POST",
      url: `/v1/findings/${findingId}/close`,
      payload: { principalId: actorId },
    });
    assert.equal(close.statusCode, 200);
    assert.equal(close.json().finding.status, "closed");

    const reopen = await app.inject({
      method: "POST",
      url: `/v1/findings/${findingId}/reopen`,
      payload: { principalId: actorId },
    });
    assert.equal(reopen.statusCode, 200);
    assert.equal(reopen.json().finding.status, "open");

    const syncAgain = await app.inject({
      method: "POST",
      url:
        `/v1/checks/${check.json().check.id}/findings/sync`,
      payload: {},
    });
    assert.equal(syncAgain.statusCode, 200);
    assert.equal(syncAgain.json().findings.length, 1);
  } finally {
    await app.close();
    await pool.end();
  }
});
