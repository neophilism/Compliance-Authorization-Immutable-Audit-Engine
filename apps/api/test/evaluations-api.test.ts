import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { EvidenceService } from "@caiae/evidence";
import { buildApp } from "../src/app.js";

const RULESET = {
  schemaVersion: "1",
  id: "api-evaluation",
  version: "1",
  title: "API Evaluation",
  rules: [
    {
      id: "control-enabled",
      title: "Control enabled",
      severity: "high",
      require: {
        field: "resource.attributes.controlEnabled",
        operator: "equals",
        value: true,
      },
      requiredEvidenceTypes: ["control-evidence"],
    },
  ],
};

test("evaluation API runs manual, event, batch, and schedule workflows", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resource1 = randomUUID();
  const resource2 = randomUUID();
  const principalId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Evaluation API Test', $2, 'active')`,
    [organizationId, `evaluation-api-${organizationId}`],
  );

  await pool.query(
    `INSERT INTO resources(
       id, organization_id, resource_type, name, status, attributes
     ) VALUES
       ($1, $3, 'system', 'System One', 'active',
        '{"controlEnabled":true}'::jsonb),
       ($2, $3, 'system', 'System Two', 'active',
        '{"controlEnabled":false}'::jsonb)`,
    [resource1, resource2, organizationId],
  );

  await pool.query(
    `INSERT INTO principals(
       id, organization_id, kind, display_name, status
     ) VALUES ($1, $2, 'user', 'API Evaluator', 'active')`,
    [principalId, organizationId],
  );

  const evidence = new EvidenceService(pool);
  for (const resourceId of [resource1, resource2]) {
    await evidence.create({
      organizationId,
      resourceId,
      evidenceType: "control-evidence",
      title: "Control Evidence",
      submittedByPrincipalId: principalId,
    });
  }

  const app = await buildApp();

  try {
    const manual = await app.inject({
      method: "POST",
      url: "/v1/checks/run",
      payload: {
        organizationId,
        resourceId: resource1,
        requestedByPrincipalId: principalId,
        ruleSet: RULESET,
      },
    });

    assert.equal(manual.statusCode, 201);
    assert.equal(manual.json().check.status, "passed");

    const event = await app.inject({
      method: "POST",
      url: "/v1/checks/event",
      payload: {
        organizationId,
        resourceId: resource1,
        requestedByPrincipalId: principalId,
        ruleSet: RULESET,
        eventType: "system.changed",
        event: {
          source: "integration-test",
        },
      },
    });

    assert.equal(event.statusCode, 201);
    assert.equal(event.json().check.trigger, "event");

    const batch = await app.inject({
      method: "POST",
      url: "/v1/checks/batch",
      payload: {
        organizationId,
        resourceIds: [resource1, resource2],
        requestedByPrincipalId: principalId,
        ruleSet: RULESET,
      },
    });

    assert.equal(batch.statusCode, 201);
    assert.deepEqual(
      batch.json().checks.map(
        (item: any) => item.check.status,
      ),
      ["passed", "failed"],
    );

    const schedule = await app.inject({
      method: "POST",
      url: "/v1/evaluation-schedules",
      payload: {
        organizationId,
        resourceId: resource1,
        createdByPrincipalId: principalId,
        ruleSet: RULESET,
        intervalSeconds: 3600,
        nextRunAt: new Date(
          Date.now() + 60_000,
        ).toISOString(),
      },
    });

    assert.equal(schedule.statusCode, 201);
    assert.equal(schedule.json().schedule.active, true);

    const deactivate = await app.inject({
      method: "POST",
      url:
        `/v1/evaluation-schedules/${schedule.json().schedule.id}/active`,
      payload: {
        active: false,
        principalId,
      },
    });

    assert.equal(deactivate.statusCode, 200);
    assert.equal(
      deactivate.json().schedule.active,
      false,
    );
  } finally {
    await app.close();
    await pool.end();
  }
});
