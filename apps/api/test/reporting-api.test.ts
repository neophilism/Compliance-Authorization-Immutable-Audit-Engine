import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import { buildApp } from "../src/app.js";

test("reporting API serves JSON CSV and human-readable compliance reports", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const checkId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Reporting API Test', $2, 'active'
     )`,
    [
      organizationId,
      `reporting-api-${organizationId}`,
    ],
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
       $1, $2, 'system',
       'Reporting API System',
       'active',
       '{}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  await pool.query(
    `INSERT INTO checks(
       id,
       organization_id,
       resource_id,
       status,
       trigger,
       evaluated_at,
       completed_at,
       rule_set_snapshot,
       context_snapshot,
       evidence_trace,
       result,
       metadata
     ) VALUES (
       $1, $2, $3,
       'passed',
       'manual',
       '2026-10-05T10:00:00Z',
       '2026-10-05T10:00:01Z',
       '{"id":"api-report","version":"1"}'::jsonb,
       '{}'::jsonb,
       '[]'::jsonb,
       '{"counts":{"pass":1,"fail":0,"unknown":0,"notApplicable":0}}'::jsonb,
       '{}'::jsonb
     )`,
    [
      checkId,
      organizationId,
      resourceId,
    ],
  );

  const ledger = new AuditLedger(pool);
  await ledger.append({
    organizationId,
    aggregateType: "check",
    aggregateId: checkId,
    eventType: "check.completed",
    occurredAt:
      "2026-10-05T10:00:01Z",
    payload: {},
  });

  const app = await buildApp();

  try {
    const json = await app.inject({
      method: "GET",
      url:
        `/v1/reports/organizations/${organizationId}/compliance?asOf=2026-10-05T12%3A00%3A00Z`,
    });

    assert.equal(json.statusCode, 200);
    assert.equal(
      json.json().summary.checks.total,
      1,
    );
    assert.equal(
      json.json().summary.audit.allChainsValid,
      true,
    );

    const resourceJson = await app.inject({
      method: "GET",
      url:
        `/v1/reports/organizations/${organizationId}/resources/${resourceId}/compliance`,
    });

    assert.equal(
      resourceJson.statusCode,
      200,
    );
    assert.equal(
      resourceJson.json().resource.id,
      resourceId,
    );

    const csv = await app.inject({
      method: "GET",
      url:
        `/v1/reports/organizations/${organizationId}/compliance?format=csv`,
    });

    assert.equal(csv.statusCode, 200);
    assert.match(
      csv.headers["content-type"] ?? "",
      /^text\/csv/,
    );
    assert.match(
      csv.body,
      /^section,resource_id,entity_type,/,
    );

    const text = await app.inject({
      method: "GET",
      url:
        `/v1/reports/organizations/${organizationId}/compliance?format=text`,
    });

    assert.equal(text.statusCode, 200);
    assert.match(
      text.headers["content-type"] ?? "",
      /^text\/markdown/,
    );
    assert.match(
      text.body,
      /# Compliance Report/,
    );

    const invalid = await app.inject({
      method: "GET",
      url:
        `/v1/reports/organizations/${organizationId}/compliance?format=pdf`,
    });

    assert.equal(invalid.statusCode, 400);

    const missing = await app.inject({
      method: "GET",
      url:
        `/v1/reports/organizations/${organizationId}/resources/${randomUUID()}/compliance`,
    });

    assert.equal(missing.statusCode, 404);
  } finally {
    await app.close();
    await pool.end();
  }
});
