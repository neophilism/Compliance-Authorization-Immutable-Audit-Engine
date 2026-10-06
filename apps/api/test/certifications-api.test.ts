import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import { buildApp } from "../src/app.js";

const RULESET = {
  schemaVersion: "1",
  id: "api-certification-rules",
  version: "1",
  title: "API Certification Rules",
  rules: [
    {
      id: "control-enabled",
      title: "Control must be enabled",
      severity: "high",
      require: {
        field: "resource.attributes.controlEnabled",
        operator: "equals",
        value: true,
      },
    },
  ],
};

test("API issues a certificate, verifies it publicly, and automatically suspends it after a material failed check", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const issuerId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Certification API Test', $2, 'active')`,
    [
      organizationId,
      `certification-api-${organizationId}`,
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
       $1, $2, 'system', 'Certification API System',
       'active', '{"controlEnabled":true}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  await pool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES ($1, $2, 'user', 'Certification Issuer', 'active')`,
    [issuerId, organizationId],
  );

  const app = await buildApp();

  try {
    const passingCheck = await app.inject({
      method: "POST",
      url: "/v1/checks/run",
      payload: {
        organizationId,
        resourceId,
        requestedByPrincipalId: issuerId,
        ruleSet: RULESET,
      },
    });

    assert.equal(passingCheck.statusCode, 201);
    assert.equal(
      passingCheck.json().check.status,
      "passed",
    );

    const issue = await app.inject({
      method: "POST",
      url: "/v1/certifications",
      payload: {
        organizationId,
        resourceId,
        certificationType: "api-baseline",
        supportingCheckId:
          passingCheck.json().check.id,
        issuedByPrincipalId: issuerId,
        validitySeconds: 3600,
        criteria: {
          ruleSetId: "api-certification-rules",
          ruleSetVersion: "1",
          blockingFindingSeverities: [],
          materialFailureSeverities: [
            "high",
            "critical",
          ],
        },
      },
    });

    assert.equal(issue.statusCode, 201);
    const certification =
      issue.json().certification;
    assert.equal(certification.status, "active");
    assert.ok(certification.artifact);
    assert.ok(certification.publicArtifact);

    const verify = await app.inject({
      method: "GET",
      url:
        `/v1/public/certifications/verify/${certification.verificationCode}`,
    });

    assert.equal(verify.statusCode, 200);
    assert.equal(verify.json().valid, true);
    assert.equal(
      verify.json().effectiveStatus,
      "active",
    );

    await pool.query(
      `UPDATE resources
       SET attributes = '{"controlEnabled":false}'::jsonb
       WHERE id = $1`,
      [resourceId],
    );

    const failedCheck = await app.inject({
      method: "POST",
      url: "/v1/checks/run",
      payload: {
        organizationId,
        resourceId,
        requestedByPrincipalId: issuerId,
        ruleSet: RULESET,
      },
    });

    assert.equal(failedCheck.statusCode, 201);
    assert.equal(
      failedCheck.json().check.status,
      "failed",
    );

    const afterFailure = await app.inject({
      method: "GET",
      url:
        `/v1/certifications/${certification.id}`,
    });

    assert.equal(afterFailure.statusCode, 200);
    assert.equal(
      afterFailure.json().certification.status,
      "suspended",
    );
    assert.equal(
      afterFailure.json().certification.suspensionCheckId,
      failedCheck.json().check.id,
    );

    const invalidVerification = await app.inject({
      method: "GET",
      url:
        `/v1/public/certifications/verify/${certification.verificationCode}`,
    });

    assert.equal(
      invalidVerification.json().valid,
      false,
    );
    assert.equal(
      invalidVerification.json().effectiveStatus,
      "suspended",
    );

    await pool.query(
      `UPDATE resources
       SET attributes = '{"controlEnabled":true}'::jsonb
       WHERE id = $1`,
      [resourceId],
    );

    const recoveryCheck = await app.inject({
      method: "POST",
      url: "/v1/checks/run",
      payload: {
        organizationId,
        resourceId,
        requestedByPrincipalId: issuerId,
        ruleSet: RULESET,
      },
    });

    assert.equal(
      recoveryCheck.json().check.status,
      "passed",
    );

    const reinstate = await app.inject({
      method: "POST",
      url:
        `/v1/certifications/${certification.id}/reinstate`,
      payload: {
        supportingCheckId:
          recoveryCheck.json().check.id,
        principalId: issuerId,
        rationale:
          "Recovery check passed after remediation.",
      },
    });

    assert.equal(reinstate.statusCode, 200);
    assert.equal(
      reinstate.json().certification.status,
      "active",
    );

    const renewed = await app.inject({
      method: "POST",
      url:
        `/v1/certifications/${certification.id}/renew`,
      payload: {
        supportingCheckId:
          recoveryCheck.json().check.id,
        issuedByPrincipalId: issuerId,
        validitySeconds: 7200,
      },
    });

    assert.equal(renewed.statusCode, 201);
    assert.equal(
      renewed.json().certification.renewedFromCertificationId,
      certification.id,
    );

    const old = await app.inject({
      method: "GET",
      url:
        `/v1/certifications/${certification.id}`,
    });

    assert.equal(
      old.json().certification.status,
      "superseded",
    );
  } finally {
    await app.close();
    await pool.end();
  }
});
