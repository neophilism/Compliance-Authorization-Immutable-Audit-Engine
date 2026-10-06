import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import { buildApp } from "../src/app.js";

const SECRET =
  "traceability-bootstrap-secret-1234";

test("registered ruleset revision propagates source traceability into checks and reports", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);
  const organizationId =
    randomUUID();
  const principalId =
    randomUUID();
  const policyId =
    randomUUID();
  const resourceId =
    randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Traceability API',
       $2, 'active'
     )`,
    [
      organizationId,
      `trace-api-${organizationId}`,
    ],
  );
  await pool.query(
    `INSERT INTO principals(
       id, organization_id, kind,
       display_name, status
     ) VALUES (
       $1, $2, 'user',
       'Traceability Admin',
       'active'
     )`,
    [principalId, organizationId],
  );
  await pool.query(
    `INSERT INTO policies(
       id, organization_id, key,
       title, status
     ) VALUES (
       $1, $2, 'policy',
       'Traceability Policy',
       'active'
     )`,
    [policyId, organizationId],
  );
  await pool.query(
    `INSERT INTO resources(
       id, organization_id,
       resource_type, name,
       status, attributes
     ) VALUES (
       $1, $2, 'generic',
       'Traceable Resource',
       'active', '{}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  const app = await buildApp({
    securityMode: "enforce",
    bootstrapSecret: SECRET,
  });

  try {
    const bootstrap =
      await app.inject({
        method: "POST",
        url: "/v1/security/bootstrap",
        headers: {
          "x-caiae-bootstrap-secret":
            SECRET,
        },
        payload: {
          organizationId,
          principalId,
          credentialName:
            "trace-admin",
        },
      });
    assert.equal(
      bootstrap.statusCode,
      201,
    );
    const headers = {
      authorization:
        `Bearer ${bootstrap.json().token}`,
    };

    const authority =
      await app.inject({
        method: "POST",
        url:
          "/v1/authority-sources",
        headers,
        payload: {
          organizationId,
          sourceType: "regulation",
          jurisdiction: "generic",
          citation:
            "GEN-RULE § 12(a)",
          title:
            "Generic Regulatory Source",
          uri:
            "https://example.invalid/source",
        },
      });
    assert.equal(
      authority.statusCode,
      201,
    );

    const ruleSet = {
      schemaVersion: "1",
      id: "traceable-rules",
      version: "2026.1",
      title:
        "Traceable Rules",
      rules: [
        {
          id: "active",
          title:
            "Resource must be active",
          severity: "high",
          require: {
            field:
              "resource.status",
            operator: "equals",
            value: "active",
          },
        },
      ],
    };

    const registered =
      await app.inject({
        method: "POST",
        url:
          "/v1/rule-set-revisions",
        headers,
        payload: {
          organizationId,
          policyId,
          ruleSet,
          authorityLinks: [
            {
              authoritySourceId:
                authority.json().id,
              relation:
                "implements",
              locator: "§ 12(a)(1)",
            },
          ],
        },
      });
    assert.equal(
      registered.statusCode,
      201,
    );
    const revision =
      registered.json();

    const activated =
      await app.inject({
        method: "POST",
        url:
          `/v1/rule-set-revisions/${revision.id}/activate`,
        headers,
        payload: {},
      });
    assert.equal(
      activated.statusCode,
      200,
    );

    const check =
      await app.inject({
        method: "POST",
        url: "/v1/checks/run",
        headers,
        payload: {
          organizationId,
          resourceId,
          ruleSet,
          ruleSetRevisionId:
            revision.id,
          requestedByPrincipalId:
            principalId,
          evaluatedAt:
            "2026-10-06T13:00:00Z",
        },
      });
    assert.equal(
      check.statusCode,
      201,
    );
    assert.equal(
      check.json().check
        .ruleSetRevisionId,
      revision.id,
    );

    const report =
      await app.inject({
        method: "GET",
        url:
          `/v1/reports/organizations/${organizationId}/resources/${resourceId}/compliance`,
        headers,
      });
    assert.equal(
      report.statusCode,
      200,
    );
    const reportCheck =
      report.json().checks[0];
    assert.equal(
      reportCheck.ruleSetRevisionId,
      revision.id,
    );
    assert.equal(
      reportCheck.ruleSetContentHash,
      revision.contentHash,
    );
    assert.equal(
      reportCheck.authoritySources[0]
        .citation,
      "GEN-RULE § 12(a)",
    );
    assert.equal(
      reportCheck.authoritySources[0]
        .locator,
      "§ 12(a)(1)",
    );

    const changed = {
      ...ruleSet,
      title: "Tampered Rules",
    };
    const mismatch =
      await app.inject({
        method: "POST",
        url: "/v1/checks/run",
        headers,
        payload: {
          organizationId,
          resourceId,
          ruleSet: changed,
          ruleSetRevisionId:
            revision.id,
          requestedByPrincipalId:
            principalId,
        },
      });
    assert.equal(
      mismatch.statusCode,
      400,
    );
  } finally {
    await app.close();
    await pool.end();
  }
});
