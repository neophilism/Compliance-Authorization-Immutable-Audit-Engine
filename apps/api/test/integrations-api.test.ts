import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  API_ROUTE_MANIFEST,
} from "@caiae/integrations";
import { buildApp } from "../src/app.js";

const RULESET = {
  schemaVersion: "1",
  id: "integration-api-baseline",
  version: "1",
  title: "Integration API Baseline",
  rules: [
    {
      id: "resource-active",
      title: "Resource is active",
      severity: "high",
      require: {
        field: "resource.status",
        operator: "equals",
        value: "active",
      },
    },
  ],
};

test("external client can use the complete authenticated integration workflow", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const adminId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Integration API Organization', $2, 'active'
     )`,
    [
      organizationId,
      `integration-api-${organizationId}`,
    ],
  );

  await pool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES (
       $1, $2, 'user',
       'Integration API Administrator',
       'active'
     )`,
    [adminId, organizationId],
  );

  const app = await buildApp();

  try {
    const openapi =
      await app.inject({
        method: "GET",
        url: "/openapi.json",
      });

    assert.equal(
      openapi.statusCode,
      200,
    );
    const document =
      openapi.json();
    assert.equal(
      document.openapi,
      "3.1.0",
    );
    assert.ok(
      document.paths[
        "/v1/authorizations/{id}"
      ],
    );
    assert.ok(
      document.paths[
        "/v1/integration/resources"
      ],
    );
    assert.ok(
      document.components
        .securitySchemes
        .serviceBearer,
    );
    assert.equal(
      Object.keys(
        document.paths,
      ).length,
      new Set(
        API_ROUTE_MANIFEST.map(
          (entry) =>
            entry.path.replace(
              /:([A-Za-z0-9_]+)/g,
              "{$1}",
            ),
        ),
      ).size,
    );

    const serviceAccount =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/service-accounts",
        payload: {
          organizationId,
          displayName:
            "External Test Client",
          credentialName:
            `external-${randomUUID()}`,
          createdByPrincipalId:
            adminId,
          scopes: ["*"],
        },
      });

    assert.equal(
      serviceAccount.statusCode,
      201,
    );
    const issued =
      serviceAccount.json();
    const token = issued.token as string;
    const servicePrincipalId =
      issued.principal.id as string;
    const credentialId =
      issued.credential.id as string;

    const storedCredential =
      await pool.query(
        `SELECT token_hash
         FROM api_credentials
         WHERE id = $1`,
        [credentialId],
      );

    assert.notEqual(
      storedCredential.rows[0]
        ?.token_hash,
      token,
    );

    const unauthorized =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/resources",
      });

    assert.equal(
      unauthorized.statusCode,
      401,
    );

    const headers = {
      authorization:
        `Bearer ${token}`,
    };

    const create =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/resources",
        headers: {
          ...headers,
          "idempotency-key":
            "api-resource-1",
        },
        payload: {
          resourceType: "system",
          name:
            "External Alpha",
          externalRef:
            "external-alpha",
          attributes: {
            controlEnabled: true,
          },
        },
      });

    assert.equal(
      create.statusCode,
      201,
    );
    assert.equal(
      create.headers[
        "idempotency-replayed"
      ],
      "false",
    );
    const resourceId =
      create.json().id as string;

    const replay =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/resources",
        headers: {
          ...headers,
          "idempotency-key":
            "api-resource-1",
        },
        payload: {
          resourceType: "system",
          name:
            "External Alpha",
          externalRef:
            "external-alpha",
          attributes: {
            controlEnabled: true,
          },
        },
      });

    assert.equal(
      replay.statusCode,
      201,
    );
    assert.equal(
      replay.headers[
        "idempotency-replayed"
      ],
      "true",
    );
    assert.equal(
      replay.json().id,
      resourceId,
    );

    const conflict =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/resources",
        headers: {
          ...headers,
          "idempotency-key":
            "api-resource-1",
        },
        payload: {
          resourceType: "system",
          name:
            "Changed Input",
        },
      });

    assert.equal(
      conflict.statusCode,
      409,
    );

    const second =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/resources",
        headers: {
          ...headers,
          "idempotency-key":
            "api-resource-2",
        },
        payload: {
          resourceType: "system",
          name:
            "External Beta",
        },
      });
    assert.equal(second.statusCode, 201);

    const page1 =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/resources?limit=1",
        headers,
      });

    assert.equal(
      page1.statusCode,
      200,
    );
    assert.equal(
      page1.json().items.length,
      1,
    );
    assert.ok(
      page1.json().nextCursor,
    );

    const page2 =
      await app.inject({
        method: "GET",
        url:
          `/v1/integration/resources?limit=1&cursor=${encodeURIComponent(page1.json().nextCursor)}`,
        headers,
      });

    assert.equal(
      page2.statusCode,
      200,
    );
    assert.equal(
      page2.json().items.length,
      1,
    );

    const check =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/checks/run",
        headers: {
          ...headers,
          "idempotency-key":
            "api-check-1",
        },
        payload: {
          resourceId,
          ruleSet: RULESET,
        },
      });

    assert.equal(
      check.statusCode,
      201,
    );
    assert.equal(
      check.json().check.status,
      "passed",
    );

    const storedCheck =
      await pool.query(
        `SELECT requested_by_principal_id
         FROM checks
         WHERE id = $1`,
        [
          check.json().check.id,
        ],
      );

    assert.equal(
      storedCheck.rows[0]
        ?.requested_by_principal_id,
      servicePrincipalId,
    );

    const webhook =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/webhooks",
        headers,
        payload: {
          name:
            `api-hook-${randomUUID()}`,
          url:
            "https://example.invalid/hook",
          eventTypes: [
            "resource.created",
          ],
        },
      });

    assert.equal(
      webhook.statusCode,
      201,
    );
    assert.ok(
      webhook.json().signingSecret,
    );

    const third =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/resources",
        headers: {
          ...headers,
          "idempotency-key":
            "api-resource-3",
        },
        payload: {
          resourceType: "system",
          name:
            "External Gamma",
        },
      });
    assert.equal(third.statusCode, 201);

    const queued =
      await pool.query(
        `SELECT d.status
         FROM webhook_deliveries AS d
         INNER JOIN integration_events AS e
           ON e.id = d.event_id
         WHERE d.subscription_id = $1
           AND e.event_type = 'resource.created'`,
        [
          webhook.json()
            .subscription.id,
        ],
      );

    assert.equal(
      queued.rows.length,
      1,
    );
    assert.equal(
      queued.rows[0]?.status,
      "pending",
    );

    const events =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/events?eventType=resource.created",
        headers,
      });

    assert.equal(
      events.statusCode,
      200,
    );
    assert.ok(
      events.json().items.length >= 3,
    );

    const projection =
      await app.inject({
        method: "GET",
        url:
          `/v1/integration/resources/${resourceId}/registry-projection`,
        headers,
      });

    assert.equal(
      projection.statusCode,
      200,
    );
    assert.equal(
      projection.json()
        .latestCheck.status,
      "passed",
    );

    const findingId = randomUUID();
    await pool.query(
      `INSERT INTO findings(
         id,
         organization_id,
         resource_id,
         severity,
         status,
         title,
         description,
         opened_at,
         metadata
       ) VALUES (
         $1, $2, $3,
         'critical', 'open',
         'Integration API review',
         'Synthetic review trigger',
         now(), '{}'::jsonb
       )`,
      [
        findingId,
        organizationId,
        resourceId,
      ],
    );

    const caseTriggers =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/case-triggers",
        headers,
      });

    assert.equal(
      caseTriggers.statusCode,
      200,
    );
    assert.equal(
      caseTriggers
        .json()
        .some(
          (item: any) =>
            item.aggregateId ===
            findingId,
        ),
      true,
    );

    const imported =
      await app.inject({
        method: "POST",
        url:
          "/v1/integration/import/resources",
        headers: {
          ...headers,
          "idempotency-key":
            "api-import-1",
        },
        payload: {
          schemaVersion: "1",
          source:
            "registry-engine",
          items: [
            {
              externalId:
                "registry-import-1",
              resourceType:
                "system",
              name:
                "Imported Through API",
            },
          ],
        },
      });

    assert.equal(
      imported.statusCode,
      200,
    );
    assert.equal(
      imported.json().created,
      1,
    );

    const exported =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/export/resources",
        headers,
      });

    assert.equal(
      exported.statusCode,
      200,
    );
    assert.equal(
      exported.json()
        .schemaVersion,
      "1",
    );
    assert.ok(
      exported.json().items
        .length >= 4,
    );

    const credentials =
      await app.inject({
        method: "GET",
        url:
          `/v1/integration/organizations/${organizationId}/api-credentials`,
      });

    assert.equal(
      credentials.statusCode,
      200,
    );
    assert.equal(
      credentials
        .json()
        .some(
          (item: any) =>
            item.id === credentialId,
        ),
      true,
    );

    const revoke =
      await app.inject({
        method: "POST",
        url:
          `/v1/integration/api-credentials/${credentialId}/revoke`,
        payload: {
          principalId: adminId,
          reason:
            "End-to-end test complete",
        },
      });

    assert.equal(
      revoke.statusCode,
      200,
    );
    assert.equal(
      revoke.json().status,
      "revoked",
    );

    const afterRevoke =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/resources",
        headers,
      });

    assert.equal(
      afterRevoke.statusCode,
      401,
    );
  } finally {
    await app.close();
    await pool.end();
  }
});
