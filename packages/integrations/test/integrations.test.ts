import assert from "node:assert/strict";
import test from "node:test";
import {
  createHmac,
  randomUUID,
} from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  IntegrationError,
  IntegrationService,
} from "../src/index.js";

async function fixture(options: {
  fetchImpl?: typeof fetch;
} = {}) {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const adminId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Integration Test Organization', $2, 'active'
     )`,
    [
      organizationId,
      `integration-test-${organizationId}`,
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
       $1, $2, 'user', 'Integration Administrator', 'active'
     )`,
    [adminId, organizationId],
  );

  const service = new IntegrationService(
    pool,
    {
      webhookMasterSecret:
        "integration-test-master-secret",
      fetchImpl: options.fetchImpl,
      maxWebhookAttempts: 3,
    },
  );

  return {
    pool,
    service,
    organizationId,
    adminId,
  };
}

test("service credentials are returned once, hashed at rest, scoped, and revocable", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    const issued =
      await f.service.createServiceAccount({
        organizationId:
          f.organizationId,
        displayName:
          "Registry Connector",
        credentialName:
          "registry-primary",
        createdByPrincipalId:
          f.adminId,
        scopes: [
          "resources:read",
          "adapters:read",
        ],
      });

    assert.match(
      issued.token,
      /^caiae_[0-9a-f]{10}_[A-Za-z0-9_-]+$/,
    );
    assert.equal(
      issued.principal.status,
      "active",
    );
    assert.deepEqual(
      issued.credential.scopes,
      [
        "resources:read",
        "adapters:read",
      ],
    );

    const stored =
      await f.pool.query(
        `SELECT token_hash
         FROM api_credentials
         WHERE id = $1`,
        [issued.credential.id],
      );

    assert.notEqual(
      stored.rows[0]?.token_hash,
      issued.token,
    );
    assert.equal(
      String(
        stored.rows[0]?.token_hash,
      ).length,
      64,
    );

    const auth =
      await f.service.authenticate(
        issued.token,
        ["resources:read"],
      );
    assert.equal(
      auth.principal.id,
      issued.principal.id,
    );
    assert.notEqual(
      auth.credential.lastUsedAt,
      null,
    );

    await assert.rejects(
      f.service.authenticate(
        issued.token,
        ["checks:run"],
      ),
      (error: unknown) =>
        error instanceof
          IntegrationError &&
        error.code === "forbidden",
    );

    await f.service.revokeCredential({
      credentialId:
        issued.credential.id,
      principalId: f.adminId,
      reason:
        "Connector rotated",
    });

    await assert.rejects(
      f.service.authenticate(
        issued.token,
      ),
      (error: unknown) =>
        error instanceof
          IntegrationError &&
        error.code ===
          "unauthorized",
    );
  } finally {
    await f.pool.end();
  }
});

test("idempotent resource creation replays identical requests and rejects key reuse with different input", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    const issued =
      await f.service.createServiceAccount({
        organizationId:
          f.organizationId,
        displayName:
          "Resource Connector",
        credentialName:
          "resource-primary",
        createdByPrincipalId:
          f.adminId,
        scopes: [
          "resources:read",
          "resources:write",
          "events:read",
        ],
      });
    const auth =
      await f.service.authenticate(
        issued.token,
      );

    const first =
      await f.service.createResource(
        auth,
        "resource-create-1",
        {
          resourceType:
            "federal-system",
          name: "Alpha",
          externalRef:
            "registry-alpha",
          attributes: {
            sensitivity: "high",
          },
        },
      );

    assert.equal(
      first.replayed,
      false,
    );
    assert.equal(
      first.statusCode,
      201,
    );

    const replay =
      await f.service.createResource(
        auth,
        "resource-create-1",
        {
          resourceType:
            "federal-system",
          name: "Alpha",
          externalRef:
            "registry-alpha",
          attributes: {
            sensitivity: "high",
          },
        },
      );

    assert.equal(
      replay.replayed,
      true,
    );
    assert.equal(
      replay.body.id,
      first.body.id,
    );

    await assert.rejects(
      f.service.createResource(
        auth,
        "resource-create-1",
        {
          resourceType:
            "federal-system",
          name: "Different",
        },
      ),
      (error: unknown) =>
        error instanceof
          IntegrationError &&
        error.code === "conflict",
    );

    await f.service.createResource(
      auth,
      "resource-create-2",
      {
        resourceType:
          "federal-system",
        name: "Beta",
      },
    );

    const page1 =
      await f.service.listResources(
        auth,
        { limit: 1 },
      );
    assert.equal(
      page1.items.length,
      1,
    );
    assert.notEqual(
      page1.nextCursor,
      null,
    );

    const page2 =
      await f.service.listResources(
        auth,
        {
          limit: 1,
          cursor:
            page1.nextCursor,
        },
      );
    assert.equal(
      page2.items.length,
      1,
    );
    assert.notEqual(
      page2.items[0]?.id,
      page1.items[0]?.id,
    );

    const events =
      await f.service.listEvents(
        auth,
        {
          eventType:
            "resource.created",
        },
      );

    assert.equal(
      events.items.length,
      2,
    );
  } finally {
    await f.pool.end();
  }
});

test("audit outbox fans out subscribed events and webhook delivery is HMAC signed", async () => {
  if (!process.env.DATABASE_URL) return;

  const requests: Array<{
    url: string;
    headers: Record<string, string>;
    body: string;
  }> = [];

  const fakeFetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const headers =
      new Headers(init?.headers);
    requests.push({
      url: String(input),
      headers:
        Object.fromEntries(
          headers.entries(),
        ),
      body:
        String(init?.body ?? ""),
    });

    return new Response("", {
      status: 204,
    });
  }) as typeof fetch;

  const f = await fixture({
    fetchImpl: fakeFetch,
  });

  try {
    const issued =
      await f.service.createServiceAccount({
        organizationId:
          f.organizationId,
        displayName:
          "Webhook Connector",
        credentialName:
          "webhook-primary",
        createdByPrincipalId:
          f.adminId,
        scopes: [
          "resources:write",
          "webhooks:write",
          "webhooks:read",
          "events:read",
        ],
      });
    const auth =
      await f.service.authenticate(
        issued.token,
      );

    const webhook =
      await f.service.createWebhookSubscription(
        auth,
        {
          name:
            "resource-events",
          url:
            "https://example.invalid/caiae-hook",
          eventTypes: [
            "resource.created",
          ],
        },
      );

    await f.service.createResource(
      auth,
      "webhook-resource-1",
      {
        resourceType:
          "system",
        name:
          "Webhook Resource",
      },
    );

    const deliveries =
      await f.pool.query(
        `SELECT d.*
         FROM webhook_deliveries AS d
         INNER JOIN integration_events AS e
           ON e.id = d.event_id
         WHERE d.subscription_id = $1
           AND e.event_type = 'resource.created'`,
        [
          webhook.subscription.id,
        ],
      );

    assert.equal(
      deliveries.rows.length,
      1,
    );
    assert.equal(
      deliveries.rows[0]?.status,
      "pending",
    );

    const sweep =
      await f.service.deliverPendingWebhooks(
        10,
      );

    assert.equal(
      sweep.claimed,
      1,
    );
    assert.equal(
      sweep.succeeded,
      1,
    );
    assert.equal(
      sweep.failed,
      0,
    );
    assert.equal(
      requests.length,
      1,
    );

    const request =
      requests[0]!;
    const timestamp =
      request.headers[
        "x-caiae-timestamp"
      ]!;
    const expected =
      createHmac(
        "sha256",
        webhook.signingSecret,
      )
        .update(
          `${timestamp}.${request.body}`,
          "utf8",
        )
        .digest("hex");

    assert.equal(
      request.headers[
        "x-caiae-signature"
      ],
      `sha256=${expected}`,
    );

    const delivered =
      await f.pool.query(
        `SELECT status, attempts
         FROM webhook_deliveries
         WHERE id = $1`,
        [
          deliveries.rows[0].id,
        ],
      );

    assert.equal(
      delivered.rows[0]?.status,
      "succeeded",
    );
    assert.equal(
      Number(
        delivered.rows[0]?.attempts,
      ),
      1,
    );
  } finally {
    await f.pool.end();
  }
});

test("resource import is mapping-idempotent, export is portable, and adapters expose neutral projections", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();

  try {
    const issued =
      await f.service.createServiceAccount({
        organizationId:
          f.organizationId,
        displayName:
          "Cross Engine Connector",
        credentialName:
          "cross-engine",
        createdByPrincipalId:
          f.adminId,
        scopes: [
          "imports:write",
          "exports:read",
          "adapters:read",
          "checks:run",
        ],
      });
    const auth =
      await f.service.authenticate(
        issued.token,
      );

    const firstImport =
      await f.service.importResources(
        auth,
        "import-1",
        {
          schemaVersion: "1",
          source: "registry-engine",
          items: [
            {
              externalId:
                "registry-42",
              resourceType:
                "system",
              name:
                "Imported System",
              externalRef:
                "registry-42",
            },
          ],
        },
      );

    assert.equal(
      firstImport.body.created,
      1,
    );

    const replay =
      await f.service.importResources(
        auth,
        "import-1",
        {
          schemaVersion: "1",
          source: "registry-engine",
          items: [
            {
              externalId:
                "registry-42",
              resourceType:
                "system",
              name:
                "Imported System",
              externalRef:
                "registry-42",
            },
          ],
        },
      );

    assert.equal(
      replay.replayed,
      true,
    );

    const secondImport =
      await f.service.importResources(
        auth,
        "import-2",
        {
          schemaVersion: "1",
          source: "registry-engine",
          items: [
            {
              externalId:
                "registry-42",
              resourceType:
                "system",
              name:
                "Imported System Updated",
              externalRef:
                "registry-42",
            },
          ],
        },
      );

    assert.equal(
      secondImport.body.updated,
      1,
    );
    assert.equal(
      secondImport.body.resourceIds[0],
      firstImport.body.resourceIds[0],
    );

    const resourceId =
      firstImport.body.resourceIds[0]!;

    const check =
      await f.service.runCheck(
        auth,
        "check-1",
        {
          resourceId,
          ruleSet: {
            schemaVersion: "1",
            id: "adapter-baseline",
            version: "1",
            title: "Adapter Baseline",
            rules: [
              {
                id: "name-exists",
                title:
                  "Name exists",
                severity: "low",
                require: {
                  field:
                    "resource.name",
                  operator:
                    "exists",
                },
              },
            ],
          },
        },
      );

    assert.equal(
      (check.body as any).check.status,
      "passed",
    );

    const projection =
      await f.service.getRegistryProjection(
        auth,
        resourceId,
      );

    assert.equal(
      projection.resource.name,
      "Imported System Updated",
    );
    assert.equal(
      projection.latestCheck?.status,
      "passed",
    );

    const findingId = randomUUID();
    await f.pool.query(
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
         $1, $2, $3, 'critical', 'open',
         'Human review required',
         'Synthetic integration test finding',
         now(), '{}'::jsonb
       )`,
      [
        findingId,
        f.organizationId,
        resourceId,
      ],
    );

    const triggers =
      await f.service.listCaseTriggers(
        auth,
      );

    assert.equal(
      triggers.some(
        (trigger) =>
          trigger.aggregateId ===
            findingId &&
          trigger.triggerType ===
            "finding_human_review",
      ),
      true,
    );

    const exported =
      await f.service.exportResources(
        auth,
      );

    assert.equal(
      exported.schemaVersion,
      "1",
    );
    assert.equal(
      exported.items.some(
        (item) =>
          item.resource.id ===
          resourceId,
      ),
      true,
    );
  } finally {
    await f.pool.end();
  }
});
