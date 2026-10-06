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

const BOOTSTRAP =
  "traceability-bootstrap-secret-123456";

test("ruleset registry API preserves legal/source provenance and binds checks to registered versions", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId =
    randomUUID();
  const policyId =
    randomUUID();
  const principalId =
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
    `INSERT INTO policies(
       id, organization_id,
       key, title, status
     ) VALUES (
       $1, $2, 'trace-policy',
       'Trace Policy', 'active'
     )`,
    [policyId, organizationId],
  );
  await pool.query(
    `INSERT INTO principals(
       id, organization_id,
       kind, display_name, status
     ) VALUES (
       $1, $2, 'user',
       'Trace Administrator',
       'active'
     )`,
    [principalId, organizationId],
  );
  await pool.query(
    `INSERT INTO resources(
       id, organization_id,
       resource_type, name,
       status, attributes
     ) VALUES (
       $1, $2, 'generic',
       'Trace Resource',
       'active', '{}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  const app =
    await buildApp({
      securityMode: "enforce",
      bootstrapSecret:
        BOOTSTRAP,
    });

  try {
    const bootstrap =
      await app.inject({
        method: "POST",
        url:
          "/v1/security/bootstrap",
        headers: {
          "x-caiae-bootstrap-secret":
            BOOTSTRAP,
        },
        payload: {
          organizationId,
          principalId,
          credentialName:
            `trace-admin-${randomUUID()}`,
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

    const created =
      await app.inject({
        method: "POST",
        url: "/v1/rulesets",
        headers,
        payload: {
          organizationId,
          policyId,
          key:
            "api-trace-rules",
          effectiveFrom:
            "2026-01-01T00:00:00Z",
          authorities: [
            {
              authorityType:
                "statute",
              citation:
                "Example Authority 7",
              locator:
                "section 7",
            },
          ],
          ruleSet: {
            schemaVersion: "1",
            id:
              "api-trace-rules",
            version: "1",
            title:
              "API Trace Rules",
            rules: [
              {
                id: "active",
                title:
                  "Resource active",
                severity: "high",
                require: {
                  field:
                    "resource.status",
                  operator:
                    "equals",
                  value: "active",
                },
              },
            ],
          },
        },
      });

    assert.equal(
      created.statusCode,
      201,
    );
    const ruleSetId =
      created.json().id as string;
    const ruleSetHash =
      created.json()
        .definitionHash as string;

    const activate =
      await app.inject({
        method: "POST",
        url:
          `/v1/rulesets/${ruleSetId}/activate`,
        headers,
        payload: {
          effectiveFrom:
            "2026-01-01T00:00:00Z",
        },
      });

    assert.equal(
      activate.statusCode,
      200,
    );

    const manifest =
      await app.inject({
        method: "GET",
        url:
          `/v1/rulesets/${ruleSetId}/traceability`,
        headers,
      });

    assert.equal(
      manifest.statusCode,
      200,
    );
    assert.equal(
      manifest.json()
        .authorities[0]
        .authority.citation,
      "Example Authority 7",
    );

    const resolved =
      await app.inject({
        method: "GET",
        url:
          `/v1/organizations/${organizationId}/rulesets/resolve/api-trace-rules?at=2026-02-01T00%3A00%3A00Z`,
        headers,
      });

    assert.equal(
      resolved.statusCode,
      200,
    );
    assert.equal(
      resolved.json().id,
      ruleSetId,
    );

    const check =
      await app.inject({
        method: "POST",
        url: "/v1/checks/run",
        headers,
        payload: {
          organizationId,
          resourceId,
          registeredRuleSetId:
            ruleSetId,
          requestedByPrincipalId:
            principalId,
          evaluatedAt:
            "2026-02-01T00:00:00Z",
        },
      });

    assert.equal(
      check.statusCode,
      201,
    );
    assert.equal(
      check.json().check
        .ruleSetId,
      ruleSetId,
    );
    assert.equal(
      check.json().check
        .ruleSetHash,
      ruleSetHash,
    );
    assert.equal(
      check.json().check
        .ruleSetProvenance
        .registrationMode,
      "registered",
    );

    const openapi =
      await app.inject({
        method: "GET",
        url: "/openapi.json",
      });
    const document =
      openapi.json();

    assert.ok(
      document.paths[
        "/v1/rulesets/{id}/traceability"
      ],
    );
    assert.deepEqual(
      document.paths[
        "/v1/rulesets/{id}/traceability"
      ].get.security,
      [
        {
          operatorBearer: [],
        },
      ],
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
  } finally {
    await app.close();
    await pool.end();
  }
});
