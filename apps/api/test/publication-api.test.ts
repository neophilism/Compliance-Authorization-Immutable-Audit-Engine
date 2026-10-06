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

test("publication APIs expose only published snapshots and remain OpenAPI-complete", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId =
    randomUUID();
  const principalId =
    randomUUID();
  const resourceId =
    randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Publication API Organization',
       $2, 'active'
     )`,
    [
      organizationId,
      `publication-api-${organizationId}`,
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
       'Publisher', 'active'
     )`,
    [
      principalId,
      organizationId,
    ],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       attributes,
       metadata
     ) VALUES (
       $1, $2, 'generic',
       'Publication API Resource',
       'active',
       '{"private":"attribute"}'::jsonb,
       '{"private":"metadata"}'::jsonb
     )`,
    [
      resourceId,
      organizationId,
    ],
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
    assert.ok(
      document.paths[
        "/v1/publications/publish"
      ],
    );
    assert.ok(
      document.paths[
        "/v1/public/publications/{id}"
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

    const before =
      await app.inject({
        method: "GET",
        url:
          `/v1/public/organizations/${organizationId}/publications`,
      });
    assert.equal(
      before.statusCode,
      200,
    );
    assert.deepEqual(
      before.json(),
      [],
    );

    const preview =
      await app.inject({
        method: "POST",
        url:
          "/v1/publications/preview",
        payload: {
          organizationId,
          subjectType:
            "resource",
          subjectId: resourceId,
          projectionType:
            "resource_compliance",
          asOf:
            "2026-10-06T12:00:00Z",
        },
      });
    assert.equal(
      preview.statusCode,
      200,
    );
    const previewBody =
      preview.json();
    assert.equal(
      JSON.stringify(
        previewBody,
      ).includes(
        "attribute",
      ),
      false,
    );
    assert.equal(
      JSON.stringify(
        previewBody,
      ).includes(
        "metadata",
      ),
      false,
    );

    const publish =
      await app.inject({
        method: "POST",
        url:
          "/v1/publications/publish",
        payload: {
          organizationId,
          subjectType:
            "resource",
          subjectId: resourceId,
          projectionType:
            "resource_compliance",
          principalId,
          asOf:
            "2026-10-06T12:00:00Z",
        },
      });
    assert.equal(
      publish.statusCode,
      200,
    );
    const published =
      publish.json();

    const publicRead =
      await app.inject({
        method: "GET",
        url:
          `/v1/public/publications/${published.id}`,
      });
    assert.equal(
      publicRead.statusCode,
      200,
    );
    assert.equal(
      publicRead.json().projection
        .resource.id,
      resourceId,
    );
    assert.equal(
      "policy" in
        publicRead.json(),
      false,
    );
    assert.equal(
      "publishedByPrincipalId" in
        publicRead.json(),
      false,
    );

    const unpublish =
      await app.inject({
        method: "POST",
        url:
          "/v1/publications/unpublish",
        payload: {
          organizationId,
          subjectType:
            "resource",
          subjectId: resourceId,
          projectionType:
            "resource_compliance",
          principalId,
          reason: "test",
        },
      });
    assert.equal(
      unpublish.statusCode,
      200,
    );
    assert.equal(
      unpublish.json().state,
      "private",
    );

    const after =
      await app.inject({
        method: "GET",
        url:
          `/v1/public/publications/${published.id}`,
      });
    assert.equal(
      after.statusCode,
      404,
    );
  } finally {
    await app.close();
    await pool.end();
  }
});
