import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { buildApp } from "../src/app.js";

test("deadline API supports relative clocks and simulated status queries", async () => {
  if (!process.env.DATABASE_URL) return;

  const seedPool = createPool();
  await runMigrations(seedPool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const principalId = randomUUID();

  await seedPool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Deadline API Test', $2, 'active')`,
    [organizationId, `deadline-api-${organizationId}`],
  );

  await seedPool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status
     ) VALUES ($1, $2, 'system', 'Deadline API System', 'active')`,
    [resourceId, organizationId],
  );

  await seedPool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES ($1, $2, 'user', 'Clock Owner', 'active')`,
    [principalId, organizationId],
  );

  const app = await buildApp();

  try {
    const anchor = new Date(
      Date.now() + 600_000,
    );

    const createResponse = await app.inject({
      method: "POST",
      url: "/v1/deadlines",
      payload: {
        organizationId,
        resourceId,
        subjectType: "resource",
        subjectId: resourceId,
        deadlineType: "relative-api-clock",
        createdByPrincipalId: principalId,
        anchorAt: anchor.toISOString(),
        dueAfterSeconds: 120,
        warningWindowSeconds: 60,
        gracePeriodSeconds: 30,
      },
    });

    assert.equal(createResponse.statusCode, 201);
    const created = createResponse.json();

    const warningResponse = await app.inject({
      method: "GET",
      url:
        `/v1/deadlines/${created.deadline.id}/status?at=${encodeURIComponent(
          new Date(
            anchor.getTime() + 90_000,
          ).toISOString(),
        )}`,
    });

    assert.equal(warningResponse.statusCode, 200);
    assert.equal(
      warningResponse.json().status,
      "warning",
    );

    const satisfyResponse = await app.inject({
      method: "POST",
      url:
        `/v1/deadlines/${created.deadline.id}/satisfy`,
      payload: {
        principalId,
        satisfiedAt: new Date(
          anchor.getTime() + 100_000,
        ).toISOString(),
      },
    });

    assert.equal(satisfyResponse.statusCode, 200);
    assert.equal(
      satisfyResponse.json().deadline.status,
      "satisfied",
    );
    assert.equal(
      satisfyResponse.json().occurrences.length,
      1,
    );
  } finally {
    await app.close();
    await seedPool.end();
  }
});
