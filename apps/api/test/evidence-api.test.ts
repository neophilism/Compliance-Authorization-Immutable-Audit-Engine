import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { buildApp } from "../src/app.js";

test("evidence API exposes only currently valid evidence types", async () => {
  if (!process.env.DATABASE_URL) return;

  const seedPool = createPool();
  await runMigrations(seedPool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const principalId = randomUUID();

  await seedPool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Evidence API Test', $2, 'active')`,
    [organizationId, `evidence-api-${organizationId}`],
  );

  await seedPool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status
     ) VALUES ($1, $2, 'system', 'API System', 'active')`,
    [resourceId, organizationId],
  );

  await seedPool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES ($1, $2, 'user', 'Submitter', 'active')`,
    [principalId, organizationId],
  );

  const app = await buildApp();

  try {
    const createResponse = await app.inject({
      method: "POST",
      url: "/v1/evidence",
      payload: {
        organizationId,
        resourceId,
        evidenceType: "configuration-export",
        title: "Configuration Export",
        submittedByPrincipalId: principalId,
        uri: "urn:example:config",
        checksumAlgorithm: "sha256",
        checksum: "1234",
        provenance: {
          sourceSystem: "demo",
        },
      },
    });

    assert.equal(createResponse.statusCode, 201);
    const created = createResponse.json();

    const typesResponse = await app.inject({
      method: "GET",
      url:
        `/v1/organizations/${organizationId}/resources/${resourceId}/evidence-types`,
    });

    assert.equal(typesResponse.statusCode, 200);
    assert.deepEqual(typesResponse.json(), {
      evidenceTypes: ["configuration-export"],
    });

    const attestationResponse = await app.inject({
      method: "POST",
      url:
        `/v1/evidence/${created.evidence.id}/attestations`,
      payload: {
        principalId,
        attestationType: "submitter-attestation",
        statement: "This export is complete.",
      },
    });

    assert.equal(attestationResponse.statusCode, 200);
    assert.equal(
      attestationResponse.json().attestations.length,
      1,
    );

    const revokeResponse = await app.inject({
      method: "POST",
      url: `/v1/evidence/${created.evidence.id}/revoke`,
      payload: {
        principalId,
        reason: "Record no longer current",
      },
    });

    assert.equal(revokeResponse.statusCode, 200);
    assert.equal(
      revokeResponse.json().evidence.status,
      "revoked",
    );

    const afterRevoke = await app.inject({
      method: "GET",
      url:
        `/v1/organizations/${organizationId}/resources/${resourceId}/evidence-types`,
    });

    assert.deepEqual(afterRevoke.json(), {
      evidenceTypes: [],
    });
  } finally {
    await app.close();
    await seedPool.end();
  }
});
