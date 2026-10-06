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

const BOOTSTRAP_SECRET =
  "api-bootstrap-secret-123456789";

test("operator authentication, RBAC, organization isolation, and anti-impersonation are enforced", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const adminId = randomUUID();
  const limitedId = randomUUID();
  const resourceId = randomUUID();
  const otherOrganizationId =
    randomUUID();
  const otherPrincipalId =
    randomUUID();
  const otherResourceId =
    randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES
       ($1, 'Security API Org', $2, 'active'),
       ($3, 'Other Security Org', $4, 'active')`,
    [
      organizationId,
      `security-api-${organizationId}`,
      otherOrganizationId,
      `security-api-other-${otherOrganizationId}`,
    ],
  );

  for (const [
    id,
    orgId,
    name,
  ] of [
    [
      adminId,
      organizationId,
      "Security Administrator",
    ],
    [
      limitedId,
      organizationId,
      "Limited Reader",
    ],
    [
      otherPrincipalId,
      otherOrganizationId,
      "Other Operator",
    ],
  ]) {
    await pool.query(
      `INSERT INTO principals(
         id,
         organization_id,
         kind,
         display_name,
         status
       ) VALUES (
         $1, $2, 'user', $3, 'active'
       )`,
      [id, orgId, name],
    );
  }

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       attributes
     ) VALUES
       ($1, $2, 'generic', 'Own Resource', 'active', '{}'::jsonb),
       ($3, $4, 'generic', 'Other Resource', 'active', '{}'::jsonb)`,
    [
      resourceId,
      organizationId,
      otherResourceId,
      otherOrganizationId,
    ],
  );

  const app = await buildApp({
    securityMode: "enforce",
    bootstrapSecret:
      BOOTSTRAP_SECRET,
  });

  try {
    const anonymous =
      await app.inject({
        method: "GET",
        url:
          `/v1/resources/${resourceId}`,
      });
    assert.equal(
      anonymous.statusCode,
      401,
    );

    const wrongBootstrap =
      await app.inject({
        method: "POST",
        url:
          "/v1/security/bootstrap",
        headers: {
          "x-caiae-bootstrap-secret":
            "wrong-secret",
        },
        payload: {
          organizationId,
          principalId: adminId,
          credentialName:
            "api-admin-wrong",
        },
      });
    assert.equal(
      wrongBootstrap.statusCode,
      401,
    );

    const bootstrap =
      await app.inject({
        method: "POST",
        url:
          "/v1/security/bootstrap",
        headers: {
          "x-caiae-bootstrap-secret":
            BOOTSTRAP_SECRET,
        },
        payload: {
          organizationId,
          principalId: adminId,
          credentialName:
            "api-admin",
        },
      });
    assert.equal(
      bootstrap.statusCode,
      201,
    );
    const adminToken =
      bootstrap.json().token as string;
    const adminHeaders = {
      authorization:
        `Bearer ${adminToken}`,
    };

    const me =
      await app.inject({
        method: "GET",
        url: "/v1/security/me",
        headers: adminHeaders,
      });
    assert.equal(
      me.statusCode,
      200,
    );
    assert.equal(
      me.json().principal.id,
      adminId,
    );

    const ownResource =
      await app.inject({
        method: "GET",
        url:
          `/v1/resources/${resourceId}`,
        headers: adminHeaders,
      });
    assert.equal(
      ownResource.statusCode,
      200,
    );

    const crossOrg =
      await app.inject({
        method: "GET",
        url:
          `/v1/resources/${otherResourceId}`,
        headers: adminHeaders,
      });
    assert.equal(
      crossOrg.statusCode,
      403,
    );

    const spoof =
      await app.inject({
        method: "POST",
        url: "/v1/authorizations",
        headers: adminHeaders,
        payload: {
          organizationId,
          resourceId,
          authorizationType:
            "generic-approval",
          requestedByPrincipalId:
            limitedId,
          approvalQuorum: 1,
          eligibleApproverPrincipalIds: [
            adminId,
          ],
        },
      });
    assert.equal(
      spoof.statusCode,
      403,
    );

    const role =
      await app.inject({
        method: "POST",
        url: "/v1/security/roles",
        headers: adminHeaders,
        payload: {
          organizationId,
          key: "api-resource-reader",
          name: "API Resource Reader",
          permissions: [
            "resources.read",
          ],
        },
      });
    assert.equal(
      role.statusCode,
      201,
    );

    const assignment =
      await app.inject({
        method: "POST",
        url:
          "/v1/security/role-assignments",
        headers: adminHeaders,
        payload: {
          organizationId,
          principalId: limitedId,
          roleId: role.json().id,
        },
      });
    assert.equal(
      assignment.statusCode,
      201,
    );

    const limitedCredential =
      await app.inject({
        method: "POST",
        url:
          "/v1/security/operator-credentials",
        headers: adminHeaders,
        payload: {
          organizationId,
          principalId: limitedId,
          name: "api-limited",
        },
      });
    assert.equal(
      limitedCredential.statusCode,
      201,
    );
    const limitedToken =
      limitedCredential.json()
        .token as string;
    const limitedHeaders = {
      authorization:
        `Bearer ${limitedToken}`,
    };

    const limitedRead =
      await app.inject({
        method: "GET",
        url:
          `/v1/resources/${resourceId}`,
        headers: limitedHeaders,
      });
    assert.equal(
      limitedRead.statusCode,
      200,
    );

    const limitedWrite =
      await app.inject({
        method: "POST",
        url: "/v1/resources",
        headers: limitedHeaders,
        payload: {
          organizationId,
          resourceType:
            "generic",
          name: "Forbidden Create",
        },
      });
    assert.equal(
      limitedWrite.statusCode,
      403,
    );

    const publicCertification =
      await app.inject({
        method: "GET",
        url:
          "/v1/public/certifications/verify/not-a-real-code",
      });
    assert.equal(
      publicCertification.statusCode,
      200,
    );

    const integrationWithoutServiceToken =
      await app.inject({
        method: "GET",
        url:
          "/v1/integration/resources",
        headers: adminHeaders,
      });
    assert.equal(
      integrationWithoutServiceToken
        .statusCode,
      401,
    );

    const revoke =
      await app.inject({
        method: "POST",
        url:
          `/v1/security/operator-credentials/${limitedCredential.json().credential.id}/revoke`,
        headers: adminHeaders,
        payload: {
          reason: "rotation",
        },
      });
    assert.equal(
      revoke.statusCode,
      200,
    );

    const revokedUse =
      await app.inject({
        method: "GET",
        url:
          `/v1/resources/${resourceId}`,
        headers: limitedHeaders,
      });
    assert.equal(
      revokedUse.statusCode,
      401,
    );

    const openapi =
      await app.inject({
        method: "GET",
        url: "/openapi.json",
      });
    const document =
      openapi.json();

    assert.ok(
      document.components
        .securitySchemes
        .operatorBearer,
    );
    assert.deepEqual(
      document.paths[
        "/v1/resources/{id}"
      ].get.security,
      [
        {
          operatorBearer: [],
        },
      ],
    );
    assert.equal(
      document.paths[
        "/v1/public/certifications/verify/{code}"
      ].get.security,
      undefined,
    );
    assert.deepEqual(
      document.paths[
        "/v1/integration/resources"
      ].get.security,
      [
        {
          serviceBearer: [],
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
