import assert from "node:assert/strict";
import test from "node:test";
import { buildApp } from "../src/app.js";

test("core domain can be created and retrieved through the API", async () => {
  if (!process.env.DATABASE_URL) return;

  const app = await buildApp();
  try {
    const suffix = Date.now().toString(36);

    const orgResponse = await app.inject({
      method: "POST",
      url: "/v1/organizations",
      payload: {
        name: "API Test Organization",
        slug: `api-test-${suffix}`,
      },
    });
    assert.equal(orgResponse.statusCode, 201);
    const organization = orgResponse.json();

    const policyResponse = await app.inject({
      method: "POST",
      url: "/v1/policies",
      payload: {
        organizationId: organization.id,
        key: `policy-${suffix}`,
        title: "API Test Policy",
        status: "active",
      },
    });
    assert.equal(policyResponse.statusCode, 201);

    const resourceResponse = await app.inject({
      method: "POST",
      url: "/v1/resources",
      payload: {
        organizationId: organization.id,
        resourceType: "information-system",
        name: "API Test System",
        attributes: { environment: "test" },
      },
    });
    assert.equal(resourceResponse.statusCode, 201);
    const resource = resourceResponse.json();

    const getResponse = await app.inject({
      method: "GET",
      url: `/v1/resources/${resource.id}`,
    });
    assert.equal(getResponse.statusCode, 200);
    assert.equal(getResponse.json().name, "API Test System");

    const listResponse = await app.inject({
      method: "GET",
      url: `/v1/organizations/${organization.id}/resources?resourceType=information-system`,
    });
    assert.equal(listResponse.statusCode, 200);
    const listed = listResponse.json();
    assert.equal(listed.length, 1);
    assert.equal(listed[0].id, resource.id);
  } finally {
    await app.close();
  }
});
