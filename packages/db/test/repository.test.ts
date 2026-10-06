import assert from "node:assert/strict";
import test from "node:test";
import { createPool } from "../src/client.js";
import { runMigrations } from "../src/migrations.js";
import { DomainRepository } from "../src/repository.js";

test("organization, policy, and resource persist and round-trip", async () => {
  if (!process.env.DATABASE_URL) {
    return;
  }

  const pool = createPool();
  try {
    await runMigrations(pool);
    const repo = new DomainRepository(pool);
    const suffix = Date.now().toString(36);

    const organization = await repo.createOrganization({
      name: "Repository Test Organization",
      slug: `repository-test-${suffix}`,
    });
    const policy = await repo.createPolicy({
      organizationId: organization.id,
      key: `policy-${suffix}`,
      title: "Repository Test Policy",
    });
    const resource = await repo.createResource({
      organizationId: organization.id,
      resourceType: "test-resource",
      name: "Repository Test Resource",
      attributes: { test: true },
    });

    assert.equal((await repo.getOrganization(organization.id))?.name, organization.name);
    assert.equal((await repo.getPolicy(policy.id))?.key, policy.key);
    assert.equal((await repo.getResource(resource.id))?.resourceType, "test-resource");

    const resources = await repo.listResources(organization.id, "test-resource");
    assert.equal(resources.length, 1);
    assert.equal(resources[0]?.id, resource.id);
  } finally {
    await pool.end();
  }
});
