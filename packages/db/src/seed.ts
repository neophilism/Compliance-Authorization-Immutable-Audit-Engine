import { createPool } from "./client.js";
import { runMigrations } from "./migrations.js";
import { DomainRepository } from "./repository.js";

const pool = createPool();

try {
  await runMigrations(pool);
  const repository = new DomainRepository(pool);

  const slug = "example-civic-compliance";
  const existing = await pool.query("SELECT id FROM organizations WHERE slug = $1", [slug]);

  if (existing.rows[0]) {
    console.log(JSON.stringify({ seeded: false, organizationId: existing.rows[0].id }));
  } else {
    const organization = await repository.createOrganization({
      name: "Example Civic Compliance Office",
      slug,
      metadata: { purpose: "PR 2 demonstration tenant" },
    });

    const policy = await repository.createPolicy({
      organizationId: organization.id,
      key: "baseline-security",
      title: "Baseline Security Policy",
      description: "Fictional policy used to exercise the domain model.",
      status: "active",
    });

    const resource = await repository.createResource({
      organizationId: organization.id,
      resourceType: "information-system",
      name: "Example Records System",
      externalRef: "demo-system-001",
      attributes: {
        environment: "demonstration",
        containsSensitiveInformation: false,
      },
    });

    console.log(
      JSON.stringify({
        seeded: true,
        organizationId: organization.id,
        policyId: policy.id,
        resourceId: resource.id,
      }),
    );
  }
} finally {
  await pool.end();
}
