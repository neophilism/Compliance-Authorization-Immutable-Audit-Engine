import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createPool } from "@caiae/db";

const BOOTSTRAP_REF = "caiae-bootstrap-primary-operator";

export function validateTenantInput({ slug, organizationName, operatorName }) {
  if (typeof slug !== "string" || !/^[a-z][a-z0-9-]{2,62}[a-z0-9]$/.test(slug)) {
    throw new Error("Organization slug must be 4-64 lowercase letters, digits or hyphens");
  }
  if (typeof organizationName !== "string" || organizationName.trim().length < 3 ||
      organizationName.length > 200) {
    throw new Error("A valid organization name is required");
  }
  if (typeof operatorName !== "string" || operatorName.trim().length < 3 ||
      operatorName.length > 200) {
    throw new Error("A valid operator display name is required");
  }
  return { slug, organizationName: organizationName.trim(), operatorName: operatorName.trim() };
}

export async function provisionFirstTenant(pool, options) {
  const { slug, organizationName, operatorName } = validateTenantInput(options);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
      "caiae-first-tenant-" + slug,
    ]);
    const existingOrganization = await client.query(
      "SELECT id, status FROM organizations WHERE slug = $1 FOR UPDATE", [slug],
    );
    if (existingOrganization.rowCount > 1) throw new Error("Duplicate organization slug");
    let organizationId;
    let createdOrganization = false;
    if (existingOrganization.rowCount === 1) {
      if (existingOrganization.rows[0].status !== "active") {
        throw new Error("Existing organization is not active");
      }
      organizationId = existingOrganization.rows[0].id;
    } else {
      organizationId = randomUUID();
      await client.query(
        "INSERT INTO organizations (id, name, slug, status, metadata) " +
        "VALUES ($1, $2, $3, 'active', $4::jsonb)",
        [organizationId, organizationName, slug, JSON.stringify({ createdBy: "caiae-first-tenant-cli" })],
      );
      createdOrganization = true;
    }

    const existingPrincipals = await client.query(
      "SELECT id, status FROM principals " +
      "WHERE organization_id = $1 AND kind = 'user' AND external_ref = $2 FOR UPDATE",
      [organizationId, BOOTSTRAP_REF],
    );
    if (existingPrincipals.rowCount > 1) {
      throw new Error("More than one bootstrap principal exists; manual review required");
    }
    let principalId;
    let createdPrincipal = false;
    if (existingPrincipals.rowCount === 1) {
      if (existingPrincipals.rows[0].status !== "active") {
        throw new Error("Existing bootstrap principal is not active");
      }
      principalId = existingPrincipals.rows[0].id;
    } else {
      principalId = randomUUID();
      await client.query(
        "INSERT INTO principals (id, organization_id, kind, display_name, external_ref, status, metadata) " +
        "VALUES ($1, $2, 'user', $3, $4, 'active', '{}'::jsonb)",
        [principalId, organizationId, operatorName, BOOTSTRAP_REF],
      );
      createdPrincipal = true;
    }
    await client.query("COMMIT");
    return { organizationId, principalId, createdOrganization, createdPrincipal };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function main() {
  if (process.env.CAIAE_BOOTSTRAP_CONFIRM !== "CREATE_PRODUCTION_TENANT") {
    throw new Error("Set CAIAE_BOOTSTRAP_CONFIRM=CREATE_PRODUCTION_TENANT to authorize tenant setup");
  }
  const databaseUrl = process.env.DATABASE_URL_UNPOOLED;
  if (!databaseUrl || !/^postgres(ql)?:\/\//.test(databaseUrl)) {
    throw new Error("DATABASE_URL_UNPOOLED direct PostgreSQL connection is required");
  }
  const pool = createPool({ connectionString: databaseUrl });
  try {
    const result = await provisionFirstTenant(pool, {
      slug: process.env.CAIAE_BOOTSTRAP_ORG_SLUG,
      organizationName: process.env.CAIAE_BOOTSTRAP_ORG_NAME,
      operatorName: process.env.CAIAE_BOOTSTRAP_OPERATOR_NAME,
    });
    console.log(JSON.stringify(result));
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error("Production tenant initialization failed: " +
      (error instanceof Error ? error.message : "unknown error"));
    process.exitCode = 1;
  });
}
