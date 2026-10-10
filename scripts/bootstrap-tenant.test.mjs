import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createPool, runMigrations } from "@caiae/db";
import { provisionFirstTenant, validateTenantInput } from "./bootstrap-tenant.mjs";

test("explicit tenant input refuses unsafe or ambiguous organization identifiers", () => {
  assert.throws(() => validateTenantInput({
    slug: "NOT-SAFE", organizationName: "Example Office", operatorName: "Test Administrator",
  }), /slug/);
  assert.throws(() => validateTenantInput({
    slug: "office-test", organizationName: " ", operatorName: "Test Administrator",
  }), /organization name/);
  assert.equal(validateTenantInput({
    slug: "office-test", organizationName: " Example Office ", operatorName: " First Admin ",
  }).organizationName, "Example Office");
});

test("first-tenant provisioning is idempotent and creates no credentials automatically", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  try {
    await runMigrations(pool);
    const input = {
      slug: "bootstrap-" + randomUUID(),
      organizationName: "CAIAE Production Provisioning Regression",
      operatorName: "Initial Administrator",
    };
    const first = await provisionFirstTenant(pool, input);
    assert.equal(first.createdOrganization, true);
    assert.equal(first.createdPrincipal, true);
    const second = await provisionFirstTenant(pool, input);
    assert.equal(second.createdOrganization, false);
    assert.equal(second.createdPrincipal, false);
    assert.equal(second.organizationId, first.organizationId);
    assert.equal(second.principalId, first.principalId);

    const principals = await pool.query(
      "SELECT id FROM principals WHERE organization_id = $1 AND external_ref = $2",
      [first.organizationId, "caiae-bootstrap-primary-operator"],
    );
    assert.equal(principals.rowCount, 1);

    const credentials = await pool.query(
      "SELECT count(*)::integer AS count FROM operator_credentials WHERE organization_id = $1",
      [first.organizationId],
    );
    assert.equal(credentials.rows[0].count, 0);
  } finally {
    await pool.end();
  }
});
