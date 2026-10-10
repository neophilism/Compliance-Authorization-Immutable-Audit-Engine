import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { AuditLedger, createPool, runMigrations } from "@caiae/db";
import { buildApp } from "../src/app.js";

const RULESET = {
  schemaVersion: "1",
  id: "integration-control",
  version: "1",
  title: "Integrated control",
  rules: [{
    id: "control-enabled",
    title: "Control is enabled",
    severity: "high",
    require: { field: "resource.attributes.controlEnabled", operator: "equals", value: true },
  }],
};

test("enforced full compliance lifecycle keeps private data out of publications", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  await runMigrations(pool);
  const organizationId = randomUUID();
  const otherOrganizationId = randomUUID();
  const principalId = randomUUID();
  const resourceId = randomUUID();
  const otherResourceId = randomUUID();
  const secret = "INTERNAL-DO-NOT-PUBLISH-" + randomUUID();

  await pool.query(
    "INSERT INTO organizations (id, name, slug, status) " +
    "VALUES ($1, 'Integration Org', $2, 'active'), ($3, 'Other Org', $4, 'active')",
    [organizationId, "integration-" + organizationId, otherOrganizationId, "other-" + otherOrganizationId],
  );
  await pool.query(
    "INSERT INTO principals (id, organization_id, kind, display_name, status) " +
    "VALUES ($1, $2, 'user', 'Integration Admin', 'active')",
    [principalId, organizationId],
  );
  await pool.query(
    "INSERT INTO resources (id, organization_id, resource_type, name, status, attributes, metadata) " +
    "VALUES ($1, $2, 'system', 'Protected System', 'active', $3::jsonb, $4::jsonb), " +
    "($5, $6, 'system', 'Foreign System', 'active', '{}'::jsonb, '{}'::jsonb)",
    [resourceId, organizationId, JSON.stringify({ controlEnabled: false }), JSON.stringify({ confidential: secret }), otherResourceId, otherOrganizationId],
  );

  const app = await buildApp({
    securityMode: "enforce",
    bootstrapSecret: "integration-bootstrap-secret-123456789",
  });
  try {
    const bootstrap = await app.inject({
      method: "POST", url: "/v1/security/bootstrap",
      headers: { "x-caiae-bootstrap-secret": "integration-bootstrap-secret-123456789" },
      payload: { organizationId, principalId, credentialName: "integration-admin" },
    });
    assert.equal(bootstrap.statusCode, 201, bootstrap.body);
    const headers = { authorization: "Bearer " + bootstrap.json().token };

    const foreign = await app.inject({ method: "GET", url: "/v1/resources/" + otherResourceId, headers });
    assert.equal(foreign.statusCode, 403, foreign.body);

    const evidence = await app.inject({
      method: "POST", url: "/v1/evidence", headers,
      payload: { organizationId, resourceId, evidenceType: "control-export",
        title: "Evidence for reviewed system", submittedByPrincipalId: principalId,
        uri: "urn:integration:evidence" },
    });
    assert.equal(evidence.statusCode, 201, evidence.body);

    const check = await app.inject({
      method: "POST", url: "/v1/checks/run", headers,
      payload: { organizationId, resourceId, requestedByPrincipalId: principalId, ruleSet: RULESET },
    });
    assert.equal(check.statusCode, 201, check.body);
    assert.equal(check.json().check.status, "failed");

    const findings = await app.inject({
      method: "GET",
      url: "/v1/organizations/" + organizationId + "/resources/" + resourceId + "/findings", headers,
    });
    assert.equal(findings.statusCode, 200, findings.body);
    assert.equal(findings.json().length, 1);

    const report = await app.inject({
      method: "GET", url: "/v1/reports/organizations/" + organizationId + "/compliance", headers,
    });
    assert.equal(report.statusCode, 200, report.body);
    assert.ok(report.json().summary.checks.total >= 1);
    assert.equal(report.json().summary.audit.allChainsValid, true);

    const hidden = await app.inject({
      method: "GET", url: "/v1/public/organizations/" + organizationId + "/publications",
    });
    assert.equal(hidden.statusCode, 200);
    assert.deepEqual(hidden.json(), []);

    const published = await app.inject({
      method: "POST", url: "/v1/publications/publish", headers,
      payload: { organizationId, subjectType: "resource", subjectId: resourceId,
        projectionType: "resource_compliance", principalId },
    });
    assert.equal(published.statusCode, 200, published.body);

    const publicRead = await app.inject({
      method: "GET", url: "/v1/public/publications/" + published.json().id,
    });
    assert.equal(publicRead.statusCode, 200, publicRead.body);
    assert.equal(publicRead.json().projection.resource.id, resourceId);
    assert.equal(publicRead.body.includes(secret), false);
    assert.equal(publicRead.body.includes("confidential"), false);
    assert.equal(publicRead.body.includes("publishedByPrincipalId"), false);

    const ledger = new AuditLedger(pool);
    const events = await ledger.list(organizationId, "finding", findings.json()[0].id);
    assert.ok(events.length > 0);
    assert.deepEqual(await ledger.verify(organizationId, "finding", findings.json()[0].id), {
      valid: true, checked: events.length,
    });

    const unpublished = await app.inject({
      method: "POST", url: "/v1/publications/unpublish", headers,
      payload: { organizationId, subjectType: "resource", subjectId: resourceId,
        projectionType: "resource_compliance", principalId, reason: "integration-test" },
    });
    assert.equal(unpublished.statusCode, 200, unpublished.body);
    const withdrawn = await app.inject({
      method: "GET", url: "/v1/public/publications/" + published.json().id,
    });
    assert.equal(withdrawn.statusCode, 404, withdrawn.body);
  } finally {
    await app.close();
    await pool.end();
  }
});
