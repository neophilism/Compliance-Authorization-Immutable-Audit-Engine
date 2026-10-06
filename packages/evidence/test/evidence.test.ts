import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  evaluateRuleSet,
  parseRuleSet,
} from "@caiae/rules";
import {
  EvidenceError,
  EvidenceService,
} from "../src/index.js";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const submitterId = randomUUID();
  const attesterId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Evidence Test Organization', $2, 'active')`,
    [organizationId, `evidence-test-${organizationId}`],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       status,
       attributes
     ) VALUES (
       $1, $2, 'information-system', 'Evidence Test System',
       'active', '{"controlEnabled":true}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [submitterId, "Submitter"],
    [attesterId, "Attester"],
  ]) {
    await pool.query(
      `INSERT INTO principals(
         id,
         organization_id,
         kind,
         display_name,
         status
       ) VALUES ($1, $2, 'user', $3, 'active')`,
      [id, organizationId, name],
    );
  }

  return {
    pool,
    service: new EvidenceService(pool),
    organizationId,
    resourceId,
    submitterId,
    attesterId,
  };
}

test("evidence preserves reference, checksum, provenance, and metadata", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "configuration-export",
      title: "Configuration Export",
      submittedByPrincipalId: f.submitterId,
      source: "configuration-management-system",
      uri: "urn:example:evidence:config-1",
      mediaType: "application/json",
      fileName: "config.json",
      checksumAlgorithm: "sha256",
      checksum: "abc123",
      capturedAt: new Date().toISOString(),
      provenance: {
        collector: "automated-export",
        system: "demo",
      },
      attributes: {
        region: "test",
      },
      metadata: {
        note: "integration fixture",
      },
    });

    assert.equal(record.evidence.status, "active");
    assert.equal(record.evidence.checksumAlgorithm, "sha256");
    assert.equal(record.evidence.checksum, "abc123");
    assert.deepEqual(record.evidence.provenance, {
      collector: "automated-export",
      system: "demo",
    });
    assert.deepEqual(record.evidence.attributes, {
      region: "test",
    });

    await assert.rejects(
      f.service.create({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        evidenceType: "bad-checksum",
        title: "Bad Checksum",
        checksum: "hash-without-algorithm",
      }),
      (error: unknown) =>
        error instanceof EvidenceError &&
        error.code === "validation",
    );
  } finally {
    await f.pool.end();
  }
});

test("valid evidence types honor validFrom and validUntil", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const now = Date.now();

    await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "time-bound-evidence",
      title: "Time Bound Evidence",
      validFrom: new Date(now + 60_000).toISOString(),
      validUntil: new Date(now + 120_000).toISOString(),
    });

    assert.deepEqual(
      await f.service.validEvidenceTypes(
        f.organizationId,
        f.resourceId,
        new Date(now + 30_000),
      ),
      [],
    );

    assert.deepEqual(
      await f.service.validEvidenceTypes(
        f.organizationId,
        f.resourceId,
        new Date(now + 90_000),
      ),
      ["time-bound-evidence"],
    );

    assert.deepEqual(
      await f.service.validEvidenceTypes(
        f.organizationId,
        f.resourceId,
        new Date(now + 121_000),
      ),
      [],
    );
  } finally {
    await f.pool.end();
  }
});

test("supersession preserves history while removing prior evidence from validity", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const original = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "security-assessment",
      title: "Assessment v1",
      submittedByPrincipalId: f.submitterId,
    });

    const replacement = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "security-assessment",
      title: "Assessment v2",
      submittedByPrincipalId: f.submitterId,
      supersedesEvidenceId: original.evidence.id,
    });

    assert.deepEqual(
      await f.service.validity(original.evidence.id),
      { valid: false, reason: "superseded" },
    );

    assert.deepEqual(
      await f.service.validity(replacement.evidence.id),
      { valid: true, reason: "active" },
    );

    const originalAfter = await f.service.get(
      original.evidence.id,
    );
    assert.equal(
      originalAfter.evidence.status,
      "superseded",
    );
    assert.notEqual(
      originalAfter.evidence.supersededAt,
      null,
    );

    const ledger = new AuditLedger(f.pool);
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "evidence",
        original.evidence.id,
      ),
      { valid: true, checked: 2 },
    );
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "evidence",
        replacement.evidence.id,
      ),
      { valid: true, checked: 1 },
    );
  } finally {
    await f.pool.end();
  }
});

test("attestations carry claims and can be revoked without deleting history", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const evidence = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "review-report",
      title: "Review Report",
    });

    const withAttestation = await f.service.addAttestation({
      evidenceId: evidence.evidence.id,
      principalId: f.attesterId,
      attestationType: "reviewer-attestation",
      statement: "I reviewed this record.",
      claims: {
        reviewed: true,
      },
      validUntil: new Date(
        Date.now() + 3_600_000,
      ).toISOString(),
    });

    assert.equal(withAttestation.attestations.length, 1);
    const attestation =
      withAttestation.attestations[0]!;
    assert.deepEqual(attestation.claims, {
      reviewed: true,
    });

    assert.equal(
      (
        await f.service.validAttestations(
          evidence.evidence.id,
        )
      ).length,
      1,
    );

    await f.service.revokeAttestation({
      attestationId: attestation.id,
      principalId: f.attesterId,
      reason: "Attestation withdrawn",
    });

    assert.equal(
      (
        await f.service.validAttestations(
          evidence.evidence.id,
        )
      ).length,
      0,
    );

    const after = await f.service.get(evidence.evidence.id);
    assert.notEqual(
      after.attestations[0]?.revokedAt,
      null,
    );
  } finally {
    await f.pool.end();
  }
});

test("rules move from unknown to pass only when valid evidence exists", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const ruleSet = parseRuleSet({
      schemaVersion: "1",
      id: "evidence-requirement",
      version: "1",
      title: "Evidence Requirement",
      rules: [
        {
          id: "control-evidenced",
          title: "Control is enabled and evidenced",
          severity: "high",
          require: {
            field: "resource.attributes.controlEnabled",
            operator: "equals",
            value: true,
          },
          requiredEvidenceTypes: [
            "control-configuration",
          ],
        },
      ],
    });

    const baseContext = {
      resource: {
        resourceType: "information-system",
        status: "active",
        attributes: {
          controlEnabled: true,
        },
      },
    };

    const before = evaluateRuleSet(
      ruleSet,
      await f.service.buildRuleEvaluationContext(
        f.organizationId,
        f.resourceId,
        baseContext,
      ),
    );

    assert.equal(before.status, "unknown");
    assert.deepEqual(
      before.rules[0]?.missingEvidenceTypes,
      ["control-configuration"],
    );

    const evidence = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "control-configuration",
      title: "Control Configuration",
      submittedByPrincipalId: f.submitterId,
    });

    const afterCreate = evaluateRuleSet(
      ruleSet,
      await f.service.buildRuleEvaluationContext(
        f.organizationId,
        f.resourceId,
        baseContext,
      ),
    );

    assert.equal(afterCreate.status, "pass");

    await f.service.revoke({
      evidenceId: evidence.evidence.id,
      principalId: f.submitterId,
      reason: "Configuration no longer current",
    });

    const afterRevoke = evaluateRuleSet(
      ruleSet,
      await f.service.buildRuleEvaluationContext(
        f.organizationId,
        f.resourceId,
        baseContext,
      ),
    );

    assert.equal(afterRevoke.status, "unknown");
  } finally {
    await f.pool.end();
  }
});

test("evidence revocation immediately removes it from valid evidence types", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const record = await f.service.create({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      evidenceType: "revocable-evidence",
      title: "Revocable Evidence",
      submittedByPrincipalId: f.submitterId,
    });

    assert.deepEqual(
      await f.service.validEvidenceTypes(
        f.organizationId,
        f.resourceId,
      ),
      ["revocable-evidence"],
    );

    await f.service.revoke({
      evidenceId: record.evidence.id,
      principalId: f.submitterId,
      reason: "Source withdrawn",
    });

    assert.deepEqual(
      await f.service.validEvidenceTypes(
        f.organizationId,
        f.resourceId,
      ),
      [],
    );
  } finally {
    await f.pool.end();
  }
});
