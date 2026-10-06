import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  CertificationError,
  CertificationService,
} from "../src/index.js";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const resourceId = randomUUID();
  const issuerId = randomUUID();
  const reviewerId = randomUUID();
  const passingCheckId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(id, name, slug, status)
     VALUES ($1, 'Certification Test Organization', $2, 'active')`,
    [
      organizationId,
      `certification-test-${organizationId}`,
    ],
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
       $1, $2, 'system', 'Certification Test System',
       'active', '{"controlEnabled":true}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  for (const [id, name] of [
    [issuerId, "Certification Issuer"],
    [reviewerId, "Certification Reviewer"],
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

  const evaluatedAt = new Date().toISOString();

  await pool.query(
    `INSERT INTO checks(
       id,
       organization_id,
       resource_id,
       status,
       trigger,
       requested_by_principal_id,
       evaluated_at,
       completed_at,
       rule_set_snapshot,
       context_snapshot,
       evidence_trace,
       result,
       metadata
     ) VALUES (
       $1, $2, $3, 'passed', 'manual', $4, $5, $5,
       $6::jsonb, '{}'::jsonb, $7::jsonb, $8::jsonb,
       '{}'::jsonb
     )`,
    [
      passingCheckId,
      organizationId,
      resourceId,
      issuerId,
      evaluatedAt,
      JSON.stringify({
        schemaVersion: "1",
        id: "baseline-certification",
        version: "1.0.0",
        title: "Baseline Certification",
        rules: [],
      }),
      JSON.stringify([
        {
          evidenceId: randomUUID(),
          evidenceType: "configuration-export",
          checksumAlgorithm: "sha256",
          checksum: "abc123",
        },
      ]),
      JSON.stringify({
        ruleSetId: "baseline-certification",
        version: "1.0.0",
        status: "pass",
        counts: {
          pass: 1,
          fail: 0,
          unknown: 0,
          notApplicable: 0,
        },
        rules: [],
      }),
    ],
  );

  return {
    pool,
    service: new CertificationService(pool),
    organizationId,
    resourceId,
    issuerId,
    reviewerId,
    passingCheckId,
  };
}

async function insertFailedCheck(
  f: Awaited<ReturnType<typeof fixture>>,
  severity: "low" | "medium" | "high" | "critical",
): Promise<string> {
  const id = randomUUID();
  const evaluatedAt = new Date().toISOString();

  await f.pool.query(
    `INSERT INTO checks(
       id,
       organization_id,
       resource_id,
       status,
       trigger,
       requested_by_principal_id,
       evaluated_at,
       completed_at,
       rule_set_snapshot,
       context_snapshot,
       evidence_trace,
       result,
       metadata
     ) VALUES (
       $1, $2, $3, 'failed', 'manual', $4, $5, $5,
       $6::jsonb, '{}'::jsonb, '[]'::jsonb, $7::jsonb,
       '{}'::jsonb
     )`,
    [
      id,
      f.organizationId,
      f.resourceId,
      f.issuerId,
      evaluatedAt,
      JSON.stringify({
        schemaVersion: "1",
        id: "baseline-certification",
        version: "1.0.0",
        title: "Baseline Certification",
        rules: [],
      }),
      JSON.stringify({
        ruleSetId: "baseline-certification",
        version: "1.0.0",
        status: "fail",
        counts: {
          pass: 0,
          fail: 1,
          unknown: 0,
          notApplicable: 0,
        },
        rules: [
          {
            ruleId: "control-enabled",
            title: "Control must be enabled",
            severity,
            applicable: true,
            requirement: false,
            status: "fail",
            requiredEvidenceTypes: [],
            missingEvidenceTypes: [],
          },
        ],
      }),
    ],
  );

  return id;
}

test("issuance persists criteria, artifacts, verification code, and audit history", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const issued = await f.service.issue({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      certificationType: "baseline-compliance",
      supportingCheckId: f.passingCheckId,
      issuedByPrincipalId: f.issuerId,
      validitySeconds: 3600,
      criteria: {
        ruleSetId: "baseline-certification",
        ruleSetVersion: "1.0.0",
        maximumCheckAgeSeconds: 3600,
        blockingFindingSeverities: [],
        materialFailureSeverities: [
          "high",
          "critical",
        ],
      },
      conditions: {
        scope: "test-system",
      },
    });

    assert.equal(
      issued.certification.status,
      "active",
    );
    assert.match(
      issued.certification.certificateNumber,
      /^CERT-[A-F0-9]{16}$/,
    );
    assert.equal(
      issued.certification.artifact.certificationId,
      issued.certification.id,
    );
    assert.equal(
      issued.certification.publicArtifact.resourceId,
      f.resourceId,
    );

    const verification = await f.service.verify(
      issued.certification.verificationCode,
    );

    assert.equal(verification.found, true);
    assert.equal(verification.valid, true);
    assert.equal(
      verification.effectiveStatus,
      "active",
    );

    const ledger = new AuditLedger(f.pool);
    assert.deepEqual(
      await ledger.verify(
        f.organizationId,
        "certification",
        issued.certification.id,
      ),
      { valid: true, checked: 1 },
    );
  } finally {
    await f.pool.end();
  }
});

test("issuance rejects non-passing checks and unresolved blocking findings", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const failedCheckId =
      await insertFailedCheck(f, "high");

    await assert.rejects(
      f.service.issue({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        certificationType: "baseline-compliance",
        supportingCheckId: failedCheckId,
        issuedByPrincipalId: f.issuerId,
        validitySeconds: 3600,
      }),
      (error: unknown) =>
        error instanceof CertificationError &&
        error.code === "invalid_state",
    );

    await f.pool.query(
      `INSERT INTO findings(
         id,
         organization_id,
         resource_id,
         severity,
         status,
         title,
         description,
         opened_at,
         metadata
       ) VALUES (
         $1, $2, $3, 'high', 'open',
         'Blocking finding', 'Open material finding',
         now(), '{}'::jsonb
       )`,
      [
        randomUUID(),
        f.organizationId,
        f.resourceId,
      ],
    );

    await assert.rejects(
      f.service.issue({
        organizationId: f.organizationId,
        resourceId: f.resourceId,
        certificationType: "baseline-compliance",
        supportingCheckId: f.passingCheckId,
        issuedByPrincipalId: f.issuerId,
        validitySeconds: 3600,
      }),
      (error: unknown) =>
        error instanceof CertificationError &&
        error.code === "invalid_state",
    );
  } finally {
    await f.pool.end();
  }
});

test("verification is time-derived before worker persistence and sweep persists activation and expiration", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const validFrom = new Date(
      Date.now() + 60_000,
    );

    const issued = await f.service.issue({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      certificationType: "future-certification",
      supportingCheckId: f.passingCheckId,
      issuedByPrincipalId: f.issuerId,
      validFrom: validFrom.toISOString(),
      validitySeconds: 60,
      criteria: {
        blockingFindingSeverities: [],
      },
    });

    assert.equal(
      issued.certification.status,
      "pending",
    );

    const mid = new Date(
      validFrom.getTime() + 30_000,
    );

    const beforeSweep = await f.service.verify(
      issued.certification.verificationCode,
      mid,
    );

    assert.equal(
      beforeSweep.storedStatus,
      "pending",
    );
    assert.equal(
      beforeSweep.effectiveStatus,
      "active",
    );
    assert.equal(beforeSweep.valid, true);

    const activation = await f.service.sweep(mid);
    assert.equal(activation.activated, 1);

    assert.equal(
      (
        await f.service.get(
          issued.certification.id,
        )
      ).certification.status,
      "active",
    );

    const afterExpiry = new Date(
      validFrom.getTime() + 61_000,
    );

    const timeDerivedExpired =
      await f.service.verify(
        issued.certification.verificationCode,
        afterExpiry,
      );
    assert.equal(
      timeDerivedExpired.effectiveStatus,
      "expired",
    );
    assert.equal(timeDerivedExpired.valid, false);

    const expirySweep =
      await f.service.sweep(afterExpiry);
    assert.equal(expirySweep.expired, 1);

    assert.equal(
      (
        await f.service.get(
          issued.certification.id,
        )
      ).certification.status,
      "expired",
    );
  } finally {
    await f.pool.end();
  }
});

test("material failure suspension respects configured severities", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const issued = await f.service.issue({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      certificationType: "critical-only-certification",
      supportingCheckId: f.passingCheckId,
      issuedByPrincipalId: f.issuerId,
      validitySeconds: 3600,
      criteria: {
        blockingFindingSeverities: [],
        materialFailureSeverities: ["critical"],
      },
    });

    const highCheck =
      await insertFailedCheck(f, "high");
    const highResult =
      await f.service.suspendForMaterialFailure(
        highCheck,
      );

    assert.equal(
      highResult.certificationsSuspended,
      0,
    );
    assert.equal(
      (
        await f.service.get(
          issued.certification.id,
        )
      ).certification.status,
      "active",
    );

    const criticalCheck =
      await insertFailedCheck(f, "critical");
    const criticalResult =
      await f.service.suspendForMaterialFailure(
        criticalCheck,
      );

    assert.equal(
      criticalResult.certificationsSuspended,
      1,
    );

    const suspended = (
      await f.service.get(
        issued.certification.id,
      )
    ).certification;

    assert.equal(suspended.status, "suspended");
    assert.equal(
      suspended.suspensionCheckId,
      criticalCheck,
    );
  } finally {
    await f.pool.end();
  }
});

test("manual suspension can be reinstated with a passing check and later revoked", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const issued = await f.service.issue({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      certificationType: "manual-lifecycle",
      supportingCheckId: f.passingCheckId,
      issuedByPrincipalId: f.issuerId,
      validitySeconds: 3600,
      criteria: {
        blockingFindingSeverities: [],
      },
    });

    const suspended = await f.service.suspend({
      certificationId: issued.certification.id,
      principalId: f.reviewerId,
      reason: "Manual review required",
    });

    assert.equal(
      suspended.certification.status,
      "suspended",
    );

    const reinstated =
      await f.service.reinstate({
        certificationId: issued.certification.id,
        supportingCheckId: f.passingCheckId,
        principalId: f.reviewerId,
        rationale:
          "Passing check confirms continued compliance.",
      });

    assert.equal(
      reinstated.certification.status,
      "active",
    );
    assert.equal(
      reinstated.certification.reinstatementCheckId,
      f.passingCheckId,
    );

    const revoked = await f.service.revoke({
      certificationId: issued.certification.id,
      principalId: f.reviewerId,
      reason: "Credential withdrawn",
    });

    assert.equal(
      revoked.certification.status,
      "revoked",
    );

    const verification = await f.service.verify(
      issued.certification.verificationCode,
    );
    assert.equal(verification.valid, false);
    assert.equal(
      verification.effectiveStatus,
      "revoked",
    );
  } finally {
    await f.pool.end();
  }
});

test("renewal creates a new credential and supersedes the prior certification", async () => {
  if (!process.env.DATABASE_URL) return;

  const f = await fixture();
  try {
    const first = await f.service.issue({
      organizationId: f.organizationId,
      resourceId: f.resourceId,
      certificationType: "renewable-certification",
      supportingCheckId: f.passingCheckId,
      issuedByPrincipalId: f.issuerId,
      validitySeconds: 3600,
      criteria: {
        blockingFindingSeverities: [],
      },
    });

    const renewed = await f.service.renew({
      certificationId: first.certification.id,
      supportingCheckId: f.passingCheckId,
      issuedByPrincipalId: f.issuerId,
      validitySeconds: 7200,
    });

    assert.notEqual(
      renewed.certification.id,
      first.certification.id,
    );
    assert.equal(
      renewed.certification.renewedFromCertificationId,
      first.certification.id,
    );

    const old = (
      await f.service.get(
        first.certification.id,
      )
    ).certification;

    assert.equal(old.status, "superseded");
    assert.equal(
      old.supersededByCertificationId,
      renewed.certification.id,
    );

    const oldVerification =
      await f.service.verify(
        first.certification.verificationCode,
      );

    assert.equal(oldVerification.valid, false);
    assert.equal(
      oldVerification.effectiveStatus,
      "superseded",
    );

    const newVerification =
      await f.service.verify(
        renewed.certification.verificationCode,
      );

    assert.equal(newVerification.valid, true);
  } finally {
    await f.pool.end();
  }
});
