import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  PublicationError,
  PublicationService,
} from "../src/index.js";

const AS_OF =
  "2026-10-06T12:00:00.000Z";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const principalId = randomUUID();
  const resourceId = randomUUID();
  const checkId = randomUUID();
  const findingId = randomUUID();
  const certificationId = randomUUID();
  const certificateNumber =
    `CERT-${certificationId
      .replaceAll("-", "")
      .slice(0, 16)
      .toUpperCase()}`;
  const verificationCode =
    `publication-${certificationId}`;

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status, metadata
     ) VALUES (
       $1, 'Publication Test Organization',
       $2, 'active',
       '{"internal":"organization-secret"}'::jsonb
     )`,
    [
      organizationId,
      `publication-test-${organizationId}`,
    ],
  );

  await pool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status,
       metadata
     ) VALUES (
       $1, $2, 'user',
       'Publication Operator',
       'active',
       '{"internal":"principal-secret"}'::jsonb
     )`,
    [
      principalId,
      organizationId,
    ],
  );

  await pool.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       external_ref,
       status,
       attributes,
       metadata
     ) VALUES (
       $1, $2, 'generic-system',
       'Public Candidate',
       'external-123',
       'active',
       '{"sensitiveAttribute":"do-not-publish"}'::jsonb,
       '{"internal":"resource-secret"}'::jsonb
     )`,
    [
      resourceId,
      organizationId,
    ],
  );

  await pool.query(
    `INSERT INTO checks(
       id,
       organization_id,
       resource_id,
       status,
       trigger,
       evaluated_at,
       completed_at,
       rule_set_snapshot,
       context_snapshot,
       evidence_trace,
       result,
       metadata
     ) VALUES (
       $1, $2, $3, 'passed', 'manual',
       '2026-10-06T10:00:00Z',
       '2026-10-06T10:00:01Z',
       '{"id":"ruleset-a","version":"3","internal":"hidden"}'::jsonb,
       '{"secret":"context"}'::jsonb,
       '[{"evidence":"hidden"}]'::jsonb,
       '{"counts":{"pass":1}}'::jsonb,
       '{"internal":"check-secret"}'::jsonb
     )`,
    [
      checkId,
      organizationId,
      resourceId,
    ],
  );

  await pool.query(
    `INSERT INTO findings(
       id,
       organization_id,
       resource_id,
       check_id,
       severity,
       status,
       title,
       description,
       rule_key,
       rule_set_key,
       rule_set_version,
       rule_result,
       opened_at,
       metadata
     ) VALUES (
       $1, $2, $3, $4,
       'high', 'open',
       'Public-safe title',
       'Internal finding narrative',
       'rule-a', 'ruleset-a', '3',
       '{"internal":"finding-result"}'::jsonb,
       '2026-10-06T10:05:00Z',
       '{"internal":"finding-secret"}'::jsonb
     )`,
    [
      findingId,
      organizationId,
      resourceId,
      checkId,
    ],
  );

  await pool.query(
    `INSERT INTO certifications(
       id,
       organization_id,
       resource_id,
       supporting_check_id,
       certification_type,
       status,
       certificate_number,
       verification_code,
       issued_by_principal_id,
       issued_at,
       valid_from,
       valid_until,
       criteria,
       conditions,
       artifact,
       public_artifact,
       metadata
     ) VALUES (
       $1, $2, $3, $4,
       'generic-compliance',
       'active',
       $6,
       $7,
       $5,
       '2026-10-06T10:10:00Z',
       '2026-10-06T10:10:00Z',
       '2026-10-07T10:10:00Z',
       '{"internal":"criteria"}'::jsonb,
       '{"internal":"conditions"}'::jsonb,
       '{"secret":"full-artifact"}'::jsonb,
       '{"schemaVersion":"1","certificateNumber":"CERT-PUBLIC-001","safe":"yes"}'::jsonb,
       '{"internal":"certification-secret"}'::jsonb
     )`,
    [
      certificationId,
      organizationId,
      resourceId,
      checkId,
      principalId,
      certificateNumber,
      verificationCode,
    ],
  );

  return {
    pool,
    organizationId,
    principalId,
    resourceId,
    findingId,
    certificationId,
    certificateNumber,
    service:
      new PublicationService(pool, {
        now: () =>
          new Date(AS_OF),
      }),
  };
}

test("public projections are allowlisted, deterministic, and redactable", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    const first =
      await f.service.preview({
        organizationId:
          f.organizationId,
        subjectType: "resource",
        subjectId: f.resourceId,
        projectionType:
          "resource_compliance",
        asOf: AS_OF,
      });

    const second =
      await f.service.preview({
        organizationId:
          f.organizationId,
        subjectType: "resource",
        subjectId: f.resourceId,
        projectionType:
          "resource_compliance",
        asOf: AS_OF,
      });

    assert.equal(
      first.projectionHash,
      second.projectionHash,
    );
    assert.deepEqual(
      first.projection,
      second.projection,
    );

    const serialized =
      JSON.stringify(
        first.projection,
      );

    for (const forbidden of [
      "resource-secret",
      "sensitiveAttribute",
      "context",
      "evidence",
      "check-secret",
      "finding-secret",
      "full-artifact",
    ]) {
      assert.equal(
        serialized.includes(
          forbidden,
        ),
        false,
      );
    }

    const redacted =
      await f.service.preview({
        organizationId:
          f.organizationId,
        subjectType: "resource",
        subjectId: f.resourceId,
        projectionType:
          "resource_compliance",
        asOf: AS_OF,
        policy: {
          omitPaths: [
            "resource.externalRef",
          ],
          replacements: {
            "resource.name":
              "Redacted Resource",
          },
        },
      });

    assert.equal(
      (
        redacted.projection
          .resource as any
      ).externalRef,
      undefined,
    );
    assert.equal(
      (
        redacted.projection
          .resource as any
      ).name,
      "Redacted Resource",
    );
  } finally {
    await f.pool.end();
  }
});

test("publication is private by default and publish/unpublish is audited", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    assert.deepEqual(
      await f.service.listPublic(
        f.organizationId,
      ),
      [],
    );

    const published =
      await f.service.publish({
        organizationId:
          f.organizationId,
        subjectType: "finding",
        subjectId: f.findingId,
        projectionType:
          "finding_summary",
        principalId:
          f.principalId,
        asOf: AS_OF,
      });

    assert.equal(
      published.state,
      "published",
    );
    assert.equal(
      published.revision,
      1,
    );

    const publicRecord =
      await f.service.getPublicById(
        published.id,
      );
    const serialized =
      JSON.stringify(
        publicRecord,
      );

    assert.equal(
      serialized.includes(
        "Internal finding narrative",
      ),
      false,
    );
    assert.equal(
      serialized.includes(
        "finding-secret",
      ),
      false,
    );
    assert.equal(
      serialized.includes(
        f.principalId,
      ),
      false,
    );

    const ledger =
      new AuditLedger(f.pool);
    const events =
      await ledger.list(
        f.organizationId,
        "publication",
        published.id,
      );

    assert.equal(
      events.length,
      1,
    );
    assert.equal(
      events[0]?.eventType,
      "publication.published",
    );
    assert.equal(
      (
        events[0]?.payload as any
      ).projectionHash,
      published.projectionHash,
    );

    const unpublished =
      await f.service.unpublish({
        organizationId:
          f.organizationId,
        subjectType: "finding",
        subjectId: f.findingId,
        projectionType:
          "finding_summary",
        principalId:
          f.principalId,
        reason:
          "Publication withdrawn",
      });

    assert.equal(
      unpublished.state,
      "private",
    );

    await assert.rejects(
      f.service.getPublicById(
        published.id,
      ),
      (error: unknown) =>
        error instanceof
          PublicationError &&
        error.code ===
          "not_found",
    );

    const finalEvents =
      await ledger.list(
        f.organizationId,
        "publication",
        published.id,
      );
    assert.deepEqual(
      finalEvents.map(
        (event) =>
          event.eventType,
      ),
      [
        "publication.published",
        "publication.unpublished",
      ],
    );
  } finally {
    await f.pool.end();
  }
});

test("certification publication uses only the pre-existing public artifact", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    const preview =
      await f.service.preview({
        organizationId:
          f.organizationId,
        subjectType:
          "certification",
        subjectId:
          f.certificationId,
        projectionType:
          "certification_summary",
        asOf: AS_OF,
      });

    const serialized =
      JSON.stringify(
        preview.projection,
      );

    assert.equal(
      serialized.includes(
        f.certificateNumber,
      ),
      true,
    );
    assert.equal(
      serialized.includes(
        "full-artifact",
      ),
      false,
    );
    assert.equal(
      serialized.includes(
        "criteria",
      ),
      false,
    );
    assert.equal(
      serialized.includes(
        "conditions",
      ),
      false,
    );
    assert.equal(
      serialized.includes(
        "certification-secret",
      ),
      false,
    );
  } finally {
    await f.pool.end();
  }
});
