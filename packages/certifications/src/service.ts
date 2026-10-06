import { randomBytes, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  Certification,
  CertificationStatus,
  JsonObject,
} from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import {
  CertificationError,
  type CertificationActionInput,
  type CertificationCriteria,
  type CertificationSeverity,
  type CertificationSweepResult,
  type CertificationVerification,
  type CertificationView,
  type IssueCertificationInput,
  type MaterialFailureResult,
  type ReinstateCertificationInput,
  type RenewCertificationInput,
} from "./types.js";

const DEFAULT_BLOCKING_SEVERITIES: CertificationSeverity[] = [
  "high",
  "critical",
];

const DEFAULT_MATERIAL_FAILURE_SEVERITIES: CertificationSeverity[] = [
  "high",
  "critical",
];

type NormalizedCriteria = {
  ruleSetId: string | null;
  ruleSetVersion: string | null;
  maximumCheckAgeSeconds: number | null;
  blockingFindingSeverities: CertificationSeverity[];
  materialFailureSeverities: CertificationSeverity[];
};

type SupportingCheck = {
  id: string;
  organizationId: string;
  resourceId: string;
  status: string;
  completedAt: string | null;
  evaluatedAt: string | null;
  requestedByPrincipalId: string | null;
  registeredRuleSetId: string | null;
  ruleSetHash: string | null;
  ruleSetProvenance: Record<string, any>;
  ruleSetSnapshot: Record<string, any>;
  evidenceTrace: unknown[];
  result: Record<string, any>;
};

type PreparedIssuance = {
  id: string;
  organizationId: string;
  resourceId: string;
  supportingCheckId: string;
  certificationType: string;
  status: "pending" | "active";
  certificateNumber: string;
  verificationCode: string;
  issuedByPrincipalId: string;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  criteria: NormalizedCriteria;
  conditions: JsonObject;
  artifact: JsonObject;
  publicArtifact: JsonObject;
  metadata: JsonObject;
  renewedFromCertificationId: string | null;
};

export class CertificationService {
  constructor(private readonly pool: Pool) {}

  async issue(
    input: IssueCertificationInput,
  ): Promise<CertificationView> {
    validateIssueInput(input);

    const prepared = await this.prepareIssuance({
      ...input,
      renewedFromCertificationId: null,
    });

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      await this.insertPreparedCertification(
        client,
        prepared,
        input.correlationId ?? null,
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(prepared.id);
  }

  async renew(
    input: RenewCertificationInput,
  ): Promise<CertificationView> {
    const existing = (
      await this.get(input.certificationId)
    ).certification;

    if (
      existing.status === "revoked" ||
      existing.status === "superseded"
    ) {
      throw new CertificationError(
        "invalid_state",
        "revoked or superseded certifications cannot be renewed",
      );
    }

    const prepared = await this.prepareIssuance({
      organizationId: existing.organizationId,
      resourceId: existing.resourceId,
      certificationType: existing.certificationType,
      supportingCheckId: input.supportingCheckId,
      issuedByPrincipalId: input.issuedByPrincipalId,
      validFrom: input.validFrom,
      validUntil: input.validUntil,
      validitySeconds: input.validitySeconds,
      criteria:
        input.criteria ??
        criteriaFromJson(existing.criteria),
      conditions:
        input.conditions ?? existing.conditions,
      metadata: input.metadata ?? {},
      correlationId: input.correlationId,
      renewedFromCertificationId:
        existing.id,
    });

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const locked = mapCertification(
        await lockCertification(
          client,
          existing.id,
        ),
      );

      if (
        locked.status === "revoked" ||
        locked.status === "superseded"
      ) {
        throw new CertificationError(
          "invalid_state",
          "certification became ineligible for renewal",
        );
      }

      await this.insertPreparedCertification(
        client,
        prepared,
        input.correlationId ?? null,
      );

      const supersededAt = prepared.issuedAt;

      await client.query(
        `UPDATE certifications
         SET status = 'superseded',
             superseded_at = $2,
             superseded_by_certification_id = $3,
             updated_at = now()
         WHERE id = $1`,
        [
          locked.id,
          supersededAt,
          prepared.id,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: locked.organizationId,
        aggregateType: "certification",
        aggregateId: locked.id,
        eventType: "certification.superseded",
        actorPrincipalId:
          input.issuedByPrincipalId,
        occurredAt: supersededAt,
        correlationId: input.correlationId ?? null,
        payload: {
          supersededByCertificationId:
            prepared.id,
          certificateNumber:
            prepared.certificateNumber,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(prepared.id);
  }

  async get(
    certificationId: string,
  ): Promise<CertificationView> {
    const result = await this.pool.query(
      `SELECT *
       FROM certifications
       WHERE id = $1`,
      [certificationId],
    );

    if (!result.rows[0]) {
      throw new CertificationError(
        "not_found",
        "certification not found",
      );
    }

    return {
      certification: mapCertification(
        result.rows[0],
      ),
    };
  }

  async listForResource(
    organizationId: string,
    resourceId: string,
  ): Promise<Certification[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM certifications
       WHERE organization_id = $1
         AND resource_id = $2
         AND certificate_number IS NOT NULL
       ORDER BY issued_at DESC, id DESC`,
      [organizationId, resourceId],
    );

    return result.rows.map(mapCertification);
  }

  async verify(
    verificationCode: string,
    at = new Date(),
  ): Promise<CertificationVerification> {
    const result = await this.pool.query(
      `SELECT *
       FROM certifications
       WHERE verification_code = $1`,
      [verificationCode],
    );

    const checkedAt = at.toISOString();

    if (!result.rows[0]) {
      return {
        found: false,
        valid: false,
        certificationId: null,
        certificateNumber: null,
        storedStatus: null,
        effectiveStatus: null,
        checkedAt,
        publicArtifact: null,
      };
    }

    const certification = mapCertification(
      result.rows[0],
    );
    const effectiveStatus =
      effectiveStatusAt(certification, at);

    return {
      found: true,
      valid: effectiveStatus === "active",
      certificationId: certification.id,
      certificateNumber:
        certification.certificateNumber,
      storedStatus: certification.status,
      effectiveStatus,
      checkedAt,
      publicArtifact:
        certification.publicArtifact,
    };
  }

  async suspend(
    input: CertificationActionInput,
  ): Promise<CertificationView> {
    const reason = requireReason(input.reason);

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const certification = mapCertification(
        await lockCertification(
          client,
          input.certificationId,
        ),
      );

      if (certification.status !== "active") {
        throw new CertificationError(
          "invalid_state",
          "only active certifications can be suspended",
        );
      }

      await assertPrincipal(
        client,
        certification.organizationId,
        input.principalId,
      );

      const suspendedAt =
        new Date().toISOString();

      await client.query(
        `UPDATE certifications
         SET status = 'suspended',
             suspended_at = $2,
             suspended_by_principal_id = $3,
             suspension_reason = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          certification.id,
          suspendedAt,
          input.principalId,
          reason,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId:
          certification.organizationId,
        aggregateType: "certification",
        aggregateId: certification.id,
        eventType: "certification.suspended",
        actorPrincipalId: input.principalId,
        occurredAt: suspendedAt,
        correlationId:
          input.correlationId ?? null,
        payload: {
          reason,
          source: "manual",
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.certificationId);
  }

  async revoke(
    input: CertificationActionInput,
  ): Promise<CertificationView> {
    const reason = requireReason(input.reason);

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const certification = mapCertification(
        await lockCertification(
          client,
          input.certificationId,
        ),
      );

      if (
        !["pending", "active", "suspended"].includes(
          certification.status,
        )
      ) {
        throw new CertificationError(
          "invalid_state",
          "only pending, active, or suspended certifications can be revoked",
        );
      }

      await assertPrincipal(
        client,
        certification.organizationId,
        input.principalId,
      );

      const revokedAt = new Date().toISOString();

      await client.query(
        `UPDATE certifications
         SET status = 'revoked',
             revoked_at = $2,
             revoked_by_principal_id = $3,
             revocation_reason = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          certification.id,
          revokedAt,
          input.principalId,
          reason,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId:
          certification.organizationId,
        aggregateType: "certification",
        aggregateId: certification.id,
        eventType: "certification.revoked",
        actorPrincipalId: input.principalId,
        occurredAt: revokedAt,
        correlationId:
          input.correlationId ?? null,
        payload: { reason },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.certificationId);
  }

  async reinstate(
    input: ReinstateCertificationInput,
  ): Promise<CertificationView> {
    const rationale = input.rationale.trim();

    if (!rationale) {
      throw new CertificationError(
        "validation",
        "reinstatement rationale is required",
      );
    }

    const existing = (
      await this.get(input.certificationId)
    ).certification;

    if (existing.status !== "suspended") {
      throw new CertificationError(
        "invalid_state",
        "only suspended certifications can be reinstated",
      );
    }

    const now = new Date();

    if (
      now.getTime() >=
      new Date(existing.validUntil).getTime()
    ) {
      throw new CertificationError(
        "invalid_state",
        "expired certification cannot be reinstated",
      );
    }

    const check = await this.loadSupportingCheck(
      existing.organizationId,
      existing.resourceId,
      input.supportingCheckId,
    );

    const criteria =
      normalizeCriteria(
        criteriaFromJson(existing.criteria),
      );

    await this.validateCheckAgainstCriteria(
      check,
      criteria,
      now,
    );

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const certification = mapCertification(
        await lockCertification(
          client,
          existing.id,
        ),
      );

      if (certification.status !== "suspended") {
        throw new CertificationError(
          "invalid_state",
          "certification is no longer suspended",
        );
      }

      await assertPrincipal(
        client,
        certification.organizationId,
        input.principalId,
      );

      const reinstatedAt =
        now.toISOString();

      await client.query(
        `UPDATE certifications
         SET status = 'active',
             reinstated_at = $2,
             reinstated_by_principal_id = $3,
             reinstatement_check_id = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          certification.id,
          reinstatedAt,
          input.principalId,
          check.id,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId:
          certification.organizationId,
        aggregateType: "certification",
        aggregateId: certification.id,
        eventType: "certification.reinstated",
        actorPrincipalId: input.principalId,
        occurredAt: reinstatedAt,
        correlationId:
          input.correlationId ?? null,
        payload: {
          rationale,
          supportingCheckId: check.id,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.certificationId);
  }

  async suspendForMaterialFailure(
    checkId: string,
    correlationId?: string | null,
  ): Promise<MaterialFailureResult> {
    const client = await this.pool.connect();
    let certificationsExamined = 0;
    let certificationsSuspended = 0;

    try {
      await client.query("BEGIN");

      const checkResult = await client.query(
        `SELECT *
         FROM checks
         WHERE id = $1
         FOR UPDATE`,
        [checkId],
      );

      if (!checkResult.rows[0]) {
        throw new CertificationError(
          "not_found",
          "check not found",
        );
      }

      const check = mapSupportingCheck(
        checkResult.rows[0],
      );

      if (check.status !== "failed") {
        throw new CertificationError(
          "invalid_state",
          "material-failure suspension requires a failed check",
        );
      }

      const failedSeverities =
        failedRuleSeverities(check.result);
      const checkTime = new Date(
        check.evaluatedAt ??
          check.completedAt ??
          new Date().toISOString(),
      );

      const certificationResult =
        await client.query(
          `SELECT *
           FROM certifications
           WHERE organization_id = $1
             AND resource_id = $2
             AND status = 'active'
             AND certificate_number IS NOT NULL
           ORDER BY issued_at ASC, id ASC
           FOR UPDATE`,
          [
            check.organizationId,
            check.resourceId,
          ],
        );

      for (const row of certificationResult.rows) {
        const certification =
          mapCertification(row);
        certificationsExamined += 1;

        if (
          checkTime.getTime() <
            new Date(
              certification.validFrom,
            ).getTime() ||
          checkTime.getTime() >=
            new Date(
              certification.validUntil,
            ).getTime()
        ) {
          continue;
        }

        const criteria =
          normalizeCriteria(
            criteriaFromJson(
              certification.criteria,
            ),
          );
        const material =
          criteria.materialFailureSeverities.filter(
            (severity) =>
              failedSeverities.has(severity),
          );

        if (material.length === 0) {
          continue;
        }

        const suspendedAt =
          check.completedAt ??
          check.evaluatedAt ??
          new Date().toISOString();
        const reason =
          `Material compliance failure in check ${check.id}: ${material.join(", ")} severity rule failure.`;

        const updated = await client.query(
          `UPDATE certifications
           SET status = 'suspended',
               suspended_at = $2,
               suspended_by_principal_id = NULL,
               suspension_reason = $3,
               suspension_check_id = $4,
               updated_at = now()
           WHERE id = $1
             AND status = 'active'
           RETURNING id`,
          [
            certification.id,
            suspendedAt,
            reason,
            check.id,
          ],
        );

        if (!updated.rows[0]) continue;

        certificationsSuspended += 1;

        await appendAuditEventWithClient(client, {
          organizationId:
            certification.organizationId,
          aggregateType: "certification",
          aggregateId: certification.id,
          eventType:
            "certification.suspended",
          actorPrincipalId: null,
          occurredAt: suspendedAt,
          correlationId:
            correlationId ?? null,
          payload: {
            reason,
            source:
              "material_compliance_failure",
            supportingCheckId: check.id,
            failedSeverities: [
              ...failedSeverities,
            ],
            materialFailureSeverities:
              material,
          },
        });
      }

      await client.query("COMMIT");

      return {
        certificationsExamined,
        certificationsSuspended,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async sweep(
    at = new Date(),
  ): Promise<CertificationSweepResult> {
    const client = await this.pool.connect();
    let examined = 0;
    let activated = 0;
    let expired = 0;

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `SELECT *
         FROM certifications
         WHERE status IN (
           'pending',
           'active',
           'suspended'
         )
           AND certificate_number IS NOT NULL
         ORDER BY valid_until ASC, id ASC
         FOR UPDATE SKIP LOCKED`,
      );

      for (const row of result.rows) {
        const certification =
          mapCertification(row);
        examined += 1;

        if (
          at.getTime() >=
          new Date(
            certification.validUntil,
          ).getTime()
        ) {
          await client.query(
            `UPDATE certifications
             SET status = 'expired',
                 updated_at = now()
             WHERE id = $1`,
            [certification.id],
          );

          await appendAuditEventWithClient(client, {
            organizationId:
              certification.organizationId,
            aggregateType: "certification",
            aggregateId: certification.id,
            eventType:
              "certification.expired",
            occurredAt:
              certification.validUntil,
            payload: {
              validUntil:
                certification.validUntil,
            },
          });

          expired += 1;
          continue;
        }

        if (
          certification.status === "pending" &&
          at.getTime() >=
            new Date(
              certification.validFrom,
            ).getTime()
        ) {
          await client.query(
            `UPDATE certifications
             SET status = 'active',
                 updated_at = now()
             WHERE id = $1`,
            [certification.id],
          );

          await appendAuditEventWithClient(client, {
            organizationId:
              certification.organizationId,
            aggregateType: "certification",
            aggregateId: certification.id,
            eventType:
              "certification.activated",
            occurredAt:
              certification.validFrom,
            payload: {
              validFrom:
                certification.validFrom,
            },
          });

          activated += 1;
        }
      }

      await client.query("COMMIT");

      return {
        examined,
        activated,
        expired,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  private async prepareIssuance(
    input: IssueCertificationInput & {
      renewedFromCertificationId: string | null;
    },
  ): Promise<PreparedIssuance> {
    validateIssueInput(input);

    const issuedAtDate = new Date();
    const issuedAt = issuedAtDate.toISOString();
    const validFrom = input.validFrom
      ? normalizeRequiredDate(
          input.validFrom,
          "validFrom",
        )
      : issuedAt;
    const validUntil =
      resolveValidUntil(
        validFrom,
        input.validUntil,
        input.validitySeconds,
      );

    if (
      new Date(validUntil).getTime() <=
      new Date(validFrom).getTime()
    ) {
      throw new CertificationError(
        "validation",
        "validUntil must be after validFrom",
      );
    }

    if (
      new Date(validUntil).getTime() <=
      issuedAtDate.getTime()
    ) {
      throw new CertificationError(
        "validation",
        "certification validity must extend beyond issuance time",
      );
    }

    await this.assertPrincipalOutsideTransaction(
      input.organizationId,
      input.issuedByPrincipalId,
    );

    const check =
      await this.loadSupportingCheck(
        input.organizationId,
        input.resourceId,
        input.supportingCheckId,
      );
    const criteria =
      normalizeCriteria(input.criteria);

    await this.validateCheckAgainstCriteria(
      check,
      criteria,
      issuedAtDate,
    );

    const id = randomUUID();
    const certificateNumber =
      `CERT-${randomUUID().replaceAll("-", "").slice(0, 16).toUpperCase()}`;
    const verificationCode =
      randomBytes(24).toString("hex");
    const status =
      new Date(validFrom).getTime() >
      issuedAtDate.getTime()
        ? "pending"
        : "active";
    const conditions =
      input.conditions ?? {};

    const supportingSummary =
      supportingCheckSummary(check);
    const criteriaJson =
      toJsonObject(criteria);

    const artifact = toJsonObject({
      schemaVersion: "1",
      certificationId: id,
      certificateNumber,
      verificationCode,
      organizationId: input.organizationId,
      resourceId: input.resourceId,
      certificationType:
        input.certificationType.trim(),
      issuanceStatus: status,
      issuedByPrincipalId:
        input.issuedByPrincipalId,
      issuedAt,
      validFrom,
      validUntil,
      criteria: criteriaJson,
      conditions,
      supportingCheck:
        supportingSummary,
      renewedFromCertificationId:
        input.renewedFromCertificationId,
    });

    const publicArtifact =
      toJsonObject({
        schemaVersion: "1",
        certificationId: id,
        certificateNumber,
        organizationId:
          input.organizationId,
        resourceId: input.resourceId,
        certificationType:
          input.certificationType.trim(),
        issuedAt,
        validFrom,
        validUntil,
        supportingCheck: {
          id: check.id,
          evaluatedAt:
            check.evaluatedAt,
          ruleSetId:
            stringOrNull(
              check.ruleSetSnapshot.id,
            ),
          ruleSetVersion:
            stringOrNull(
              check.ruleSetSnapshot.version,
            ),
          registeredRuleSetId:
            check.registeredRuleSetId,
          ruleSetHash:
            check.ruleSetHash,
        },
      });

    return {
      id,
      organizationId:
        input.organizationId,
      resourceId: input.resourceId,
      supportingCheckId: check.id,
      certificationType:
        input.certificationType.trim(),
      status,
      certificateNumber,
      verificationCode,
      issuedByPrincipalId:
        input.issuedByPrincipalId,
      issuedAt,
      validFrom,
      validUntil,
      criteria,
      conditions,
      artifact,
      publicArtifact,
      metadata: input.metadata ?? {},
      renewedFromCertificationId:
        input.renewedFromCertificationId,
    };
  }

  private async insertPreparedCertification(
    client: PoolClient,
    prepared: PreparedIssuance,
    correlationId: string | null,
  ): Promise<void> {
    await client.query(
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
         renewed_from_certification_id,
         metadata
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9,
         $10, $11, $12, $13::jsonb, $14::jsonb,
         $15::jsonb, $16::jsonb, $17, $18::jsonb
       )`,
      [
        prepared.id,
        prepared.organizationId,
        prepared.resourceId,
        prepared.supportingCheckId,
        prepared.certificationType,
        prepared.status,
        prepared.certificateNumber,
        prepared.verificationCode,
        prepared.issuedByPrincipalId,
        prepared.issuedAt,
        prepared.validFrom,
        prepared.validUntil,
        JSON.stringify(
          toJsonObject(
            prepared.criteria,
          ),
        ),
        JSON.stringify(
          prepared.conditions,
        ),
        JSON.stringify(
          prepared.artifact,
        ),
        JSON.stringify(
          prepared.publicArtifact,
        ),
        prepared.renewedFromCertificationId,
        JSON.stringify(prepared.metadata),
      ],
    );

    await appendAuditEventWithClient(client, {
      organizationId:
        prepared.organizationId,
      aggregateType: "certification",
      aggregateId: prepared.id,
      eventType: "certification.issued",
      actorPrincipalId:
        prepared.issuedByPrincipalId,
      occurredAt: prepared.issuedAt,
      correlationId,
      payload: {
        certificateNumber:
          prepared.certificateNumber,
        resourceId: prepared.resourceId,
        certificationType:
          prepared.certificationType,
        supportingCheckId:
          prepared.supportingCheckId,
        status: prepared.status,
        validFrom: prepared.validFrom,
        validUntil: prepared.validUntil,
        renewedFromCertificationId:
          prepared.renewedFromCertificationId,
      },
    });
  }

  private async validateCheckAgainstCriteria(
    check: SupportingCheck,
    criteria: NormalizedCriteria,
    decisionTime: Date,
  ): Promise<void> {
    if (check.status !== "passed") {
      throw new CertificationError(
        "invalid_state",
        "supporting check must have passed",
      );
    }

    const checkRuleSetId =
      stringOrNull(
        check.ruleSetSnapshot.id,
      );
    const checkRuleSetVersion =
      stringOrNull(
        check.ruleSetSnapshot.version,
      );

    if (
      criteria.ruleSetId !== null &&
      checkRuleSetId !== criteria.ruleSetId
    ) {
      throw new CertificationError(
        "invalid_state",
        "supporting check ruleset does not satisfy certification criteria",
      );
    }

    if (
      criteria.ruleSetVersion !== null &&
      checkRuleSetVersion !==
        criteria.ruleSetVersion
    ) {
      throw new CertificationError(
        "invalid_state",
        "supporting check ruleset version does not satisfy certification criteria",
      );
    }

    if (
      criteria.maximumCheckAgeSeconds !== null
    ) {
      const checkTimeRaw =
        check.evaluatedAt ??
        check.completedAt;

      if (checkTimeRaw === null) {
        throw new CertificationError(
          "invalid_state",
          "supporting check has no evaluation timestamp",
        );
      }

      const ageSeconds =
        Math.floor(
          (
            decisionTime.getTime() -
            new Date(
              checkTimeRaw,
            ).getTime()
          ) / 1_000,
        );

      if (
        ageSeconds < 0 ||
        ageSeconds >
          criteria.maximumCheckAgeSeconds
      ) {
        throw new CertificationError(
          "invalid_state",
          "supporting check is outside the permitted age window",
        );
      }
    }

    if (
      criteria.blockingFindingSeverities
        .length > 0
    ) {
      const blocking =
        await this.pool.query(
          `SELECT id
           FROM findings
           WHERE organization_id = $1
             AND resource_id = $2
             AND status NOT IN (
               'resolved',
               'closed'
             )
             AND severity = ANY($3::text[])
           LIMIT 1`,
          [
            check.organizationId,
            check.resourceId,
            criteria.blockingFindingSeverities,
          ],
        );

      if (blocking.rows[0]) {
        throw new CertificationError(
          "invalid_state",
          "unresolved material findings block certification",
        );
      }
    }
  }

  private async loadSupportingCheck(
    organizationId: string,
    resourceId: string,
    checkId: string,
  ): Promise<SupportingCheck> {
    const result = await this.pool.query(
      `SELECT *
       FROM checks
       WHERE id = $1
         AND organization_id = $2
         AND resource_id = $3`,
      [
        checkId,
        organizationId,
        resourceId,
      ],
    );

    if (!result.rows[0]) {
      throw new CertificationError(
        "not_found",
        "supporting check not found for resource",
      );
    }

    return mapSupportingCheck(
      result.rows[0],
    );
  }

  private async assertPrincipalOutsideTransaction(
    organizationId: string,
    principalId: string,
  ): Promise<void> {
    const result = await this.pool.query(
      `SELECT 1
       FROM principals
       WHERE id = $1
         AND organization_id = $2
         AND status = 'active'`,
      [principalId, organizationId],
    );

    if (!result.rows[0]) {
      throw new CertificationError(
        "not_found",
        "active principal not found in organization",
      );
    }
  }
}

function validateIssueInput(
  input: IssueCertificationInput,
): void {
  if (!input.organizationId.trim()) {
    throw new CertificationError(
      "validation",
      "organizationId is required",
    );
  }
  if (!input.resourceId.trim()) {
    throw new CertificationError(
      "validation",
      "resourceId is required",
    );
  }
  if (!input.certificationType.trim()) {
    throw new CertificationError(
      "validation",
      "certificationType is required",
    );
  }
  if (!input.supportingCheckId.trim()) {
    throw new CertificationError(
      "validation",
      "supportingCheckId is required",
    );
  }
  if (!input.issuedByPrincipalId.trim()) {
    throw new CertificationError(
      "validation",
      "issuedByPrincipalId is required",
    );
  }

  const hasUntil =
    input.validUntil !== undefined;
  const hasSeconds =
    input.validitySeconds !== undefined;

  if (hasUntil === hasSeconds) {
    throw new CertificationError(
      "validation",
      "provide exactly one of validUntil or validitySeconds",
    );
  }

  if (input.validitySeconds !== undefined) {
    validatePositiveSafeInteger(
      input.validitySeconds,
      "validitySeconds",
    );
  }

  normalizeCriteria(input.criteria);
}

function normalizeCriteria(
  input:
    | CertificationCriteria
    | undefined,
): NormalizedCriteria {
  const ruleSetId =
    normalizeNullableString(
      input?.ruleSetId,
    );
  const ruleSetVersion =
    normalizeNullableString(
      input?.ruleSetVersion,
    );
  const maximumCheckAgeSeconds =
    input?.maximumCheckAgeSeconds ??
    null;

  if (
    maximumCheckAgeSeconds !== null
  ) {
    validatePositiveSafeInteger(
      maximumCheckAgeSeconds,
      "maximumCheckAgeSeconds",
    );
  }

  return {
    ruleSetId,
    ruleSetVersion,
    maximumCheckAgeSeconds,
    blockingFindingSeverities:
      normalizeSeverities(
        input?.blockingFindingSeverities ??
          DEFAULT_BLOCKING_SEVERITIES,
        "blockingFindingSeverities",
      ),
    materialFailureSeverities:
      normalizeSeverities(
        input?.materialFailureSeverities ??
          DEFAULT_MATERIAL_FAILURE_SEVERITIES,
        "materialFailureSeverities",
      ),
  };
}

function criteriaFromJson(
  value: JsonObject,
): CertificationCriteria {
  const raw =
    value as Record<string, unknown>;

  return {
    ruleSetId:
      typeof raw.ruleSetId === "string"
        ? raw.ruleSetId
        : null,
    ruleSetVersion:
      typeof raw.ruleSetVersion === "string"
        ? raw.ruleSetVersion
        : null,
    maximumCheckAgeSeconds:
      typeof raw.maximumCheckAgeSeconds ===
      "number"
        ? raw.maximumCheckAgeSeconds
        : null,
    blockingFindingSeverities:
      Array.isArray(
        raw.blockingFindingSeverities,
      )
        ? raw.blockingFindingSeverities as CertificationSeverity[]
        : undefined,
    materialFailureSeverities:
      Array.isArray(
        raw.materialFailureSeverities,
      )
        ? raw.materialFailureSeverities as CertificationSeverity[]
        : undefined,
  };
}

function normalizeSeverities(
  values: CertificationSeverity[],
  field: string,
): CertificationSeverity[] {
  if (!Array.isArray(values)) {
    throw new CertificationError(
      "validation",
      `${field} must be an array`,
    );
  }

  const normalized =
    values.map((value, index) => {
      if (
        value !== "info" &&
        value !== "low" &&
        value !== "medium" &&
        value !== "high" &&
        value !== "critical"
      ) {
        throw new CertificationError(
          "validation",
          `${field}[${index}] is invalid`,
        );
      }
      return value;
    });

  return [...new Set(normalized)];
}

function resolveValidUntil(
  validFrom: string,
  validUntil: string | undefined,
  validitySeconds: number | undefined,
): string {
  if (validUntil !== undefined) {
    return normalizeRequiredDate(
      validUntil,
      "validUntil",
    );
  }

  return new Date(
    new Date(validFrom).getTime() +
      validitySeconds! * 1_000,
  ).toISOString();
}

function effectiveStatusAt(
  certification: Certification,
  at: Date,
): CertificationStatus {
  if (
    certification.status === "revoked" ||
    certification.status === "expired" ||
    certification.status === "superseded"
  ) {
    return certification.status;
  }

  if (
    at.getTime() >=
    new Date(
      certification.validUntil,
    ).getTime()
  ) {
    return "expired";
  }

  if (
    at.getTime() <
    new Date(
      certification.validFrom,
    ).getTime()
  ) {
    return "pending";
  }

  if (
    certification.status === "suspended"
  ) {
    return "suspended";
  }

  return "active";
}

function supportingCheckSummary(
  check: SupportingCheck,
): JsonObject {
  const resultCounts =
    check.result.counts !== null &&
    typeof check.result.counts ===
      "object" &&
    !Array.isArray(check.result.counts)
      ? check.result.counts
      : {};

  return toJsonObject({
    id: check.id,
    status: check.status,
    evaluatedAt: check.evaluatedAt,
    completedAt: check.completedAt,
    ruleSetId:
      stringOrNull(
        check.ruleSetSnapshot.id,
      ),
    ruleSetVersion:
      stringOrNull(
        check.ruleSetSnapshot.version,
      ),
    registeredRuleSetId:
      check.registeredRuleSetId,
    ruleSetHash:
      check.ruleSetHash,
    ruleSetProvenance:
      toJsonObject(
        check.ruleSetProvenance,
      ),
    counts: resultCounts,
    evidenceIds:
      check.evidenceTrace
        .map((item) => {
          if (
            item !== null &&
            typeof item === "object" &&
            !Array.isArray(item) &&
            typeof (
              item as Record<string, unknown>
            ).evidenceId === "string"
          ) {
            return (
              item as Record<string, string>
            ).evidenceId;
          }
          return null;
        })
        .filter(
          (value): value is string =>
            value !== null,
        ),
  });
}

function failedRuleSeverities(
  result: Record<string, any>,
): Set<CertificationSeverity> {
  const severities =
    new Set<CertificationSeverity>();
  const rules = Array.isArray(result.rules)
    ? result.rules
    : [];

  for (const item of rules) {
    if (
      item === null ||
      typeof item !== "object" ||
      Array.isArray(item)
    ) {
      continue;
    }

    const rule =
      item as Record<string, unknown>;

    if (rule.status !== "fail") {
      continue;
    }

    const severity = rule.severity;

    if (
      severity === "info" ||
      severity === "low" ||
      severity === "medium" ||
      severity === "high" ||
      severity === "critical"
    ) {
      severities.add(severity);
    }
  }

  return severities;
}

async function assertPrincipal(
  client: PoolClient,
  organizationId: string,
  principalId: string,
): Promise<void> {
  const result = await client.query(
    `SELECT 1
     FROM principals
     WHERE id = $1
       AND organization_id = $2
       AND status = 'active'`,
    [principalId, organizationId],
  );

  if (!result.rows[0]) {
    throw new CertificationError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function lockCertification(
  client: PoolClient,
  certificationId: string,
): Promise<any> {
  const result = await client.query(
    `SELECT *
     FROM certifications
     WHERE id = $1
     FOR UPDATE`,
    [certificationId],
  );

  if (!result.rows[0]) {
    throw new CertificationError(
      "not_found",
      "certification not found",
    );
  }

  return result.rows[0];
}

function mapSupportingCheck(
  row: any,
): SupportingCheck {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    status: row.status,
    completedAt:
      nullableIso(row.completed_at),
    evaluatedAt:
      nullableIso(row.evaluated_at),
    requestedByPrincipalId:
      row.requested_by_principal_id,
    registeredRuleSetId:
      row.rule_set_id ?? null,
    ruleSetHash:
      row.rule_set_hash ?? null,
    ruleSetProvenance:
      row.rule_set_provenance ?? {},
    ruleSetSnapshot:
      row.rule_set_snapshot ?? {},
    evidenceTrace:
      Array.isArray(row.evidence_trace)
        ? row.evidence_trace
        : [],
    result: row.result ?? {},
  };
}

function mapCertification(
  row: any,
): Certification {
  if (
    row.certificate_number === null ||
    row.verification_code === null ||
    row.supporting_check_id === null ||
    row.issued_by_principal_id === null ||
    row.issued_at === null ||
    row.valid_from === null ||
    row.valid_until === null
  ) {
    throw new CertificationError(
      "invalid_state",
      "legacy certification record is missing PR 11 issuance fields",
    );
  }

  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    supportingCheckId:
      row.supporting_check_id,
    certificationType:
      row.certification_type,
    status: row.status,
    certificateNumber:
      row.certificate_number,
    verificationCode:
      row.verification_code,
    issuedByPrincipalId:
      row.issued_by_principal_id,
    issuedAt: iso(row.issued_at),
    validFrom: iso(row.valid_from),
    validUntil: iso(row.valid_until),
    criteria: row.criteria ?? {},
    conditions: row.conditions ?? {},
    artifact: row.artifact ?? {},
    publicArtifact:
      row.public_artifact ?? {},
    suspendedAt:
      nullableIso(row.suspended_at),
    suspendedByPrincipalId:
      row.suspended_by_principal_id,
    suspensionReason:
      row.suspension_reason,
    suspensionCheckId:
      row.suspension_check_id,
    reinstatedAt:
      nullableIso(row.reinstated_at),
    reinstatedByPrincipalId:
      row.reinstated_by_principal_id,
    reinstatementCheckId:
      row.reinstatement_check_id,
    revokedAt:
      nullableIso(row.revoked_at),
    revokedByPrincipalId:
      row.revoked_by_principal_id,
    revocationReason:
      row.revocation_reason,
    renewedFromCertificationId:
      row.renewed_from_certification_id,
    supersededAt:
      nullableIso(row.superseded_at),
    supersededByCertificationId:
      row.superseded_by_certification_id,
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function requireReason(
  value: string,
): string {
  const reason = value.trim();

  if (!reason) {
    throw new CertificationError(
      "validation",
      "reason is required",
    );
  }

  return reason;
}

function normalizeRequiredDate(
  value: string,
  field: string,
): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new CertificationError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }

  return date.toISOString();
}

function validatePositiveSafeInteger(
  value: number,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw new CertificationError(
      "validation",
      `${field} must be a positive safe integer`,
    );
  }
}

function normalizeNullableString(
  value:
    | string
    | null
    | undefined,
): string | null {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const normalized = value.trim();

  return normalized === ""
    ? null
    : normalized;
}

function stringOrNull(
  value: unknown,
): string | null {
  return typeof value === "string"
    ? value
    : null;
}

function toJsonObject(
  value: unknown,
): JsonObject {
  return JSON.parse(
    JSON.stringify(value),
  ) as JsonObject;
}

function iso(
  value: Date | string,
): string {
  return (
    value instanceof Date
      ? value
      : new Date(value)
  ).toISOString();
}

function nullableIso(
  value:
    | Date
    | string
    | null
    | undefined,
): string | null {
  return value === null ||
    value === undefined
    ? null
    : iso(value);
}

function normalizeError(
  error: unknown,
): unknown {
  return error instanceof CertificationError
    ? error
    : error;
}
