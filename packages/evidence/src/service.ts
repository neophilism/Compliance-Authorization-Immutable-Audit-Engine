import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  Evidence,
  EvidenceAttestation,
  JsonObject,
} from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import type { EvaluationContext } from "@caiae/rules";
import {
  EvidenceError,
  type AddAttestationInput,
  type CreateEvidenceInput,
  type EvidenceValidity,
  type EvidenceView,
  type RevokeAttestationInput,
  type RevokeEvidenceInput,
  type RuleEvaluationContextInput,
} from "./types.js";

export class EvidenceService {
  constructor(private readonly pool: Pool) {}

  async create(input: CreateEvidenceInput): Promise<EvidenceView> {
    validateCreateInput(input);

    const client = await this.pool.connect();
    const evidenceId = randomUUID();

    try {
      await client.query("BEGIN");

      await assertResource(
        client,
        input.organizationId,
        input.resourceId,
      );

      if (input.submittedByPrincipalId) {
        await assertPrincipal(
          client,
          input.organizationId,
          input.submittedByPrincipalId,
        );
      }

      const capturedAt = normalizeOptionalDate(
        input.capturedAt,
        "capturedAt",
      );
      const validFrom = normalizeOptionalDate(
        input.validFrom,
        "validFrom",
      );
      const validUntil = normalizeOptionalDate(
        input.validUntil,
        "validUntil",
      );

      validateValidityWindow(validFrom, validUntil);

      const supersedesEvidenceId =
        input.supersedesEvidenceId ?? null;

      if (supersedesEvidenceId) {
        const priorRow = await lockEvidence(
          client,
          supersedesEvidenceId,
        );
        const prior = mapEvidence(priorRow);

        if (
          prior.organizationId !== input.organizationId ||
          prior.resourceId !== input.resourceId
        ) {
          throw new EvidenceError(
            "validation",
            "superseded evidence must belong to the same organization and resource",
          );
        }

        if (prior.evidenceType !== input.evidenceType) {
          throw new EvidenceError(
            "validation",
            "superseded evidence must have the same evidenceType",
          );
        }

        if (prior.status !== "active") {
          throw new EvidenceError(
            "invalid_state",
            "only active evidence can be superseded",
          );
        }

        const supersededAt = new Date().toISOString();

        await client.query(
          `UPDATE evidence
           SET status = 'superseded',
               superseded_at = $2,
               updated_at = now()
           WHERE id = $1`,
          [prior.id, supersededAt],
        );

        await appendAuditEventWithClient(client, {
          organizationId: prior.organizationId,
          aggregateType: "evidence",
          aggregateId: prior.id,
          eventType: "evidence.superseded",
          actorPrincipalId:
            input.submittedByPrincipalId ?? null,
          correlationId: input.correlationId ?? null,
          payload: {
            replacementEvidenceId: evidenceId,
            supersededAt,
          },
        });
      }

      await client.query(
        `INSERT INTO evidence(
           id,
           organization_id,
           resource_id,
           evidence_type,
           title,
           status,
           submitted_by_principal_id,
           source,
           uri,
           media_type,
           file_name,
           checksum_algorithm,
           checksum,
           captured_at,
           valid_from,
           valid_until,
           provenance,
           supersedes_evidence_id,
           attributes,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, 'active', $6, $7, $8, $9,
           $10, $11, $12, $13, $14, $15, $16::jsonb, $17,
           $18::jsonb, $19::jsonb
         )`,
        [
          evidenceId,
          input.organizationId,
          input.resourceId,
          input.evidenceType.trim(),
          input.title.trim(),
          input.submittedByPrincipalId ?? null,
          normalizeNullableString(input.source),
          normalizeNullableString(input.uri),
          normalizeNullableString(input.mediaType),
          normalizeNullableString(input.fileName),
          normalizeNullableString(input.checksumAlgorithm),
          normalizeNullableString(input.checksum),
          capturedAt,
          validFrom,
          validUntil,
          JSON.stringify(input.provenance ?? {}),
          supersedesEvidenceId,
          JSON.stringify(input.attributes ?? {}),
          JSON.stringify(input.metadata ?? {}),
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: input.organizationId,
        aggregateType: "evidence",
        aggregateId: evidenceId,
        eventType: "evidence.created",
        actorPrincipalId:
          input.submittedByPrincipalId ?? null,
        correlationId: input.correlationId ?? null,
        payload: {
          resourceId: input.resourceId,
          evidenceType: input.evidenceType.trim(),
          title: input.title.trim(),
          source: normalizeNullableString(input.source),
          uri: normalizeNullableString(input.uri),
          mediaType: normalizeNullableString(input.mediaType),
          fileName: normalizeNullableString(input.fileName),
          checksumAlgorithm: normalizeNullableString(
            input.checksumAlgorithm,
          ),
          checksum: normalizeNullableString(input.checksum),
          capturedAt,
          validFrom,
          validUntil,
          provenance: input.provenance ?? {},
          supersedesEvidenceId,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(evidenceId);
  }

  async get(evidenceId: string): Promise<EvidenceView> {
    const evidenceResult = await this.pool.query(
      "SELECT * FROM evidence WHERE id = $1",
      [evidenceId],
    );

    if (!evidenceResult.rows[0]) {
      throw new EvidenceError(
        "not_found",
        "evidence not found",
      );
    }

    const attestationsResult = await this.pool.query(
      `SELECT *
       FROM evidence_attestations
       WHERE evidence_id = $1
       ORDER BY attested_at ASC, id ASC`,
      [evidenceId],
    );

    return {
      evidence: mapEvidence(evidenceResult.rows[0]),
      attestations: attestationsResult.rows.map(mapAttestation),
    };
  }

  async listForResource(
    organizationId: string,
    resourceId: string,
  ): Promise<Evidence[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM evidence
       WHERE organization_id = $1
         AND resource_id = $2
       ORDER BY created_at ASC, id ASC`,
      [organizationId, resourceId],
    );

    return result.rows.map(mapEvidence);
  }

  async validity(
    evidenceId: string,
    at = new Date(),
  ): Promise<EvidenceValidity> {
    const { evidence } = await this.get(evidenceId);
    return evaluateValidity(evidence, at);
  }

  async validEvidenceForResource(
    organizationId: string,
    resourceId: string,
    at = new Date(),
  ): Promise<Evidence[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM evidence
       WHERE organization_id = $1
         AND resource_id = $2
         AND status = 'active'
         AND (valid_from IS NULL OR valid_from <= $3)
         AND (valid_until IS NULL OR valid_until > $3)
       ORDER BY created_at ASC, id ASC`,
      [organizationId, resourceId, at.toISOString()],
    );

    return result.rows.map(mapEvidence);
  }

  async validEvidenceTypes(
    organizationId: string,
    resourceId: string,
    at = new Date(),
  ): Promise<string[]> {
    const evidence = await this.validEvidenceForResource(
      organizationId,
      resourceId,
      at,
    );

    return [
      ...new Set(evidence.map((item) => item.evidenceType)),
    ].sort();
  }

  async buildRuleEvaluationContext(
    organizationId: string,
    resourceId: string,
    base: RuleEvaluationContextInput,
    at = new Date(),
  ): Promise<EvaluationContext> {
    return {
      ...base,
      evidenceTypes: await this.validEvidenceTypes(
        organizationId,
        resourceId,
        at,
      ),
    };
  }

  async addAttestation(
    input: AddAttestationInput,
  ): Promise<EvidenceView> {
    validateAttestationInput(input);

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const evidenceRow = await lockEvidence(
        client,
        input.evidenceId,
      );
      const evidence = mapEvidence(evidenceRow);

      if (evidence.status !== "active") {
        throw new EvidenceError(
          "invalid_state",
          "attestations can only be added to active evidence",
        );
      }

      await assertPrincipal(
        client,
        evidence.organizationId,
        input.principalId,
      );

      const attestedAt = input.attestedAt
        ? normalizeRequiredDate(input.attestedAt, "attestedAt")
        : new Date().toISOString();
      const validUntil = normalizeOptionalDate(
        input.validUntil,
        "validUntil",
      );

      if (
        validUntil !== null &&
        new Date(validUntil).getTime() <=
          new Date(attestedAt).getTime()
      ) {
        throw new EvidenceError(
          "validation",
          "attestation validUntil must be after attestedAt",
        );
      }

      const attestationId = randomUUID();

      await client.query(
        `INSERT INTO evidence_attestations(
           id,
           organization_id,
           evidence_id,
           principal_id,
           attestation_type,
           statement,
           claims,
           attested_at,
           valid_until,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::jsonb
         )`,
        [
          attestationId,
          evidence.organizationId,
          evidence.id,
          input.principalId,
          input.attestationType.trim(),
          input.statement.trim(),
          JSON.stringify(input.claims ?? {}),
          attestedAt,
          validUntil,
          JSON.stringify(input.metadata ?? {}),
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: evidence.organizationId,
        aggregateType: "evidence",
        aggregateId: evidence.id,
        eventType: "evidence.attested",
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: {
          attestationId,
          attestationType: input.attestationType.trim(),
          statement: input.statement.trim(),
          claims: input.claims ?? {},
          attestedAt,
          validUntil,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.evidenceId);
  }

  async validAttestations(
    evidenceId: string,
    at = new Date(),
  ): Promise<EvidenceAttestation[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM evidence_attestations
       WHERE evidence_id = $1
         AND revoked_at IS NULL
         AND attested_at <= $2
         AND (valid_until IS NULL OR valid_until > $2)
       ORDER BY attested_at ASC, id ASC`,
      [evidenceId, at.toISOString()],
    );

    return result.rows.map(mapAttestation);
  }

  async revoke(
    input: RevokeEvidenceInput,
  ): Promise<EvidenceView> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new EvidenceError(
        "validation",
        "revocation reason is required",
      );
    }

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const evidenceRow = await lockEvidence(
        client,
        input.evidenceId,
      );
      const evidence = mapEvidence(evidenceRow);

      if (evidence.status !== "active") {
        throw new EvidenceError(
          "invalid_state",
          "only active evidence can be revoked",
        );
      }

      await assertPrincipal(
        client,
        evidence.organizationId,
        input.principalId,
      );

      await client.query(
        `UPDATE evidence
         SET status = 'revoked',
             updated_at = now()
         WHERE id = $1`,
        [evidence.id],
      );

      await appendAuditEventWithClient(client, {
        organizationId: evidence.organizationId,
        aggregateType: "evidence",
        aggregateId: evidence.id,
        eventType: "evidence.revoked",
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: { reason },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.evidenceId);
  }

  async revokeAttestation(
    input: RevokeAttestationInput,
  ): Promise<EvidenceView> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new EvidenceError(
        "validation",
        "revocation reason is required",
      );
    }

    const client = await this.pool.connect();
    let evidenceId = "";

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `SELECT a.*, e.organization_id AS evidence_organization_id,
                e.id AS parent_evidence_id
         FROM evidence_attestations a
         JOIN evidence e ON e.id = a.evidence_id
         WHERE a.id = $1
         FOR UPDATE OF a`,
        [input.attestationId],
      );

      if (!result.rows[0]) {
        throw new EvidenceError(
          "not_found",
          "attestation not found",
        );
      }

      const row = result.rows[0];
      if (row.revoked_at !== null) {
        throw new EvidenceError(
          "invalid_state",
          "attestation is already revoked",
        );
      }

      evidenceId = row.parent_evidence_id;

      await assertPrincipal(
        client,
        row.evidence_organization_id,
        input.principalId,
      );

      const revokedAt = new Date().toISOString();

      await client.query(
        `UPDATE evidence_attestations
         SET revoked_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [input.attestationId, revokedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: row.evidence_organization_id,
        aggregateType: "evidence",
        aggregateId: evidenceId,
        eventType: "evidence.attestation_revoked",
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: {
          attestationId: input.attestationId,
          reason,
          revokedAt,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(evidenceId);
  }
}

export function evaluateValidity(
  evidence: Evidence,
  at = new Date(),
): EvidenceValidity {
  if (evidence.status === "superseded") {
    return { valid: false, reason: "superseded" };
  }

  if (evidence.status === "revoked") {
    return { valid: false, reason: "revoked" };
  }

  const time = at.getTime();

  if (
    evidence.validFrom !== null &&
    time < new Date(evidence.validFrom).getTime()
  ) {
    return { valid: false, reason: "not_yet_valid" };
  }

  if (
    evidence.validUntil !== null &&
    time >= new Date(evidence.validUntil).getTime()
  ) {
    return { valid: false, reason: "expired" };
  }

  return { valid: true, reason: "active" };
}

function validateCreateInput(input: CreateEvidenceInput): void {
  if (!input.organizationId.trim()) {
    throw new EvidenceError(
      "validation",
      "organizationId is required",
    );
  }
  if (!input.resourceId.trim()) {
    throw new EvidenceError(
      "validation",
      "resourceId is required",
    );
  }
  if (!input.evidenceType.trim()) {
    throw new EvidenceError(
      "validation",
      "evidenceType is required",
    );
  }
  if (!input.title.trim()) {
    throw new EvidenceError(
      "validation",
      "title is required",
    );
  }

  const checksum = normalizeNullableString(input.checksum);
  const algorithm = normalizeNullableString(
    input.checksumAlgorithm,
  );

  if ((checksum === null) !== (algorithm === null)) {
    throw new EvidenceError(
      "validation",
      "checksum and checksumAlgorithm must be provided together",
    );
  }
}

function validateAttestationInput(
  input: AddAttestationInput,
): void {
  if (!input.evidenceId.trim()) {
    throw new EvidenceError(
      "validation",
      "evidenceId is required",
    );
  }
  if (!input.principalId.trim()) {
    throw new EvidenceError(
      "validation",
      "principalId is required",
    );
  }
  if (!input.attestationType.trim()) {
    throw new EvidenceError(
      "validation",
      "attestationType is required",
    );
  }
  if (!input.statement.trim()) {
    throw new EvidenceError(
      "validation",
      "statement is required",
    );
  }
}

function validateValidityWindow(
  validFrom: string | null,
  validUntil: string | null,
): void {
  if (
    validFrom !== null &&
    validUntil !== null &&
    new Date(validUntil).getTime() <=
      new Date(validFrom).getTime()
  ) {
    throw new EvidenceError(
      "validation",
      "validUntil must be after validFrom",
    );
  }
}

function normalizeOptionalDate(
  value: string | null | undefined,
  field: string,
): string | null {
  if (value === undefined || value === null) return null;
  return normalizeRequiredDate(value, field);
}

function normalizeRequiredDate(
  value: string,
  field: string,
): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new EvidenceError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
}

function normalizeNullableString(
  value: string | null | undefined,
): string | null {
  if (value === undefined || value === null) return null;
  const normalized = value.trim();
  return normalized === "" ? null : normalized;
}

async function assertResource(
  client: PoolClient,
  organizationId: string,
  resourceId: string,
): Promise<void> {
  const result = await client.query(
    `SELECT 1
     FROM resources
     WHERE id = $1
       AND organization_id = $2
       AND status <> 'archived'`,
    [resourceId, organizationId],
  );

  if (!result.rows[0]) {
    throw new EvidenceError(
      "not_found",
      "resource not found in organization",
    );
  }
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
    throw new EvidenceError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function lockEvidence(
  client: PoolClient,
  evidenceId: string,
): Promise<any> {
  const result = await client.query(
    "SELECT * FROM evidence WHERE id = $1 FOR UPDATE",
    [evidenceId],
  );

  if (!result.rows[0]) {
    throw new EvidenceError(
      "not_found",
      "evidence not found",
    );
  }

  return result.rows[0];
}

function mapEvidence(row: any): Evidence {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    evidenceType: row.evidence_type,
    title: row.title,
    status: row.status,
    submittedByPrincipalId: row.submitted_by_principal_id,
    source: row.source,
    uri: row.uri,
    mediaType: row.media_type,
    fileName: row.file_name,
    checksumAlgorithm: row.checksum_algorithm,
    checksum: row.checksum,
    capturedAt: nullableIso(row.captured_at),
    validFrom: nullableIso(row.valid_from),
    validUntil: nullableIso(row.valid_until),
    provenance: (row.provenance ?? {}) as JsonObject,
    supersedesEvidenceId: row.supersedes_evidence_id,
    supersededAt: nullableIso(row.superseded_at),
    attributes: (row.attributes ?? {}) as JsonObject,
    metadata: (row.metadata ?? {}) as JsonObject,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapAttestation(row: any): EvidenceAttestation {
  return {
    id: row.id,
    organizationId: row.organization_id,
    evidenceId: row.evidence_id,
    principalId: row.principal_id,
    attestationType: row.attestation_type,
    statement: row.statement,
    claims: (row.claims ?? {}) as JsonObject,
    attestedAt: iso(row.attested_at),
    validUntil: nullableIso(row.valid_until),
    revokedAt: nullableIso(row.revoked_at),
    metadata: (row.metadata ?? {}) as JsonObject,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function iso(value: Date | string): string {
  return (
    value instanceof Date ? value : new Date(value)
  ).toISOString();
}

function nullableIso(
  value: Date | string | null | undefined,
): string | null {
  return value === null || value === undefined
    ? null
    : iso(value);
}

function normalizeError(error: unknown): unknown {
  return error instanceof EvidenceError ? error : error;
}
