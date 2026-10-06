import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  Authorization,
  AuthorizationDecision,
  JsonObject,
} from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import {
  AuthorizationError,
  type AuthorizationEffectiveness,
  type AuthorizationRecord,
  type ExpirationResult,
  type RecordAuthorizationDecisionInput,
  type RequestAuthorizationInput,
  type RevokeAuthorizationInput,
} from "./types.js";

export class AuthorizationService {
  constructor(private readonly pool: Pool) {}

  async request(
    input: RequestAuthorizationInput,
  ): Promise<AuthorizationRecord> {
    validateRequest(input);

    const client = await this.pool.connect();
    let authorizationId = "";
    try {
      await client.query("BEGIN");

      await assertResource(
        client,
        input.organizationId,
        input.resourceId,
      );
      await assertPrincipal(
        client,
        input.organizationId,
        input.requestedByPrincipalId,
      );

      const eligibleApproverPrincipalIds = [
        ...new Set(input.eligibleApproverPrincipalIds ?? []),
      ];

      for (const principalId of eligibleApproverPrincipalIds) {
        await assertPrincipal(
          client,
          input.organizationId,
          principalId,
        );
      }

      const approvalQuorum = input.approvalQuorum ?? 1;
      if (
        eligibleApproverPrincipalIds.length > 0 &&
        approvalQuorum > eligibleApproverPrincipalIds.length
      ) {
        throw new AuthorizationError(
          "validation",
          "approvalQuorum cannot exceed the number of eligible approvers",
        );
      }

      const requestedAt = new Date().toISOString();
      const emergency = input.emergency ?? false;
      const validFrom = normalizeOptionalDate(
        input.validFrom,
        "validFrom",
      );
      const validUntil = normalizeOptionalDate(
        input.validUntil,
        "validUntil",
      );
      const emergencyReviewDueAt = normalizeOptionalDate(
        input.emergencyReviewDueAt,
        "emergencyReviewDueAt",
      );

      validateWindows({
        requestedAt,
        validFrom,
        validUntil,
        emergency,
        emergencyReviewDueAt,
      });

      authorizationId = randomUUID();
      const initialStatus = emergency ? "approved" : "pending";
      const effectiveValidFrom =
        emergency && validFrom === null ? requestedAt : validFrom;

      await client.query(
        `INSERT INTO authorizations(
           id,
           organization_id,
           resource_id,
           authorization_type,
           status,
           requested_by_principal_id,
           requested_at,
           valid_from,
           valid_until,
           scope,
           conditions,
           approval_quorum,
           approval_authority,
           emergency,
           emergency_review_due_at,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9,
           $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16::jsonb
         )`,
        [
          authorizationId,
          input.organizationId,
          input.resourceId,
          input.authorizationType,
          initialStatus,
          input.requestedByPrincipalId,
          requestedAt,
          effectiveValidFrom,
          validUntil,
          JSON.stringify(input.scope ?? {}),
          JSON.stringify(input.conditions ?? {}),
          approvalQuorum,
          input.approvalAuthority ?? null,
          emergency,
          emergencyReviewDueAt,
          JSON.stringify(input.metadata ?? {}),
        ],
      );

      for (const principalId of eligibleApproverPrincipalIds) {
        await client.query(
          `INSERT INTO authorization_eligible_approvers(
             organization_id,
             authorization_id,
             principal_id
           ) VALUES ($1, $2, $3)`,
          [input.organizationId, authorizationId, principalId],
        );
      }

      await appendAuditEventWithClient(client, {
        organizationId: input.organizationId,
        aggregateType: "authorization",
        aggregateId: authorizationId,
        eventType: "authorization.requested",
        actorPrincipalId: input.requestedByPrincipalId,
        correlationId: input.correlationId ?? null,
        payload: {
          authorizationType: input.authorizationType,
          resourceId: input.resourceId,
          approvalQuorum,
          approvalAuthority: input.approvalAuthority ?? null,
          emergency,
          validFrom: effectiveValidFrom,
          validUntil,
          emergencyReviewDueAt,
          scope: input.scope ?? {},
          conditions: input.conditions ?? {},
          eligibleApproverCount: eligibleApproverPrincipalIds.length,
        },
      });

      if (emergency) {
        await appendAuditEventWithClient(client, {
          organizationId: input.organizationId,
          aggregateType: "authorization",
          aggregateId: authorizationId,
          eventType: "authorization.emergency_granted",
          actorPrincipalId: input.requestedByPrincipalId,
          correlationId: input.correlationId ?? null,
          payload: {
            validFrom: effectiveValidFrom,
            validUntil,
            emergencyReviewDueAt,
          },
        });
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizePgError(error);
    } finally {
      client.release();
    }

    return this.get(authorizationId);
  }

  async get(authorizationId: string): Promise<AuthorizationRecord> {
    const authorizationResult = await this.pool.query(
      "SELECT * FROM authorizations WHERE id = $1",
      [authorizationId],
    );

    if (!authorizationResult.rows[0]) {
      throw new AuthorizationError(
        "not_found",
        "authorization not found",
      );
    }

    const decisionsResult = await this.pool.query(
      `SELECT *
       FROM authorization_decisions
       WHERE authorization_id = $1
       ORDER BY decided_at ASC, id ASC`,
      [authorizationId],
    );

    const approversResult = await this.pool.query(
      `SELECT principal_id
       FROM authorization_eligible_approvers
       WHERE authorization_id = $1
       ORDER BY principal_id ASC`,
      [authorizationId],
    );

    const decisions = decisionsResult.rows.map(mapDecision);

    return {
      authorization: mapAuthorization(authorizationResult.rows[0]),
      decisions,
      eligibleApproverPrincipalIds: approversResult.rows.map(
        (row) => row.principal_id as string,
      ),
      approvalCount: decisions.filter(
        (decision) => decision.decision === "approve",
      ).length,
    };
  }

  async recordDecision(
    input: RecordAuthorizationDecisionInput,
  ): Promise<AuthorizationRecord> {
    const rationale = input.rationale?.trim() ?? "";
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const row = await lockAuthorization(
        client,
        input.authorizationId,
      );
      const authorization = mapAuthorization(row);

      assertReviewable(authorization);
      assertEmergencyReviewDeadlineOpen(authorization, new Date());

      await assertPrincipal(
        client,
        authorization.organizationId,
        input.principalId,
      );
      await assertEligibleApprover(
        client,
        authorization.id,
        input.principalId,
      );

      const decidedAt = new Date().toISOString();

      await client.query(
        `INSERT INTO authorization_decisions(
           id,
           organization_id,
           authorization_id,
           principal_id,
           decision,
           rationale,
           decided_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          randomUUID(),
          authorization.organizationId,
          authorization.id,
          input.principalId,
          input.decision,
          rationale,
          decidedAt,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: authorization.organizationId,
        aggregateType: "authorization",
        aggregateId: authorization.id,
        eventType: "authorization.decision_recorded",
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: {
          decision: input.decision,
          rationale,
        },
      });

      if (input.decision === "deny") {
        const nextStatus = authorization.emergency
          ? "revoked"
          : "denied";

        await client.query(
          `UPDATE authorizations
           SET status = $2,
               decided_by_principal_id = $3,
               decided_at = $4,
               emergency_reviewed_at =
                 CASE WHEN emergency THEN $4 ELSE emergency_reviewed_at END,
               updated_at = now()
           WHERE id = $1`,
          [
            authorization.id,
            nextStatus,
            input.principalId,
            decidedAt,
          ],
        );

        await appendAuditEventWithClient(client, {
          organizationId: authorization.organizationId,
          aggregateType: "authorization",
          aggregateId: authorization.id,
          eventType: authorization.emergency
            ? "authorization.emergency_review_denied"
            : "authorization.denied",
          actorPrincipalId: input.principalId,
          correlationId: input.correlationId ?? null,
          payload: { rationale },
        });
      } else {
        const approvals = await client.query<{ count: string }>(
          `SELECT count(*)::text AS count
           FROM authorization_decisions
           WHERE authorization_id = $1
             AND decision = 'approve'`,
          [authorization.id],
        );
        const approvalCount = Number(approvals.rows[0]?.count ?? "0");

        if (approvalCount >= authorization.approvalQuorum) {
          if (authorization.emergency) {
            await client.query(
              `UPDATE authorizations
               SET decided_by_principal_id = $2,
                   decided_at = $3,
                   emergency_reviewed_at = $3,
                   updated_at = now()
               WHERE id = $1`,
              [authorization.id, input.principalId, decidedAt],
            );

            await appendAuditEventWithClient(client, {
              organizationId: authorization.organizationId,
              aggregateType: "authorization",
              aggregateId: authorization.id,
              eventType: "authorization.emergency_review_approved",
              actorPrincipalId: input.principalId,
              correlationId: input.correlationId ?? null,
              payload: {
                approvalCount,
                approvalQuorum: authorization.approvalQuorum,
              },
            });
          } else if (
            authorization.validUntil !== null &&
            new Date(authorization.validUntil).getTime() <=
              new Date(decidedAt).getTime()
          ) {
            await client.query(
              `UPDATE authorizations
               SET status = 'expired',
                   decided_by_principal_id = $2,
                   decided_at = $3,
                   updated_at = now()
               WHERE id = $1`,
              [authorization.id, input.principalId, decidedAt],
            );

            await appendAuditEventWithClient(client, {
              organizationId: authorization.organizationId,
              aggregateType: "authorization",
              aggregateId: authorization.id,
              eventType: "authorization.expired",
              actorPrincipalId: input.principalId,
              correlationId: input.correlationId ?? null,
              payload: {
                reason: "approval_after_validity_window",
                validUntil: authorization.validUntil,
              },
            });
          } else {
            await client.query(
              `UPDATE authorizations
               SET status = 'approved',
                   decided_by_principal_id = $2,
                   decided_at = $3,
                   valid_from = COALESCE(valid_from, $3),
                   updated_at = now()
               WHERE id = $1`,
              [authorization.id, input.principalId, decidedAt],
            );

            await appendAuditEventWithClient(client, {
              organizationId: authorization.organizationId,
              aggregateType: "authorization",
              aggregateId: authorization.id,
              eventType: "authorization.approved",
              actorPrincipalId: input.principalId,
              correlationId: input.correlationId ?? null,
              payload: {
                approvalCount,
                approvalQuorum: authorization.approvalQuorum,
              },
            });
          }
        }
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizePgError(error);
    } finally {
      client.release();
    }

    return this.get(input.authorizationId);
  }

  async revoke(
    input: RevokeAuthorizationInput,
  ): Promise<AuthorizationRecord> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new AuthorizationError(
        "validation",
        "revocation reason is required",
      );
    }

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      const row = await lockAuthorization(
        client,
        input.authorizationId,
      );
      const authorization = mapAuthorization(row);

      if (authorization.status !== "approved") {
        throw new AuthorizationError(
          "invalid_state",
          "only an approved authorization can be revoked",
        );
      }

      await assertPrincipal(
        client,
        authorization.organizationId,
        input.principalId,
      );

      await client.query(
        `UPDATE authorizations
         SET status = 'revoked',
             updated_at = now()
         WHERE id = $1`,
        [authorization.id],
      );

      await appendAuditEventWithClient(client, {
        organizationId: authorization.organizationId,
        aggregateType: "authorization",
        aggregateId: authorization.id,
        eventType: "authorization.revoked",
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: { reason },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizePgError(error);
    } finally {
      client.release();
    }

    return this.get(input.authorizationId);
  }

  async effectiveness(
    authorizationId: string,
    at = new Date(),
  ): Promise<AuthorizationEffectiveness> {
    const record = await this.get(authorizationId);
    const authorization = record.authorization;
    const time = at.getTime();

    if (authorization.status !== "approved") {
      return {
        effective: false,
        reason: authorization.status,
      };
    }

    if (
      authorization.validFrom !== null &&
      time < new Date(authorization.validFrom).getTime()
    ) {
      return { effective: false, reason: "not_yet_valid" };
    }

    if (
      authorization.validUntil !== null &&
      time >= new Date(authorization.validUntil).getTime()
    ) {
      return { effective: false, reason: "validity_expired" };
    }

    if (
      authorization.emergency &&
      authorization.emergencyReviewedAt === null &&
      authorization.emergencyReviewDueAt !== null &&
      time >= new Date(authorization.emergencyReviewDueAt).getTime()
    ) {
      return {
        effective: false,
        reason: "emergency_review_overdue",
      };
    }

    return { effective: true, reason: "approved" };
  }

  async expireDue(at = new Date()): Promise<ExpirationResult> {
    const client = await this.pool.connect();
    let expired = 0;
    let emergencyRevoked = 0;

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `SELECT *
         FROM authorizations
         WHERE status = 'approved'
           AND (
             (valid_until IS NOT NULL AND valid_until <= $1)
             OR (
               emergency = true
               AND emergency_reviewed_at IS NULL
               AND emergency_review_due_at IS NOT NULL
               AND emergency_review_due_at <= $1
             )
           )
         ORDER BY id
         FOR UPDATE SKIP LOCKED`,
        [at.toISOString()],
      );

      for (const row of result.rows) {
        const authorization = mapAuthorization(row);
        const reviewOverdue =
          authorization.emergency &&
          authorization.emergencyReviewedAt === null &&
          authorization.emergencyReviewDueAt !== null &&
          new Date(authorization.emergencyReviewDueAt).getTime() <=
            at.getTime();

        if (reviewOverdue) {
          await client.query(
            `UPDATE authorizations
             SET status = 'revoked',
                 updated_at = now()
             WHERE id = $1`,
            [authorization.id],
          );

          await appendAuditEventWithClient(client, {
            organizationId: authorization.organizationId,
            aggregateType: "authorization",
            aggregateId: authorization.id,
            eventType: "authorization.emergency_review_overdue",
            payload: {
              reviewDueAt: authorization.emergencyReviewDueAt,
            },
          });
          emergencyRevoked += 1;
        } else {
          await client.query(
            `UPDATE authorizations
             SET status = 'expired',
                 updated_at = now()
             WHERE id = $1`,
            [authorization.id],
          );

          await appendAuditEventWithClient(client, {
            organizationId: authorization.organizationId,
            aggregateType: "authorization",
            aggregateId: authorization.id,
            eventType: "authorization.expired",
            payload: {
              validUntil: authorization.validUntil,
            },
          });
          expired += 1;
        }
      }

      await client.query("COMMIT");
      return { expired, emergencyRevoked };
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizePgError(error);
    } finally {
      client.release();
    }
  }
}

function validateRequest(input: RequestAuthorizationInput): void {
  if (!input.organizationId.trim()) {
    throw new AuthorizationError(
      "validation",
      "organizationId is required",
    );
  }
  if (!input.resourceId.trim()) {
    throw new AuthorizationError("validation", "resourceId is required");
  }
  if (!input.authorizationType.trim()) {
    throw new AuthorizationError(
      "validation",
      "authorizationType is required",
    );
  }
  if (!input.requestedByPrincipalId.trim()) {
    throw new AuthorizationError(
      "validation",
      "requestedByPrincipalId is required",
    );
  }

  const quorum = input.approvalQuorum ?? 1;
  if (!Number.isInteger(quorum) || quorum < 1) {
    throw new AuthorizationError(
      "validation",
      "approvalQuorum must be a positive integer",
    );
  }
}

function validateWindows(input: {
  requestedAt: string;
  validFrom: string | null;
  validUntil: string | null;
  emergency: boolean;
  emergencyReviewDueAt: string | null;
}): void {
  const requested = new Date(input.requestedAt).getTime();
  const validFrom =
    input.validFrom === null
      ? requested
      : new Date(input.validFrom).getTime();
  const validUntil =
    input.validUntil === null
      ? null
      : new Date(input.validUntil).getTime();

  if (validUntil !== null && validUntil <= validFrom) {
    throw new AuthorizationError(
      "validation",
      "validUntil must be after validFrom",
    );
  }

  if (!input.emergency) {
    if (input.emergencyReviewDueAt !== null) {
      throw new AuthorizationError(
        "validation",
        "emergencyReviewDueAt is only valid for emergency authorizations",
      );
    }
    return;
  }

  if (input.emergencyReviewDueAt === null) {
    throw new AuthorizationError(
      "validation",
      "emergency authorizations require emergencyReviewDueAt",
    );
  }

  if (validUntil === null) {
    throw new AuthorizationError(
      "validation",
      "emergency authorizations require validUntil",
    );
  }

  const reviewDue = new Date(input.emergencyReviewDueAt).getTime();
  if (reviewDue <= requested) {
    throw new AuthorizationError(
      "validation",
      "emergencyReviewDueAt must be after the request time",
    );
  }

  if (reviewDue > validUntil) {
    throw new AuthorizationError(
      "validation",
      "emergencyReviewDueAt cannot be after validUntil",
    );
  }
}

function normalizeOptionalDate(
  value: string | null | undefined,
  field: string,
): string | null {
  if (value === undefined || value === null) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new AuthorizationError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
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
    throw new AuthorizationError(
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
    throw new AuthorizationError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function assertEligibleApprover(
  client: PoolClient,
  authorizationId: string,
  principalId: string,
): Promise<void> {
  const configured = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count
     FROM authorization_eligible_approvers
     WHERE authorization_id = $1`,
    [authorizationId],
  );

  if (Number(configured.rows[0]?.count ?? "0") === 0) {
    return;
  }

  const eligible = await client.query(
    `SELECT 1
     FROM authorization_eligible_approvers
     WHERE authorization_id = $1
       AND principal_id = $2`,
    [authorizationId, principalId],
  );

  if (!eligible.rows[0]) {
    throw new AuthorizationError(
      "forbidden_approver",
      "principal is not eligible to decide this authorization",
    );
  }
}

async function lockAuthorization(
  client: PoolClient,
  authorizationId: string,
): Promise<any> {
  const result = await client.query(
    "SELECT * FROM authorizations WHERE id = $1 FOR UPDATE",
    [authorizationId],
  );

  if (!result.rows[0]) {
    throw new AuthorizationError(
      "not_found",
      "authorization not found",
    );
  }

  return result.rows[0];
}

function assertReviewable(authorization: Authorization): void {
  if (
    authorization.status === "pending" ||
    (authorization.emergency &&
      authorization.status === "approved" &&
      authorization.emergencyReviewedAt === null)
  ) {
    return;
  }

  throw new AuthorizationError(
    "invalid_state",
    "authorization is not awaiting a decision",
  );
}

function assertEmergencyReviewDeadlineOpen(
  authorization: Authorization,
  at: Date,
): void {
  if (
    authorization.emergency &&
    authorization.emergencyReviewedAt === null &&
    authorization.emergencyReviewDueAt !== null &&
    at.getTime() >=
      new Date(authorization.emergencyReviewDueAt).getTime()
  ) {
    throw new AuthorizationError(
      "invalid_state",
      "emergency review deadline has passed",
    );
  }
}

function mapAuthorization(row: any): Authorization {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    authorizationType: row.authorization_type,
    status: row.status,
    requestedByPrincipalId: row.requested_by_principal_id,
    decidedByPrincipalId: row.decided_by_principal_id,
    requestedAt: iso(row.requested_at),
    decidedAt: nullableIso(row.decided_at),
    validFrom: nullableIso(row.valid_from),
    validUntil: nullableIso(row.valid_until),
    scope: (row.scope ?? {}) as JsonObject,
    conditions: (row.conditions ?? {}) as JsonObject,
    approvalQuorum: Number(row.approval_quorum),
    approvalAuthority: row.approval_authority,
    emergency: row.emergency,
    emergencyReviewDueAt: nullableIso(
      row.emergency_review_due_at,
    ),
    emergencyReviewedAt: nullableIso(row.emergency_reviewed_at),
    metadata: (row.metadata ?? {}) as JsonObject,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapDecision(row: any): AuthorizationDecision {
  return {
    id: row.id,
    organizationId: row.organization_id,
    authorizationId: row.authorization_id,
    principalId: row.principal_id,
    decision: row.decision,
    rationale: row.rationale,
    decidedAt: iso(row.decided_at),
    metadata: (row.metadata ?? {}) as JsonObject,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function iso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

function nullableIso(value: Date | string | null): string | null {
  return value === null || value === undefined ? null : iso(value);
}

function normalizePgError(error: unknown): unknown {
  if (error instanceof AuthorizationError) return error;

  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "23505"
  ) {
    return new AuthorizationError(
      "duplicate_decision",
      "principal has already decided this authorization",
    );
  }

  return error;
}
