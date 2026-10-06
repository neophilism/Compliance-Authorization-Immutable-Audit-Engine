import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  ExceptionDecision,
  ExceptionRecord,
  JsonObject,
} from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import {
  ExceptionError,
  type ExceptionEffectiveness,
  type ExceptionExpirationResult,
  type ExceptionRecordView,
  type RecordExceptionDecisionInput,
  type RequestExceptionInput,
  type RevokeExceptionInput,
} from "./types.js";

export class ExceptionService {
  constructor(private readonly pool: Pool) {}

  async request(
    input: RequestExceptionInput,
  ): Promise<ExceptionRecordView> {
    validateRequest(input);

    const client = await this.pool.connect();
    let exceptionId = "";

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

      if (input.ruleId) {
        await assertRule(
          client,
          input.organizationId,
          input.ruleId,
        );
      }

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
        throw new ExceptionError(
          "validation",
          "approvalQuorum cannot exceed the number of eligible approvers",
        );
      }

      const requestedAt = new Date().toISOString();
      const validFrom = normalizeOptionalDate(
        input.validFrom,
        "validFrom",
      );
      const validUntil = normalizeRequiredDate(
        input.validUntil,
        "validUntil",
      );

      validateValidityWindow(
        requestedAt,
        validFrom,
        validUntil,
      );

      exceptionId = randomUUID();

      await client.query(
        `INSERT INTO exceptions(
           id,
           organization_id,
           resource_id,
           rule_id,
           kind,
           status,
           requested_by_principal_id,
           requested_at,
           justification,
           valid_from,
           valid_until,
           scope,
           conditions,
           approval_quorum,
           approval_authority,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, 'requested', $6, $7, $8,
           $9, $10, $11::jsonb, $12::jsonb, $13, $14, $15::jsonb
         )`,
        [
          exceptionId,
          input.organizationId,
          input.resourceId,
          input.ruleId ?? null,
          input.kind,
          input.requestedByPrincipalId,
          requestedAt,
          input.justification.trim(),
          validFrom,
          validUntil,
          JSON.stringify(input.scope ?? {}),
          JSON.stringify(input.conditions ?? {}),
          approvalQuorum,
          input.approvalAuthority ?? null,
          JSON.stringify(input.metadata ?? {}),
        ],
      );

      for (const principalId of eligibleApproverPrincipalIds) {
        await client.query(
          `INSERT INTO exception_eligible_approvers(
             organization_id,
             exception_id,
             principal_id
           ) VALUES ($1, $2, $3)`,
          [input.organizationId, exceptionId, principalId],
        );
      }

      await appendAuditEventWithClient(client, {
        organizationId: input.organizationId,
        aggregateType: "exception",
        aggregateId: exceptionId,
        eventType: `${input.kind}.requested`,
        actorPrincipalId: input.requestedByPrincipalId,
        correlationId: input.correlationId ?? null,
        payload: {
          kind: input.kind,
          resourceId: input.resourceId,
          ruleId: input.ruleId ?? null,
          justification: input.justification.trim(),
          validFrom,
          validUntil,
          scope: input.scope ?? {},
          conditions: input.conditions ?? {},
          approvalQuorum,
          approvalAuthority: input.approvalAuthority ?? null,
          eligibleApproverCount: eligibleApproverPrincipalIds.length,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizePgError(error);
    } finally {
      client.release();
    }

    return this.get(exceptionId);
  }

  async get(exceptionId: string): Promise<ExceptionRecordView> {
    const exceptionResult = await this.pool.query(
      "SELECT * FROM exceptions WHERE id = $1",
      [exceptionId],
    );

    if (!exceptionResult.rows[0]) {
      throw new ExceptionError(
        "not_found",
        "exception or waiver not found",
      );
    }

    const decisionsResult = await this.pool.query(
      `SELECT *
       FROM exception_decisions
       WHERE exception_id = $1
       ORDER BY decided_at ASC, id ASC`,
      [exceptionId],
    );

    const approversResult = await this.pool.query(
      `SELECT principal_id
       FROM exception_eligible_approvers
       WHERE exception_id = $1
       ORDER BY principal_id ASC`,
      [exceptionId],
    );

    const decisions = decisionsResult.rows.map(mapDecision);

    return {
      exception: mapException(exceptionResult.rows[0]),
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
    input: RecordExceptionDecisionInput,
  ): Promise<ExceptionRecordView> {
    const client = await this.pool.connect();
    const rationale = input.rationale?.trim() ?? "";

    try {
      await client.query("BEGIN");

      const row = await lockException(client, input.exceptionId);
      const record = mapException(row);

      if (record.status !== "requested") {
        throw new ExceptionError(
          "invalid_state",
          "exception or waiver is not awaiting a decision",
        );
      }

      await assertPrincipal(
        client,
        record.organizationId,
        input.principalId,
      );
      await assertEligibleApprover(
        client,
        record.id,
        input.principalId,
      );

      const decidedAt = new Date().toISOString();

      await client.query(
        `INSERT INTO exception_decisions(
           id,
           organization_id,
           exception_id,
           principal_id,
           decision,
           rationale,
           decided_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          randomUUID(),
          record.organizationId,
          record.id,
          input.principalId,
          input.decision,
          rationale,
          decidedAt,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: record.organizationId,
        aggregateType: "exception",
        aggregateId: record.id,
        eventType: `${record.kind}.decision_recorded`,
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: {
          decision: input.decision,
          rationale,
        },
      });

      if (input.decision === "deny") {
        await client.query(
          `UPDATE exceptions
           SET status = 'denied',
               decided_by_principal_id = $2,
               decided_at = $3,
               updated_at = now()
           WHERE id = $1`,
          [record.id, input.principalId, decidedAt],
        );

        await appendAuditEventWithClient(client, {
          organizationId: record.organizationId,
          aggregateType: "exception",
          aggregateId: record.id,
          eventType: `${record.kind}.denied`,
          actorPrincipalId: input.principalId,
          correlationId: input.correlationId ?? null,
          payload: { rationale },
        });
      } else {
        const approvals = await client.query<{ count: string }>(
          `SELECT count(*)::text AS count
           FROM exception_decisions
           WHERE exception_id = $1
             AND decision = 'approve'`,
          [record.id],
        );
        const approvalCount = Number(
          approvals.rows[0]?.count ?? "0",
        );

        if (approvalCount >= record.approvalQuorum) {
          if (
            new Date(record.validUntil).getTime() <=
            new Date(decidedAt).getTime()
          ) {
            await client.query(
              `UPDATE exceptions
               SET status = 'expired',
                   decided_by_principal_id = $2,
                   decided_at = $3,
                   updated_at = now()
               WHERE id = $1`,
              [record.id, input.principalId, decidedAt],
            );

            await appendAuditEventWithClient(client, {
              organizationId: record.organizationId,
              aggregateType: "exception",
              aggregateId: record.id,
              eventType: `${record.kind}.expired`,
              actorPrincipalId: input.principalId,
              correlationId: input.correlationId ?? null,
              payload: {
                reason: "approval_after_validity_window",
                validUntil: record.validUntil,
              },
            });
          } else {
            await client.query(
              `UPDATE exceptions
               SET status = 'approved',
                   decided_by_principal_id = $2,
                   decided_at = $3,
                   valid_from = COALESCE(valid_from, $3),
                   updated_at = now()
               WHERE id = $1`,
              [record.id, input.principalId, decidedAt],
            );

            await appendAuditEventWithClient(client, {
              organizationId: record.organizationId,
              aggregateType: "exception",
              aggregateId: record.id,
              eventType: `${record.kind}.approved`,
              actorPrincipalId: input.principalId,
              correlationId: input.correlationId ?? null,
              payload: {
                approvalCount,
                approvalQuorum: record.approvalQuorum,
                validUntil: record.validUntil,
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

    return this.get(input.exceptionId);
  }

  async revoke(
    input: RevokeExceptionInput,
  ): Promise<ExceptionRecordView> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new ExceptionError(
        "validation",
        "revocation reason is required",
      );
    }

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const row = await lockException(client, input.exceptionId);
      const record = mapException(row);

      if (record.status !== "approved") {
        throw new ExceptionError(
          "invalid_state",
          "only an approved exception or waiver can be revoked",
        );
      }

      await assertPrincipal(
        client,
        record.organizationId,
        input.principalId,
      );
      await assertEligibleApprover(
        client,
        record.id,
        input.principalId,
      );

      await client.query(
        `UPDATE exceptions
         SET status = 'revoked',
             updated_at = now()
         WHERE id = $1`,
        [record.id],
      );

      await appendAuditEventWithClient(client, {
        organizationId: record.organizationId,
        aggregateType: "exception",
        aggregateId: record.id,
        eventType: `${record.kind}.revoked`,
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

    return this.get(input.exceptionId);
  }

  async effectiveness(
    exceptionId: string,
    at = new Date(),
  ): Promise<ExceptionEffectiveness> {
    const view = await this.get(exceptionId);
    const record = view.exception;
    const time = at.getTime();

    if (record.status !== "approved") {
      return {
        effective: false,
        reason: record.status,
      };
    }

    if (
      record.validFrom !== null &&
      time < new Date(record.validFrom).getTime()
    ) {
      return {
        effective: false,
        reason: "not_yet_valid",
      };
    }

    if (time >= new Date(record.validUntil).getTime()) {
      return {
        effective: false,
        reason: "validity_expired",
      };
    }

    return { effective: true, reason: "approved" };
  }

  async expireDue(
    at = new Date(),
  ): Promise<ExceptionExpirationResult> {
    const client = await this.pool.connect();
    let expired = 0;

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `SELECT *
         FROM exceptions
         WHERE status IN ('requested', 'approved')
           AND valid_until <= $1
         ORDER BY id
         FOR UPDATE SKIP LOCKED`,
        [at.toISOString()],
      );

      for (const row of result.rows) {
        const record = mapException(row);

        await client.query(
          `UPDATE exceptions
           SET status = 'expired',
               updated_at = now()
           WHERE id = $1`,
          [record.id],
        );

        await appendAuditEventWithClient(client, {
          organizationId: record.organizationId,
          aggregateType: "exception",
          aggregateId: record.id,
          eventType: `${record.kind}.expired`,
          payload: {
            validUntil: record.validUntil,
            priorStatus: record.status,
          },
        });

        expired += 1;
      }

      await client.query("COMMIT");
      return { expired };
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizePgError(error);
    } finally {
      client.release();
    }
  }
}

function validateRequest(input: RequestExceptionInput): void {
  if (!input.organizationId.trim()) {
    throw new ExceptionError(
      "validation",
      "organizationId is required",
    );
  }
  if (!input.resourceId.trim()) {
    throw new ExceptionError(
      "validation",
      "resourceId is required",
    );
  }
  if (
    input.kind !== "exception" &&
    input.kind !== "waiver"
  ) {
    throw new ExceptionError(
      "validation",
      "kind must be exception or waiver",
    );
  }
  if (!input.requestedByPrincipalId.trim()) {
    throw new ExceptionError(
      "validation",
      "requestedByPrincipalId is required",
    );
  }
  if (!input.justification.trim()) {
    throw new ExceptionError(
      "validation",
      "justification is required",
    );
  }
  if (!input.validUntil?.trim()) {
    throw new ExceptionError(
      "validation",
      "validUntil is required",
    );
  }

  const quorum = input.approvalQuorum ?? 1;
  if (!Number.isInteger(quorum) || quorum < 1) {
    throw new ExceptionError(
      "validation",
      "approvalQuorum must be a positive integer",
    );
  }
}

function validateValidityWindow(
  requestedAt: string,
  validFrom: string | null,
  validUntil: string,
): void {
  const start = validFrom
    ? new Date(validFrom).getTime()
    : new Date(requestedAt).getTime();
  const end = new Date(validUntil).getTime();

  if (end <= start) {
    throw new ExceptionError(
      "validation",
      "validUntil must be after validFrom or request time",
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
    throw new ExceptionError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
}

function normalizeRequiredDate(
  value: string,
  field: string,
): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new ExceptionError(
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
    throw new ExceptionError(
      "not_found",
      "resource not found in organization",
    );
  }
}

async function assertRule(
  client: PoolClient,
  organizationId: string,
  ruleId: string,
): Promise<void> {
  const result = await client.query(
    `SELECT 1
     FROM rules
     WHERE id = $1
       AND organization_id = $2
       AND enabled = true`,
    [ruleId, organizationId],
  );

  if (!result.rows[0]) {
    throw new ExceptionError(
      "not_found",
      "enabled rule not found in organization",
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
    throw new ExceptionError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function assertEligibleApprover(
  client: PoolClient,
  exceptionId: string,
  principalId: string,
): Promise<void> {
  const configured = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count
     FROM exception_eligible_approvers
     WHERE exception_id = $1`,
    [exceptionId],
  );

  if (Number(configured.rows[0]?.count ?? "0") === 0) {
    return;
  }

  const eligible = await client.query(
    `SELECT 1
     FROM exception_eligible_approvers
     WHERE exception_id = $1
       AND principal_id = $2`,
    [exceptionId, principalId],
  );

  if (!eligible.rows[0]) {
    throw new ExceptionError(
      "forbidden_approver",
      "principal is not eligible to decide this exception or waiver",
    );
  }
}

async function lockException(
  client: PoolClient,
  exceptionId: string,
): Promise<any> {
  const result = await client.query(
    "SELECT * FROM exceptions WHERE id = $1 FOR UPDATE",
    [exceptionId],
  );

  if (!result.rows[0]) {
    throw new ExceptionError(
      "not_found",
      "exception or waiver not found",
    );
  }

  return result.rows[0];
}

function mapException(row: any): ExceptionRecord {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    ruleId: row.rule_id,
    kind: row.kind,
    status: row.status,
    requestedByPrincipalId: row.requested_by_principal_id,
    decidedByPrincipalId: row.decided_by_principal_id,
    requestedAt: iso(row.requested_at),
    decidedAt: nullableIso(row.decided_at),
    justification: row.justification,
    validFrom: nullableIso(row.valid_from),
    validUntil: iso(row.valid_until),
    scope: (row.scope ?? {}) as JsonObject,
    conditions: (row.conditions ?? {}) as JsonObject,
    approvalQuorum: Number(row.approval_quorum),
    approvalAuthority: row.approval_authority,
    metadata: (row.metadata ?? {}) as JsonObject,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapDecision(row: any): ExceptionDecision {
  return {
    id: row.id,
    organizationId: row.organization_id,
    exceptionId: row.exception_id,
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

function normalizePgError(error: unknown): unknown {
  if (error instanceof ExceptionError) return error;

  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "23505"
  ) {
    return new ExceptionError(
      "duplicate_decision",
      "principal has already decided this exception or waiver",
    );
  }

  return error;
}
