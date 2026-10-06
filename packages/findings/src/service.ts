import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  Finding,
  FindingStatus,
  JsonObject,
  Remediation,
  RemediationStatus,
} from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import { DeadlineService } from "@caiae/deadlines";
import {
  FindingError,
  type AssignFindingOwnerInput,
  type CancelRemediationInput,
  type CreateRemediationInput,
  type DisputeFindingInput,
  type FindingActionInput,
  type FindingListFilter,
  type FindingView,
  type RejectRemediationInput,
  type RemediationActionInput,
  type ResolveDisputeInput,
  type VerifyRemediationInput,
} from "./types.js";

const ACTIVE_REMEDIATION_STATUSES: RemediationStatus[] = [
  "planned",
  "in_progress",
  "ready_for_verification",
];

export class FindingService {
  private readonly deadlines: DeadlineService;

  constructor(private readonly pool: Pool) {
    this.deadlines = new DeadlineService(pool);
  }

  async syncFailedCheck(
    checkId: string,
    correlationId?: string | null,
  ): Promise<Finding[]> {
    const client = await this.pool.connect();

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
        throw new FindingError(
          "not_found",
          "check not found",
        );
      }

      const check = checkResult.rows[0];

      if (check.status !== "failed") {
        throw new FindingError(
          "invalid_state",
          "findings can only be synchronized from failed checks",
        );
      }

      const result = objectValue(
        check.result,
        "check result",
      );
      const ruleSetSnapshot = objectValue(
        check.rule_set_snapshot,
        "ruleset snapshot",
      );
      const ruleResults = arrayValue(
        result.rules,
        "check result.rules",
      );
      const ruleDefinitions = Array.isArray(
        ruleSetSnapshot.rules,
      )
        ? ruleSetSnapshot.rules
        : [];
      const ruleSetKey =
        typeof ruleSetSnapshot.id === "string"
          ? ruleSetSnapshot.id
          : null;
      const ruleSetVersion =
        typeof ruleSetSnapshot.version === "string"
          ? ruleSetSnapshot.version
          : null;

      for (const rawRuleResult of ruleResults) {
        const ruleResult = objectValue(
          rawRuleResult,
          "rule result",
        );

        if (ruleResult.status !== "fail") {
          continue;
        }

        const ruleKey = requiredStringValue(
          ruleResult.ruleId,
          "rule result.ruleId",
        );
        const severity = normalizeSeverity(
          ruleResult.severity,
        );
        const title = requiredStringValue(
          ruleResult.title,
          "rule result.title",
        );
        const definition = ruleDefinitions.find(
          (candidate) =>
            candidate !== null &&
            typeof candidate === "object" &&
            !Array.isArray(candidate) &&
            (candidate as Record<string, unknown>).id ===
              ruleKey,
        ) as Record<string, unknown> | undefined;
        const description =
          typeof definition?.description === "string"
            ? definition.description
            : `Rule ${ruleKey} failed during compliance check ${checkId}.`;
        const findingId = randomUUID();
        const openedAt = check.completed_at
          ? iso(check.completed_at)
          : new Date().toISOString();

        const inserted = await client.query(
          `INSERT INTO findings(
             id,
             organization_id,
             resource_id,
             check_id,
             rule_id,
             rule_key,
             rule_set_key,
             rule_set_version,
             severity,
             status,
             title,
             description,
             rule_result,
             opened_at,
             metadata
           ) VALUES (
             $1, $2, $3, $4, NULL, $5, $6, $7, $8,
             'open', $9, $10, $11::jsonb, $12, '{}'::jsonb
           )
           ON CONFLICT (check_id, rule_key)
             WHERE check_id IS NOT NULL
               AND rule_key IS NOT NULL
           DO NOTHING
           RETURNING *`,
          [
            findingId,
            check.organization_id,
            check.resource_id,
            checkId,
            ruleKey,
            ruleSetKey,
            ruleSetVersion,
            severity,
            title,
            description,
            JSON.stringify(toJsonObject(ruleResult)),
            openedAt,
          ],
        );

        if (inserted.rows[0]) {
          await appendAuditEventWithClient(client, {
            organizationId: check.organization_id,
            aggregateType: "finding",
            aggregateId: findingId,
            eventType: "finding.opened",
            actorPrincipalId:
              check.requested_by_principal_id,
            occurredAt: openedAt,
            correlationId: correlationId ?? null,
            payload: {
              checkId,
              resourceId: check.resource_id,
              ruleKey,
              ruleSetKey,
              ruleSetVersion,
              severity,
              title,
            },
          });
        }
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    const result = await this.pool.query(
      `SELECT *
       FROM findings
       WHERE check_id = $1
       ORDER BY created_at ASC, id ASC`,
      [checkId],
    );

    return result.rows.map(mapFinding);
  }

  async get(findingId: string): Promise<FindingView> {
    const findingResult = await this.pool.query(
      "SELECT * FROM findings WHERE id = $1",
      [findingId],
    );

    if (!findingResult.rows[0]) {
      throw new FindingError(
        "not_found",
        "finding not found",
      );
    }

    const remediationResult = await this.pool.query(
      `SELECT *
       FROM remediations
       WHERE finding_id = $1
       ORDER BY created_at ASC, id ASC`,
      [findingId],
    );

    return {
      finding: mapFinding(findingResult.rows[0]),
      remediations: remediationResult.rows.map(
        mapRemediation,
      ),
    };
  }

  async listForResource(
    organizationId: string,
    resourceId: string,
    filter: FindingListFilter = {},
  ): Promise<Finding[]> {
    const values: unknown[] = [
      organizationId,
      resourceId,
    ];
    let where = `
      organization_id = $1
      AND resource_id = $2
    `;

    if (filter.status) {
      values.push(filter.status);
      where += ` AND status = $${values.length}`;
    }

    const result = await this.pool.query(
      `SELECT *
       FROM findings
       WHERE ${where}
       ORDER BY opened_at DESC, id DESC`,
      values,
    );

    return result.rows.map(mapFinding);
  }

  async assignOwner(
    input: AssignFindingOwnerInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );

      if (finding.status === "closed") {
        throw new FindingError(
          "invalid_state",
          "closed findings cannot be reassigned",
        );
      }

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      if (input.ownerPrincipalId) {
        await assertPrincipal(
          client,
          finding.organizationId,
          input.ownerPrincipalId,
        );
      }

      await client.query(
        `UPDATE findings
         SET owner_principal_id = $2,
             updated_at = now()
         WHERE id = $1`,
        [finding.id, input.ownerPrincipalId ?? null],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.owner_assigned",
        actorPrincipalId: input.principalId,
        correlationId: input.correlationId ?? null,
        payload: {
          ownerPrincipalId:
            input.ownerPrincipalId ?? null,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.findingId);
  }

  async acknowledge(
    input: FindingActionInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );

      if (finding.status !== "open") {
        throw new FindingError(
          "invalid_state",
          "only open findings can be acknowledged",
        );
      }

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const acknowledgedAt =
        new Date().toISOString();

      await client.query(
        `UPDATE findings
         SET status = 'acknowledged',
             acknowledged_at = $2,
             acknowledged_by_principal_id = $3,
             updated_at = now()
         WHERE id = $1`,
        [
          finding.id,
          acknowledgedAt,
          input.principalId,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.acknowledged",
        actorPrincipalId: input.principalId,
        occurredAt: acknowledgedAt,
        correlationId: input.correlationId ?? null,
        payload: {},
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.findingId);
  }

  async dispute(
    input: DisputeFindingInput,
  ): Promise<FindingView> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new FindingError(
        "validation",
        "dispute reason is required",
      );
    }

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );

      if (
        finding.status !== "open" &&
        finding.status !== "acknowledged"
      ) {
        throw new FindingError(
          "invalid_state",
          "only open or acknowledged findings can be disputed",
        );
      }

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const disputedAt = new Date().toISOString();

      await client.query(
        `UPDATE findings
         SET status = 'disputed',
             disputed_at = $2,
             disputed_by_principal_id = $3,
             dispute_reason = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          finding.id,
          disputedAt,
          input.principalId,
          reason,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.disputed",
        actorPrincipalId: input.principalId,
        occurredAt: disputedAt,
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

    return this.get(input.findingId);
  }

  async resolveDispute(
    input: ResolveDisputeInput,
  ): Promise<FindingView> {
    const rationale = input.rationale.trim();
    if (!rationale) {
      throw new FindingError(
        "validation",
        "dispute resolution rationale is required",
      );
    }

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );

      if (finding.status !== "disputed") {
        throw new FindingError(
          "invalid_state",
          "only disputed findings can have a dispute resolved",
        );
      }

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const resolvedAt = new Date().toISOString();
      const status =
        input.outcome === "uphold"
          ? "acknowledged"
          : "closed";

      await client.query(
        `UPDATE findings
         SET status = $2,
             acknowledged_at = CASE
               WHEN $2 = 'acknowledged' THEN $3
               ELSE acknowledged_at
             END,
             acknowledged_by_principal_id = CASE
               WHEN $2 = 'acknowledged' THEN $4
               ELSE acknowledged_by_principal_id
             END,
             resolved_at = CASE
               WHEN $2 = 'closed' THEN $3
               ELSE resolved_at
             END,
             closed_at = CASE
               WHEN $2 = 'closed' THEN $3
               ELSE closed_at
             END,
             updated_at = now()
         WHERE id = $1`,
        [
          finding.id,
          status,
          resolvedAt,
          input.principalId,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.dispute_resolved",
        actorPrincipalId: input.principalId,
        occurredAt: resolvedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          outcome: input.outcome,
          rationale,
          resultingStatus: status,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.findingId);
  }

  async createRemediation(
    input: CreateRemediationInput,
  ): Promise<FindingView> {
    const plan = input.plan.trim();
    if (!plan) {
      throw new FindingError(
        "validation",
        "remediation plan is required",
      );
    }

    const dueAt = normalizeOptionalDate(
      input.dueAt,
      "dueAt",
    );
    validateClockOptions(input);

    const initialFinding = await this.get(
      input.findingId,
    );

    assertFindingCanRemediate(
      initialFinding.finding,
    );

    await this.assertPrincipalOutsideTransaction(
      initialFinding.finding.organizationId,
      input.createdByPrincipalId,
    );

    if (input.ownerPrincipalId) {
      await this.assertPrincipalOutsideTransaction(
        initialFinding.finding.organizationId,
        input.ownerPrincipalId,
      );
    }

    const remediationId = randomUUID();
    let deadlineId: string | null = null;

    if (dueAt) {
      const deadline = await this.deadlines.create({
        organizationId:
          initialFinding.finding.organizationId,
        resourceId:
          initialFinding.finding.resourceId,
        subjectType: "remediation",
        subjectId: remediationId,
        deadlineType: "remediation-completion",
        createdByPrincipalId:
          input.createdByPrincipalId,
        dueAt,
        warningWindowSeconds:
          input.warningWindowSeconds ?? 0,
        gracePeriodSeconds:
          input.gracePeriodSeconds ?? 0,
        escalationAfterSeconds:
          input.escalationAfterSeconds ?? [],
        metadata: {
          findingId: input.findingId,
        },
        correlationId: input.correlationId ?? null,
      });

      deadlineId = deadline.deadline.id;
    }

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );
      assertFindingCanRemediate(finding);

      await assertPrincipal(
        client,
        finding.organizationId,
        input.createdByPrincipalId,
      );

      if (input.ownerPrincipalId) {
        await assertPrincipal(
          client,
          finding.organizationId,
          input.ownerPrincipalId,
        );
      }

      await client.query(
        `INSERT INTO remediations(
           id,
           organization_id,
           finding_id,
           deadline_id,
           created_by_principal_id,
           owner_principal_id,
           status,
           plan,
           due_at,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           'planned', $7, $8, $9::jsonb
         )`,
        [
          remediationId,
          finding.organizationId,
          finding.id,
          deadlineId,
          input.createdByPrincipalId,
          input.ownerPrincipalId ?? null,
          plan,
          dueAt,
          JSON.stringify(input.metadata ?? {}),
        ],
      );

      await client.query(
        `UPDATE findings
         SET status = 'remediating',
             updated_at = now()
         WHERE id = $1`,
        [finding.id],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "remediation",
        aggregateId: remediationId,
        eventType: "remediation.created",
        actorPrincipalId:
          input.createdByPrincipalId,
        correlationId: input.correlationId ?? null,
        payload: {
          findingId: finding.id,
          ownerPrincipalId:
            input.ownerPrincipalId ?? null,
          plan,
          dueAt,
          deadlineId,
        },
      });

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.remediation_started",
        actorPrincipalId:
          input.createdByPrincipalId,
        correlationId: input.correlationId ?? null,
        payload: {
          remediationId,
          dueAt,
          deadlineId,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");

      if (deadlineId) {
        await this.deadlines
          .cancel({
            deadlineId,
            principalId:
              input.createdByPrincipalId,
            reason:
              "Remediation creation failed before activation",
            correlationId:
              input.correlationId ?? null,
          })
          .catch(() => undefined);
      }

      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.findingId);
  }

  async startRemediation(
    input: RemediationActionInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();
    let findingId = "";

    try {
      await client.query("BEGIN");
      const remediation = mapRemediation(
        await lockRemediation(
          client,
          input.remediationId,
        ),
      );
      findingId = remediation.findingId;

      if (remediation.status !== "planned") {
        throw new FindingError(
          "invalid_state",
          "only planned remediations can be started",
        );
      }

      const finding = mapFinding(
        await lockFinding(
          client,
          remediation.findingId,
        ),
      );

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const startedAt = new Date().toISOString();

      await client.query(
        `UPDATE remediations
         SET status = 'in_progress',
             started_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [remediation.id, startedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "remediation",
        aggregateId: remediation.id,
        eventType: "remediation.started",
        actorPrincipalId: input.principalId,
        occurredAt: startedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          findingId: finding.id,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(findingId);
  }

  async submitForVerification(
    input: RemediationActionInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();
    let findingId = "";

    try {
      await client.query("BEGIN");
      const remediation = mapRemediation(
        await lockRemediation(
          client,
          input.remediationId,
        ),
      );
      findingId = remediation.findingId;

      if (remediation.status !== "in_progress") {
        throw new FindingError(
          "invalid_state",
          "only in-progress remediations can be submitted for verification",
        );
      }

      const finding = mapFinding(
        await lockFinding(
          client,
          remediation.findingId,
        ),
      );

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const completedAt =
        new Date().toISOString();

      await client.query(
        `UPDATE remediations
         SET status = 'ready_for_verification',
             completed_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [remediation.id, completedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "remediation",
        aggregateId: remediation.id,
        eventType:
          "remediation.submitted_for_verification",
        actorPrincipalId: input.principalId,
        occurredAt: completedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          findingId: finding.id,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(findingId);
  }

  async verifyRemediation(
    input: VerifyRemediationInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();
    let findingId = "";
    let deadlineId: string | null = null;
    let verifiedAt = "";

    try {
      await client.query("BEGIN");
      const remediation = mapRemediation(
        await lockRemediation(
          client,
          input.remediationId,
        ),
      );
      findingId = remediation.findingId;
      deadlineId = remediation.deadlineId;

      if (
        remediation.status !==
        "ready_for_verification"
      ) {
        throw new FindingError(
          "invalid_state",
          "only remediations ready for verification can be verified",
        );
      }

      const finding = mapFinding(
        await lockFinding(
          client,
          remediation.findingId,
        ),
      );

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      verifiedAt = new Date().toISOString();
      const note =
        normalizeNullableString(input.note);

      await client.query(
        `UPDATE remediations
         SET status = 'verified',
             verified_at = $2,
             verified_by_principal_id = $3,
             verification_note = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          remediation.id,
          verifiedAt,
          input.principalId,
          note,
        ],
      );

      await client.query(
        `UPDATE findings
         SET status = 'resolved',
             resolved_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [finding.id, verifiedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "remediation",
        aggregateId: remediation.id,
        eventType: "remediation.verified",
        actorPrincipalId: input.principalId,
        occurredAt: verifiedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          findingId: finding.id,
          note,
        },
      });

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.resolved",
        actorPrincipalId: input.principalId,
        occurredAt: verifiedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          remediationId: remediation.id,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    if (deadlineId) {
      await this.deadlines.satisfy({
        deadlineId,
        principalId: input.principalId,
        satisfiedAt: verifiedAt,
        correlationId: input.correlationId ?? null,
      });
    }

    return this.get(findingId);
  }

  async rejectRemediation(
    input: RejectRemediationInput,
  ): Promise<FindingView> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new FindingError(
        "validation",
        "rejection reason is required",
      );
    }

    const client = await this.pool.connect();
    let findingId = "";
    let deadlineId: string | null = null;

    try {
      await client.query("BEGIN");
      const remediation = mapRemediation(
        await lockRemediation(
          client,
          input.remediationId,
        ),
      );
      findingId = remediation.findingId;
      deadlineId = remediation.deadlineId;

      if (
        remediation.status !==
        "ready_for_verification"
      ) {
        throw new FindingError(
          "invalid_state",
          "only remediations ready for verification can be rejected",
        );
      }

      const finding = mapFinding(
        await lockFinding(
          client,
          remediation.findingId,
        ),
      );

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const rejectedAt = new Date().toISOString();

      await client.query(
        `UPDATE remediations
         SET status = 'rejected',
             rejected_at = $2,
             rejected_by_principal_id = $3,
             rejection_reason = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          remediation.id,
          rejectedAt,
          input.principalId,
          reason,
        ],
      );

      await client.query(
        `UPDATE findings
         SET status = 'remediating',
             updated_at = now()
         WHERE id = $1`,
        [finding.id],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "remediation",
        aggregateId: remediation.id,
        eventType: "remediation.rejected",
        actorPrincipalId: input.principalId,
        occurredAt: rejectedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          findingId: finding.id,
          reason,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    if (deadlineId) {
      await this.deadlines
        .cancel({
          deadlineId,
          principalId: input.principalId,
          reason:
            "Remediation rejected during verification",
          correlationId: input.correlationId ?? null,
        })
        .catch(() => undefined);
    }

    return this.get(findingId);
  }

  async cancelRemediation(
    input: CancelRemediationInput,
  ): Promise<FindingView> {
    const reason = input.reason.trim();
    if (!reason) {
      throw new FindingError(
        "validation",
        "cancellation reason is required",
      );
    }

    const client = await this.pool.connect();
    let findingId = "";
    let deadlineId: string | null = null;

    try {
      await client.query("BEGIN");
      const remediation = mapRemediation(
        await lockRemediation(
          client,
          input.remediationId,
        ),
      );
      findingId = remediation.findingId;
      deadlineId = remediation.deadlineId;

      if (
        !ACTIVE_REMEDIATION_STATUSES.includes(
          remediation.status,
        )
      ) {
        throw new FindingError(
          "invalid_state",
          "only active remediations can be cancelled",
        );
      }

      const finding = mapFinding(
        await lockFinding(
          client,
          remediation.findingId,
        ),
      );

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const cancelledAt = new Date().toISOString();

      await client.query(
        `UPDATE remediations
         SET status = 'cancelled',
             cancelled_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [remediation.id, cancelledAt],
      );

      const remaining = await client.query(
        `SELECT count(*)::int AS count
         FROM remediations
         WHERE finding_id = $1
           AND id <> $2
           AND status IN (
             'planned',
             'in_progress',
             'ready_for_verification'
           )`,
        [finding.id, remediation.id],
      );

      if (Number(remaining.rows[0]?.count ?? 0) === 0) {
        const fallbackStatus: FindingStatus =
          finding.acknowledgedAt !== null
            ? "acknowledged"
            : "open";

        await client.query(
          `UPDATE findings
           SET status = $2,
               updated_at = now()
           WHERE id = $1`,
          [finding.id, fallbackStatus],
        );
      }

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "remediation",
        aggregateId: remediation.id,
        eventType: "remediation.cancelled",
        actorPrincipalId: input.principalId,
        occurredAt: cancelledAt,
        correlationId: input.correlationId ?? null,
        payload: {
          findingId: finding.id,
          reason,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    if (deadlineId) {
      await this.deadlines
        .cancel({
          deadlineId,
          principalId: input.principalId,
          reason,
          correlationId: input.correlationId ?? null,
        })
        .catch(() => undefined);
    }

    return this.get(findingId);
  }

  async close(
    input: FindingActionInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );

      if (finding.status !== "resolved") {
        throw new FindingError(
          "invalid_state",
          "only resolved findings can be closed",
        );
      }

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const closedAt = new Date().toISOString();

      await client.query(
        `UPDATE findings
         SET status = 'closed',
             closed_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [finding.id, closedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.closed",
        actorPrincipalId: input.principalId,
        occurredAt: closedAt,
        correlationId: input.correlationId ?? null,
        payload: {},
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.findingId);
  }

  async reopen(
    input: FindingActionInput,
  ): Promise<FindingView> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const finding = mapFinding(
        await lockFinding(client, input.findingId),
      );

      if (
        finding.status !== "resolved" &&
        finding.status !== "closed"
      ) {
        throw new FindingError(
          "invalid_state",
          "only resolved or closed findings can be reopened",
        );
      }

      await assertPrincipal(
        client,
        finding.organizationId,
        input.principalId,
      );

      const reopenedAt = new Date().toISOString();

      await client.query(
        `UPDATE findings
         SET status = 'open',
             resolved_at = NULL,
             closed_at = NULL,
             reopened_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [finding.id, reopenedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: finding.organizationId,
        aggregateType: "finding",
        aggregateId: finding.id,
        eventType: "finding.reopened",
        actorPrincipalId: input.principalId,
        occurredAt: reopenedAt,
        correlationId: input.correlationId ?? null,
        payload: {},
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.findingId);
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
      throw new FindingError(
        "not_found",
        "active principal not found in organization",
      );
    }
  }
}

function assertFindingCanRemediate(
  finding: Finding,
): void {
  if (
    finding.status === "disputed" ||
    finding.status === "resolved" ||
    finding.status === "closed"
  ) {
    throw new FindingError(
      "invalid_state",
      "finding must be open, acknowledged, or remediating to create remediation",
    );
  }
}

function validateClockOptions(
  input: CreateRemediationInput,
): void {
  for (const [field, value] of [
    [
      "warningWindowSeconds",
      input.warningWindowSeconds,
    ],
    [
      "gracePeriodSeconds",
      input.gracePeriodSeconds,
    ],
  ] as const) {
    if (
      value !== undefined &&
      (!Number.isSafeInteger(value) || value < 0)
    ) {
      throw new FindingError(
        "validation",
        `${field} must be a nonnegative safe integer`,
      );
    }
  }

  if (
    input.escalationAfterSeconds !== undefined
  ) {
    if (!Array.isArray(input.escalationAfterSeconds)) {
      throw new FindingError(
        "validation",
        "escalationAfterSeconds must be an array",
      );
    }

    const values =
      input.escalationAfterSeconds;
    if (
      values.some(
        (value) =>
          !Number.isSafeInteger(value) ||
          value < 0,
      )
    ) {
      throw new FindingError(
        "validation",
        "escalationAfterSeconds must contain nonnegative safe integers",
      );
    }

    if (
      new Set(values).size !== values.length
    ) {
      throw new FindingError(
        "validation",
        "escalationAfterSeconds cannot contain duplicates",
      );
    }
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
    throw new FindingError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function lockFinding(
  client: PoolClient,
  findingId: string,
): Promise<any> {
  const result = await client.query(
    `SELECT *
     FROM findings
     WHERE id = $1
     FOR UPDATE`,
    [findingId],
  );

  if (!result.rows[0]) {
    throw new FindingError(
      "not_found",
      "finding not found",
    );
  }

  return result.rows[0];
}

async function lockRemediation(
  client: PoolClient,
  remediationId: string,
): Promise<any> {
  const result = await client.query(
    `SELECT *
     FROM remediations
     WHERE id = $1
     FOR UPDATE`,
    [remediationId],
  );

  if (!result.rows[0]) {
    throw new FindingError(
      "not_found",
      "remediation not found",
    );
  }

  return result.rows[0];
}

function mapFinding(row: any): Finding {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    checkId: row.check_id,
    ruleId: row.rule_id,
    ruleKey: row.rule_key,
    ruleSetKey: row.rule_set_key,
    ruleSetVersion: row.rule_set_version,
    severity: row.severity,
    status: row.status,
    ownerPrincipalId: row.owner_principal_id,
    title: row.title,
    description: row.description,
    ruleResult: row.rule_result ?? {},
    openedAt: iso(row.opened_at),
    acknowledgedAt: nullableIso(
      row.acknowledged_at,
    ),
    acknowledgedByPrincipalId:
      row.acknowledged_by_principal_id,
    disputedAt: nullableIso(row.disputed_at),
    disputedByPrincipalId:
      row.disputed_by_principal_id,
    disputeReason: row.dispute_reason,
    resolvedAt: nullableIso(row.resolved_at),
    closedAt: nullableIso(row.closed_at),
    reopenedAt: nullableIso(row.reopened_at),
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapRemediation(row: any): Remediation {
  return {
    id: row.id,
    organizationId: row.organization_id,
    findingId: row.finding_id,
    deadlineId: row.deadline_id,
    createdByPrincipalId:
      row.created_by_principal_id,
    ownerPrincipalId: row.owner_principal_id,
    status: row.status,
    plan: row.plan,
    dueAt: nullableIso(row.due_at),
    startedAt: nullableIso(row.started_at),
    completedAt: nullableIso(row.completed_at),
    verifiedAt: nullableIso(row.verified_at),
    verifiedByPrincipalId:
      row.verified_by_principal_id,
    verificationNote: row.verification_note,
    rejectedAt: nullableIso(row.rejected_at),
    rejectedByPrincipalId:
      row.rejected_by_principal_id,
    rejectionReason: row.rejection_reason,
    cancelledAt: nullableIso(row.cancelled_at),
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function normalizeSeverity(
  value: unknown,
): Finding["severity"] {
  if (
    value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  ) {
    return value;
  }

  throw new FindingError(
    "validation",
    "failed rule contains invalid severity",
  );
}

function objectValue(
  value: unknown,
  field: string,
): Record<string, any> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new FindingError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function arrayValue(
  value: unknown,
  field: string,
): unknown[] {
  if (!Array.isArray(value)) {
    throw new FindingError(
      "validation",
      `${field} must be an array`,
    );
  }
  return value;
}

function requiredStringValue(
  value: unknown,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new FindingError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function normalizeOptionalDate(
  value: string | null | undefined,
  field: string,
): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new FindingError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
}

function normalizeNullableString(
  value: string | null | undefined,
): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  const normalized = value.trim();
  return normalized === "" ? null : normalized;
}

function toJsonObject(
  value: unknown,
): JsonObject {
  return JSON.parse(
    JSON.stringify(value),
  ) as JsonObject;
}

function iso(value: Date | string): string {
  return (
    value instanceof Date
      ? value
      : new Date(value)
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
  return error instanceof FindingError
    ? error
    : error;
}
