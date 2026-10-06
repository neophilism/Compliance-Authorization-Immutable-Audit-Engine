import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  Check,
  CheckTrigger,
  EvaluationSchedule,
  JsonObject,
  Resource,
} from "@caiae/core";
import {
  appendAuditEventWithClient,
} from "@caiae/db";
import { CertificationService } from "@caiae/certifications";
import { EvidenceService } from "@caiae/evidence";
import { FindingService } from "@caiae/findings";
import {
  evaluateRuleSet,
  parseRuleSet,
  type DeclarativeRuleSet,
  type EvaluationContext,
  type RuleSetEvaluationResult,
} from "@caiae/rules";
import {
  TraceabilityError,
  TraceabilityService,
  type RuleSetTraceability,
} from "@caiae/traceability";
import {
  EvaluationError,
  type CheckView,
  type CreateScheduleInput,
  type EvaluationScheduleView,
  type RunBatchInput,
  type RunCheckInput,
  type RunEventInput,
  type ScheduleSweepResult,
} from "./types.js";

export class EvaluationService {
  private readonly evidence: EvidenceService;
  private readonly findings: FindingService;
  private readonly certifications: CertificationService;
  private readonly traceability: TraceabilityService;

  constructor(private readonly pool: Pool) {
    this.evidence = new EvidenceService(pool);
    this.findings = new FindingService(pool);
    this.certifications = new CertificationService(pool);
    this.traceability = new TraceabilityService(pool);
  }

  async run(input: RunCheckInput): Promise<CheckView> {
    validateRunInput(input);
    const evaluatedAt = input.evaluatedAt
      ? normalizeRequiredDate(input.evaluatedAt, "evaluatedAt")
      : new Date().toISOString();
    const resolved =
      await this.resolveRuleSet(
        input.organizationId,
        input.ruleSet,
        input.registeredRuleSetId,
        evaluatedAt,
      );

    const checkId = await this.createPendingCheck(
      input,
      resolved.ruleSet,
      resolved.registeredRuleSetId,
      resolved.manifest,
      evaluatedAt,
    );

    return this.executeCheck(
      checkId,
      resolved.ruleSet,
      input.facts ?? {},
      new Date(evaluatedAt),
      input.correlationId ?? null,
    );
  }

  async runBatch(input: RunBatchInput): Promise<CheckView[]> {
    if (
      !Array.isArray(input.resourceIds) ||
      input.resourceIds.length === 0
    ) {
      throw new EvaluationError(
        "validation",
        "resourceIds must contain at least one resource ID",
      );
    }

    const uniqueResourceIds = [...new Set(input.resourceIds)];
    if (uniqueResourceIds.some((id) => !id.trim())) {
      throw new EvaluationError(
        "validation",
        "resourceIds cannot contain blank values",
      );
    }

    const evaluatedAt = input.evaluatedAt
      ? normalizeRequiredDate(input.evaluatedAt, "evaluatedAt")
      : new Date().toISOString();

    const results: CheckView[] = [];
    for (const resourceId of uniqueResourceIds) {
      results.push(
        await this.run({
          ...input,
          resourceId,
          evaluatedAt,
        }),
      );
    }

    return results;
  }

  async runEvent(input: RunEventInput): Promise<CheckView> {
    if (!input.eventType.trim()) {
      throw new EvaluationError(
        "validation",
        "eventType is required",
      );
    }

    return this.run({
      ...input,
      trigger: "event",
      triggerDetail: {
        eventType: input.eventType.trim(),
        event: input.event,
      },
    });
  }

  async get(checkId: string): Promise<CheckView> {
    const result = await this.pool.query(
      "SELECT * FROM checks WHERE id = $1",
      [checkId],
    );

    if (!result.rows[0]) {
      throw new EvaluationError(
        "not_found",
        "check not found",
      );
    }

    const check = mapCheck(result.rows[0]);
    const evaluation =
      check.status === "passed" ||
      check.status === "failed" ||
      check.status === "unknown"
        ? (check.result as unknown as RuleSetEvaluationResult)
        : null;

    return { check, evaluation };
  }

  async listForResource(
    organizationId: string,
    resourceId: string,
  ): Promise<Check[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM checks
       WHERE organization_id = $1
         AND resource_id = $2
       ORDER BY created_at DESC, id DESC`,
      [organizationId, resourceId],
    );

    return result.rows.map(mapCheck);
  }

  async createSchedule(
    input: CreateScheduleInput,
  ): Promise<EvaluationScheduleView> {
    validateScheduleInput(input);
    const nextRunAt = input.nextRunAt
      ? normalizeRequiredDate(input.nextRunAt, "nextRunAt")
      : new Date().toISOString();
    const resolved =
      await this.resolveRuleSet(
        input.organizationId,
        input.ruleSet,
        input.registeredRuleSetId,
        nextRunAt,
      );
    const ruleSet = resolved.ruleSet;

    const client = await this.pool.connect();
    const scheduleId = randomUUID();

    try {
      await client.query("BEGIN");
      await assertOrganization(client, input.organizationId);

      if (input.resourceId) {
        await assertResource(
          client,
          input.organizationId,
          input.resourceId,
        );
      }

      if (input.createdByPrincipalId) {
        await assertPrincipal(
          client,
          input.organizationId,
          input.createdByPrincipalId,
        );
      }

      await client.query(
        `INSERT INTO evaluation_schedules(
           id,
           organization_id,
           resource_id,
           resource_type,
           created_by_principal_id,
           registered_rule_set_id,
           rule_set_snapshot,
           rule_set_hash,
           rule_set_provenance,
           facts,
           interval_seconds,
           next_run_at,
           active,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7::jsonb, $8,
           $9::jsonb, $10::jsonb, $11, $12, true, $13::jsonb
         )`,
        [
          scheduleId,
          input.organizationId,
          input.resourceId ?? null,
          normalizeNullableString(input.resourceType),
          input.createdByPrincipalId ?? null,
          resolved.registeredRuleSetId,
          JSON.stringify(toJsonObject(ruleSet)),
          resolved.manifest.definitionHash,
          JSON.stringify(
            toJsonObject(resolved.manifest),
          ),
          JSON.stringify(input.facts ?? {}),
          input.intervalSeconds,
          nextRunAt,
          JSON.stringify(input.metadata ?? {}),
        ],
      );
      await appendAuditEventWithClient(client, {
        organizationId: input.organizationId,
        aggregateType: "evaluation_schedule",
        aggregateId: scheduleId,
        eventType: "evaluation_schedule.created",
        actorPrincipalId:
          input.createdByPrincipalId ?? null,
        correlationId: input.correlationId ?? null,
        payload: {
          resourceId: input.resourceId ?? null,
          resourceType:
            normalizeNullableString(input.resourceType),
          ruleSetId: ruleSet.id,
          ruleSetVersion: ruleSet.version,
          registeredRuleSetId:
            resolved.registeredRuleSetId,
          ruleSetHash:
            resolved.manifest.definitionHash,
          intervalSeconds: input.intervalSeconds,
          nextRunAt,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.getSchedule(scheduleId);
  }

  async getSchedule(
    scheduleId: string,
  ): Promise<EvaluationScheduleView> {
    const result = await this.pool.query(
      "SELECT * FROM evaluation_schedules WHERE id = $1",
      [scheduleId],
    );

    if (!result.rows[0]) {
      throw new EvaluationError(
        "not_found",
        "evaluation schedule not found",
      );
    }

    return {
      schedule: mapSchedule(result.rows[0]),
    };
  }

  async setScheduleActive(
    scheduleId: string,
    active: boolean,
    principalId: string,
    correlationId?: string | null,
  ): Promise<EvaluationScheduleView> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const row = await lockSchedule(client, scheduleId);
      const schedule = mapSchedule(row);

      await assertPrincipal(
        client,
        schedule.organizationId,
        principalId,
      );

      await client.query(
        `UPDATE evaluation_schedules
         SET active = $2,
             updated_at = now()
         WHERE id = $1`,
        [scheduleId, active],
      );

      await appendAuditEventWithClient(client, {
        organizationId: schedule.organizationId,
        aggregateType: "evaluation_schedule",
        aggregateId: schedule.id,
        eventType: active
          ? "evaluation_schedule.activated"
          : "evaluation_schedule.deactivated",
        actorPrincipalId: principalId,
        correlationId: correlationId ?? null,
        payload: { active },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.getSchedule(scheduleId);
  }

  async runDueSchedules(
    at = new Date(),
  ): Promise<ScheduleSweepResult> {
    const due = await this.pool.query(
      `SELECT *
       FROM evaluation_schedules
       WHERE active = true
         AND next_run_at <= $1
       ORDER BY next_run_at ASC, id ASC`,
      [at.toISOString()],
    );

    let schedulesClaimed = 0;
    let checksCreated = 0;
    let errors = 0;

    for (const row of due.rows) {
      const schedule = mapSchedule(row);
      const scheduledFor = schedule.nextRunAt;
      const nextRunAt = advanceNextRun(
        schedule.nextRunAt,
        schedule.intervalSeconds,
        at,
      );

      const claimed = await this.pool.query(
        `UPDATE evaluation_schedules
         SET last_run_at = $2,
             next_run_at = $3,
             updated_at = now()
         WHERE id = $1
           AND active = true
           AND next_run_at = $4
         RETURNING id`,
        [
          schedule.id,
          at.toISOString(),
          nextRunAt,
          schedule.nextRunAt,
        ],
      );

      if (!claimed.rows[0]) continue;
      schedulesClaimed += 1;

      try {
        const resourceIds = await this.scheduleResourceIds(
          schedule,
        );

        for (const resourceId of resourceIds) {
          await this.run({
            organizationId: schedule.organizationId,
            resourceId,
            ...(schedule.registeredRuleSetId
              ? {
                  registeredRuleSetId:
                    schedule.registeredRuleSetId,
                }
              : {
                  ruleSet:
                    schedule.ruleSetSnapshot,
                }),
            requestedByPrincipalId:
              schedule.createdByPrincipalId,
            facts: schedule.facts,
            trigger: "scheduled",
            triggerDetail: {
              scheduleId: schedule.id,
            },
            scheduleId: schedule.id,
            scheduledFor,
            evaluatedAt: at.toISOString(),
            metadata: {
              scheduleCycleDueAt: scheduledFor,
            },
          });
          checksCreated += 1;
        }
      } catch {
        errors += 1;
      }
    }

    return {
      schedulesExamined: due.rowCount ?? due.rows.length,
      schedulesClaimed,
      checksCreated,
      errors,
    };
  }

  private async createPendingCheck(
    input: RunCheckInput,
    ruleSet: DeclarativeRuleSet,
    registeredRuleSetId: string | null,
    manifest: RuleSetTraceability,
    evaluatedAt: string,
  ): Promise<string> {
    const client = await this.pool.connect();
    const checkId = randomUUID();
    const trigger = input.trigger ?? "manual";

    try {
      await client.query("BEGIN");
      await assertOrganization(client, input.organizationId);
      await assertResource(
        client,
        input.organizationId,
        input.resourceId,
      );

      if (input.requestedByPrincipalId) {
        await assertPrincipal(
          client,
          input.organizationId,
          input.requestedByPrincipalId,
        );
      }

      if (input.scheduleId) {
        const schedule = mapSchedule(
          await lockSchedule(client, input.scheduleId),
        );
        if (schedule.organizationId !== input.organizationId) {
          throw new EvaluationError(
            "validation",
            "schedule belongs to another organization",
          );
        }
      }

      await client.query(
        `INSERT INTO checks(
           id,
           organization_id,
           resource_id,
           rule_set_id,
           schedule_id,
           trigger,
           trigger_detail,
           requested_by_principal_id,
           status,
           scheduled_for,
           evaluated_at,
           rule_set_snapshot,
           rule_set_hash,
           rule_set_provenance,
           result,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7::jsonb, $8,
           'pending', $9, $10, $11::jsonb, $12,
           $13::jsonb, '{}'::jsonb, $14::jsonb
         )`,
        [
          checkId,
          input.organizationId,
          input.resourceId,
          registeredRuleSetId,
          input.scheduleId ?? null,
          trigger,
          JSON.stringify(input.triggerDetail ?? {}),
          input.requestedByPrincipalId ?? null,
          normalizeOptionalDate(
            input.scheduledFor,
            "scheduledFor",
          ),
          evaluatedAt,
          JSON.stringify(toJsonObject(ruleSet)),
          manifest.definitionHash,
          JSON.stringify(
            toJsonObject(manifest),
          ),
          JSON.stringify(input.metadata ?? {}),
        ],
      );
      await appendAuditEventWithClient(client, {
        organizationId: input.organizationId,
        aggregateType: "check",
        aggregateId: checkId,
        eventType: "check.created",
        actorPrincipalId:
          input.requestedByPrincipalId ?? null,
        correlationId: input.correlationId ?? null,
        payload: {
          resourceId: input.resourceId,
          trigger,
          ruleSetId: ruleSet.id,
          ruleSetVersion: ruleSet.version,
          registeredRuleSetId,
          ruleSetHash:
            manifest.definitionHash,
          scheduledFor:
            normalizeOptionalDate(
              input.scheduledFor,
              "scheduledFor",
            ),
          evaluatedAt,
        },
      });

      await client.query("COMMIT");
      return checkId;
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  private async executeCheck(
    checkId: string,
    ruleSet: DeclarativeRuleSet,
    facts: JsonObject,
    evaluatedAt: Date,
    correlationId: string | null,
  ): Promise<CheckView> {
    const startedAt = new Date().toISOString();

    await this.transitionToRunning(
      checkId,
      startedAt,
      correlationId,
    );

    try {
      const check = (await this.get(checkId)).check;
      const resource = await this.getResource(
        check.organizationId,
        check.resourceId,
      );
      const validEvidence =
        await this.evidence.validEvidenceForResource(
          check.organizationId,
          check.resourceId,
          evaluatedAt,
        );

      const context: EvaluationContext = {
        resource: {
          resourceType: resource.resourceType,
          status: resource.status,
          attributes: resource.attributes,
          metadata: resource.metadata,
        },
        facts,
        evidenceTypes: [
          ...new Set(
            validEvidence.map(
              (item) => item.evidenceType,
            ),
          ),
        ].sort(),
      };

      const evaluation = evaluateRuleSet(
        ruleSet,
        context,
      );
      const status = mapEvaluationStatus(
        evaluation.status,
      );
      const evidenceTrace = validEvidence.map(
        (item) =>
          ({
            evidenceId: item.id,
            evidenceType: item.evidenceType,
            source: item.source,
            uri: item.uri,
            checksumAlgorithm:
              item.checksumAlgorithm,
            checksum: item.checksum,
            capturedAt: item.capturedAt,
            validFrom: item.validFrom,
            validUntil: item.validUntil,
          }) as JsonObject,
      );

      const completedAt = new Date().toISOString();
      const client = await this.pool.connect();

      try {
        await client.query("BEGIN");

        await client.query(
          `UPDATE checks
           SET status = $2,
               context_snapshot = $3::jsonb,
               evidence_trace = $4::jsonb,
               result = $5::jsonb,
               completed_at = $6,
               updated_at = now()
           WHERE id = $1`,
          [
            checkId,
            status,
            JSON.stringify(toJsonObject(context)),
            JSON.stringify(evidenceTrace),
            JSON.stringify(toJsonObject(evaluation)),
            completedAt,
          ],
        );

        await appendAuditEventWithClient(client, {
          organizationId: check.organizationId,
          aggregateType: "check",
          aggregateId: checkId,
          eventType: "check.completed",
          actorPrincipalId:
            check.requestedByPrincipalId,
          occurredAt: completedAt,
          correlationId,
          payload: {
            status,
            evaluatedAt:
              evaluatedAt.toISOString(),
            ruleSetId: ruleSet.id,
            ruleSetVersion: ruleSet.version,
            evidenceIds: evidenceTrace.map(
              (item) => item.evidenceId,
            ),
            counts: evaluation.counts,
          },
        });

        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }

      if (status === "failed") {
        try {
          await this.findings.syncFailedCheck(
            checkId,
            correlationId,
          );
        } catch (findingError) {
          await this.recordPostProcessingError(
            checkId,
            "check.finding_sync_error",
            findingError,
            correlationId,
          ).catch(() => undefined);
        }

        try {
          await this.certifications.suspendForMaterialFailure(
            checkId,
            correlationId,
          );
        } catch (certificationError) {
          await this.recordPostProcessingError(
            checkId,
            "check.certification_sync_error",
            certificationError,
            correlationId,
          ).catch(() => undefined);
        }
      }
    } catch (error) {
      await this.markError(
        checkId,
        error,
        correlationId,
      );
    }

    return this.get(checkId);
  }

  private async recordPostProcessingError(
    checkId: string,
    eventType: string,
    error: unknown,
    correlationId: string | null,
  ): Promise<void> {
    const result = await this.pool.query(
      "SELECT * FROM checks WHERE id = $1",
      [checkId],
    );

    if (!result.rows[0]) return;

    const check = mapCheck(result.rows[0]);
    const message =
      error instanceof Error
        ? error.message
        : "unknown finding synchronization error";

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      await appendAuditEventWithClient(client, {
        organizationId: check.organizationId,
        aggregateType: "check",
        aggregateId: check.id,
        eventType,
        actorPrincipalId:
          check.requestedByPrincipalId,
        correlationId,
        payload: { message },
      });

      await client.query("COMMIT");
    } catch (secondaryError) {
      await client.query("ROLLBACK");
      throw secondaryError;
    } finally {
      client.release();
    }
  }

  private async transitionToRunning(
    checkId: string,
    startedAt: string,
    correlationId: string | null,
  ): Promise<void> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const result = await client.query(
        "SELECT * FROM checks WHERE id = $1 FOR UPDATE",
        [checkId],
      );

      if (!result.rows[0]) {
        throw new EvaluationError(
          "not_found",
          "check not found",
        );
      }

      const check = mapCheck(result.rows[0]);
      if (check.status !== "pending") {
        throw new EvaluationError(
          "invalid_state",
          "only pending checks can start",
        );
      }

      await client.query(
        `UPDATE checks
         SET status = 'running',
             started_at = $2,
             updated_at = now()
         WHERE id = $1`,
        [checkId, startedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: check.organizationId,
        aggregateType: "check",
        aggregateId: check.id,
        eventType: "check.started",
        actorPrincipalId:
          check.requestedByPrincipalId,
        occurredAt: startedAt,
        correlationId,
        payload: {
          resourceId: check.resourceId,
          trigger: check.trigger,
        },
      });

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  private async markError(
    checkId: string,
    error: unknown,
    correlationId: string | null,
  ): Promise<void> {
    const client = await this.pool.connect();
    const message =
      error instanceof Error
        ? error.message
        : "unknown evaluation error";

    try {
      await client.query("BEGIN");
      const result = await client.query(
        "SELECT * FROM checks WHERE id = $1 FOR UPDATE",
        [checkId],
      );

      if (!result.rows[0]) {
        throw error;
      }

      const check = mapCheck(result.rows[0]);
      const completedAt = new Date().toISOString();

      await client.query(
        `UPDATE checks
         SET status = 'error',
             error_message = $2,
             completed_at = $3,
             updated_at = now()
         WHERE id = $1`,
        [checkId, message, completedAt],
      );

      await appendAuditEventWithClient(client, {
        organizationId: check.organizationId,
        aggregateType: "check",
        aggregateId: check.id,
        eventType: "check.error",
        actorPrincipalId:
          check.requestedByPrincipalId,
        occurredAt: completedAt,
        correlationId,
        payload: { message },
      });

      await client.query("COMMIT");
    } catch (secondaryError) {
      await client.query("ROLLBACK");
      throw secondaryError;
    } finally {
      client.release();
    }
  }

  private async resolveRuleSet(
    organizationId: string,
    ruleSetInput:
      | DeclarativeRuleSet
      | unknown
      | undefined,
    registeredRuleSetId:
      | string
      | null
      | undefined,
    at: string,
  ): Promise<{
    ruleSet: DeclarativeRuleSet;
    registeredRuleSetId: string | null;
    manifest: RuleSetTraceability;
  }> {
    const hasRegistered =
      typeof registeredRuleSetId ===
        "string" &&
      registeredRuleSetId.trim() !== "";
    const hasAdHoc =
      ruleSetInput !== undefined;

    if (hasRegistered === hasAdHoc) {
      throw new EvaluationError(
        "validation",
        "provide exactly one of ruleSet or registeredRuleSetId",
      );
    }

    try {
      if (hasRegistered) {
        const loaded =
          await this.traceability
            .loadForEvaluation(
              organizationId,
              registeredRuleSetId as string,
              at,
            );

        return {
          ruleSet: loaded.ruleSet,
          registeredRuleSetId:
            registeredRuleSetId as string,
          manifest:
            loaded.manifest,
        };
      }

      const normalized =
        normalizeRuleSet(
          ruleSetInput,
        );

      return {
        ruleSet: normalized,
        registeredRuleSetId: null,
        manifest:
          this.traceability
            .adHocManifest(
              normalized,
            ),
      };
    } catch (error) {
      if (
        error instanceof
        EvaluationError
      ) {
        throw error;
      }

      if (
        error instanceof
        TraceabilityError
      ) {
        throw new EvaluationError(
          error.code === "not_found"
            ? "not_found"
            : error.code === "invalid_state"
              ? "invalid_state"
              : "validation",
          error.message,
        );
      }

      throw error;
    }
  }

  private async getResource(
    organizationId: string,
    resourceId: string,
  ): Promise<Resource> {
    const result = await this.pool.query(
      `SELECT *
       FROM resources
       WHERE id = $1
         AND organization_id = $2`,
      [resourceId, organizationId],
    );

    if (!result.rows[0]) {
      throw new EvaluationError(
        "not_found",
        "resource not found in organization",
      );
    }

    const row = result.rows[0];
    return {
      id: row.id,
      organizationId: row.organization_id,
      resourceType: row.resource_type,
      name: row.name,
      externalRef: row.external_ref,
      status: row.status,
      attributes: row.attributes ?? {},
      metadata: row.metadata ?? {},
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
    };
  }

  private async scheduleResourceIds(
    schedule: EvaluationSchedule,
  ): Promise<string[]> {
    if (schedule.resourceId) {
      return [schedule.resourceId];
    }

    const result = await this.pool.query(
      `SELECT id
       FROM resources
       WHERE organization_id = $1
         AND resource_type = $2
         AND status <> 'archived'
       ORDER BY id ASC`,
      [
        schedule.organizationId,
        schedule.resourceType,
      ],
    );

    return result.rows.map((row) => row.id);
  }
}

function validateRunInput(input: RunCheckInput): void {
  const hasRegistered =
    typeof input.registeredRuleSetId ===
      "string" &&
    input.registeredRuleSetId.trim() !== "";
  const hasAdHoc =
    input.ruleSet !== undefined;

  if (hasRegistered === hasAdHoc) {
    throw new EvaluationError(
      "validation",
      "provide exactly one of ruleSet or registeredRuleSetId",
    );
  }

  if (!input.organizationId.trim()) {
    throw new EvaluationError(
      "validation",
      "organizationId is required",
    );
  }
  if (!input.resourceId.trim()) {
    throw new EvaluationError(
      "validation",
      "resourceId is required",
    );
  }
  if (
    input.trigger !== undefined &&
    !["manual", "event", "scheduled"].includes(
      input.trigger,
    )
  ) {
    throw new EvaluationError(
      "validation",
      "trigger is invalid",
    );
  }
}

function validateScheduleInput(
  input: CreateScheduleInput,
): void {
  const hasRegistered =
    typeof input.registeredRuleSetId ===
      "string" &&
    input.registeredRuleSetId.trim() !== "";
  const hasAdHoc =
    input.ruleSet !== undefined;

  if (hasRegistered === hasAdHoc) {
    throw new EvaluationError(
      "validation",
      "provide exactly one of ruleSet or registeredRuleSetId",
    );
  }

  if (!input.organizationId.trim()) {
    throw new EvaluationError(
      "validation",
      "organizationId is required",
    );
  }

  const hasResource = Boolean(
    input.resourceId?.trim(),
  );
  const hasType = Boolean(
    input.resourceType?.trim(),
  );

  if (hasResource === hasType) {
    throw new EvaluationError(
      "validation",
      "provide exactly one of resourceId or resourceType",
    );
  }

  if (
    !Number.isSafeInteger(input.intervalSeconds) ||
    input.intervalSeconds < 60
  ) {
    throw new EvaluationError(
      "validation",
      "intervalSeconds must be a safe integer of at least 60",
    );
  }
}

function normalizeRuleSet(
  input: DeclarativeRuleSet | unknown,
): DeclarativeRuleSet {
  try {
    return parseRuleSet(input);
  } catch (error) {
    throw new EvaluationError(
      "validation",
      error instanceof Error
        ? error.message
        : "invalid ruleset",
    );
  }
}

function mapEvaluationStatus(
  status: RuleSetEvaluationResult["status"],
): Check["status"] {
  switch (status) {
    case "pass":
      return "passed";
    case "fail":
      return "failed";
    case "unknown":
      return "unknown";
  }
}

function advanceNextRun(
  scheduledFor: string,
  intervalSeconds: number,
  at: Date,
): string {
  let next =
    new Date(scheduledFor).getTime() +
    intervalSeconds * 1_000;

  while (next <= at.getTime()) {
    next += intervalSeconds * 1_000;
  }

  return new Date(next).toISOString();
}

async function assertOrganization(
  client: PoolClient,
  organizationId: string,
): Promise<void> {
  const result = await client.query(
    `SELECT 1
     FROM organizations
     WHERE id = $1
       AND status = 'active'`,
    [organizationId],
  );

  if (!result.rows[0]) {
    throw new EvaluationError(
      "not_found",
      "active organization not found",
    );
  }
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
    throw new EvaluationError(
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
    throw new EvaluationError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function lockSchedule(
  client: PoolClient,
  scheduleId: string,
): Promise<any> {
  const result = await client.query(
    `SELECT *
     FROM evaluation_schedules
     WHERE id = $1
     FOR UPDATE`,
    [scheduleId],
  );

  if (!result.rows[0]) {
    throw new EvaluationError(
      "not_found",
      "evaluation schedule not found",
    );
  }

  return result.rows[0];
}

function mapCheck(row: any): Check {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    ruleSetId: row.rule_set_id,
    scheduleId: row.schedule_id,
    trigger: row.trigger,
    triggerDetail: row.trigger_detail ?? {},
    requestedByPrincipalId:
      row.requested_by_principal_id,
    status: row.status,
    scheduledFor: nullableIso(row.scheduled_for),
    startedAt: nullableIso(row.started_at),
    completedAt: nullableIso(row.completed_at),
    evaluatedAt: nullableIso(row.evaluated_at),
    ruleSetSnapshot: row.rule_set_snapshot ?? {},
    ruleSetHash:
      row.rule_set_hash ?? null,
    ruleSetProvenance:
      row.rule_set_provenance ?? {},
    contextSnapshot: row.context_snapshot ?? {},
    evidenceTrace: Array.isArray(row.evidence_trace)
      ? row.evidence_trace
      : [],
    result: row.result ?? {},
    errorMessage: row.error_message,
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapSchedule(row: any): EvaluationSchedule {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    resourceType: row.resource_type,
    createdByPrincipalId:
      row.created_by_principal_id,
    registeredRuleSetId:
      row.registered_rule_set_id ??
      null,
    ruleSetSnapshot:
      row.rule_set_snapshot ?? {},
    ruleSetHash:
      row.rule_set_hash ?? null,
    ruleSetProvenance:
      row.rule_set_provenance ?? {},
    facts: row.facts ?? {},
    intervalSeconds: Number(row.interval_seconds),
    nextRunAt: iso(row.next_run_at),
    lastRunAt: nullableIso(row.last_run_at),
    active: row.active,
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function normalizeRequiredDate(
  value: string,
  field: string,
): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new EvaluationError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
}

function normalizeOptionalDate(
  value: string | null | undefined,
  field: string,
): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  return normalizeRequiredDate(value, field);
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

function toJsonObject(value: unknown): JsonObject {
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
  return error instanceof EvaluationError
    ? error
    : error;
}
