import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  Deadline,
  DeadlineOccurrence,
  DeadlineStatus,
  JsonObject,
} from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import {
  DeadlineError,
  type CancelDeadlineInput,
  type CreateDeadlineInput,
  type DeadlineClockState,
  type DeadlineStatusSnapshot,
  type DeadlineSweepResult,
  type DeadlineView,
  type SatisfyDeadlineInput,
} from "./types.js";

const ACTIVE_STATUS_ORDER: Exclude<
  DeadlineStatus,
  "satisfied" | "cancelled"
>[] = ["scheduled", "warning", "due", "overdue"];

export class DeadlineService {
  constructor(private readonly pool: Pool) {}

  async create(input: CreateDeadlineInput): Promise<DeadlineView> {
    validateCreateInput(input);

    const client = await this.pool.connect();
    const deadlineId = randomUUID();

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

      const now = new Date();
      const timing = resolveTiming(input, now);
      const warningWindowSeconds =
        input.warningWindowSeconds ?? 0;
      const gracePeriodSeconds =
        input.gracePeriodSeconds ?? 0;
      const recurrenceIntervalSeconds =
        input.recurrenceIntervalSeconds ?? null;
      const recurrenceEndAt = normalizeOptionalDate(
        input.recurrenceEndAt,
        "recurrenceEndAt",
      );
      const maxOccurrences =
        input.maxOccurrences ?? null;
      const escalationAfterSeconds =
        normalizeEscalationThresholds(
          input.escalationAfterSeconds ?? [],
        );

      validateRecurrence(
        timing.dueAt,
        recurrenceIntervalSeconds,
        recurrenceEndAt,
        maxOccurrences,
      );

      const insert = await client.query(
        `INSERT INTO deadlines(
           id,
           organization_id,
           resource_id,
           subject_type,
           subject_id,
           deadline_type,
           status,
           created_by_principal_id,
           anchor_at,
           due_offset_seconds,
           due_at,
           warning_window_seconds,
           grace_period_seconds,
           recurrence_interval_seconds,
           recurrence_end_at,
           max_occurrences,
           cycle_number,
           escalation_after_seconds,
           escalation_level,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, 'scheduled', $7, $8, $9,
           $10, $11, $12, $13, $14, $15, 1, $16::jsonb, 0, $17::jsonb
         )
         RETURNING *`,
        [
          deadlineId,
          input.organizationId,
          input.resourceId ?? null,
          input.subjectType.trim(),
          input.subjectId.trim(),
          input.deadlineType.trim(),
          input.createdByPrincipalId ?? null,
          timing.anchorAt,
          timing.dueOffsetSeconds,
          timing.dueAt,
          warningWindowSeconds,
          gracePeriodSeconds,
          recurrenceIntervalSeconds,
          recurrenceEndAt,
          maxOccurrences,
          JSON.stringify(escalationAfterSeconds),
          JSON.stringify(input.metadata ?? {}),
        ],
      );

      let deadline = mapDeadline(insert.rows[0]);

      await appendAuditEventWithClient(client, {
        organizationId: deadline.organizationId,
        aggregateType: "deadline",
        aggregateId: deadline.id,
        eventType: "deadline.created",
        actorPrincipalId:
          input.createdByPrincipalId ?? null,
        correlationId: input.correlationId ?? null,
        payload: {
          resourceId: deadline.resourceId,
          subjectType: deadline.subjectType,
          subjectId: deadline.subjectId,
          deadlineType: deadline.deadlineType,
          anchorAt: deadline.anchorAt,
          dueOffsetSeconds: deadline.dueOffsetSeconds,
          dueAt: deadline.dueAt,
          warningWindowSeconds:
            deadline.warningWindowSeconds,
          gracePeriodSeconds: deadline.gracePeriodSeconds,
          recurrenceIntervalSeconds:
            deadline.recurrenceIntervalSeconds,
          recurrenceEndAt: deadline.recurrenceEndAt,
          maxOccurrences: deadline.maxOccurrences,
          escalationAfterSeconds:
            deadline.escalationAfterSeconds,
        },
      });

      const transition = await advanceClockLocked(
        client,
        deadline,
        now,
        input.correlationId ?? null,
      );

      if (transition.changed) {
        const refreshed = await client.query(
          "SELECT * FROM deadlines WHERE id = $1",
          [deadline.id],
        );
        deadline = mapDeadline(refreshed.rows[0]);
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(deadlineId);
  }

  async get(deadlineId: string): Promise<DeadlineView> {
    const deadlineResult = await this.pool.query(
      "SELECT * FROM deadlines WHERE id = $1",
      [deadlineId],
    );

    if (!deadlineResult.rows[0]) {
      throw new DeadlineError(
        "not_found",
        "deadline not found",
      );
    }

    const deadline = mapDeadline(deadlineResult.rows[0]);

    return {
      deadline,
      clock:
        deadline.status === "satisfied" ||
        deadline.status === "cancelled"
          ? null
          : calculateDeadlineClock(deadline, new Date()),
      occurrences: await this.listOccurrences(deadlineId),
    };
  }

  async listBySubject(
    organizationId: string,
    subjectType: string,
    subjectId: string,
  ): Promise<Deadline[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM deadlines
       WHERE organization_id = $1
         AND subject_type = $2
         AND subject_id = $3
       ORDER BY due_at ASC, id ASC`,
      [organizationId, subjectType, subjectId],
    );

    return result.rows.map(mapDeadline);
  }

  async listOccurrences(
    deadlineId: string,
  ): Promise<DeadlineOccurrence[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM deadline_occurrences
       WHERE deadline_id = $1
       ORDER BY cycle_number ASC`,
      [deadlineId],
    );

    return result.rows.map(mapOccurrence);
  }

  async statusAt(
    deadlineId: string,
    at = new Date(),
  ): Promise<DeadlineStatusSnapshot> {
    const result = await this.pool.query(
      "SELECT * FROM deadlines WHERE id = $1",
      [deadlineId],
    );

    if (!result.rows[0]) {
      throw new DeadlineError(
        "not_found",
        "deadline not found",
      );
    }

    const deadline = mapDeadline(result.rows[0]);
    const clock = calculateDeadlineClock(deadline, at);

    return {
      status:
        deadline.status === "satisfied" ||
        deadline.status === "cancelled"
          ? deadline.status
          : clock.status,
      escalationLevel:
        deadline.status === "satisfied" ||
        deadline.status === "cancelled"
          ? deadline.escalationLevel
          : clock.escalationLevel,
      warningAt: clock.warningAt,
      dueAt: clock.dueAt,
      overdueAt: clock.overdueAt,
    };
  }

  async sweep(
    at = new Date(),
  ): Promise<DeadlineSweepResult> {
    const client = await this.pool.connect();
    let deadlinesExamined = 0;
    let statusTransitions = 0;
    let escalations = 0;

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `SELECT *
         FROM deadlines
         WHERE status NOT IN ('satisfied', 'cancelled')
         ORDER BY due_at ASC, id ASC
         FOR UPDATE SKIP LOCKED`,
      );

      for (const row of result.rows) {
        const deadline = mapDeadline(row);
        deadlinesExamined += 1;

        const transition = await advanceClockLocked(
          client,
          deadline,
          at,
          null,
        );

        statusTransitions += transition.statusTransitions;
        escalations += transition.escalations;
      }

      await client.query("COMMIT");
      return {
        deadlinesExamined,
        statusTransitions,
        escalations,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async satisfy(
    input: SatisfyDeadlineInput,
  ): Promise<DeadlineView> {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const row = await lockDeadline(
        client,
        input.deadlineId,
      );
      let deadline = mapDeadline(row);

      assertActive(deadline);

      await assertPrincipal(
        client,
        deadline.organizationId,
        input.principalId,
      );

      const satisfiedAt = input.satisfiedAt
        ? normalizeRequiredDate(
            input.satisfiedAt,
            "satisfiedAt",
          )
        : new Date().toISOString();
      const satisfiedDate = new Date(satisfiedAt);

      await advanceClockLocked(
        client,
        deadline,
        satisfiedDate,
        input.correlationId ?? null,
      );

      const refreshed = await client.query(
        "SELECT * FROM deadlines WHERE id = $1 FOR UPDATE",
        [deadline.id],
      );
      deadline = mapDeadline(refreshed.rows[0]);

      const clock = calculateDeadlineClock(
        deadline,
        satisfiedDate,
      );
      const outcome =
        satisfiedDate.getTime() <
        new Date(clock.overdueAt).getTime()
          ? "on_time"
          : "late";

      await client.query(
        `INSERT INTO deadline_occurrences(
           id,
           organization_id,
           deadline_id,
           cycle_number,
           due_at,
           satisfied_at,
           satisfied_by_principal_id,
           outcome,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb
         )`,
        [
          randomUUID(),
          deadline.organizationId,
          deadline.id,
          deadline.cycleNumber,
          deadline.dueAt,
          satisfiedAt,
          input.principalId,
          outcome,
        ],
      );

      await appendAuditEventWithClient(client, {
        organizationId: deadline.organizationId,
        aggregateType: "deadline",
        aggregateId: deadline.id,
        eventType: "deadline.satisfied",
        actorPrincipalId: input.principalId,
        occurredAt: satisfiedAt,
        correlationId: input.correlationId ?? null,
        payload: {
          cycleNumber: deadline.cycleNumber,
          dueAt: deadline.dueAt,
          satisfiedAt,
          outcome,
        },
      });

      const nextDue = nextRecurringDue(deadline);
      const canAdvance =
        nextDue !== null &&
        recurrenceAllowsNext(deadline, nextDue);

      if (!canAdvance) {
        await client.query(
          `UPDATE deadlines
           SET status = 'satisfied',
               satisfied_at = $2,
               updated_at = now()
           WHERE id = $1`,
          [deadline.id, satisfiedAt],
        );
      } else {
        const nextCycle = deadline.cycleNumber + 1;

        await client.query(
          `UPDATE deadlines
           SET due_at = $2,
               cycle_number = $3,
               status = 'scheduled',
               escalation_level = 0,
               satisfied_at = NULL,
               updated_at = now()
           WHERE id = $1`,
          [
            deadline.id,
            nextDue.toISOString(),
            nextCycle,
          ],
        );

        await appendAuditEventWithClient(client, {
          organizationId: deadline.organizationId,
          aggregateType: "deadline",
          aggregateId: deadline.id,
          eventType: "deadline.cycle_advanced",
          actorPrincipalId: input.principalId,
          occurredAt: satisfiedAt,
          correlationId: input.correlationId ?? null,
          payload: {
            completedCycleNumber: deadline.cycleNumber,
            nextCycleNumber: nextCycle,
            nextDueAt: nextDue.toISOString(),
          },
        });

        const nextRow = await client.query(
          "SELECT * FROM deadlines WHERE id = $1 FOR UPDATE",
          [deadline.id],
        );
        const nextDeadline = mapDeadline(nextRow.rows[0]);

        await advanceClockLocked(
          client,
          nextDeadline,
          satisfiedDate,
          input.correlationId ?? null,
        );
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.get(input.deadlineId);
  }

  async cancel(
    input: CancelDeadlineInput,
  ): Promise<DeadlineView> {
    const reason = input.reason.trim();

    if (!reason) {
      throw new DeadlineError(
        "validation",
        "cancellation reason is required",
      );
    }

    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const row = await lockDeadline(
        client,
        input.deadlineId,
      );
      const deadline = mapDeadline(row);

      assertActive(deadline);

      await assertPrincipal(
        client,
        deadline.organizationId,
        input.principalId,
      );

      const cancelledAt = new Date().toISOString();

      await client.query(
        `UPDATE deadlines
         SET status = 'cancelled',
             updated_at = now()
         WHERE id = $1`,
        [deadline.id],
      );

      await appendAuditEventWithClient(client, {
        organizationId: deadline.organizationId,
        aggregateType: "deadline",
        aggregateId: deadline.id,
        eventType: "deadline.cancelled",
        actorPrincipalId: input.principalId,
        occurredAt: cancelledAt,
        correlationId: input.correlationId ?? null,
        payload: {
          cycleNumber: deadline.cycleNumber,
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

    return this.get(input.deadlineId);
  }
}

export function calculateDeadlineClock(
  deadline: Deadline,
  at = new Date(),
): DeadlineClockState {
  const due = new Date(deadline.dueAt);
  const warningAt = new Date(
    due.getTime() -
      deadline.warningWindowSeconds * 1_000,
  );
  const overdueAt = new Date(
    due.getTime() +
      deadline.gracePeriodSeconds * 1_000,
  );
  const time = at.getTime();

  let status: DeadlineClockState["status"];

  if (time < warningAt.getTime()) {
    status = "scheduled";
  } else if (time < due.getTime()) {
    status = "warning";
  } else if (time < overdueAt.getTime()) {
    status = "due";
  } else {
    status = "overdue";
  }

  let escalationLevel = 0;

  if (status === "overdue") {
    const overdueAgeSeconds = Math.floor(
      (time - overdueAt.getTime()) / 1_000,
    );

    escalationLevel =
      deadline.escalationAfterSeconds.filter(
        (threshold) =>
          overdueAgeSeconds >= threshold,
      ).length;
  }

  return {
    status,
    escalationLevel,
    warningAt: warningAt.toISOString(),
    dueAt: due.toISOString(),
    overdueAt: overdueAt.toISOString(),
  };
}

async function advanceClockLocked(
  client: PoolClient,
  deadline: Deadline,
  at: Date,
  correlationId: string | null,
): Promise<{
  changed: boolean;
  statusTransitions: number;
  escalations: number;
}> {
  if (
    deadline.status === "satisfied" ||
    deadline.status === "cancelled"
  ) {
    return {
      changed: false,
      statusTransitions: 0,
      escalations: 0,
    };
  }

  const target = calculateDeadlineClock(deadline, at);
  const currentRank = ACTIVE_STATUS_ORDER.indexOf(
    deadline.status,
  );
  const targetRank = ACTIVE_STATUS_ORDER.indexOf(
    target.status,
  );

  let statusTransitions = 0;
  let escalations = 0;
  let changed = false;

  if (targetRank > currentRank) {
    for (
      let index = currentRank + 1;
      index <= targetRank;
      index += 1
    ) {
      const status = ACTIVE_STATUS_ORDER[index]!;
      const occurredAt = transitionTime(
        status,
        target,
      );

      await appendAuditEventWithClient(client, {
        organizationId: deadline.organizationId,
        aggregateType: "deadline",
        aggregateId: deadline.id,
        eventType: `deadline.${status}`,
        occurredAt,
        correlationId,
        payload: {
          cycleNumber: deadline.cycleNumber,
          dueAt: deadline.dueAt,
          status,
        },
      });

      statusTransitions += 1;
    }

    changed = true;
  }

  if (
    target.status === "overdue" &&
    target.escalationLevel >
      deadline.escalationLevel
  ) {
    for (
      let level = deadline.escalationLevel + 1;
      level <= target.escalationLevel;
      level += 1
    ) {
      const thresholdSeconds =
        deadline.escalationAfterSeconds[level - 1]!;
      const occurredAt = new Date(
        new Date(target.overdueAt).getTime() +
          thresholdSeconds * 1_000,
      ).toISOString();

      await appendAuditEventWithClient(client, {
        organizationId: deadline.organizationId,
        aggregateType: "deadline",
        aggregateId: deadline.id,
        eventType: "deadline.escalated",
        occurredAt,
        correlationId,
        payload: {
          cycleNumber: deadline.cycleNumber,
          escalationLevel: level,
          thresholdSeconds,
        },
      });

      escalations += 1;
    }

    changed = true;
  }

  if (changed) {
    await client.query(
      `UPDATE deadlines
       SET status = $2,
           escalation_level = $3,
           updated_at = now()
       WHERE id = $1`,
      [
        deadline.id,
        targetRank > currentRank
          ? target.status
          : deadline.status,
        Math.max(
          deadline.escalationLevel,
          target.escalationLevel,
        ),
      ],
    );
  }

  return {
    changed,
    statusTransitions,
    escalations,
  };
}

function transitionTime(
  status: DeadlineClockState["status"],
  clock: DeadlineClockState,
): string {
  switch (status) {
    case "scheduled":
      return clock.warningAt;
    case "warning":
      return clock.warningAt;
    case "due":
      return clock.dueAt;
    case "overdue":
      return clock.overdueAt;
  }
}

function nextRecurringDue(
  deadline: Deadline,
): Date | null {
  if (deadline.recurrenceIntervalSeconds === null) {
    return null;
  }

  return new Date(
    new Date(deadline.dueAt).getTime() +
      deadline.recurrenceIntervalSeconds * 1_000,
  );
}

function recurrenceAllowsNext(
  deadline: Deadline,
  nextDue: Date,
): boolean {
  const nextCycle = deadline.cycleNumber + 1;

  if (
    deadline.maxOccurrences !== null &&
    nextCycle > deadline.maxOccurrences
  ) {
    return false;
  }

  if (
    deadline.recurrenceEndAt !== null &&
    nextDue.getTime() >
      new Date(deadline.recurrenceEndAt).getTime()
  ) {
    return false;
  }

  return true;
}

function validateCreateInput(
  input: CreateDeadlineInput,
): void {
  if (!input.organizationId.trim()) {
    throw new DeadlineError(
      "validation",
      "organizationId is required",
    );
  }
  if (!input.subjectType.trim()) {
    throw new DeadlineError(
      "validation",
      "subjectType is required",
    );
  }
  if (!input.subjectId.trim()) {
    throw new DeadlineError(
      "validation",
      "subjectId is required",
    );
  }
  if (!input.deadlineType.trim()) {
    throw new DeadlineError(
      "validation",
      "deadlineType is required",
    );
  }

  const hasAbsolute = input.dueAt !== undefined;
  const hasRelative =
    input.dueAfterSeconds !== undefined;

  if (hasAbsolute === hasRelative) {
    throw new DeadlineError(
      "validation",
      "provide exactly one of dueAt or dueAfterSeconds",
    );
  }

  if (
    input.anchorAt !== undefined &&
    !hasRelative
  ) {
    throw new DeadlineError(
      "validation",
      "anchorAt is only valid with dueAfterSeconds",
    );
  }

  validateNonnegativeSafeInteger(
    input.warningWindowSeconds ?? 0,
    "warningWindowSeconds",
  );
  validateNonnegativeSafeInteger(
    input.gracePeriodSeconds ?? 0,
    "gracePeriodSeconds",
  );

  if (input.dueAfterSeconds !== undefined) {
    validatePositiveSafeInteger(
      input.dueAfterSeconds,
      "dueAfterSeconds",
    );
  }

  if (
    input.recurrenceIntervalSeconds !== undefined &&
    input.recurrenceIntervalSeconds !== null
  ) {
    validatePositiveSafeInteger(
      input.recurrenceIntervalSeconds,
      "recurrenceIntervalSeconds",
    );
  }

  if (
    input.maxOccurrences !== undefined &&
    input.maxOccurrences !== null
  ) {
    validatePositiveSafeInteger(
      input.maxOccurrences,
      "maxOccurrences",
    );
  }

  normalizeEscalationThresholds(
    input.escalationAfterSeconds ?? [],
  );
}

function resolveTiming(
  input: CreateDeadlineInput,
  now: Date,
): {
  anchorAt: string | null;
  dueOffsetSeconds: number | null;
  dueAt: string;
} {
  if (input.dueAt !== undefined) {
    return {
      anchorAt: null,
      dueOffsetSeconds: null,
      dueAt: normalizeRequiredDate(
        input.dueAt,
        "dueAt",
      ),
    };
  }

  const anchorAt = input.anchorAt
    ? normalizeRequiredDate(
        input.anchorAt,
        "anchorAt",
      )
    : now.toISOString();
  const dueOffsetSeconds =
    input.dueAfterSeconds!;

  return {
    anchorAt,
    dueOffsetSeconds,
    dueAt: new Date(
      new Date(anchorAt).getTime() +
        dueOffsetSeconds * 1_000,
    ).toISOString(),
  };
}

function validateRecurrence(
  dueAt: string,
  recurrenceIntervalSeconds: number | null,
  recurrenceEndAt: string | null,
  maxOccurrences: number | null,
): void {
  if (
    recurrenceIntervalSeconds === null &&
    (recurrenceEndAt !== null ||
      maxOccurrences !== null)
  ) {
    throw new DeadlineError(
      "validation",
      "recurrenceEndAt and maxOccurrences require recurrenceIntervalSeconds",
    );
  }

  if (
    recurrenceEndAt !== null &&
    new Date(recurrenceEndAt).getTime() <=
      new Date(dueAt).getTime()
  ) {
    throw new DeadlineError(
      "validation",
      "recurrenceEndAt must be after the first dueAt",
    );
  }
}

function normalizeEscalationThresholds(
  values: number[],
): number[] {
  if (!Array.isArray(values)) {
    throw new DeadlineError(
      "validation",
      "escalationAfterSeconds must be an array",
    );
  }

  const normalized = values.map((value, index) => {
    validateNonnegativeSafeInteger(
      value,
      `escalationAfterSeconds[${index}]`,
    );
    return value;
  });

  const unique = [...new Set(normalized)].sort(
    (a, b) => a - b,
  );

  if (unique.length !== normalized.length) {
    throw new DeadlineError(
      "validation",
      "escalationAfterSeconds cannot contain duplicates",
    );
  }

  return unique;
}

function validatePositiveSafeInteger(
  value: number,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw new DeadlineError(
      "validation",
      `${field} must be a positive safe integer`,
    );
  }
}

function validateNonnegativeSafeInteger(
  value: number,
  field: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new DeadlineError(
      "validation",
      `${field} must be a nonnegative safe integer`,
    );
  }
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

function normalizeRequiredDate(
  value: string,
  field: string,
): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new DeadlineError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }

  return date.toISOString();
}

function assertActive(deadline: Deadline): void {
  if (
    deadline.status === "satisfied" ||
    deadline.status === "cancelled"
  ) {
    throw new DeadlineError(
      "invalid_state",
      "deadline is already terminal",
    );
  }
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
    throw new DeadlineError(
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
    throw new DeadlineError(
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
    throw new DeadlineError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

async function lockDeadline(
  client: PoolClient,
  deadlineId: string,
): Promise<any> {
  const result = await client.query(
    "SELECT * FROM deadlines WHERE id = $1 FOR UPDATE",
    [deadlineId],
  );

  if (!result.rows[0]) {
    throw new DeadlineError(
      "not_found",
      "deadline not found",
    );
  }

  return result.rows[0];
}

function mapDeadline(row: any): Deadline {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceId: row.resource_id,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    deadlineType: row.deadline_type,
    status: row.status,
    createdByPrincipalId:
      row.created_by_principal_id,
    anchorAt: nullableIso(row.anchor_at),
    dueOffsetSeconds:
      row.due_offset_seconds === null
        ? null
        : Number(row.due_offset_seconds),
    dueAt: iso(row.due_at),
    warningWindowSeconds: Number(
      row.warning_window_seconds,
    ),
    gracePeriodSeconds: Number(
      row.grace_period_seconds,
    ),
    recurrenceIntervalSeconds:
      row.recurrence_interval_seconds === null
        ? null
        : Number(row.recurrence_interval_seconds),
    recurrenceEndAt: nullableIso(
      row.recurrence_end_at,
    ),
    maxOccurrences:
      row.max_occurrences === null
        ? null
        : Number(row.max_occurrences),
    cycleNumber: Number(row.cycle_number),
    escalationAfterSeconds: Array.isArray(
      row.escalation_after_seconds,
    )
      ? row.escalation_after_seconds.map(Number)
      : [],
    escalationLevel: Number(
      row.escalation_level,
    ),
    satisfiedAt: nullableIso(row.satisfied_at),
    metadata: (row.metadata ?? {}) as JsonObject,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapOccurrence(
  row: any,
): DeadlineOccurrence {
  return {
    id: row.id,
    organizationId: row.organization_id,
    deadlineId: row.deadline_id,
    cycleNumber: Number(row.cycle_number),
    dueAt: iso(row.due_at),
    satisfiedAt: iso(row.satisfied_at),
    satisfiedByPrincipalId:
      row.satisfied_by_principal_id,
    outcome: row.outcome,
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
  return error instanceof DeadlineError
    ? error
    : error;
}
