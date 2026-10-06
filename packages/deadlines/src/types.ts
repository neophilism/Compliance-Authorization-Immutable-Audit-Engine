import type {
  Deadline,
  DeadlineOccurrence,
  DeadlineStatus,
  JsonObject,
} from "@caiae/core";

export type DeadlineErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state";

export class DeadlineError extends Error {
  constructor(
    public readonly code: DeadlineErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "DeadlineError";
  }
}

export type CreateDeadlineInput = {
  organizationId: string;
  resourceId?: string | null;
  subjectType: string;
  subjectId: string;
  deadlineType: string;
  createdByPrincipalId?: string | null;
  dueAt?: string;
  anchorAt?: string;
  dueAfterSeconds?: number;
  warningWindowSeconds?: number;
  gracePeriodSeconds?: number;
  recurrenceIntervalSeconds?: number | null;
  recurrenceEndAt?: string | null;
  maxOccurrences?: number | null;
  escalationAfterSeconds?: number[];
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type SatisfyDeadlineInput = {
  deadlineId: string;
  principalId: string;
  satisfiedAt?: string;
  correlationId?: string | null;
};

export type CancelDeadlineInput = {
  deadlineId: string;
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type DeadlineClockState = {
  status: Exclude<DeadlineStatus, "satisfied" | "cancelled">;
  escalationLevel: number;
  warningAt: string;
  dueAt: string;
  overdueAt: string;
};

export type DeadlineView = {
  deadline: Deadline;
  clock: DeadlineClockState | null;
  occurrences: DeadlineOccurrence[];
};

export type DeadlineSweepResult = {
  deadlinesExamined: number;
  statusTransitions: number;
  escalations: number;
};
