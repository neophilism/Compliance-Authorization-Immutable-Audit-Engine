import type {
  Check,
  CheckTrigger,
  EvaluationSchedule,
  JsonObject,
} from "@caiae/core";
import type {
  DeclarativeRuleSet,
  RuleSetEvaluationResult,
} from "@caiae/rules";

export type EvaluationErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state";

export class EvaluationError extends Error {
  constructor(
    public readonly code: EvaluationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "EvaluationError";
  }
}

export type RunCheckInput = {
  organizationId: string;
  resourceId: string;
  ruleSet: DeclarativeRuleSet | unknown;
  ruleSetRevisionId?: string | null;
  requestedByPrincipalId?: string | null;
  facts?: JsonObject;
  trigger?: CheckTrigger;
  triggerDetail?: JsonObject;
  scheduleId?: string | null;
  scheduledFor?: string | null;
  evaluatedAt?: string;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RunBatchInput = Omit<
  RunCheckInput,
  "resourceId" | "scheduleId" | "scheduledFor"
> & {
  resourceIds: string[];
};

export type RunEventInput = Omit<
  RunCheckInput,
  "trigger" | "triggerDetail"
> & {
  eventType: string;
  event: JsonObject;
};

export type CreateScheduleInput = {
  organizationId: string;
  resourceId?: string | null;
  resourceType?: string | null;
  ruleSet: DeclarativeRuleSet | unknown;
  ruleSetRevisionId?: string | null;
  facts?: JsonObject;
  intervalSeconds: number;
  nextRunAt?: string;
  createdByPrincipalId?: string | null;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type CheckView = {
  check: Check;
  evaluation: RuleSetEvaluationResult | null;
};

export type ScheduleSweepResult = {
  schedulesExamined: number;
  schedulesClaimed: number;
  checksCreated: number;
  errors: number;
};

export type EvaluationScheduleView = {
  schedule: EvaluationSchedule;
};
