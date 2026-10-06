import type {
  Finding,
  FindingStatus,
  JsonObject,
  Remediation,
} from "@caiae/core";

export type FindingErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state";

export class FindingError extends Error {
  constructor(
    public readonly code: FindingErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "FindingError";
  }
}

export type FindingView = {
  finding: Finding;
  remediations: Remediation[];
};

export type AssignFindingOwnerInput = {
  findingId: string;
  principalId: string;
  ownerPrincipalId: string | null;
  correlationId?: string | null;
};

export type FindingActionInput = {
  findingId: string;
  principalId: string;
  correlationId?: string | null;
};

export type DisputeFindingInput = FindingActionInput & {
  reason: string;
};

export type ResolveDisputeInput = FindingActionInput & {
  outcome: "uphold" | "dismiss";
  rationale: string;
};

export type CreateRemediationInput = {
  findingId: string;
  createdByPrincipalId: string;
  ownerPrincipalId?: string | null;
  plan: string;
  dueAt?: string | null;
  warningWindowSeconds?: number;
  gracePeriodSeconds?: number;
  escalationAfterSeconds?: number[];
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RemediationActionInput = {
  remediationId: string;
  principalId: string;
  correlationId?: string | null;
};

export type VerifyRemediationInput = RemediationActionInput & {
  note?: string;
};

export type RejectRemediationInput = RemediationActionInput & {
  reason: string;
};

export type CancelRemediationInput = RemediationActionInput & {
  reason: string;
};

export type FindingListFilter = {
  status?: FindingStatus;
};
