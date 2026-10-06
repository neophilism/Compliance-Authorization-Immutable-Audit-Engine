import type {
  ExceptionDecision,
  ExceptionDecisionValue,
  ExceptionKind,
  ExceptionRecord,
  JsonObject,
} from "@caiae/core";

export type ExceptionErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state"
  | "forbidden_approver"
  | "duplicate_decision";

export class ExceptionError extends Error {
  constructor(
    public readonly code: ExceptionErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ExceptionError";
  }
}

export type RequestExceptionInput = {
  organizationId: string;
  resourceId: string;
  ruleId?: string | null;
  kind: ExceptionKind;
  requestedByPrincipalId: string;
  justification: string;
  validFrom?: string | null;
  validUntil: string;
  scope?: JsonObject;
  conditions?: JsonObject;
  approvalQuorum?: number;
  approvalAuthority?: string | null;
  eligibleApproverPrincipalIds?: string[];
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RecordExceptionDecisionInput = {
  exceptionId: string;
  principalId: string;
  decision: ExceptionDecisionValue;
  rationale?: string;
  correlationId?: string | null;
};

export type RevokeExceptionInput = {
  exceptionId: string;
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type ExceptionRecordView = {
  exception: ExceptionRecord;
  decisions: ExceptionDecision[];
  eligibleApproverPrincipalIds: string[];
  approvalCount: number;
};

export type ExceptionEffectiveness =
  | { effective: true; reason: "approved" }
  | {
      effective: false;
      reason:
        | "requested"
        | "denied"
        | "revoked"
        | "expired"
        | "not_yet_valid"
        | "validity_expired";
    };

export type ExceptionExpirationResult = {
  expired: number;
};
