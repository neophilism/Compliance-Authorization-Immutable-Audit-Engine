import type {
  Authorization,
  AuthorizationDecision,
  AuthorizationDecisionValue,
  JsonObject,
} from "@caiae/core";

export type AuthorizationErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state"
  | "forbidden_approver"
  | "duplicate_decision";

export class AuthorizationError extends Error {
  constructor(
    public readonly code: AuthorizationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AuthorizationError";
  }
}

export type RequestAuthorizationInput = {
  organizationId: string;
  resourceId: string;
  authorizationType: string;
  requestedByPrincipalId: string;
  validFrom?: string | null;
  validUntil?: string | null;
  scope?: JsonObject;
  conditions?: JsonObject;
  approvalQuorum?: number;
  approvalAuthority?: string | null;
  eligibleApproverPrincipalIds?: string[];
  emergency?: boolean;
  emergencyReviewDueAt?: string | null;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RecordAuthorizationDecisionInput = {
  authorizationId: string;
  principalId: string;
  decision: AuthorizationDecisionValue;
  rationale?: string;
  correlationId?: string | null;
};

export type RevokeAuthorizationInput = {
  authorizationId: string;
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type AuthorizationRecord = {
  authorization: Authorization;
  decisions: AuthorizationDecision[];
  eligibleApproverPrincipalIds: string[];
  approvalCount: number;
};

export type AuthorizationEffectiveness =
  | { effective: true; reason: "approved" }
  | {
      effective: false;
      reason:
        | "pending"
        | "denied"
        | "revoked"
        | "expired"
        | "not_yet_valid"
        | "validity_expired"
        | "emergency_review_overdue";
    };

export type ExpirationResult = {
  expired: number;
  emergencyRevoked: number;
};
