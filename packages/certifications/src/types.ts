import type {
  Certification,
  CertificationStatus,
  JsonObject,
} from "@caiae/core";

export type CertificationSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type CertificationCriteria = {
  ruleSetId?: string | null;
  ruleSetVersion?: string | null;
  maximumCheckAgeSeconds?: number | null;
  blockingFindingSeverities?: CertificationSeverity[];
  materialFailureSeverities?: CertificationSeverity[];
};

export type CertificationErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state";

export class CertificationError extends Error {
  constructor(
    public readonly code: CertificationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CertificationError";
  }
}

export type IssueCertificationInput = {
  organizationId: string;
  resourceId: string;
  certificationType: string;
  supportingCheckId: string;
  issuedByPrincipalId: string;
  validFrom?: string;
  validUntil?: string;
  validitySeconds?: number;
  criteria?: CertificationCriteria;
  conditions?: JsonObject;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RenewCertificationInput = {
  certificationId: string;
  supportingCheckId: string;
  issuedByPrincipalId: string;
  validFrom?: string;
  validUntil?: string;
  validitySeconds?: number;
  criteria?: CertificationCriteria;
  conditions?: JsonObject;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type CertificationActionInput = {
  certificationId: string;
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type ReinstateCertificationInput = {
  certificationId: string;
  supportingCheckId: string;
  principalId: string;
  rationale: string;
  correlationId?: string | null;
};

export type CertificationView = {
  certification: Certification;
};

export type CertificationVerification = {
  found: boolean;
  valid: boolean;
  certificationId: string | null;
  certificateNumber: string | null;
  storedStatus: CertificationStatus | null;
  effectiveStatus: CertificationStatus | null;
  checkedAt: string;
  publicArtifact: JsonObject | null;
};

export type CertificationSweepResult = {
  examined: number;
  activated: number;
  expired: number;
};

export type MaterialFailureResult = {
  certificationsExamined: number;
  certificationsSuspended: number;
};
