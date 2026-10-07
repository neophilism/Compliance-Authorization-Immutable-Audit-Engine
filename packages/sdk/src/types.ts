import type {
  Authorization,
  AuthorizationDecision,
  AuthorizationDecisionValue,
  Deadline,
  DeadlineOccurrence,
  Evidence,
  EvidenceAttestation,
  DeadlineStatus,
  ExceptionDecision,
  ExceptionDecisionValue,
  ExceptionKind,
  ExceptionRecord,
  Evidence,
  EvidenceAttestation,
  Finding,
  FindingStatus,
  JsonObject,
  Organization,
  Remediation,
  Certification,
  Resource,
} from "@caiae/core";
import type {
  DeclarativeRuleSet,
} from "@caiae/rules";
import type {
  Paginated,
  RegistryComplianceProjection,
  ResourceListOptions,
  ServiceScope,
} from "@caiae/integrations";

export type SdkAuthMode =
  | "public"
  | "operator"
  | "service";

export type ThinAppFeatureFlags = {
  rulesets?: boolean;
  resources?: boolean;
  checks?: boolean;
  authorizations?: boolean;
  exceptions?: boolean;
  evidence?: boolean;
  deadlines?: boolean;
  findings?: boolean;
  remediations?: boolean;
  certifications?: boolean;
  reporting?: boolean;
  publication?: boolean;
  integrations?: boolean;
  security?: boolean;
};

export type ThinAppConfig = {
  schemaVersion: "1";
  appId: string;
  displayName: string;
  description?: string;
  engine: {
    apiBaseUrl: string;
    organizationId?: string;
    requestTimeoutMs?: number;
  };
  features?: ThinAppFeatureFlags;
  resourceTypes?: Record<
    string,
    {
      label: string;
      description?: string;
      metadata?: JsonObject;
    }
  >;
  metadata?: JsonObject;
};

export type RuntimeSecrets = {
  operatorToken?: string;
  serviceToken?: string;
};

export type ThinAppRuntimeConfig = {
  config: ThinAppConfig;
  secrets?: RuntimeSecrets;
};

export type PublicThinAppConfig = ThinAppConfig;

export type ClientTransport = {
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
};

export type SdkClientOptions = {
  baseUrl: string;
  organizationId?: string;
  auth?: {
    mode: SdkAuthMode;
    token?: string;
  };
  requestTimeoutMs?: number;
  transport?: ClientTransport;
};

export type SdkRequestOptions = {
  method?: string;
  query?: Record<
    string,
    | string
    | number
    | boolean
    | null
    | undefined
  >;
  body?: unknown;
  headers?: Record<string, string>;
  idempotencyKey?: string;
  signal?: AbortSignal;
};

export type SdkResponse<T> = {
  status: number;
  headers: Headers;
  data: T;
};

export class SdkError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly payload: unknown,
  ) {
    super(message);
    this.name = "SdkError";
  }
}

export type UpdateResourceInput = {
  expectedUpdatedAt: string;
  name?: string;
  externalRef?: string | null;
  status?: Resource["status"];
  attributes?: JsonObject;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RequestAuthorizationInput = {
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
  principalId: string;
  decision: AuthorizationDecisionValue;
  rationale?: string;
  correlationId?: string | null;
};

export type RevokeAuthorizationInput = {
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
  | {
      effective: true;
      reason: "approved";
    }
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

export type RequestExceptionInput = {
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
  principalId: string;
  decision: ExceptionDecisionValue;
  rationale?: string;
  correlationId?: string | null;
};

export type RevokeExceptionInput = {
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
  | {
      effective: true;
      reason: "approved";
    }
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

export type CreateEvidenceInput = {
  resourceId: string;
  evidenceType: string;
  title: string;
  submittedByPrincipalId?: string | null;
  source?: string | null;
  uri?: string | null;
  mediaType?: string | null;
  fileName?: string | null;
  checksumAlgorithm?: string | null;
  checksum?: string | null;
  capturedAt?: string | null;
  validFrom?: string | null;
  validUntil?: string | null;
  provenance?: JsonObject;
  supersedesEvidenceId?: string | null;
  attributes?: JsonObject;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type AddEvidenceAttestationInput = {
  principalId: string;
  attestationType: string;
  statement: string;
  claims?: JsonObject;
  attestedAt?: string;
  validUntil?: string | null;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RevokeEvidenceInput = {
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type RevokeEvidenceAttestationInput =
  RevokeEvidenceInput;

export type EvidenceView = {
  evidence: Evidence;
  attestations: EvidenceAttestation[];
};

export type EvidenceTypesResult = {
  evidenceTypes: string[];
};

export type CreateDeadlineInput = {
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
  principalId: string;
  satisfiedAt?: string;
  correlationId?: string | null;
};

export type CancelDeadlineInput = {
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type DeadlineClockState = {
  status: Exclude<
    DeadlineStatus,
    "satisfied" | "cancelled"
  >;
  escalationLevel: number;
  warningAt: string;
  dueAt: string;
  overdueAt: string;
};

export type DeadlineStatusSnapshot = {
  status: DeadlineStatus;
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

export type FindingView = {
  finding: Finding;
  remediations: Remediation[];
};

export type SyncFindingsResult = {
  findings: Finding[];
};

export type FindingListFilter = {
  status?: FindingStatus;
};

export type AssignFindingOwnerInput = {
  principalId: string;
  ownerPrincipalId: string | null;
  correlationId?: string | null;
};

export type FindingActionInput = {
  principalId: string;
  correlationId?: string | null;
};

export type DisputeFindingInput =
  FindingActionInput & {
    reason: string;
  };

export type ResolveDisputeInput =
  FindingActionInput & {
    outcome: "uphold" | "dismiss";
    rationale: string;
  };

export type CreateRemediationInput = {
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
  principalId: string;
  correlationId?: string | null;
};

export type VerifyRemediationInput =
  RemediationActionInput & {
    note?: string;
  };

export type RejectRemediationInput =
  RemediationActionInput & {
    reason: string;
  };

export type CancelRemediationInput =
  RemediationActionInput & {
    reason: string;
  };

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

export type IssueCertificationInput = {
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
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type ReinstateCertificationInput = {
  supportingCheckId: string;
  principalId: string;
  rationale: string;
  correlationId?: string | null;
};

export type CertificationView = {
  certification: Certification;
};

export type RunCheckInput = {
  resourceId: string;
  requestedByPrincipalId?: string | null;
  evaluatedAt?: string;
  facts?: JsonObject;
  metadata?: JsonObject;
  correlationId?: string | null;
} & (
  | {
      ruleSet: DeclarativeRuleSet;
      registeredRuleSetId?: never;
    }
  | {
      registeredRuleSetId: string;
      ruleSet?: never;
    }
);

export type RunCheckResult = {
  check: {
    id: string;
    organizationId: string;
    resourceId: string;
    registeredRuleSetId?: string | null;
    ruleSetHash?: string | null;
    registrationMode?: string | null;
    status: string;
    [key: string]: unknown;
  };
  evaluation: unknown;
};

export type RegisteredRuleSetSummary = {
  id: string;
  organizationId: string;
  policyId: string;
  key: string;
  version: string;
  status: string;
  definitionHash: string;
  effectiveFrom: string | null;
  effectiveTo: string | null;
  [key: string]: unknown;
};

export type EngineHealth = {
  status: string;
  service: string;
  release?: string | null;
  timestamp: string;
};

export type RenderedComplianceFormat =
  | "csv"
  | "text";

export type RenderedComplianceReport = {
  format: RenderedComplianceFormat;
  mediaType: string;
  body: string;
};

export type ComplianceReport = {
  schemaVersion: "1";
  reportType: "compliance";
  scope: {
    organizationId: string;
    resourceId: string | null;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
    status: string;
  };
  resources: Array<{
    id: string;
    resourceType: string;
    name: string;
    status: string;
    externalRef: string | null;
  }>;
  checks: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  certifications: Array<Record<string, unknown>>;
  [key: string]: unknown;
};

export type {
  Certification,
  Deadline,
  DeadlineOccurrence,
  DeadlineStatus,
  DeclarativeRuleSet,
  Finding,
  FindingStatus,
  JsonObject,
  Organization,
  Paginated,
  RegistryComplianceProjection,
  Remediation,
  Resource,
  ResourceListOptions,
  ServiceScope,
};
