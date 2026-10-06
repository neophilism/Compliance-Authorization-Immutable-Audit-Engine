import type {
  AuditEvent,
  JsonObject,
} from "@caiae/core";

export type ReportFormat =
  | "json"
  | "csv"
  | "text";

export type ReportingErrorCode =
  | "validation"
  | "not_found";

export class ReportingError extends Error {
  constructor(
    public readonly code: ReportingErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ReportingError";
  }
}

export type CountMap = Record<string, number>;

export type ReportResource = {
  id: string;
  resourceType: string;
  name: string;
  status: string;
  externalRef: string | null;
};

export type ReportCheck = {
  id: string;
  resourceId: string;
  trigger: string;
  status: string;
  evaluatedAt: string | null;
  completedAt: string | null;
  ruleSetId: string | null;
  ruleSetVersion: string | null;
  ruleSetRevisionId: string | null;
  ruleSetContentHash: string | null;
  authoritySources: Array<{
    sourceType: string;
    citation: string;
    title: string;
    relation: string;
    locator: string | null;
  }>;
  counts: JsonObject;
  errorMessage: string | null;
};

export type ReportException = {
  id: string;
  resourceId: string;
  kind: string;
  storedStatus: string;
  effectiveStatus: string;
  active: boolean;
  justification: string;
  validFrom: string | null;
  validUntil: string | null;
  requestedAt: string;
  decidedAt: string | null;
  approvalAuthority: string | null;
};

export type ReportDeadline = {
  id: string;
  resourceId: string | null;
  subjectType: string;
  subjectId: string;
  deadlineType: string;
  storedStatus: string;
  effectiveStatus: string;
  dueAt: string;
  satisfiedAt: string | null;
  warningWindowSeconds: number;
  gracePeriodSeconds: number;
  escalationLevel: number;
  cycleNumber: number;
};

export type ReportFinding = {
  id: string;
  resourceId: string;
  checkId: string | null;
  ruleKey: string | null;
  ruleSetKey: string | null;
  ruleSetVersion: string | null;
  severity: string;
  status: string;
  ownerPrincipalId: string | null;
  title: string;
  description: string;
  openedAt: string;
  resolvedAt: string | null;
  closedAt: string | null;
};

export type ReportRemediation = {
  id: string;
  findingId: string;
  resourceId: string;
  deadlineId: string | null;
  ownerPrincipalId: string | null;
  status: string;
  plan: string;
  dueAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  verifiedAt: string | null;
};

export type ReportCertification = {
  id: string;
  resourceId: string;
  certificationType: string;
  certificateNumber: string | null;
  supportingCheckId: string | null;
  storedStatus: string;
  effectiveStatus: string;
  valid: boolean;
  issuedAt: string | null;
  validFrom: string | null;
  validUntil: string | null;
  suspensionReason: string | null;
  revocationReason: string | null;
};

export type AuditChainReport = {
  aggregateType: string;
  aggregateId: string;
  eventCount: number;
  valid: boolean;
  failureReason: string | null;
  failureSequenceNumber: number | null;
};

export type ComplianceReportSummary = {
  resources: {
    total: number;
    byStatus: CountMap;
  };
  checks: {
    total: number;
    byStatus: CountMap;
    latestCompletedAt: string | null;
  };
  exceptions: {
    total: number;
    active: number;
    byEffectiveStatus: CountMap;
  };
  deadlines: {
    total: number;
    overdue: number;
    byEffectiveStatus: CountMap;
  };
  findings: {
    total: number;
    unresolved: number;
    unresolvedHighCritical: number;
    byStatus: CountMap;
    bySeverity: CountMap;
  };
  remediations: {
    total: number;
    overdue: number;
    byStatus: CountMap;
  };
  certifications: {
    total: number;
    valid: number;
    byEffectiveStatus: CountMap;
  };
  audit: {
    eventCount: number;
    chainCount: number;
    invalidChainCount: number;
    allChainsValid: boolean;
  };
};

export type ComplianceReport = {
  schemaVersion: "1";
  reportType: "compliance";
  generatedAt: string;
  asOf: string;
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
  resource: ReportResource | null;
  summary: ComplianceReportSummary;
  resources: ReportResource[];
  checks: ReportCheck[];
  exceptions: ReportException[];
  deadlines: ReportDeadline[];
  findings: ReportFinding[];
  remediations: ReportRemediation[];
  certifications: ReportCertification[];
  auditChains: AuditChainReport[];
  auditEvents: AuditEvent[];
};

export type GenerateReportInput = {
  organizationId: string;
  resourceId?: string | null;
  asOf?: string;
};

export type RenderedReport = {
  format: ReportFormat;
  mediaType: string;
  body: string;
};
