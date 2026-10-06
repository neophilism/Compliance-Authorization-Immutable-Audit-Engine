export type Principal = {
  id: string;
  organizationId: string;
  kind: "user" | "service";
  displayName: string;
  externalRef: string | null;
  status: "active" | "inactive";
};

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
  counts: Record<string, unknown>;
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

export type AuditChain = {
  aggregateType: string;
  aggregateId: string;
  eventCount: number;
  valid: boolean;
  failureReason: string | null;
  failureSequenceNumber: number | null;
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
  summary: {
    resources: { total: number; byStatus: Record<string, number> };
    checks: { total: number; byStatus: Record<string, number>; latestCompletedAt: string | null };
    exceptions: { total: number; active: number; byEffectiveStatus: Record<string, number> };
    deadlines: { total: number; overdue: number; byEffectiveStatus: Record<string, number> };
    findings: {
      total: number;
      unresolved: number;
      unresolvedHighCritical: number;
      byStatus: Record<string, number>;
      bySeverity: Record<string, number>;
    };
    remediations: { total: number; overdue: number; byStatus: Record<string, number> };
    certifications: { total: number; valid: number; byEffectiveStatus: Record<string, number> };
    audit: { eventCount: number; chainCount: number; invalidChainCount: number; allChainsValid: boolean };
  };
  resources: ReportResource[];
  checks: ReportCheck[];
  exceptions: ReportException[];
  deadlines: ReportDeadline[];
  findings: ReportFinding[];
  remediations: ReportRemediation[];
  certifications: ReportCertification[];
  auditChains: AuditChain[];
};

export type AuthorizationQueueItem = {
  id: string;
  organizationId: string;
  resourceId: string;
  authorizationType: string;
  status: "pending" | "approved" | "denied" | "revoked" | "expired";
  requestedByPrincipalId: string | null;
  decidedByPrincipalId: string | null;
  requestedAt: string;
  decidedAt: string | null;
  validFrom: string | null;
  validUntil: string | null;
  approvalQuorum: number;
  approvalAuthority: string | null;
  emergency: boolean;
  emergencyReviewDueAt: string | null;
  emergencyReviewedAt: string | null;
  approvalCount: number;
  eligibleApproverCount: number;
  scope: Record<string, unknown>;
  conditions: Record<string, unknown>;
};

export type EvidenceItem = {
  evidence: {
    id: string;
    organizationId: string;
    resourceId: string;
    evidenceType: string;
    title: string;
    status: string;
    submittedByPrincipalId: string | null;
    source: string | null;
    uri: string | null;
    fileName: string | null;
    checksumAlgorithm: string | null;
    checksum: string | null;
    capturedAt: string | null;
    validFrom: string | null;
    validUntil: string | null;
    attributes: Record<string, unknown>;
  };
  attestations: Array<{
    id: string;
    principalId: string;
    attestationType: string;
    statement: string;
    attestedAt: string;
    revokedAt: string | null;
  }>;
};
