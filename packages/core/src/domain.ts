export type EntityId = string;
export type ISODateTime = string;
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface BaseEntity {
  id: EntityId;
  organizationId: EntityId;
  createdAt: ISODateTime;
  updatedAt: ISODateTime;
  metadata: JsonObject;
}

export interface Organization {
  id: EntityId;
  name: string;
  slug: string;
  status: "active" | "inactive";
  createdAt: ISODateTime;
  updatedAt: ISODateTime;
  metadata: JsonObject;
}

export interface Principal extends BaseEntity {
  kind: "user" | "service";
  displayName: string;
  externalRef: string | null;
  status: "active" | "inactive";
}

export interface Resource extends BaseEntity {
  resourceType: string;
  name: string;
  externalRef: string | null;
  status: "active" | "inactive" | "archived";
  attributes: JsonObject;
}

export interface Policy extends BaseEntity {
  key: string;
  title: string;
  description: string;
  status: "draft" | "active" | "retired";
}

export interface RuleSet extends BaseEntity {
  policyId: EntityId;
  key: string;
  version: string;
  status: "draft" | "active" | "superseded" | "retired";
  effectiveFrom: ISODateTime | null;
  effectiveTo: ISODateTime | null;
}

export interface Rule extends BaseEntity {
  ruleSetId: EntityId;
  key: string;
  title: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  definition: JsonObject;
  enabled: boolean;
}

export interface Obligation extends BaseEntity {
  resourceId: EntityId;
  ruleId: EntityId | null;
  key: string;
  title: string;
  status: "pending" | "satisfied" | "waived" | "overdue" | "cancelled";
  dueAt: ISODateTime | null;
}

export type AuthorizationStatus =
  | "pending"
  | "approved"
  | "denied"
  | "revoked"
  | "expired";

export type AuthorizationDecisionValue = "approve" | "deny";

export interface Authorization extends BaseEntity {
  resourceId: EntityId;
  authorizationType: string;
  status: AuthorizationStatus;
  requestedByPrincipalId: EntityId | null;
  decidedByPrincipalId: EntityId | null;
  requestedAt: ISODateTime;
  decidedAt: ISODateTime | null;
  validFrom: ISODateTime | null;
  validUntil: ISODateTime | null;
  scope: JsonObject;
  conditions: JsonObject;
  approvalQuorum: number;
  approvalAuthority: string | null;
  emergency: boolean;
  emergencyReviewDueAt: ISODateTime | null;
  emergencyReviewedAt: ISODateTime | null;
}

export interface AuthorizationDecision extends BaseEntity {
  authorizationId: EntityId;
  principalId: EntityId;
  decision: AuthorizationDecisionValue;
  rationale: string;
  decidedAt: ISODateTime;
}

export type ExceptionKind = "exception" | "waiver";

export type ExceptionStatus =
  | "requested"
  | "approved"
  | "denied"
  | "expired"
  | "revoked";

export type ExceptionDecisionValue = "approve" | "deny";

export interface ExceptionRecord extends BaseEntity {
  resourceId: EntityId;
  ruleId: EntityId | null;
  kind: ExceptionKind;
  status: ExceptionStatus;
  requestedByPrincipalId: EntityId;
  decidedByPrincipalId: EntityId | null;
  requestedAt: ISODateTime;
  decidedAt: ISODateTime | null;
  justification: string;
  validFrom: ISODateTime | null;
  validUntil: ISODateTime;
  scope: JsonObject;
  conditions: JsonObject;
  approvalQuorum: number;
  approvalAuthority: string | null;
}

export interface ExceptionDecision extends BaseEntity {
  exceptionId: EntityId;
  principalId: EntityId;
  decision: ExceptionDecisionValue;
  rationale: string;
  decidedAt: ISODateTime;
}

export type EvidenceStatus = "active" | "superseded" | "revoked";

export interface Evidence extends BaseEntity {
  resourceId: EntityId;
  evidenceType: string;
  title: string;
  status: EvidenceStatus;
  submittedByPrincipalId: EntityId | null;
  source: string | null;
  uri: string | null;
  mediaType: string | null;
  fileName: string | null;
  checksumAlgorithm: string | null;
  checksum: string | null;
  capturedAt: ISODateTime | null;
  validFrom: ISODateTime | null;
  validUntil: ISODateTime | null;
  provenance: JsonObject;
  supersedesEvidenceId: EntityId | null;
  supersededAt: ISODateTime | null;
  attributes: JsonObject;
}

export interface EvidenceAttestation extends BaseEntity {
  evidenceId: EntityId;
  principalId: EntityId;
  attestationType: string;
  statement: string;
  claims: JsonObject;
  attestedAt: ISODateTime;
  validUntil: ISODateTime | null;
  revokedAt: ISODateTime | null;
}

export interface Check extends BaseEntity {
  resourceId: EntityId;
  ruleSetId: EntityId | null;
  status: "pending" | "running" | "passed" | "failed" | "unknown" | "error";
  startedAt: ISODateTime | null;
  completedAt: ISODateTime | null;
  result: JsonObject;
}

export interface Finding extends BaseEntity {
  resourceId: EntityId;
  checkId: EntityId | null;
  ruleId: EntityId | null;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "open" | "acknowledged" | "remediating" | "resolved" | "closed";
  title: string;
  description: string;
}

export interface Remediation extends BaseEntity {
  findingId: EntityId;
  ownerPrincipalId: EntityId | null;
  status: "planned" | "in_progress" | "ready_for_verification" | "verified" | "rejected" | "cancelled";
  plan: string;
  dueAt: ISODateTime | null;
  completedAt: ISODateTime | null;
}

export interface Certification extends BaseEntity {
  resourceId: EntityId;
  certificationType: string;
  status: "pending" | "active" | "suspended" | "revoked" | "expired";
  issuedAt: ISODateTime | null;
  validUntil: ISODateTime | null;
  conditions: JsonObject;
}

export type DeadlineStatus =
  | "scheduled"
  | "warning"
  | "due"
  | "overdue"
  | "satisfied"
  | "cancelled";

export interface Deadline extends BaseEntity {
  resourceId: EntityId | null;
  subjectType: string;
  subjectId: EntityId;
  deadlineType: string;
  status: DeadlineStatus;
  createdByPrincipalId: EntityId | null;
  anchorAt: ISODateTime | null;
  dueOffsetSeconds: number | null;
  dueAt: ISODateTime;
  warningWindowSeconds: number;
  gracePeriodSeconds: number;
  recurrenceIntervalSeconds: number | null;
  recurrenceEndAt: ISODateTime | null;
  maxOccurrences: number | null;
  cycleNumber: number;
  escalationAfterSeconds: number[];
  escalationLevel: number;
  satisfiedAt: ISODateTime | null;
}

export interface DeadlineOccurrence extends BaseEntity {
  deadlineId: EntityId;
  cycleNumber: number;
  dueAt: ISODateTime;
  satisfiedAt: ISODateTime;
  outcome: "on_time" | "late";
}

export interface AuditEvent {
  id: EntityId;
  organizationId: EntityId;
  aggregateType: string;
  aggregateId: EntityId;
  sequenceNumber: number;
  eventType: string;
  actorPrincipalId: EntityId | null;
  occurredAt: ISODateTime;
  recordedAt: ISODateTime;
  correlationId: string | null;
  payload: JsonObject;
  previousEventHash: string | null;
  eventHash: string;
}
