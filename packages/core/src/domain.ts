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

export interface Authorization extends BaseEntity {
  resourceId: EntityId;
  authorizationType: string;
  status: "pending" | "approved" | "denied" | "revoked" | "expired";
  requestedByPrincipalId: EntityId | null;
  decidedByPrincipalId: EntityId | null;
  requestedAt: ISODateTime;
  decidedAt: ISODateTime | null;
  validFrom: ISODateTime | null;
  validUntil: ISODateTime | null;
  conditions: JsonObject;
}

export interface ExceptionRecord extends BaseEntity {
  resourceId: EntityId;
  ruleId: EntityId | null;
  status: "requested" | "approved" | "denied" | "expired" | "revoked";
  justification: string;
  validFrom: ISODateTime | null;
  validUntil: ISODateTime | null;
  conditions: JsonObject;
}

export interface Evidence extends BaseEntity {
  resourceId: EntityId;
  evidenceType: string;
  title: string;
  source: string | null;
  uri: string | null;
  checksum: string | null;
  capturedAt: ISODateTime | null;
  validUntil: ISODateTime | null;
  attributes: JsonObject;
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

export interface Deadline extends BaseEntity {
  resourceId: EntityId | null;
  subjectType: string;
  subjectId: EntityId;
  deadlineType: string;
  status: "scheduled" | "warning" | "due" | "overdue" | "satisfied" | "cancelled";
  dueAt: ISODateTime;
  satisfiedAt: ISODateTime | null;
}

export interface AuditEvent {
  id: EntityId;
  organizationId: EntityId;
  aggregateType: string;
  aggregateId: EntityId;
  eventType: string;
  actorPrincipalId: EntityId | null;
  occurredAt: ISODateTime;
  recordedAt: ISODateTime;
  correlationId: string | null;
  payload: JsonObject;
  previousEventHash: string | null;
  eventHash: string | null;
}
