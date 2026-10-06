import type {
  JsonObject,
  Resource,
} from "@caiae/core";

export type IntegrationErrorCode =
  | "validation"
  | "not_found"
  | "unauthorized"
  | "forbidden"
  | "conflict";

export class IntegrationError extends Error {
  constructor(
    public readonly code: IntegrationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "IntegrationError";
  }
}

export type ServiceScope =
  | "*"
  | "resources:read"
  | "resources:write"
  | "checks:run"
  | "events:read"
  | "webhooks:read"
  | "webhooks:write"
  | "imports:write"
  | "exports:read"
  | "adapters:read";

export type ApiCredential = {
  id: string;
  organizationId: string;
  principalId: string;
  name: string;
  tokenPrefix: string;
  scopes: ServiceScope[];
  status: "active" | "revoked";
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdByPrincipalId: string | null;
  revokedAt: string | null;
  metadata: JsonObject;
  createdAt: string;
  updatedAt: string;
};

export type AuthenticatedService = {
  credential: ApiCredential;
  principal: {
    id: string;
    organizationId: string;
    displayName: string;
    externalRef: string | null;
    status: "active";
  };
};

export type CreateServiceAccountInput = {
  organizationId: string;
  displayName: string;
  credentialName: string;
  createdByPrincipalId: string;
  scopes: ServiceScope[];
  expiresAt?: string | null;
  externalRef?: string | null;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type IssuedServiceCredential = {
  principal: AuthenticatedService["principal"];
  credential: ApiCredential;
  token: string;
};

export type Paginated<T> = {
  items: T[];
  nextCursor: string | null;
};

export type ResourceListOptions = {
  limit?: number;
  cursor?: string | null;
  resourceType?: string | null;
  status?: Resource["status"] | null;
};

export type EventListOptions = {
  limit?: number;
  cursor?: string | null;
  eventType?: string | null;
};

export type IntegrationEvent = {
  id: string;
  organizationId: string;
  auditEventId: string;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  payload: JsonObject;
  occurredAt: string;
  createdAt: string;
};

export type WebhookSubscription = {
  id: string;
  organizationId: string;
  name: string;
  url: string;
  eventTypes: string[];
  status: "active" | "inactive";
  createdByPrincipalId: string | null;
  metadata: JsonObject;
  createdAt: string;
  updatedAt: string;
};

export type CreatedWebhookSubscription = {
  subscription: WebhookSubscription;
  signingSecret: string;
};

export type WebhookDeliverySweep = {
  claimed: number;
  succeeded: number;
  failed: number;
};

export type IdempotencyResult<T> = {
  replayed: boolean;
  statusCode: number;
  body: T;
  contentType: string;
};

export type ResourceImportItem = {
  externalId: string;
  resourceType: string;
  name: string;
  externalRef?: string | null;
  status?: Resource["status"];
  attributes?: JsonObject;
  metadata?: JsonObject;
};

export type ResourceImportBundle = {
  schemaVersion: "1";
  source: string;
  items: ResourceImportItem[];
};

export type ResourceImportResult = {
  source: string;
  created: number;
  updated: number;
  resourceIds: string[];
};

export type ResourceExportBundle = {
  schemaVersion: "1";
  exportedAt: string;
  organizationId: string;
  items: Array<{
    externalId: string;
    resource: Resource;
  }>;
};

export type RegistryComplianceProjection = {
  organizationId: string;
  resource: {
    id: string;
    resourceType: string;
    name: string;
    externalRef: string | null;
    status: Resource["status"];
  };
  latestCheck: {
    id: string;
    status: string;
    evaluatedAt: string | null;
    ruleSetId: string | null;
    ruleSetVersion: string | null;
  } | null;
  certifications: {
    validCount: number;
    activeCertificateNumbers: string[];
  };
  findings: {
    unresolvedCount: number;
    unresolvedHighCriticalCount: number;
  };
};

export type CaseTriggerType =
  | "finding_human_review"
  | "finding_disputed"
  | "remediation_overdue";

export type CaseWorkflowTrigger = {
  id: string;
  organizationId: string;
  resourceId: string;
  triggerType: CaseTriggerType;
  aggregateType: "finding" | "remediation";
  aggregateId: string;
  severity: string | null;
  status: string;
  title: string;
  dueAt: string | null;
  occurredAt: string;
  metadata: JsonObject;
};

export type IntegrationServiceOptions = {
  webhookMasterSecret?: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  maxWebhookAttempts?: number;
};
