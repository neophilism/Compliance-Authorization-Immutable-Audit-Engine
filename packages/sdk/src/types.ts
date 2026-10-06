import type {
  JsonObject,
  Organization,
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
  DeclarativeRuleSet,
  JsonObject,
  Organization,
  Paginated,
  RegistryComplianceProjection,
  Resource,
  ResourceListOptions,
  ServiceScope,
};
