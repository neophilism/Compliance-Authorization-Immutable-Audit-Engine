import type {
  JsonObject,
  JsonValue,
} from "@caiae/core";

export type PublicationState =
  | "private"
  | "published";

export type BuiltInProjectionType =
  | "organization_summary"
  | "organization_compliance"
  | "resource_compliance"
  | "finding_summary"
  | "certification_summary";

export type PublicationPolicy = {
  omitPaths?: string[];
  replacements?: Record<string, JsonValue>;
};

export type NormalizedPublicationPolicy = {
  omitPaths: string[];
  replacements: Record<string, JsonValue>;
};

export type PublicationErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state";

export class PublicationError extends Error {
  constructor(
    public readonly code: PublicationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PublicationError";
  }
}

export type PublicationRecord = {
  id: string;
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  state: PublicationState;
  revision: number;
  projection: JsonObject;
  projectionHash: string;
  policy: NormalizedPublicationPolicy;
  publishedAt: string | null;
  publishedByPrincipalId: string | null;
  unpublishedAt: string | null;
  unpublishedByPrincipalId: string | null;
  createdAt: string;
  updatedAt: string;
};

export type PublicPublication = {
  id: string;
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  revision: number;
  projectionHash: string;
  publishedAt: string;
  projection: JsonObject;
};

export type PublicationPreview = {
  schemaVersion: "1";
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  asOf: string;
  policy: NormalizedPublicationPolicy;
  projectionHash: string;
  projection: JsonObject;
};

export type PreviewPublicationInput = {
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  asOf?: string;
  policy?: PublicationPolicy;
};

export type PublishInput =
  PreviewPublicationInput & {
    principalId: string;
    correlationId?: string | null;
  };

export type UnpublishInput = {
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  principalId: string;
  reason?: string | null;
  correlationId?: string | null;
};

export type PublicationListOptions = {
  subjectType?: string | null;
  subjectId?: string | null;
  projectionType?: string | null;
};

export type ResourceComplianceProjection = {
  organizationId: string;
  resource: {
    id: string;
    resourceType: string;
    name: string;
    externalRef: string | null;
    status: string;
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

export type PublicationProjectionBuilderContext = {
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  asOf: string;
};

export type PublicationProjectionBuilder = (
  context: PublicationProjectionBuilderContext,
) => Promise<JsonObject>;

export type PublicationServiceOptions = {
  now?: () => Date;
  projectionBuilders?: Record<
    string,
    PublicationProjectionBuilder
  >;
};
