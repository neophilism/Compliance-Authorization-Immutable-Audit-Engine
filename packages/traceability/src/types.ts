import type { JsonObject } from "@caiae/core";
import type { DeclarativeRuleSet } from "@caiae/rules";

export type RuleSetVersionStatus =
  | "draft"
  | "active"
  | "superseded"
  | "retired";

export type TraceabilityErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state"
  | "conflict";

export class TraceabilityError extends Error {
  constructor(
    public readonly code: TraceabilityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "TraceabilityError";
  }
}

export type AuthorityReferenceInput = {
  authorityType: string;
  citation: string;
  title?: string | null;
  uri?: string | null;
  locator?: string | null;
  jurisdiction?: string | null;
  effectiveFrom?: string | null;
  effectiveTo?: string | null;
  metadata?: JsonObject;
};

export type AuthorityReference = {
  id: string;
  organizationId: string;
  authorityType: string;
  citation: string;
  title: string | null;
  uri: string | null;
  jurisdiction: string | null;
  effectiveFrom: string | null;
  effectiveTo: string | null;
  referenceHash: string;
  metadata: JsonObject;
  createdAt: string;
};

export type RuleSetAuthorityLink = {
  authority: AuthorityReference;
  locator: string | null;
  metadata: JsonObject;
};

export type RegisteredRuleSetVersion = {
  id: string;
  organizationId: string;
  policyId: string;
  key: string;
  version: string;
  title: string;
  description: string | null;
  status: RuleSetVersionStatus;
  effectiveFrom: string | null;
  effectiveTo: string | null;
  definition: DeclarativeRuleSet;
  definitionHash: string;
  supersedesRuleSetId: string | null;
  activatedAt: string | null;
  activatedByPrincipalId: string | null;
  retiredAt: string | null;
  retiredByPrincipalId: string | null;
  metadata: JsonObject;
  createdAt: string;
  updatedAt: string;
};

export type RuleSetTraceabilityManifest = {
  schemaVersion: "1";
  registrationMode: "registered";
  registeredRuleSetId: string;
  organizationId: string;
  policyId: string;
  key: string;
  version: string;
  status: RuleSetVersionStatus;
  definitionHash: string;
  effectiveFrom: string | null;
  effectiveTo: string | null;
  supersedesRuleSetId: string | null;
  authorities: RuleSetAuthorityLink[];
};

export type AdHocRuleSetTraceabilityManifest = {
  schemaVersion: "1";
  registrationMode: "ad_hoc";
  registeredRuleSetId: null;
  key: string;
  version: string;
  definitionHash: string;
  authorities: [];
};

export type RuleSetTraceability =
  | RuleSetTraceabilityManifest
  | AdHocRuleSetTraceabilityManifest;

export type RegisterRuleSetVersionInput = {
  organizationId: string;
  policyId: string;
  key: string;
  ruleSet: DeclarativeRuleSet | unknown;
  effectiveFrom?: string | null;
  effectiveTo?: string | null;
  supersedesRuleSetId?: string | null;
  authorities?: AuthorityReferenceInput[];
  createdByPrincipalId?: string | null;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type ActivateRuleSetVersionInput = {
  ruleSetId: string;
  principalId: string;
  effectiveFrom?: string | null;
  correlationId?: string | null;
};

export type RetireRuleSetVersionInput = {
  ruleSetId: string;
  principalId: string;
  effectiveTo?: string | null;
  reason?: string | null;
  correlationId?: string | null;
};

export type ResolveRuleSetInput = {
  organizationId: string;
  key: string;
  at?: string;
};

export type ListRuleSetVersionsOptions = {
  key?: string | null;
  status?: RuleSetVersionStatus | null;
};

export type TraceabilityServiceOptions = {
  now?: () => Date;
};
