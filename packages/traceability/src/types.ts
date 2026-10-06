import type { JsonObject } from "@caiae/core";
import type { DeclarativeRuleSet } from "@caiae/rules";

export type AuthoritySourceType =
  | "statute"
  | "regulation"
  | "order"
  | "case"
  | "contract"
  | "policy"
  | "standard"
  | "guidance"
  | "other";

export type TraceabilityErrorCode =
  | "validation"
  | "not_found"
  | "conflict"
  | "invalid_state";

export class TraceabilityError extends Error {
  constructor(
    public readonly code: TraceabilityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "TraceabilityError";
  }
}

export type AuthoritySource = {
  id: string;
  organizationId: string;
  sourceType: AuthoritySourceType;
  jurisdiction: string | null;
  citation: string;
  title: string;
  uri: string | null;
  sourceDate: string | null;
  effectiveFrom: string | null;
  effectiveTo: string | null;
  contentHash: string | null;
  metadata: JsonObject;
  createdAt: string;
  updatedAt: string;
};

export type RuleSetAuthorityLink = {
  id: string;
  ruleSetId: string;
  authoritySourceId: string;
  relation: string;
  locator: string | null;
  note: string | null;
  createdAt: string;
};

export type RuleSetRevision = {
  id: string;
  organizationId: string;
  policyId: string;
  key: string;
  version: string;
  status: "draft" | "active" | "superseded" | "retired";
  effectiveFrom: string | null;
  effectiveTo: string | null;
  contentHash: string;
  declarativeSnapshot: DeclarativeRuleSet;
  createdByPrincipalId: string | null;
  activatedAt: string | null;
  supersededByRuleSetId: string | null;
  metadata: JsonObject;
  authorities: Array<{
    link: RuleSetAuthorityLink;
    source: AuthoritySource;
  }>;
  createdAt: string;
  updatedAt: string;
};

export type CreateAuthoritySourceInput = {
  organizationId: string;
  sourceType: AuthoritySourceType;
  jurisdiction?: string | null;
  citation: string;
  title: string;
  uri?: string | null;
  sourceDate?: string | null;
  effectiveFrom?: string | null;
  effectiveTo?: string | null;
  contentHash?: string | null;
  metadata?: JsonObject;
  principalId?: string | null;
  correlationId?: string | null;
};

export type RegisterRuleSetRevisionInput = {
  organizationId: string;
  policyId: string;
  ruleSet: DeclarativeRuleSet | unknown;
  effectiveFrom?: string | null;
  effectiveTo?: string | null;
  metadata?: JsonObject;
  principalId?: string | null;
  authorityLinks?: Array<{
    authoritySourceId: string;
    relation?: string;
    locator?: string | null;
    note?: string | null;
  }>;
  correlationId?: string | null;
};

export type ActivateRuleSetRevisionInput = {
  ruleSetId: string;
  principalId: string;
  effectiveFrom?: string | null;
  correlationId?: string | null;
};

export type SupersedeRuleSetRevisionInput = {
  ruleSetId: string;
  supersededByRuleSetId: string;
  principalId: string;
  effectiveTo?: string | null;
  correlationId?: string | null;
};
