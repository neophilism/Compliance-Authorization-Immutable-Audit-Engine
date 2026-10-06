import type { JsonObject, JsonValue } from "@caiae/core";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type TriState = true | false | "unknown";

export type PredicateOperator =
  | "exists"
  | "equals"
  | "notEquals"
  | "in"
  | "contains"
  | "greaterThan"
  | "greaterThanOrEqual"
  | "lessThan"
  | "lessThanOrEqual";

export type RuleExpression =
  | { all: RuleExpression[] }
  | { any: RuleExpression[] }
  | { not: RuleExpression }
  | {
      field: string;
      operator: PredicateOperator;
      value?: JsonValue;
    };

export interface DeclarativeRule {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  appliesWhen?: RuleExpression;
  require: RuleExpression;
  requiredEvidenceTypes?: string[];
  metadata?: JsonObject;
}

export interface DeclarativeRuleSet {
  schemaVersion: "1";
  id: string;
  version: string;
  title: string;
  description?: string;
  rules: DeclarativeRule[];
  metadata?: JsonObject;
}

export interface EvaluationContext {
  resource: {
    resourceType: string;
    status?: string;
    attributes: JsonObject;
    metadata?: JsonObject;
  };
  facts?: JsonObject;
  evidenceTypes?: string[];
}

export type RuleResultStatus =
  | "pass"
  | "fail"
  | "unknown"
  | "not_applicable";

export interface RuleEvaluationResult {
  ruleId: string;
  title: string;
  severity: Severity;
  applicable: TriState;
  requirement: TriState | null;
  status: RuleResultStatus;
  requiredEvidenceTypes: string[];
  missingEvidenceTypes: string[];
}

export interface RuleSetEvaluationResult {
  ruleSetId: string;
  version: string;
  status: "pass" | "fail" | "unknown";
  counts: {
    pass: number;
    fail: number;
    unknown: number;
    notApplicable: number;
  };
  rules: RuleEvaluationResult[];
}
