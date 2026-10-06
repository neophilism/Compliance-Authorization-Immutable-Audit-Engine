import type { JsonValue } from "@caiae/core";
import type {
  DeclarativeRule,
  DeclarativeRuleSet,
  EvaluationContext,
  RuleEvaluationResult,
  RuleExpression,
  RuleSetEvaluationResult,
  TriState,
} from "./types.js";

const MISSING = Symbol("missing");

export function evaluateRuleSet(
  ruleSet: DeclarativeRuleSet,
  context: EvaluationContext,
): RuleSetEvaluationResult {
  const rules = ruleSet.rules.map((rule) => evaluateRule(rule, context));
  const counts = {
    pass: rules.filter((rule) => rule.status === "pass").length,
    fail: rules.filter((rule) => rule.status === "fail").length,
    unknown: rules.filter((rule) => rule.status === "unknown").length,
    notApplicable: rules.filter((rule) => rule.status === "not_applicable").length,
  };

  const status =
    counts.fail > 0 ? "fail" : counts.unknown > 0 ? "unknown" : "pass";

  return {
    ruleSetId: ruleSet.id,
    version: ruleSet.version,
    status,
    counts,
    rules,
  };
}

export function evaluateRule(
  rule: DeclarativeRule,
  context: EvaluationContext,
): RuleEvaluationResult {
  const applicable = rule.appliesWhen
    ? evaluateExpression(rule.appliesWhen, context)
    : true;

  const requiredEvidenceTypes = [...(rule.requiredEvidenceTypes ?? [])];
  const evidence = new Set(context.evidenceTypes ?? []);
  const missingEvidenceTypes = requiredEvidenceTypes.filter(
    (type) => !evidence.has(type),
  );

  if (applicable === false) {
    return {
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      applicable,
      requirement: null,
      status: "not_applicable",
      requiredEvidenceTypes,
      missingEvidenceTypes: [],
    };
  }

  if (applicable === "unknown") {
    return {
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      applicable,
      requirement: null,
      status: "unknown",
      requiredEvidenceTypes,
      missingEvidenceTypes,
    };
  }

  const requirement = evaluateExpression(rule.require, context);
  const status =
    requirement === false
      ? "fail"
      : requirement === "unknown" || missingEvidenceTypes.length > 0
        ? "unknown"
        : "pass";

  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    applicable,
    requirement,
    status,
    requiredEvidenceTypes,
    missingEvidenceTypes,
  };
}

export function evaluateExpression(
  expression: RuleExpression,
  context: EvaluationContext,
): TriState {
  if ("all" in expression) {
    return and3(expression.all.map((item) => evaluateExpression(item, context)));
  }

  if ("any" in expression) {
    return or3(expression.any.map((item) => evaluateExpression(item, context)));
  }

  if ("not" in expression) {
    return not3(evaluateExpression(expression.not, context));
  }

  const actual = getPath(context, expression.field);

  if (expression.operator === "exists") {
    return actual !== MISSING;
  }

  if (actual === MISSING) {
    return "unknown";
  }

  switch (expression.operator) {
    case "equals":
      return jsonEqual(actual as JsonValue, expression.value);
    case "notEquals":
      return !jsonEqual(actual as JsonValue, expression.value);
    case "in":
      return Array.isArray(expression.value)
        ? expression.value.some((item) => jsonEqual(actual as JsonValue, item))
        : "unknown";
    case "contains":
      if (typeof actual === "string" && typeof expression.value === "string") {
        return actual.includes(expression.value);
      }
      if (Array.isArray(actual)) {
        return actual.some((item) =>
          jsonEqual(item as JsonValue, expression.value),
        );
      }
      return "unknown";
    case "greaterThan":
      return numericCompare(actual, expression.value, (a, b) => a > b);
    case "greaterThanOrEqual":
      return numericCompare(actual, expression.value, (a, b) => a >= b);
    case "lessThan":
      return numericCompare(actual, expression.value, (a, b) => a < b);
    case "lessThanOrEqual":
      return numericCompare(actual, expression.value, (a, b) => a <= b);
    default:
      return "unknown";
  }
}

function getPath(root: unknown, path: string): unknown | typeof MISSING {
  const parts = path.split(".");
  let current: unknown = root;

  for (const part of parts) {
    if (
      part === "__proto__" ||
      part === "prototype" ||
      part === "constructor"
    ) {
      return MISSING;
    }

    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current) ||
      !Object.prototype.hasOwnProperty.call(current, part)
    ) {
      return MISSING;
    }

    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

function numericCompare(
  actual: unknown,
  expected: JsonValue | undefined,
  compare: (actual: number, expected: number) => boolean,
): TriState {
  return typeof actual === "number" && typeof expected === "number"
    ? compare(actual, expected)
    : "unknown";
}

function jsonEqual(left: JsonValue, right: JsonValue | undefined): boolean {
  if (right === undefined) return false;
  return stableStringify(left) === stableStringify(right);
}

function stableStringify(value: JsonValue): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    const record = value as Record<string, JsonValue>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key]!)}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

function and3(values: TriState[]): TriState {
  if (values.some((value) => value === false)) return false;
  if (values.some((value) => value === "unknown")) return "unknown";
  return true;
}

function or3(values: TriState[]): TriState {
  if (values.some((value) => value === true)) return true;
  if (values.some((value) => value === "unknown")) return "unknown";
  return false;
}

function not3(value: TriState): TriState {
  return value === "unknown" ? "unknown" : !value;
}
