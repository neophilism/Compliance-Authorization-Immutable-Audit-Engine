import YAML from "yaml";
import type { JsonObject, JsonValue } from "@caiae/core";
import type {
  DeclarativeRule,
  DeclarativeRuleSet,
  EvaluationContext,
  PredicateOperator,
  RuleExpression,
  Severity,
} from "./types.js";

const severities = new Set<Severity>([
  "info",
  "low",
  "medium",
  "high",
  "critical",
]);

const operators = new Set<PredicateOperator>([
  "exists",
  "equals",
  "notEquals",
  "in",
  "contains",
  "greaterThan",
  "greaterThanOrEqual",
  "lessThan",
  "lessThanOrEqual",
]);

export function parseRuleSet(input: unknown): DeclarativeRuleSet {
  const source = object(input, "ruleset");

  if (source.schemaVersion !== "1") {
    throw new Error("ruleset.schemaVersion must be \"1\"");
  }

  const rules = array(source.rules, "ruleset.rules").map((rule, index) =>
    parseRule(rule, `ruleset.rules[${index}]`),
  );

  if (rules.length === 0) {
    throw new Error("ruleset.rules cannot be empty");
  }

  const ids = new Set<string>();
  for (const rule of rules) {
    if (ids.has(rule.id)) {
      throw new Error(`duplicate rule id: ${rule.id}`);
    }
    ids.add(rule.id);
  }

  return {
    schemaVersion: "1",
    id: string(source.id, "ruleset.id"),
    version: string(source.version, "ruleset.version"),
    title: string(source.title, "ruleset.title"),
    description: optionalString(source.description, "ruleset.description"),
    rules,
    metadata: optionalJsonObject(source.metadata, "ruleset.metadata"),
  };
}

export function parseEvaluationContext(input: unknown): EvaluationContext {
  const source = object(input, "context");
  const resource = object(source.resource, "context.resource");
  const attributes = jsonValue(
    resource.attributes,
    "context.resource.attributes",
  );

  if (
    attributes === null ||
    typeof attributes !== "object" ||
    Array.isArray(attributes)
  ) {
    throw new Error("context.resource.attributes must be an object");
  }

  const metadata =
    resource.metadata === undefined
      ? undefined
      : optionalJsonObject(
          resource.metadata,
          "context.resource.metadata",
        );

  const facts =
    source.facts === undefined
      ? undefined
      : optionalJsonObject(source.facts, "context.facts");

  const evidenceTypes =
    source.evidenceTypes === undefined
      ? undefined
      : array(source.evidenceTypes, "context.evidenceTypes").map(
          (value, index) =>
            string(value, `context.evidenceTypes[${index}]`),
        );

  return {
    resource: {
      resourceType: string(
        resource.resourceType,
        "context.resource.resourceType",
      ),
      status: optionalString(
        resource.status,
        "context.resource.status",
      ),
      attributes,
      metadata,
    },
    facts,
    evidenceTypes,
  };
}

export function parseRuleSetText(
  text: string,
  format: "json" | "yaml",
): DeclarativeRuleSet {
  let parsed: unknown;

  try {
    parsed = format === "json" ? JSON.parse(text) : YAML.parse(text);
  } catch (error) {
    const message = error instanceof Error ? error.message : "parse error";
    throw new Error(`invalid ${format} ruleset: ${message}`);
  }

  return parseRuleSet(parsed);
}

function parseRule(input: unknown, path: string): DeclarativeRule {
  const source = object(input, path);
  const severity = string(source.severity, `${path}.severity`);

  if (!severities.has(severity as Severity)) {
    throw new Error(`${path}.severity is invalid`);
  }

  const requiredEvidenceTypes = source.requiredEvidenceTypes === undefined
    ? undefined
    : array(source.requiredEvidenceTypes, `${path}.requiredEvidenceTypes`).map(
        (value, index) =>
          string(value, `${path}.requiredEvidenceTypes[${index}]`),
      );

  return {
    id: string(source.id, `${path}.id`),
    title: string(source.title, `${path}.title`),
    description: optionalString(source.description, `${path}.description`),
    severity: severity as Severity,
    appliesWhen:
      source.appliesWhen === undefined
        ? undefined
        : parseExpression(source.appliesWhen, `${path}.appliesWhen`),
    require: parseExpression(source.require, `${path}.require`),
    requiredEvidenceTypes,
    metadata: optionalJsonObject(source.metadata, `${path}.metadata`),
  };
}

function parseExpression(input: unknown, path: string): RuleExpression {
  const source = object(input, path);
  const keys = ["all", "any", "not", "field"].filter(
    (key) => source[key] !== undefined,
  );

  if (keys.length !== 1) {
    throw new Error(
      `${path} must contain exactly one expression form: all, any, not, or field`,
    );
  }

  if (source.all !== undefined) {
    const items = array(source.all, `${path}.all`);
    if (items.length === 0) throw new Error(`${path}.all cannot be empty`);
    return {
      all: items.map((item, index) =>
        parseExpression(item, `${path}.all[${index}]`),
      ),
    };
  }

  if (source.any !== undefined) {
    const items = array(source.any, `${path}.any`);
    if (items.length === 0) throw new Error(`${path}.any cannot be empty`);
    return {
      any: items.map((item, index) =>
        parseExpression(item, `${path}.any[${index}]`),
      ),
    };
  }

  if (source.not !== undefined) {
    return { not: parseExpression(source.not, `${path}.not`) };
  }

  const field = string(source.field, `${path}.field`);
  validateFieldPath(field, `${path}.field`);
  const operator = string(source.operator, `${path}.operator`);

  if (!operators.has(operator as PredicateOperator)) {
    throw new Error(`${path}.operator is invalid`);
  }

  if (operator === "exists") {
    if (source.value !== undefined) {
      throw new Error(`${path}.value is not allowed for exists`);
    }
    return { field, operator: "exists" };
  }

  if (source.value === undefined) {
    throw new Error(`${path}.value is required for ${operator}`);
  }

  return {
    field,
    operator: operator as PredicateOperator,
    value: jsonValue(source.value, `${path}.value`),
  };
}

function validateFieldPath(value: string, path: string): void {
  if (!/^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.test(value)) {
    throw new Error(`${path} must be a dot-separated field path`);
  }

  const forbidden = new Set(["__proto__", "prototype", "constructor"]);
  if (value.split(".").some((part) => forbidden.has(part))) {
    throw new Error(`${path} contains a forbidden segment`);
  }
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
  return value;
}

function string(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${path} must be a non-empty string`);
  }
  return value.trim();
}

function optionalString(
  value: unknown,
  path: string,
): string | undefined {
  return value === undefined ? undefined : string(value, path);
}

function optionalJsonObject(
  value: unknown,
  path: string,
): JsonObject | undefined {
  if (value === undefined) return undefined;

  const parsed = jsonValue(value, path);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${path} must be an object`);
  }

  return parsed;
}

function jsonValue(value: unknown, path: string): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} must contain finite numbers`);
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item, index) =>
      jsonValue(item, `${path}[${index}]`),
    );
  }

  if (typeof value === "object") {
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(
      value as Record<string, unknown>,
    )) {
      if (
        key === "__proto__" ||
        key === "prototype" ||
        key === "constructor"
      ) {
        throw new Error(`${path} contains forbidden key ${key}`);
      }
      result[key] = jsonValue(item, `${path}.${key}`);
    }
    return result;
  }

  throw new Error(`${path} contains an unsupported value`);
}
