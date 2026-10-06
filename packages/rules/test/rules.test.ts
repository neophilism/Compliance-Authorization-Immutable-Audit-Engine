import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateExpression,
  evaluateRuleSet,
  parseEvaluationContext,
  parseRuleSet,
  parseRuleSetText,
} from "../src/index.js";

const context = parseEvaluationContext({
  resource: {
    resourceType: "information-system",
    status: "active",
    attributes: {
      environment: "production",
      containsSensitiveInformation: true,
      owner: "security-office",
      encryption: {
        atRest: { enabled: true },
        inTransit: { enabled: true },
        minimumTlsVersion: 1.3,
      },
      tags: ["federal", "critical"],
    },
  },
  facts: {
    annualReviewComplete: true,
  },
  evidenceTypes: [
    "encryption-configuration",
    "transport-security-configuration",
  ],
});

test("YAML rulesets load and evaluate without engine changes", () => {
  const ruleSet = parseRuleSetText(
    `
schemaVersion: "1"
id: security
version: "1.0.0"
title: Security

rules:
  - id: encryption
    title: Encryption enabled
    severity: critical
    appliesWhen:
      field: resource.attributes.containsSensitiveInformation
      operator: equals
      value: true
    require:
      field: resource.attributes.encryption.atRest.enabled
      operator: equals
      value: true
    requiredEvidenceTypes:
      - encryption-configuration
`,
    "yaml",
  );

  const result = evaluateRuleSet(ruleSet, context);

  assert.equal(result.status, "pass");
  assert.equal(result.rules[0]?.status, "pass");
  assert.equal(result.rules[0]?.severity, "critical");
});

test("JSON rulesets parse with the same schema", () => {
  const ruleSet = parseRuleSetText(
    JSON.stringify({
      schemaVersion: "1",
      id: "json-rules",
      version: "2",
      title: "JSON Rules",
      rules: [
        {
          id: "owner",
          title: "Owner defined",
          severity: "medium",
          require: {
            field: "resource.attributes.owner",
            operator: "exists",
          },
        },
      ],
    }),
    "json",
  );

  assert.equal(evaluateRuleSet(ruleSet, context).status, "pass");
});

test("missing ordinary fields propagate unknown", () => {
  const result = evaluateExpression(
    {
      field: "resource.attributes.missing.value",
      operator: "equals",
      value: true,
    },
    context,
  );

  assert.equal(result, "unknown");
});

test("exists explicitly distinguishes missing fields", () => {
  assert.equal(
    evaluateExpression(
      {
        field: "resource.attributes.owner",
        operator: "exists",
      },
      context,
    ),
    true,
  );

  assert.equal(
    evaluateExpression(
      {
        field: "resource.attributes.noOwner",
        operator: "exists",
      },
      context,
    ),
    false,
  );
});

test("all, any, and not use three-valued logic", () => {
  assert.equal(
    evaluateExpression(
      {
        all: [
          {
            field: "resource.attributes.owner",
            operator: "exists",
          },
          {
            field: "resource.attributes.missing",
            operator: "equals",
            value: true,
          },
        ],
      },
      context,
    ),
    "unknown",
  );

  assert.equal(
    evaluateExpression(
      {
        any: [
          {
            field: "resource.attributes.owner",
            operator: "exists",
          },
          {
            field: "resource.attributes.missing",
            operator: "equals",
            value: true,
          },
        ],
      },
      context,
    ),
    true,
  );

  assert.equal(
    evaluateExpression(
      {
        not: {
          field: "resource.attributes.owner",
          operator: "exists",
        },
      },
      context,
    ),
    false,
  );
});

test("numeric comparison, in, and contains operators work", () => {
  assert.equal(
    evaluateExpression(
      {
        field: "resource.attributes.encryption.minimumTlsVersion",
        operator: "greaterThanOrEqual",
        value: 1.2,
      },
      context,
    ),
    true,
  );

  assert.equal(
    evaluateExpression(
      {
        field: "resource.attributes.environment",
        operator: "in",
        value: ["production", "staging"],
      },
      context,
    ),
    true,
  );

  assert.equal(
    evaluateExpression(
      {
        field: "resource.attributes.tags",
        operator: "contains",
        value: "critical",
      },
      context,
    ),
    true,
  );
});

test("non-applicable rules do not fail a ruleset", () => {
  const ruleSet = parseRuleSet({
    schemaVersion: "1",
    id: "applicability",
    version: "1",
    title: "Applicability",
    rules: [
      {
        id: "development-only",
        title: "Development only",
        severity: "low",
        appliesWhen: {
          field: "resource.attributes.environment",
          operator: "equals",
          value: "development",
        },
        require: {
          field: "resource.attributes.impossible",
          operator: "equals",
          value: true,
        },
      },
    ],
  });

  const result = evaluateRuleSet(ruleSet, context);

  assert.equal(result.status, "pass");
  assert.equal(result.rules[0]?.status, "not_applicable");
});

test("missing required evidence turns an otherwise passing rule unknown", () => {
  const ruleSet = parseRuleSet({
    schemaVersion: "1",
    id: "evidence",
    version: "1",
    title: "Evidence",
    rules: [
      {
        id: "attestation",
        title: "Attestation",
        severity: "high",
        require: {
          field: "facts.annualReviewComplete",
          operator: "equals",
          value: true,
        },
        requiredEvidenceTypes: ["annual-review-attestation"],
      },
    ],
  });

  const result = evaluateRuleSet(ruleSet, context);

  assert.equal(result.status, "unknown");
  assert.deepEqual(result.rules[0]?.missingEvidenceTypes, [
    "annual-review-attestation",
  ]);
});

test("a false requirement fails even if evidence is absent", () => {
  const ruleSet = parseRuleSet({
    schemaVersion: "1",
    id: "failure",
    version: "1",
    title: "Failure",
    rules: [
      {
        id: "bad-control",
        title: "Bad control",
        severity: "critical",
        require: {
          field: "resource.attributes.encryption.atRest.enabled",
          operator: "equals",
          value: false,
        },
        requiredEvidenceTypes: ["missing-evidence"],
      },
    ],
  });

  const result = evaluateRuleSet(ruleSet, context);
  assert.equal(result.status, "fail");
  assert.equal(result.rules[0]?.status, "fail");
});

test("unsafe or executable-looking expressions are rejected", () => {
  assert.throws(
    () =>
      parseRuleSet({
        schemaVersion: "1",
        id: "unsafe",
        version: "1",
        title: "Unsafe",
        rules: [
          {
            id: "script",
            title: "Script",
            severity: "high",
            require: {
              field: "resource.attributes.value",
              operator: "javascript",
              value: "process.exit(0)",
            },
          },
        ],
      }),
    /operator is invalid/,
  );

  assert.throws(
    () =>
      parseRuleSet({
        schemaVersion: "1",
        id: "prototype",
        version: "1",
        title: "Prototype",
        rules: [
          {
            id: "prototype",
            title: "Prototype",
            severity: "high",
            require: {
              field: "resource.__proto__.polluted",
              operator: "exists",
            },
          },
        ],
      }),
    /forbidden segment/,
  );
});

test("malformed rulesets fail validation", () => {
  assert.throws(
    () =>
      parseRuleSet({
        schemaVersion: "2",
        id: "future",
        version: "1",
        title: "Future",
        rules: [],
      }),
    /schemaVersion/,
  );

  assert.throws(
    () =>
      parseRuleSet({
        schemaVersion: "1",
        id: "empty",
        version: "1",
        title: "Empty",
        rules: [],
      }),
    /cannot be empty/,
  );

  assert.throws(
    () =>
      parseEvaluationContext({
        resource: {
          resourceType: "system",
          attributes: {},
          metadata: [],
        },
      }),
    /metadata must be an object/,
  );
});
