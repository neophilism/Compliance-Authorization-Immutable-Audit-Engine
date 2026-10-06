import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  TraceabilityService,
} from "@caiae/traceability";
import {
  EvaluationError,
  EvaluationService,
} from "../src/index.js";

const RULESET = {
  schemaVersion: "1",
  id: "traceable-rules",
  version: "1",
  title: "Traceable Rules",
  rules: [
    {
      id: "active",
      title:
        "Resource is active",
      severity: "high",
      require: {
        field: "resource.status",
        operator: "equals",
        value: "active",
      },
    },
  ],
} as const;

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId =
    randomUUID();
  const policyId =
    randomUUID();
  const principalId =
    randomUUID();
  const resourceId =
    randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Traceable Evaluation',
       $2, 'active'
     )`,
    [
      organizationId,
      `trace-eval-${organizationId}`,
    ],
  );
  await pool.query(
    `INSERT INTO policies(
       id, organization_id,
       key, title, status
     ) VALUES (
       $1, $2,
       'traceable-policy',
       'Traceable Policy',
       'active'
     )`,
    [policyId, organizationId],
  );
  await pool.query(
    `INSERT INTO principals(
       id, organization_id,
       kind, display_name, status
     ) VALUES (
       $1, $2, 'user',
       'Evaluator', 'active'
     )`,
    [principalId, organizationId],
  );
  await pool.query(
    `INSERT INTO resources(
       id, organization_id,
       resource_type, name,
       status, attributes
     ) VALUES (
       $1, $2, 'generic',
       'Resource', 'active',
       '{}'::jsonb
     )`,
    [resourceId, organizationId],
  );

  return {
    pool,
    organizationId,
    policyId,
    principalId,
    resourceId,
    traceability:
      new TraceabilityService(pool),
    evaluations:
      new EvaluationService(pool),
  };
}

test("checks bind registered versions while preserving exact snapshots and ad-hoc compatibility", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    const registered =
      await f.traceability.register({
        organizationId:
          f.organizationId,
        policyId:
          f.policyId,
        key: "traceable-rules",
        ruleSet: RULESET,
        effectiveFrom:
          "2026-01-01T00:00:00Z",
        createdByPrincipalId:
          f.principalId,
        authorities: [
          {
            authorityType:
              "policy",
            citation:
              "Generic Policy 1",
          },
        ],
      });

    await f.traceability.activate({
      ruleSetId:
        registered.id,
      principalId:
        f.principalId,
      effectiveFrom:
        "2026-01-01T00:00:00Z",
    });

    const traced =
      await f.evaluations.run({
        organizationId:
          f.organizationId,
        resourceId:
          f.resourceId,
        registeredRuleSetId:
          registered.id,
        requestedByPrincipalId:
          f.principalId,
        evaluatedAt:
          "2026-02-01T00:00:00Z",
      });

    assert.equal(
      traced.check.status,
      "passed",
    );
    assert.equal(
      traced.check.ruleSetId,
      registered.id,
    );
    assert.equal(
      traced.check.ruleSetHash,
      registered.definitionHash,
    );
    assert.equal(
      traced.check
        .ruleSetProvenance
        .registrationMode,
      "registered",
    );
    assert.deepEqual(
      traced.check.ruleSetSnapshot,
      JSON.parse(
        JSON.stringify(
          registered.definition,
        ),
      ),
    );

    const adHoc =
      await f.evaluations.run({
        organizationId:
          f.organizationId,
        resourceId:
          f.resourceId,
        ruleSet: {
          ...RULESET,
          version: "ad-hoc-1",
        },
        requestedByPrincipalId:
          f.principalId,
      });

    assert.equal(
      adHoc.check.ruleSetId,
      null,
    );
    assert.match(
      adHoc.check.ruleSetHash ?? "",
      /^[0-9a-f]{64}$/,
    );
    assert.equal(
      adHoc.check
        .ruleSetProvenance
        .registrationMode,
      "ad_hoc",
    );

    await assert.rejects(
      f.evaluations.run({
        organizationId:
          f.organizationId,
        resourceId:
          f.resourceId,
        ruleSet: RULESET,
        registeredRuleSetId:
          registered.id,
      }),
      (error: unknown) =>
        error instanceof
          EvaluationError &&
        error.code ===
          "validation",
    );

    const draft =
      await f.traceability.register({
        organizationId:
          f.organizationId,
        policyId:
          f.policyId,
        key: "traceable-rules",
        ruleSet: {
          ...RULESET,
          version: "2",
        },
        supersedesRuleSetId:
          registered.id,
        createdByPrincipalId:
          f.principalId,
      });

    await assert.rejects(
      f.evaluations.run({
        organizationId:
          f.organizationId,
        resourceId:
          f.resourceId,
        registeredRuleSetId:
          draft.id,
      }),
      (error: unknown) =>
        error instanceof
          EvaluationError &&
        error.code ===
          "invalid_state",
    );
  } finally {
    await f.pool.end();
  }
});
