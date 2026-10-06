import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  TraceabilityError,
  TraceabilityService,
} from "../src/index.js";

const RULESET = {
  schemaVersion: "1",
  id: "generic-control",
  version: "1",
  title: "Generic Control",
  rules: [
    {
      id: "active",
      title: "Resource is active",
      severity: "high",
      require: {
        field: "resource.status",
        operator: "equals",
        value: "active",
      },
    },
  ],
};

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);
  const organizationId =
    randomUUID();
  const principalId =
    randomUUID();
  const policyId =
    randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Traceability Test',
       $2, 'active'
     )`,
    [
      organizationId,
      `trace-${organizationId}`,
    ],
  );
  await pool.query(
    `INSERT INTO principals(
       id, organization_id, kind,
       display_name, status
     ) VALUES (
       $1, $2, 'user',
       'Traceability Operator',
       'active'
     )`,
    [principalId, organizationId],
  );
  await pool.query(
    `INSERT INTO policies(
       id, organization_id, key,
       title, status
     ) VALUES (
       $1, $2, 'generic-policy',
       'Generic Policy', 'active'
     )`,
    [policyId, organizationId],
  );

  return {
    pool,
    organizationId,
    principalId,
    policyId,
    service:
      new TraceabilityService(pool),
  };
}

test("registered ruleset versions are immutable and retain source locators", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    const source =
      await f.service.createAuthoritySource({
        organizationId:
          f.organizationId,
        sourceType: "standard",
        jurisdiction: "global",
        citation: "STD-1 § 4.2",
        title:
          "Generic Compliance Standard",
        uri:
          "https://example.invalid/std-1",
        principalId:
          f.principalId,
      });

    const revision =
      await f.service.registerRuleSetRevision({
        organizationId:
          f.organizationId,
        policyId: f.policyId,
        ruleSet: RULESET,
        principalId:
          f.principalId,
        authorityLinks: [
          {
            authoritySourceId:
              source.id,
            relation:
              "implements",
            locator: "§ 4.2(a)",
            note:
              "Maps the active-state requirement",
          },
        ],
      });

    assert.equal(
      revision.key,
      RULESET.id,
    );
    assert.equal(
      revision.version,
      RULESET.version,
    );
    assert.equal(
      revision.contentHash.length,
      64,
    );
    assert.equal(
      revision.authorities[0]
        ?.source.citation,
      "STD-1 § 4.2",
    );
    assert.equal(
      revision.authorities[0]
        ?.link.locator,
      "§ 4.2(a)",
    );

    const same =
      await f.service.registerRuleSetRevision({
        organizationId:
          f.organizationId,
        policyId: f.policyId,
        ruleSet: RULESET,
        principalId:
          f.principalId,
      });
    assert.equal(
      same.id,
      revision.id,
    );

    await assert.rejects(
      f.service.registerRuleSetRevision({
        organizationId:
          f.organizationId,
        policyId: f.policyId,
        principalId:
          f.principalId,
        ruleSet: {
          ...RULESET,
          title:
            "Changed Content",
        },
      }),
      (error: unknown) =>
        error instanceof
          TraceabilityError &&
        error.code === "conflict",
    );

    const active =
      await f.service.activateRuleSetRevision({
        ruleSetId: revision.id,
        principalId:
          f.principalId,
      });
    assert.equal(
      active.status,
      "active",
    );
    assert.ok(active.activatedAt);
  } finally {
    await f.pool.end();
  }
});
