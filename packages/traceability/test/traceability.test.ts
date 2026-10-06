import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  TraceabilityService,
} from "../src/index.js";

function ruleSet(
  version: string,
) {
  return {
    schemaVersion: "1",
    id: "generic-control-set",
    version,
    title:
      "Generic Control Set",
    rules: [
      {
        id: "resource-active",
        title:
          "Resource must be active",
        severity: "high",
        require: {
          field:
            "resource.status",
          operator: "equals",
          value: "active",
        },
      },
    ],
  } as const;
}

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);
  const organizationId =
    randomUUID();
  const policyId =
    randomUUID();
  const principalId =
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
      `traceability-${organizationId}`,
    ],
  );

  await pool.query(
    `INSERT INTO policies(
       id,
       organization_id,
       key,
       title,
       status
     ) VALUES (
       $1, $2,
       'generic-policy',
       'Generic Policy',
       'active'
     )`,
    [
      policyId,
      organizationId,
    ],
  );

  await pool.query(
    `INSERT INTO principals(
       id,
       organization_id,
       kind,
       display_name,
       status
     ) VALUES (
       $1, $2, 'user',
       'Rules Administrator',
       'active'
     )`,
    [
      principalId,
      organizationId,
    ],
  );

  return {
    pool,
    organizationId,
    policyId,
    principalId,
    service:
      new TraceabilityService(
        pool,
        {
          now: () =>
            new Date(
              "2026-01-01T00:00:00Z",
            ),
        },
      ),
  };
}

test("registered rulesets are hashed, source-linked, immutable, and historically resolvable", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    const v1 =
      await f.service.register({
        organizationId:
          f.organizationId,
        policyId: f.policyId,
        key:
          "generic-control-set",
        ruleSet:
          ruleSet("1.0.0"),
        effectiveFrom:
          "2026-01-01T00:00:00Z",
        createdByPrincipalId:
          f.principalId,
        authorities: [
          {
            authorityType:
              "statute",
            citation:
              "Example Code section 1",
            title:
              "Example Authority",
            uri:
              "https://example.invalid/authority",
            locator:
              "section 1(a)",
            jurisdiction:
              "example",
          },
        ],
      });

    assert.match(
      v1.definitionHash,
      /^[0-9a-f]{64}$/,
    );

    const manifest =
      await f.service.traceability(
        v1.id,
      );

    assert.equal(
      manifest.registrationMode,
      "registered",
    );
    assert.equal(
      manifest.definitionHash,
      v1.definitionHash,
    );
    assert.equal(
      manifest.authorities.length,
      1,
    );
    assert.equal(
      manifest.authorities[0]
        ?.authority.citation,
      "Example Code section 1",
    );
    assert.equal(
      manifest.authorities[0]
        ?.locator,
      "section 1(a)",
    );

    await assert.rejects(
      f.pool.query(
        `UPDATE rule_sets
         SET definition =
           '{"tampered":true}'::jsonb
         WHERE id = $1`,
        [v1.id],
      ),
      /immutable/,
    );

    const activeV1 =
      await f.service.activate({
        ruleSetId: v1.id,
        principalId:
          f.principalId,
      });

    assert.equal(
      activeV1.status,
      "active",
    );

    const current =
      await f.service.resolve({
        organizationId:
          f.organizationId,
        key:
          "generic-control-set",
        at:
          "2026-03-01T00:00:00Z",
      });

    assert.equal(
      current.id,
      v1.id,
    );

    const v2 =
      await f.service.register({
        organizationId:
          f.organizationId,
        policyId: f.policyId,
        key:
          "generic-control-set",
        ruleSet:
          ruleSet("2.0.0"),
        effectiveFrom:
          "2026-06-01T00:00:00Z",
        supersedesRuleSetId:
          v1.id,
        createdByPrincipalId:
          f.principalId,
        authorities: [
          {
            authorityType:
              "regulation",
            citation:
              "Example Rule 2",
          },
        ],
      });

    await f.service.activate({
      ruleSetId: v2.id,
      principalId:
        f.principalId,
      effectiveFrom:
        "2026-06-01T00:00:00Z",
    });

    const old =
      await f.service.get(v1.id);

    assert.equal(
      old.status,
      "superseded",
    );
    assert.equal(
      old.effectiveTo,
      "2026-06-01T00:00:00.000Z",
    );

    assert.equal(
      (
        await f.service.resolve({
          organizationId:
            f.organizationId,
          key:
            "generic-control-set",
          at:
            "2026-03-01T00:00:00Z",
        })
      ).id,
      v1.id,
    );

    assert.equal(
      (
        await f.service.resolve({
          organizationId:
            f.organizationId,
          key:
            "generic-control-set",
          at:
            "2026-07-01T00:00:00Z",
        })
      ).id,
      v2.id,
    );

    const ledger =
      new AuditLedger(f.pool);
    const v1Events =
      await ledger.list(
        f.organizationId,
        "rule_set",
        v1.id,
      );
    const v2Events =
      await ledger.list(
        f.organizationId,
        "rule_set",
        v2.id,
      );

    assert.deepEqual(
      v1Events.map(
        (event) =>
          event.eventType,
      ),
      [
        "rule_set.registered",
        "rule_set.activated",
        "rule_set.superseded",
      ],
    );
    assert.deepEqual(
      v2Events.map(
        (event) =>
          event.eventType,
      ),
      [
        "rule_set.registered",
        "rule_set.activated",
      ],
    );
  } finally {
    await f.pool.end();
  }
});
