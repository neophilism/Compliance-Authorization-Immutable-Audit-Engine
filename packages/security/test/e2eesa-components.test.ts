import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

test("component-level E2EESA scoping does not assert repository-wide certification", () => {
  const matrix = JSON.parse(readFileSync(new URL("../e2eesa-components.json", import.meta.url), "utf8"));
  assert.equal(matrix.schemaVersion, "1");
  assert.equal(matrix.assessmentKind, "component-scope-inventory-only");
  assert.equal(matrix.securityStandard.frozenVersion, false);
  assert.equal(matrix.claims.endToEndEncryption, "not-claimed");
  assert.equal(matrix.claims.productionReadiness, "not-assessed");
  const ids = matrix.components.map((component: any) => component.id);
  assert.equal(new Set(ids).size, ids.length);
  const mandatory = [
    "operator-api", "scheduler-worker", "postgres-store",
    "browser-admin", "typed-sdk", "webhook-integrations",
    "public-projections", "audit-checkpoints", "engine-room-telemetry",
  ];
  for (const id of mandatory) assert.ok(ids.includes(id), "Missing component: " + id);
  for (const component of matrix.components) {
    assert.equal(component.e2ee, "not-claimed");
    assert.equal(component.assessment, "unverified");
    assert.ok(component.assets.length > 0 && component.gaps.length > 0);
    assert.ok(component.threats.every((threat: string) => /^TM-[A-Z-]+$/.test(threat)));
    assert.ok(component.path && component.role);
  }
  assert.ok(matrix.releaseEvidenceGates.length >= 6);
});
