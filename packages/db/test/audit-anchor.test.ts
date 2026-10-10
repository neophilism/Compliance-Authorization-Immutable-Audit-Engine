import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { AuditLedger, createPool, runMigrations } from "../src/index.js";
import {
  collectAuditCheckpoint,
  signAuditCheckpoint,
  verifyAuditCheckpointSignature,
  verifyAuditCheckpointAgainstDatabase,
} from "../src/audit-anchor.js";

function testKeys() {
  const pair = generateKeyPairSync("ed25519");
  return {
    privateKey: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

test("Ed25519 signatures protect the complete checkpoint manifest", () => {
  const { privateKey, publicKey } = testKeys();
  const checkpoint = {
    schemaVersion: 1 as const,
    createdAt: new Date().toISOString(),
    chainHeads: [],
  };
  const signed = signAuditCheckpoint(checkpoint, privateKey, "issuer-1");
  assert.equal(verifyAuditCheckpointSignature(signed, publicKey), true);
  const modified = structuredClone(signed);
  modified.checkpoint.createdAt = new Date(Date.now() + 60000).toISOString();
  assert.equal(verifyAuditCheckpointSignature(modified, publicKey), false);
  assert.equal(verifyAuditCheckpointSignature({ ...signed, signature: "bad" }, publicKey), false);
});

test("signed database checkpoint survives append but detects missing anchored history", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  try {
    await runMigrations(pool);
    const organizationId = randomUUID();
    const aggregateId = randomUUID();
    await pool.query(
      "INSERT INTO organizations(id, name, slug, status) " +
      "VALUES ($1, 'Anchoring Test', $2, 'active')",
      [organizationId, "anchor-" + organizationId],
    );
    const ledger = new AuditLedger(pool);
    await ledger.append({
      organizationId, aggregateType: "resource", aggregateId,
      eventType: "resource.created", payload: { case: "anchoring" },
    });
    const checkpoint = await collectAuditCheckpoint(pool);
    const head = checkpoint.chainHeads.find(item =>
      item.organizationId === organizationId && item.aggregateId === aggregateId);
    assert.equal(head?.sequenceNumber, 1);

    const { privateKey, publicKey } = testKeys();
    const signed = signAuditCheckpoint(checkpoint, privateKey, "auditor");
    assert.equal((await verifyAuditCheckpointAgainstDatabase(pool, signed, publicKey)).valid, true);

    await ledger.append({
      organizationId, aggregateType: "resource", aggregateId,
      eventType: "resource.reviewed", payload: { status: "reviewed" },
    });
    assert.equal((await verifyAuditCheckpointAgainstDatabase(pool, signed, publicKey)).valid, true);
    assert.equal((await verifyAuditCheckpointAgainstDatabase(pool, {
      ...signed, signature: "forged",
    }, publicKey)).reason, "invalid_signature");
  } finally {
    await pool.end();
  }
});
