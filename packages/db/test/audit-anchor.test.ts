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

test("recovery verification shares one PostgreSQL read-only snapshot across anchor, chain scan and counts", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  try {
    await runMigrations(pool);
    const organizationId = randomUUID();
    const aggregateId = randomUUID();
    await pool.query("INSERT INTO organizations(id,name,slug,status) VALUES ($1,'Recovery snapshot fixture',$2,'active')",
      [organizationId, "recovery-snapshot-" + organizationId]);
    const ledger = new AuditLedger(pool);
    await ledger.append({ organizationId, aggregateType: "resource", aggregateId,
      eventType: "resource.created", payload: { fixture: "before-snapshot" } });
    const checkpoint = await collectAuditCheckpoint(pool);
    checkpoint.chainHeads = checkpoint.chainHeads.filter(head => head.organizationId === organizationId);
    const { privateKey, publicKey } = testKeys();
    const signed = signAuditCheckpoint(checkpoint, privateKey, "recovery-fixture");
    const verifierUrl = new URL("../../../scripts/verify-recovery.mjs", import.meta.url);
    const { verifyRecovery } = await import(verifierUrl.href);
    let connections = 0;
    let snapshotCounts: { organizations: number; resources: number; audit_events: number } | undefined;
    const statements: string[] = [];
    const trackedPool = {
      connect: async () => {
        connections++;
        const client = await pool.connect();
        return {
          query: async (sql: string, params?: unknown[]) => {
            statements.push(sql);
            const result = await client.query(sql, params);
            if (sql.includes("FROM schema_migrations")) {
              snapshotCounts = (await client.query("SELECT (SELECT count(*) FROM organizations)::integer AS organizations," +
                "(SELECT count(*) FROM resources)::integer AS resources,(SELECT count(*) FROM audit_events)::integer AS audit_events")).rows[0];
              // PostgreSQL itself must reject writes, not just a SELECT-only mock.
              await client.query("SAVEPOINT recovery_write_probe");
              await assert.rejects(client.query("INSERT INTO organizations(id,name,slug,status) VALUES ($1,'Forbidden',$2,'active')",
                [randomUUID(), "forbidden-" + randomUUID()]), (error: any) => error.code === "25006");
              await client.query("ROLLBACK TO SAVEPOINT recovery_write_probe");
              await client.query("RELEASE SAVEPOINT recovery_write_probe");
              // A legitimate commit on another connection occurs after our snapshot.
              await ledger.append({ organizationId, aggregateType: "resource", aggregateId,
                eventType: "resource.reviewed", payload: { fixture: "after-snapshot" } });
            }
            return result;
          },
          release: (discard?: boolean) => client.release(discard),
        };
      },
    };
    const report = await verifyRecovery(trackedPool, signed, publicKey);
    assert.equal(connections, 1);
    assert.equal(statements.filter(sql => sql.startsWith("BEGIN")).length, 1);
    assert.equal(statements.filter(sql => sql === "COMMIT").length, 1);
    assert.equal(report.readOnly, true);
    assert.equal(report.snapshotIsolation, "repeatable read");
    assert.equal(report.anchoredChainsVerified, 1);
    assert.equal(report.audit_events, snapshotCounts!.audit_events);
    assert.equal(report.organizations, snapshotCounts!.organizations);
    assert.equal(report.resources, snapshotCounts!.resources);
    const latest = await pool.query("SELECT count(*)::integer AS count FROM audit_events WHERE organization_id=$1", [organizationId]);
    assert.equal(latest.rows[0].count, 2);
    const beforeInvalid = connections;
    await assert.rejects(verifyRecovery(trackedPool, { ...signed, signature: "forged" }, publicKey), /signature/);
    assert.equal(connections, beforeInvalid);
  } finally { await pool.end(); }
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

