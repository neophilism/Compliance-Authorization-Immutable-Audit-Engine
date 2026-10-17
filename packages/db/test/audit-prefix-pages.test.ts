import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { hashAuditEvent } from "../src/audit.js";
import { collectAuditCheckpointWithClient, signAuditCheckpoint,
  verifyAuditCheckpointAgainstDatabaseWithClient } from "../src/audit-anchor.js";
import { AuditLedger, createPool, runMigrations } from "../src/index.js";

function fixture(length: number) {
  const organizationId = randomUUID();
  const aggregateId = randomUUID();
  let previousEventHash: string | null = null;
  const rows: Record<string, any>[] = [];
  for (let sequenceNumber = 1; sequenceNumber <= length; sequenceNumber++) {
    const event = { id: randomUUID(), organizationId, aggregateId, aggregateType: "resource",
      sequenceNumber, eventType: "resource.reviewed", actorPrincipalId: null,
      occurredAt: "2026-01-01T00:00:00.000Z", recordedAt: "2026-01-01T00:00:00.000Z",
      correlationId: null, payload: { sequenceNumber }, previousEventHash };
    const eventHash = hashAuditEvent(event);
    rows.push({ id: event.id, organization_id: organizationId, aggregate_id: aggregateId,
      aggregate_type: event.aggregateType, sequence_number: sequenceNumber, event_type: event.eventType,
      actor_principal_id: null, occurred_at: event.occurredAt, recorded_at: event.recordedAt,
      correlation_id: null, payload: event.payload, previous_event_hash: previousEventHash, event_hash: eventHash });
    previousEventHash = eventHash;
  }
  const head = { organizationId, aggregateId, aggregateType: "resource", sequenceNumber: length,
    eventHash: previousEventHash! };
  const keys = generateKeyPairSync("ed25519");
  const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const signed = signAuditCheckpoint({ schemaVersion: 1, createdAt: "2026-01-01T00:00:00.000Z",
    chainHeads: [head] }, privateKey, "paged-test");
  const pages: number[] = [];
  const client = { query: async (sql: string, params?: any[]) => {
    assert.ok(sql.startsWith("SELECT "), "composition must remain SELECT-only");
    if (sql.includes("DISTINCT ON")) return { rows: [rows.at(-1)] };
    assert.match(sql, /sequence_number > \$4 AND sequence_number <= \$5/);
    assert.match(sql, /ORDER BY sequence_number ASC LIMIT \$6/);
    assert.deepEqual(params!.slice(0, 3), [organizationId, "resource", aggregateId]);
    assert.equal(params![5], 256);
    const page = rows.filter(row => row.sequence_number > params![3] && row.sequence_number <= params![4])
      .sort((a, b) => a.sequence_number - b.sequence_number).slice(0, params![5]);
    pages.push(page.length);
    return { rows: page };
  } } as any;
  return { rows, head, signed, publicKey, client, pages };
}

test("prefix verification bounds each query and carries hash state across exact and partial page boundaries", async () => {
  for (const length of [1, 255, 256, 257, 513]) {
    const f = fixture(length);
    const result = await verifyAuditCheckpointAgainstDatabaseWithClient(f.client, f.signed, f.publicKey);
    assert.deepEqual(result, { valid: true, checkedChains: 1 });
    assert.equal(f.pages.length, Math.ceil(length / 256));
    assert.ok(f.pages.every(size => size > 0 && size <= 256));
    assert.equal(f.pages.reduce((sum, size) => sum + size, 0), length);
    const collected = await collectAuditCheckpointWithClient(f.client);
    assert.deepEqual(collected.chainHeads, [f.head]);
  }
});

test("paging rejects omissions, altered payloads and broken links at both sides of a boundary", async () => {
  for (const index of [0, 255, 256, 512]) {
    for (const mutation of ["missing", "payload", "previous", "hash"] as const) {
      const f = fixture(513);
      if (mutation === "missing") f.rows.splice(index, 1);
      if (mutation === "payload") f.rows[index].payload = { tampered: true };
      if (mutation === "previous") f.rows[index].previous_event_hash = "0".repeat(64);
      if (mutation === "hash") f.rows[index].event_hash = "0".repeat(64);
      const result = await verifyAuditCheckpointAgainstDatabaseWithClient(f.client, f.signed, f.publicKey);
      assert.equal(result.valid, false, `${mutation} at ${index}`);
      assert.equal(result.reason, "missing_or_modified_chain");
    }
  }
});

test("invalid signatures query nothing and appended suffixes do not alter the signed prefix", async () => {
  const f = fixture(513);
  const invalid = await verifyAuditCheckpointAgainstDatabaseWithClient(f.client,
    { ...f.signed, signature: "forged" }, f.publicKey);
  assert.equal(invalid.reason, "invalid_signature");
  assert.equal(f.pages.length, 0);
  f.rows.push({ ...f.rows.at(-1), sequence_number: 514, payload: { outside: "signed-prefix" } });
  assert.equal((await verifyAuditCheckpointAgainstDatabaseWithClient(f.client, f.signed, f.publicKey)).valid, true);
});

test("PostgreSQL verifies a chain longer than one page in one read-only snapshot", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  try {
    await runMigrations(pool);
    const organizationId = randomUUID();
    const aggregateId = randomUUID();
    await pool.query("INSERT INTO organizations(id,name,slug,status) VALUES ($1,'Paged audit fixture',$2,'active')",
      [organizationId, "paged-audit-" + organizationId]);
    const ledger = new AuditLedger(pool);
    for (let index = 0; index < 257; index++) {
      await ledger.append({ organizationId, aggregateType: "resource", aggregateId,
        eventType: "resource.reviewed", payload: { index } });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const sizes: number[] = [];
      const tracked = { query: async (sql: string, params?: any[]) => {
        const result = await client.query(sql, params);
        if (params?.[0] === organizationId && sql.includes("LIMIT $6")) sizes.push(result.rows.length);
        return result;
      } } as any;
      const checkpoint = await collectAuditCheckpointWithClient(tracked);
      const head = checkpoint.chainHeads.find(item => item.organizationId === organizationId)!;
      assert.equal(head.sequenceNumber, 257);
      assert.deepEqual(sizes, [256, 1]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  } finally { await pool.end(); }
});
