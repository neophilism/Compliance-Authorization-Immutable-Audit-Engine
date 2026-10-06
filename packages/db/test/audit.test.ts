import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  canonicalJson,
  createPool,
  runMigrations,
  verifyAuditChain,
} from "../src/index.js";

test("canonical JSON is stable across object key order", () => {
  const left = canonicalJson({
    z: 1,
    nested: { beta: true, alpha: ["x", "y"] },
    a: "first",
  });

  const right = canonicalJson({
    a: "first",
    nested: { alpha: ["x", "y"], beta: true },
    z: 1,
  });

  assert.equal(left, right);
});

test("audit verification detects altered historical payloads", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  try {
    await runMigrations(pool);
    const organizationId = randomUUID();

    await pool.query(
      `INSERT INTO organizations(id, name, slug, status)
       VALUES ($1, $2, $3, 'active')`,
      [
        organizationId,
        "Audit Verification Test",
        `audit-verification-${organizationId}`,
      ],
    );

    const ledger = new AuditLedger(pool);
    const aggregateId = randomUUID();

    await ledger.append({
      organizationId,
      aggregateType: "resource",
      aggregateId,
      eventType: "resource.created",
      payload: { state: "draft", nested: { b: 2, a: 1 } },
    });

    await ledger.append({
      organizationId,
      aggregateType: "resource",
      aggregateId,
      eventType: "resource.activated",
      payload: { state: "active" },
    });

    const events = await ledger.list(
      organizationId,
      "resource",
      aggregateId,
    );

    assert.deepEqual(verifyAuditChain(events), {
      valid: true,
      checked: 2,
    });

    const tampered = structuredClone(events);
    tampered[0]!.payload = { state: "altered" };

    const result = verifyAuditChain(tampered);
    assert.equal(result.valid, false);
    if (!result.valid) {
      assert.equal(result.sequenceNumber, 1);
      assert.equal(result.reason, "event_hash_mismatch");
    }
  } finally {
    await pool.end();
  }
});

test("database rejects audit event update and delete", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  try {
    await runMigrations(pool);
    const organizationId = randomUUID();

    await pool.query(
      `INSERT INTO organizations(id, name, slug, status)
       VALUES ($1, $2, $3, 'active')`,
      [
        organizationId,
        "Append Only Test",
        `append-only-${organizationId}`,
      ],
    );

    const ledger = new AuditLedger(pool);
    const event = await ledger.append({
      organizationId,
      aggregateType: "authorization",
      aggregateId: randomUUID(),
      eventType: "authorization.requested",
      payload: { purpose: "test" },
    });

    await assert.rejects(
      pool.query(
        "UPDATE audit_events SET event_type = 'tampered' WHERE id = $1",
        [event.id],
      ),
      /append-only/,
    );

    await assert.rejects(
      pool.query("DELETE FROM audit_events WHERE id = $1", [event.id]),
      /append-only/,
    );
  } finally {
    await pool.end();
  }
});

test("concurrent appends serialize into one valid chain", async () => {
  if (!process.env.DATABASE_URL) return;

  const pool = createPool();
  try {
    await runMigrations(pool);
    const organizationId = randomUUID();

    await pool.query(
      `INSERT INTO organizations(id, name, slug, status)
       VALUES ($1, $2, $3, 'active')`,
      [
        organizationId,
        "Concurrent Audit Test",
        `concurrent-audit-${organizationId}`,
      ],
    );

    const ledger = new AuditLedger(pool);
    const aggregateId = randomUUID();

    await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        ledger.append({
          organizationId,
          aggregateType: "finding",
          aggregateId,
          eventType: "finding.event",
          payload: { index },
        }),
      ),
    );

    const events = await ledger.list(
      organizationId,
      "finding",
      aggregateId,
    );

    assert.deepEqual(
      events.map((event) => event.sequenceNumber),
      [1, 2, 3, 4, 5, 6, 7, 8],
    );
    assert.deepEqual(await ledger.verify(
      organizationId,
      "finding",
      aggregateId,
    ), {
      valid: true,
      checked: 8,
    });
  } finally {
    await pool.end();
  }
});
