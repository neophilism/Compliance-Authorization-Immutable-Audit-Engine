import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { AuditEvent } from "@caiae/core";
import { canonicalJson, verifyAuditChain } from "./audit.js";

export type AuditChainHead = {
  organizationId: string;
  aggregateType: string;
  aggregateId: string;
  sequenceNumber: number;
  eventHash: string;
};

export type AuditCheckpoint = {
  schemaVersion: 1;
  createdAt: string;
  chainHeads: AuditChainHead[];
};

export type SignedAuditCheckpoint = {
  schemaVersion: 1;
  algorithm: "Ed25519";
  keyId: string;
  checkpoint: AuditCheckpoint;
  signature: string;
};

export type CheckpointVerification = {
  valid: boolean;
  checkedChains: number;
  reason?: "invalid_signature" | "missing_or_modified_chain";
};

function mapEvent(row: Record<string, any>): AuditEvent {
  return {
    id: String(row.id),
    organizationId: String(row.organization_id),
    aggregateType: String(row.aggregate_type),
    aggregateId: String(row.aggregate_id),
    sequenceNumber: Number(row.sequence_number),
    eventType: String(row.event_type),
    actorPrincipalId: row.actor_principal_id === null ? null : String(row.actor_principal_id),
    occurredAt: new Date(row.occurred_at).toISOString(),
    recordedAt: new Date(row.recorded_at).toISOString(),
    correlationId: row.correlation_id === null ? null : String(row.correlation_id),
    payload: (row.payload ?? {}) as AuditEvent["payload"],
    previousEventHash: row.previous_event_hash === null ? null : String(row.previous_event_hash),
    eventHash: String(row.event_hash),
  };
}

async function verifyPrefix(client: PoolClient, head: AuditChainHead): Promise<boolean> {
  const result = await client.query(
    "SELECT * FROM audit_events " +
    "WHERE organization_id = $1 AND aggregate_type = $2 AND aggregate_id = $3 " +
    "AND sequence_number <= $4 ORDER BY sequence_number ASC",
    [head.organizationId, head.aggregateType, head.aggregateId, head.sequenceNumber],
  );
  const events = result.rows.map(mapEvent);
  if (events.length !== head.sequenceNumber) return false;
  const verification = verifyAuditChain(events);
  return verification.valid && events.at(-1)?.eventHash === head.eventHash;
}

function parseHead(row: Record<string, any>): AuditChainHead {
  return {
    organizationId: String(row.organization_id),
    aggregateType: String(row.aggregate_type),
    aggregateId: String(row.aggregate_id),
    sequenceNumber: Number(row.sequence_number),
    eventHash: String(row.event_hash),
  };
}

export async function collectAuditCheckpoint(pool: Pool): Promise<AuditCheckpoint> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const rows = await client.query(
      "SELECT DISTINCT ON (organization_id, aggregate_type, aggregate_id) " +
      "organization_id, aggregate_type, aggregate_id, sequence_number, event_hash " +
      "FROM audit_events " +
      "ORDER BY organization_id, aggregate_type, aggregate_id, sequence_number DESC",
    );
    const chainHeads = rows.rows.map(parseHead);
    for (const head of chainHeads) {
      if (!(await verifyPrefix(client, head))) {
        throw new Error("Audit chain integrity check failed before checkpoint signing");
      }
    }
    await client.query("COMMIT");
    return { schemaVersion: 1, createdAt: new Date().toISOString(), chainHeads };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function isValidCheckpoint(value: any): value is SignedAuditCheckpoint {
  if (!value || value.schemaVersion !== 1 || value.algorithm !== "Ed25519" ||
      typeof value.keyId !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(value.keyId) ||
      typeof value.signature !== "string" || value.signature.length > 300 ||
      !value.checkpoint || value.checkpoint.schemaVersion !== 1 ||
      typeof value.checkpoint.createdAt !== "string" ||
      !Number.isFinite(Date.parse(value.checkpoint.createdAt)) ||
      !Array.isArray(value.checkpoint.chainHeads)) return false;
  const seen = new Set<string>();
  for (const head of value.checkpoint.chainHeads) {
    if (!head || typeof head.organizationId !== "string" ||
        typeof head.aggregateType !== "string" || typeof head.aggregateId !== "string" ||
        !Number.isSafeInteger(head.sequenceNumber) || head.sequenceNumber < 1 ||
        typeof head.eventHash !== "string" || !/^[a-f0-9]{64}$/.test(head.eventHash)) return false;
    const key = JSON.stringify([head.organizationId, head.aggregateType, head.aggregateId]);
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

export function signAuditCheckpoint(
  checkpoint: AuditCheckpoint,
  privateKeyPem: string,
  keyId: string,
): SignedAuditCheckpoint {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) throw new Error("Invalid checkpoint key ID");
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Checkpoint signer must use Ed25519");
  const data = Buffer.from(canonicalJson(checkpoint), "utf8");
  return {
    schemaVersion: 1,
    algorithm: "Ed25519",
    keyId,
    checkpoint,
    signature: sign(null, data, key).toString("base64"),
  };
}

export function verifyAuditCheckpointSignature(
  signed: unknown,
  publicKeyPem: string,
): signed is SignedAuditCheckpoint {
  if (!isValidCheckpoint(signed)) return false;
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return false;
    return verify(
      null,
      Buffer.from(canonicalJson(signed.checkpoint), "utf8"),
      key,
      Buffer.from(signed.signature, "base64"),
    );
  } catch {
    return false;
  }
}

export async function verifyAuditCheckpointAgainstDatabase(
  pool: Pool,
  signed: unknown,
  publicKeyPem: string,
): Promise<CheckpointVerification> {
  if (!verifyAuditCheckpointSignature(signed, publicKeyPem)) {
    return { valid: false, checkedChains: 0, reason: "invalid_signature" };
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    let checkedChains = 0;
    for (const head of signed.checkpoint.chainHeads) {
      if (!(await verifyPrefix(client, head))) {
        await client.query("COMMIT");
        return { valid: false, checkedChains, reason: "missing_or_modified_chain" };
      }
      checkedChains++;
    }
    await client.query("COMMIT");
    return { valid: true, checkedChains };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
