import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { AuditEvent, JsonObject } from "@caiae/core";

export type AppendAuditEventInput = {
  organizationId: string;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  actorPrincipalId?: string | null;
  occurredAt?: string;
  correlationId?: string | null;
  payload?: JsonObject;
};

export type AuditVerificationResult =
  | { valid: true; checked: number }
  | {
      valid: false;
      checked: number;
      sequenceNumber: number;
      reason:
        | "sequence_mismatch"
        | "previous_hash_mismatch"
        | "event_hash_mismatch";
    };

export class AuditLedger {
  constructor(private readonly pool: Pool) {}

  async append(input: AppendAuditEventInput): Promise<AuditEvent> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const event = await appendAuditEventWithClient(client, input);
      await client.query("COMMIT");
      return event;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async appendInTransaction(
    client: PoolClient,
    input: AppendAuditEventInput,
  ): Promise<AuditEvent> {
    return appendAuditEventWithClient(client, input);
  }

  async list(
    organizationId: string,
    aggregateType: string,
    aggregateId: string,
  ): Promise<AuditEvent[]> {
    const result = await this.pool.query(
      `SELECT *
       FROM audit_events
       WHERE organization_id = $1
         AND aggregate_type = $2
         AND aggregate_id = $3
       ORDER BY sequence_number ASC`,
      [organizationId, aggregateType, aggregateId],
    );

    return result.rows.map(mapAuditEvent);
  }

  async verify(
    organizationId: string,
    aggregateType: string,
    aggregateId: string,
  ): Promise<AuditVerificationResult> {
    return verifyAuditChain(
      await this.list(organizationId, aggregateType, aggregateId),
    );
  }
}

export async function appendAuditEventWithClient(
  client: PoolClient,
  input: AppendAuditEventInput,
): Promise<AuditEvent> {
  const chainKey = [
    input.organizationId,
    input.aggregateType,
    input.aggregateId,
  ].join(":");

  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
    [chainKey],
  );

  const latest = await client.query(
    `SELECT *
     FROM audit_events
     WHERE organization_id = $1
       AND aggregate_type = $2
       AND aggregate_id = $3
     ORDER BY sequence_number DESC
     LIMIT 1`,
    [input.organizationId, input.aggregateType, input.aggregateId],
  );

  const previous = latest.rows[0] ? mapAuditEvent(latest.rows[0]) : null;
  if (previous && !previous.eventHash) {
    throw new Error("cannot append to an unhashed audit chain");
  }

  const occurredAt = normalizeDate(
    input.occurredAt ?? new Date().toISOString(),
  );
  const recordedAt = new Date().toISOString();
  const sequenceNumber = previous ? previous.sequenceNumber + 1 : 1;

  const eventWithoutHash: Omit<AuditEvent, "eventHash"> = {
    id: randomUUID(),
    organizationId: input.organizationId,
    aggregateType: input.aggregateType,
    aggregateId: input.aggregateId,
    sequenceNumber,
    eventType: input.eventType,
    actorPrincipalId: input.actorPrincipalId ?? null,
    occurredAt,
    recordedAt,
    correlationId: input.correlationId ?? null,
    payload: input.payload ?? {},
    previousEventHash: previous?.eventHash ?? null,
  };

  const event: AuditEvent = {
    ...eventWithoutHash,
    eventHash: hashAuditEvent(eventWithoutHash),
  };

  await insertEvent(client, event);
  return event;
}

export function hashAuditEvent(
  event: Omit<AuditEvent, "eventHash">,
): string {
  const canonical = canonicalJson({
    id: event.id,
    organizationId: event.organizationId,
    aggregateType: event.aggregateType,
    aggregateId: event.aggregateId,
    sequenceNumber: event.sequenceNumber,
    eventType: event.eventType,
    actorPrincipalId: event.actorPrincipalId,
    occurredAt: normalizeDate(event.occurredAt),
    recordedAt: normalizeDate(event.recordedAt),
    correlationId: event.correlationId,
    payload: event.payload,
    previousEventHash: event.previousEventHash,
  });

  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

export function verifyAuditChain(
  events: AuditEvent[],
): AuditVerificationResult {
  let previousHash: string | null = null;

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]!;
    const expectedSequence = index + 1;

    if (event.sequenceNumber !== expectedSequence) {
      return {
        valid: false,
        checked: index,
        sequenceNumber: event.sequenceNumber,
        reason: "sequence_mismatch",
      };
    }

    if (event.previousEventHash !== previousHash) {
      return {
        valid: false,
        checked: index,
        sequenceNumber: event.sequenceNumber,
        reason: "previous_hash_mismatch",
      };
    }

    const { eventHash, ...withoutHash } = event;
    const expectedHash = hashAuditEvent(withoutHash);

    if (eventHash !== expectedHash) {
      return {
        valid: false,
        checked: index,
        sequenceNumber: event.sequenceNumber,
        reason: "event_hash_mismatch",
      };
    }

    previousHash = event.eventHash;
  }

  return { valid: true, checked: events.length };
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("audit data cannot contain non-finite numbers");
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (typeof value === "object") {
    const source = value as Record<string, unknown>;
    const target: Record<string, unknown> = {};

    for (const key of Object.keys(source).sort()) {
      const item = source[key];
      if (item === undefined) {
        throw new Error("audit data cannot contain undefined values");
      }
      target[key] = canonicalize(item);
    }

    return target;
  }

  throw new Error(`unsupported audit value type: ${typeof value}`);
}

async function insertEvent(
  client: PoolClient,
  event: AuditEvent,
): Promise<void> {
  await client.query(
    `INSERT INTO audit_events(
       id,
       organization_id,
       aggregate_type,
       aggregate_id,
       sequence_number,
       event_type,
       actor_principal_id,
       occurred_at,
       recorded_at,
       correlation_id,
       payload,
       previous_event_hash,
       event_hash
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13
     )`,
    [
      event.id,
      event.organizationId,
      event.aggregateType,
      event.aggregateId,
      event.sequenceNumber,
      event.eventType,
      event.actorPrincipalId,
      event.occurredAt,
      event.recordedAt,
      event.correlationId,
      JSON.stringify(event.payload),
      event.previousEventHash,
      event.eventHash,
    ],
  );
}

function mapAuditEvent(row: any): AuditEvent {
  return {
    id: row.id,
    organizationId: row.organization_id,
    aggregateType: row.aggregate_type,
    aggregateId: row.aggregate_id,
    sequenceNumber: Number(row.sequence_number),
    eventType: row.event_type,
    actorPrincipalId: row.actor_principal_id,
    occurredAt: normalizeDate(row.occurred_at),
    recordedAt: normalizeDate(row.recorded_at),
    correlationId: row.correlation_id,
    payload: row.payload ?? {},
    previousEventHash: row.previous_event_hash,
    eventHash: row.event_hash,
  };
}

function normalizeDate(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}
