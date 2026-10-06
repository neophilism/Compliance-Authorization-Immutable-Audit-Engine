# Tamper-evident audit ledger

The engine records consequential history as append-only audit events.

## Chain model

Each aggregate has an independent sequence:

```
event 1 -> event 2 -> event 3
```

An aggregate is identified by:

- organization ID
- aggregate type
- aggregate ID

Every event stores a monotonically increasing sequence number, the hash of the previous event, and its own SHA-256 hash.

## Canonical hashing

The event hash is calculated over a deterministic JSON representation containing:

- event ID
- organization ID
- aggregate type and ID
- sequence number
- event type
- actor principal ID
- occurrence and recording timestamps
- correlation ID
- payload
- previous event hash

Object keys are recursively sorted before serialization so equivalent JSON objects hash identically regardless of insertion order.

## Append serialization

Writers acquire a PostgreSQL transaction-scoped advisory lock derived from the aggregate identity. The writer then reads the current chain head, assigns the next sequence number, computes the new hash, inserts the event, and commits.

This prevents concurrent application writers from producing competing chain heads.

## Database append-only enforcement

A PostgreSQL trigger rejects UPDATE and DELETE operations on `audit_events`. Corrections, revocations, and superseding decisions must therefore be represented as later events.

## Verification

`AuditLedger.verify` and the `audit:verify` command independently recompute the chain and check:

1. sequence continuity;
2. previous-hash continuity;
3. each event's content hash.

Any mismatch causes verification to fail at the first affected event.

## Security boundary

The ledger is **tamper-evident**, not magically tamper-proof. A sufficiently privileged database administrator who can disable safeguards and rewrite the entire chain could also recompute hashes. Future production hardening may add signatures or externally anchored chain heads so verification can detect that stronger attacker model.
