# ADR 0002: Append-only tamper-evident audit history

**Status:** Accepted and implemented in PR 3

Consequential state changes are represented as append-only audit events. Corrections, revocations, and superseding decisions are new events; prior events are never silently edited.

Each aggregate maintains its own ordered hash chain. Events contain a sequence number, the previous event hash, and a SHA-256 hash over a deterministic canonical representation of the current event.

Application writers serialize append operations per aggregate with PostgreSQL transaction-scoped advisory locks. A database trigger rejects UPDATE and DELETE operations on the audit event table.

Verification independently recomputes sequence continuity, previous-hash continuity, and event hashes. This makes unauthorized historical alteration detectable.

The guarantee is intentionally described as **tamper-evident** rather than absolutely immutable. A database superuser capable of disabling safeguards and rewriting an entire chain could recompute hashes. Stronger production deployments may additionally sign or externally anchor chain heads.
