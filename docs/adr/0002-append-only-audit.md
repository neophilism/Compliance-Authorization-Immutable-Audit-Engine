# ADR 0002: Append-only tamper-evident audit history

**Status:** Accepted

Consequential state changes will emit append-only audit events. Each event will eventually include the previous event hash and its own canonical-content hash.

Corrections, revocations, and superseding decisions are represented as new events rather than mutation of prior history.
