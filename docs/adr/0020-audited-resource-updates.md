# ADR 0020: Audited optimistic resource updates

## Status

Accepted.

## Context

The first downstream thin application exposed a generic lifecycle gap in the master engine.

Resources could be created and read, but their current attributes, status, metadata, or display name could not be changed. That made normal compliance lifecycle transitions impossible without creating replacement resources. A downstream workaround would duplicate infrastructure and violate the thin-application architecture.

## Decision

Add a domain-neutral resource update operation to the master engine.

The operator API exposes PATCH /v1/resources/:id.

The update supports name, externalRef, status, attributes, and metadata.

Every update requires expectedUpdatedAt. The engine locks the resource row and rejects stale writes with HTTP 409. This prevents silent lost updates when multiple operators or applications work with the same resource.

Successful updates occur in the same PostgreSQL transaction as a tamper-evident resource.updated audit event.

The audit payload records:

- changed field names;
- the complete pre-update resource snapshot;
- the complete post-update resource snapshot.

When operator authentication is enforced, the authenticated principal is recorded as the audit actor. The caller cannot choose or spoof the audit actor.

The SDK exposes getResource() and updateResource() convenience methods.

## Consequences

- downstream applications can evolve resource state without replacing resource identity;
- checks before and after an update continue to preserve their own exact context snapshots;
- stale concurrent writes are explicit conflicts;
- resource changes have tamper-evident before/after history;
- policy-specific mutation logic remains downstream;
- no bill-specific field or workflow enters the master engine.
