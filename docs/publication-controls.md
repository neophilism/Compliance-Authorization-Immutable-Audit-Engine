# Public/private publication controls

PR 15 adds a reusable publication boundary between internal compliance records and material that may be exposed publicly or passed to transparency-oriented downstream systems.

## Core rule

Internal domain records are never serialized directly to a public endpoint.

Publication uses this flow:

```
internal records
  -> allowlisted projection builder
  -> optional publication policy
  -> canonical JSON
  -> SHA-256 projection hash
  -> immutable audit event
  -> stored public snapshot
  -> public read endpoint
```

The absence of a publication control means the subject is private. Published snapshots can be withdrawn; withdrawal removes them from all public publication endpoints while preserving the internal control record and audit history.

## Built-in projections

The master engine provides policy-neutral projections for:

- organization summaries;
- organization compliance summaries;
- resource compliance summaries;
- finding summaries;
- certification summaries.

Downstream applications may register additional projection builders. Bill-specific disclosure semantics belong there, not in the master package.

## Redaction policy

A publication policy may:

- omit explicit dot-separated paths;
- replace explicit paths with configured JSON values.

The policy is applied only after an allowlisted projection is built. It therefore narrows or transforms already-safe output instead of attempting to redact an unrestricted internal object.

## Snapshots and determinism

A publication stores the exact public projection, its revision, policy, timestamp, and SHA-256 hash over canonical JSON. Re-running a projection with the same `asOf`, internal state, and policy yields the same hash.

Republishing replaces the public snapshot and increments the revision. Each publish and unpublish transition is represented as a later audit event.

## Public API

Control-plane routes:

```
POST /v1/publications/preview
POST /v1/publications/publish
POST /v1/publications/unpublish
GET  /v1/publications/:id
GET  /v1/organizations/:organizationId/publications
```

Public routes:

```
GET /v1/public/publications/:id
GET /v1/public/organizations/:organizationId/publications
```

Public responses do not include the publication policy, publisher principal IDs, internal metadata, evidence payloads, authorization details, audit payloads, or unrestricted domain objects.

## Existing certification verification

`GET /v1/public/certifications/verify/:code` remains unchanged.

The certification publication projection reuses only the certification engine's pre-existing `publicArtifact`; it never substitutes the full issuance artifact.

## Registry integration

The Registry adapter now calls the same resource compliance projection builder used by the publication package. This keeps Registry-facing fields aligned with the public-safe projection contract while retaining the existing authenticated adapter route.
