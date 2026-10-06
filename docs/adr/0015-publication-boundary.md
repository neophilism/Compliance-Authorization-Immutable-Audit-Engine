# ADR 0015: Snapshot-based publication boundary

## Status

Accepted.

## Context

The compliance engine contains intentionally rich internal objects: evidence locations and provenance, authorization decisions, finding narratives, remediation plans, audit payloads, metadata, and full certification artifacts. Returning those objects from transparency or public APIs and trying to subtract sensitive fields later creates a fragile disclosure boundary.

The engine also already had two adjacent concepts: a deliberately small certification `publicArtifact`, and a compact Registry compliance projection. PR 15 needs to generalize that pattern without duplicating reporting or introducing bill-specific disclosure rules.

## Decision

Use a dedicated publication package with an allowlist-first, snapshot-based model.

A projection builder reads internal state and constructs a new public-safe JSON object containing only intended fields. A configurable policy may then omit or replace paths in that safe object. The final projection is canonicalized, hashed, stored as a publication snapshot, and exposed from public endpoints only while its publication control is in the `published` state.

Publication controls are private by default. Publish and unpublish transitions append events to the existing tamper-evident audit ledger. Republishing increments a revision and replaces the currently visible snapshot rather than exposing live internal domain objects.

The master package includes only domain-neutral projection types. Downstream applications can register custom projection builders for specialized disclosure obligations.

The Registry adapter is implemented in terms of the same resource compliance projection builder.

## Consequences

- Public output cannot accidentally acquire newly added internal fields.
- Publication output is deterministic and hashable for a fixed `asOf`, internal state, and policy.
- Redaction configuration operates on safe projections, not raw internal objects.
- Unpublication is immediate at the public read boundary while historical publication actions remain auditable.
- Public snapshots may become stale until republished; this is intentional because publication is an explicit legal/administrative act.
- PR 16 can add final RBAC around control-plane publication actions without changing the public projection model.
