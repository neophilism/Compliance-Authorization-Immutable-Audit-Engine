# ADR 0017: Immutable ruleset versions with authority traceability

## Status

Accepted.

## Context

The engine already preserved exact declarative ruleset snapshots on every compliance check. That made an individual evaluation reproducible, but it did not answer several higher-level provenance questions consistently:

- Was the ruleset an approved/registered version or an ad-hoc input?
- What canonical content hash identifies the version?
- Which policy and source authorities support it?
- Which version superseded which prior version?
- Which version was effective on a historical date?
- Can downstream reports and certifications refer to the same immutable version identity?

The core schema already contained a `rule_sets` table with organization, policy, key, version, lifecycle state, and effective dates, so adding a second version system would create unnecessary duplication.

## Decision

Extend the existing `rule_sets` table into the canonical ruleset registry.

A registered version stores the full normalized declarative definition and its SHA-256 hash. Definition content, stable identity fields, and supersession lineage are immutable after insertion and are enforced by PostgreSQL as well as the service API.

Generic authority references are stored separately and linked to versions. The master engine treats authority type, citation, locator, URI, jurisdiction, and dates as opaque provenance fields; it does not encode bill-specific legal semantics.

Registered versions use a lifecycle of draft -> active -> superseded/retired with explicit effective windows. Historical resolution includes superseded and retired versions when the requested date falls within their prior effective window.

Evaluations continue storing exact ruleset snapshots. They additionally store a canonical hash and provenance manifest. Registered evaluations also persist the database ruleset version ID. Ad-hoc rulesets remain supported and are explicitly identified as ad hoc.

## Consequences

- Evaluation reproducibility and legal/source traceability remain separate but linked guarantees.
- A later edit cannot silently change the content behind an already registered version.
- Historical reports can identify the version in force at the relevant time.
- Supersession is explicit and auditable.
- Source/citation conventions stay configurable downstream.
- Certifications, reports, Registry projections, schedules, and service integrations can share one version identity.
- Thin applications may require registered versions for their own workflows without forcing that restriction on the reusable master engine.
