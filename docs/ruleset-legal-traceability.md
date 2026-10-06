# Ruleset versioning and legal/source traceability

PR 17 extends the existing `policies → rule_sets → rules` model rather than creating a second rules registry.

## Immutable revisions

A registered declarative ruleset revision stores:

- organization and policy;
- ruleset key and version;
- exact normalized declarative snapshot;
- canonical SHA-256 content hash;
- lifecycle state;
- effective dates;
- creator;
- activation timestamp;
- optional successor revision;
- authority/source links.

The pair `key + version` is immutable. Registering identical content is idempotent; registering different content under an existing key/version returns a conflict.

## Authority sources

Authority/source records are policy-neutral and support:

- statute;
- regulation;
- order;
- case;
- contract;
- policy;
- standard;
- guidance;
- other.

Each source can carry a jurisdiction, citation, title, URI, dates, optional SHA-256 content hash, and metadata.

A ruleset revision can link to any number of sources with a generic relation, locator, and note. For example, a downstream application may say that a rule revision `implements` a source at `§ 12(a)(1)`.

The engine does not encode bill-specific disclosure or citation semantics.

## Evaluation binding

Checks and evaluation schedules may specify `ruleSetRevisionId`.

When present, the evaluation engine:

1. loads the registered revision;
2. verifies organization ownership;
3. recomputes the canonical SHA-256 hash of the supplied ruleset snapshot;
4. rejects the evaluation if the snapshot differs from the immutable registered revision;
5. persists the revision ID alongside the pre-existing exact ruleset snapshot.

This preserves support for ad hoc/unregistered rulesets while providing a strong traceability path when a downstream application requires it.

## Reporting

Compliance reports now include, per check:

- `ruleSetRevisionId`;
- `ruleSetContentHash`;
- source type;
- citation;
- title;
- relation;
- locator.

This makes the provenance path explicit:

```
authority/source
  → registered ruleset revision
  → exact evaluation snapshot
  → check
  → finding/certification/report
```

Findings and certifications continue to inherit their existing check linkage, so the originating immutable ruleset revision remains recoverable through the supporting check.

## API

```
POST /v1/authority-sources
GET  /v1/organizations/:organizationId/authority-sources

POST /v1/rule-set-revisions
GET  /v1/rule-set-revisions/:id
GET  /v1/organizations/:organizationId/rule-set-revisions
POST /v1/rule-set-revisions/:id/activate
POST /v1/rule-set-revisions/:id/supersede
```

These are normal PR 16 operator-authenticated routes and use the generic `traceability.read` / `traceability.write` permission namespace.
