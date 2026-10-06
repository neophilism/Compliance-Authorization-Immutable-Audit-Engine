# ADR 0017: Immutable ruleset revisions and authority traceability

## Status

Accepted.

## Context

The evaluation engine already persisted exact ruleset snapshots, and findings/certifications already retained check and ruleset identifiers. What was missing was a durable answer to two questions:

1. Is the named ruleset version immutable?
2. Which legal, policy, contractual, standards, or other source authority did that exact revision implement?

Using free-form metadata alone would not make those relationships consistently queryable or testable.

## Decision

Extend the existing `rule_sets` model with a normalized declarative snapshot and canonical SHA-256 content hash. A key/version becomes immutable once registered with traceability data.

Add generic `authority_sources` and `rule_set_authority_links` tables. Authority sources are deliberately broader than law and support statutes, regulations, orders, cases, contracts, policies, standards, guidance, and other source types. Links carry a generic relation, locator, and note.

Checks and evaluation schedules gain an optional `rule_set_revision_id`. If supplied, the evaluation engine verifies that the actual ruleset snapshot hashes to the registered revision before execution.

Compliance reports surface the revision hash and authority citations/locators for each check.

## Consequences

- Exact ruleset content and named version cannot silently diverge.
- Legal/source provenance is machine-queryable and survives later rule changes.
- Evaluations still preserve their exact historical ruleset snapshots.
- Existing ad hoc ruleset execution remains supported.
- Findings and certifications remain linked through their supporting checks instead of duplicating authority records.
- Downstream thin applications may define specialized authority types or relations in configuration/metadata without hard-coding bill-specific law into the master engine.
