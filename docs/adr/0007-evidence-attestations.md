# ADR 0007: Evidence validity, provenance, and attestations

**Status:** Accepted

Evidence is modeled as durable records with explicit provenance and validity rather than as a boolean flag attached directly to a compliance rule.

## Evidence identity

Each evidence record belongs to one organization and resource and has a stable `evidenceType`. Rules declare required evidence types; the evidence service determines which types are valid at evaluation time.

## Validity

Evidence is valid only when:

- its status is `active`;
- `validFrom` is absent or has arrived; and
- `validUntil` is absent or has not passed.

The rules engine receives only evidence types that satisfy those conditions.

## References and integrity metadata

Evidence may store:

- source;
- URI/reference;
- media type;
- file name;
- checksum algorithm and checksum;
- captured time;
- structured provenance;
- structured attributes and metadata.

A checksum and checksum algorithm must be supplied together.

## Supersession

Replacement evidence does not delete the prior record. The prior record becomes `superseded`, records a supersession time, and receives a tamper-evident audit event. The replacement links to the prior evidence ID.

Only active evidence may be superseded, and the replacement must target the same organization, resource, and evidence type.

## Attestations

Attestations are separate durable records linked to evidence. They identify:

- principal;
- attestation type;
- statement;
- structured claims;
- attested time;
- optional validity end;
- optional revocation time.

Attestation revocation preserves the historical attestation rather than deleting it.

## Rules-engine boundary

The declarative rules evaluator remains database-independent. `EvidenceService.buildRuleEvaluationContext()` enriches an evaluation context with the valid evidence types for a resource at a specific time.
