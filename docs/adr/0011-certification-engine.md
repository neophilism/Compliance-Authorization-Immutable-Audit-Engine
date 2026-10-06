# ADR 0011: Criteria-backed certification credentials

**Status:** Accepted

A certification is a durable credential backed by a specific compliance check, explicit issuance criteria, a validity window, and a tamper-evident lifecycle.

## Supporting check

Every certification identifies the exact passed check used for issuance.

The issuance artifact retains a summary of that check:

- check ID;
- evaluation/completion time;
- ruleset ID/version;
- result counts;
- evidence IDs.

The check itself retains the full rules/evidence/context snapshots from PR 9.

## Criteria

Certification criteria are configuration, not hard-coded policy logic.

Supported criteria include:

- required ruleset ID;
- required ruleset version;
- maximum supporting-check age;
- unresolved finding severities that block issuance;
- failed-rule severities that count as a material subsequent failure.

Defaults block unresolved high/critical findings and treat high/critical failed rules as material.

## Validity

Issuance requires exactly one of:

- `validUntil`; or
- `validitySeconds`.

`validFrom` defaults to issuance time.

Future-dated credentials begin as `pending`. The worker activates them when `validFrom` arrives and expires pending, active, or suspended credentials when `validUntil` arrives.

Public verification also derives effective status directly from timestamps, so worker delay cannot make an expired credential appear valid.

## Lifecycle

Certification states are:

```
pending -> active
active -> suspended
suspended -> active
pending/active/suspended -> revoked
pending/active/suspended -> expired
active/suspended/expired -> superseded by renewal
```

Revoked and superseded credentials are terminal.

## Material failure

After a failed compliance check completes, active certifications on the same resource are evaluated against their configured `materialFailureSeverities`.

A matching failed-rule severity suspends the certification and stores the failed check ID as the suspension source.

Certification post-processing is isolated from check execution. A suspension-processing error is audited on the completed check and does not rewrite the check result.

## Renewal

Renewal creates a new certification record and artifact linked through `renewedFromCertificationId`.

The prior certification becomes `superseded` and records `supersededByCertificationId`.

This preserves both credential artifacts instead of rewriting the original issuance.

## Artifacts and public verification

Each credential stores:

- a full issuance artifact;
- a deliberately smaller public artifact;
- a human-readable certificate number;
- a random verification code.

The public verification endpoint returns the current effective lifecycle status and the public artifact only.
