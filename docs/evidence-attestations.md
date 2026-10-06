# Evidence and attestations

The evidence package supplies the compliance engine's reusable evidence lifecycle.

## Evidence lifecycle

Evidence begins as `active` and may later become:

- `superseded` when replaced by newer evidence of the same type; or
- `revoked` when it should no longer be relied upon.

Historical evidence is retained.

## Validity windows

An active evidence record may have `validFrom` and `validUntil`. Validity checks are calculated at query time, so an expired record stops satisfying rules immediately even if no worker has run.

## Rule integration

Rules already declare `requiredEvidenceTypes`.

The evidence service can build a rule-evaluation context using only valid evidence types:

```ts
const context =
  await evidence.buildRuleEvaluationContext(
    organizationId,
    resourceId,
    baseContext,
    evaluationTime,
  );

const result = evaluateRuleSet(ruleSet, context);
```

A rule whose control expression is true but whose required evidence is missing remains `unknown`.

## Attestations

Attestations add a named human/service assertion to an evidence record. They may contain structured claims and an optional validity window.

Revoked or expired attestations are excluded from `validAttestations()`, while the original records remain available for history and audit.

## Audit events

The evidence aggregate emits events including:

- `evidence.created`
- `evidence.superseded`
- `evidence.attested`
- `evidence.attestation_revoked`
- `evidence.revoked`

All participate in the existing tamper-evident hash chain.
