# Certification engine

The certifications package issues and manages time-bound credentials based on compliance checks.

## Issue

To issue a certification, provide:

- organization and resource;
- certification type;
- passed supporting check;
- issuing principal;
- validity period;
- optional criteria and conditions.

The engine validates the check against the configured criteria and blocks issuance when unresolved findings match configured blocking severities.

## Certificate artifact

A credential receives:

- a unique certificate number;
- a random verification code;
- a full issuance artifact;
- a smaller public artifact;
- the exact supporting check ID.

The full artifact is returned through the normal certification API. Public verification returns only the public artifact.

## Public verification

Use:

```
GET /v1/public/certifications/verify/:code
```

The response distinguishes:

- stored status; and
- time-derived effective status.

A credential is valid only when its effective status is `active`.

## Material failure

Failed PR 9 checks automatically pass through the certification suspension evaluator.

If any failed rule severity matches a credential's configured material-failure severities, an active certification is suspended and linked to that failed check.

## Reinstatement

A suspended certification may be reinstated only with a new passed check that satisfies the certification's original criteria and while the credential remains within its validity window.

## Renewal

Renewal issues a new credential and supersedes the old one.

The old verification code remains resolvable but returns `superseded` and is not valid.

## Worker lifecycle

The worker runs `CertificationService.sweep()` using `CERTIFICATION_SWEEP_MS`.

It persists:

- pending -> active at `validFrom`;
- pending/active/suspended -> expired at `validUntil`.

Public verification remains correct even between worker sweeps.
