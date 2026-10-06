# Authorization engine

The authorization engine provides a reusable lifecycle for controlled actions without embedding a particular statute or regulated activity in core code.

## Lifecycle

Normal requests:

```
request -> pending -> approve/deny -> approved -> revoke/expire
```

Multi-review requests remain pending until their approval quorum is reached.

Emergency requests:

```
emergency request -> temporarily approved -> mandatory review
                                     -> affirmed
                                     -> denied/revoked
                                     -> overdue/revoked
```

## Core fields

An authorization records:

- organization and resource;
- authorization type;
- requester;
- requested time;
- approval quorum;
- optional approval authority label;
- optional explicit eligible approvers;
- JSON scope;
- JSON conditions;
- validity window;
- emergency status and review deadline;
- terminal/finalizing decision information;
- metadata.

Each reviewer decision is retained separately with reviewer, decision, rationale, and timestamp.

## Effectiveness

`AuthorizationService.effectiveness()` is the canonical check for whether an authorization may currently be relied upon.

Approved state alone is insufficient if:

- `validFrom` has not arrived;
- `validUntil` has passed; or
- an emergency authorization's required review deadline has passed without review.

## Automatic expiration

`AuthorizationService.expireDue()` transitions due records and writes audit events in the same transaction.

The worker runs this periodically. A caller should still use `effectiveness()` before relying on an authorization, because that method immediately respects a passed deadline even before the worker has persisted the terminal state.

## Audit events

The lifecycle currently emits:

- `authorization.requested`
- `authorization.emergency_granted`
- `authorization.decision_recorded`
- `authorization.approved`
- `authorization.denied`
- `authorization.emergency_review_approved`
- `authorization.emergency_review_denied`
- `authorization.revoked`
- `authorization.expired`
- `authorization.emergency_review_overdue`

All events participate in the tamper-evident aggregate hash chain.
