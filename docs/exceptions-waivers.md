# Exceptions and waivers

The exceptions package provides a reusable, policy-neutral mechanism for controlled departures from ordinary rules.

## Exception versus waiver

The engine stores both through the same lifecycle:

- `exception` — a bounded exception for the identified resource, rule, scope, and conditions;
- `waiver` — a bounded waiver using the same review and expiration controls.

The engine does not infer the substantive legal meaning of either term. Thin applications choose the appropriate kind and supply their own policy language.

## Lifecycle

```
request -> requested -> approvals -> approved -> revoke/expire
                      \-> denial
```

A request remains ineffective until the configured approval quorum is reached.

## Required controls

Every request must include:

- resource;
- kind;
- requester;
- justification;
- finite expiration time.

Optional controls include:

- target rule;
- future valid-from time;
- scope;
- conditions;
- approval quorum;
- approval-authority label;
- explicit eligible approvers.

## Effectiveness

`ExceptionService.effectiveness()` is the canonical reliance check.

A record is effective only when:

1. status is `approved`;
2. `validFrom` has arrived, if present; and
3. `validUntil` has not passed.

## Automatic expiration

`ExceptionService.expireDue()` expires both stale pending requests and approved records whose validity window has closed.

The worker invokes this on a configurable interval using `EXCEPTION_SWEEP_MS`.

## Audit events

Event names retain the record kind, including:

- `exception.requested` / `waiver.requested`
- `*.decision_recorded`
- `*.approved`
- `*.denied`
- `*.revoked`
- `*.expired`

The aggregate type remains `exception` so both kinds use the same tamper-evident chain model.
