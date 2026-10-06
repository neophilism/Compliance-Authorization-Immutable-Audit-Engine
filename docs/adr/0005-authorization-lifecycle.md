# ADR 0005: Authorization lifecycle and quorum model

**Status:** Accepted

Authorizations are durable stateful records with explicit lifecycle transitions and append-only audit events.

## Normal lifecycle

A normal authorization begins as `pending`.

Reviewer decisions are stored separately from the authorization record. Each principal may decide a given authorization once. Approval does not become effective until the configured approval quorum is met.

A denial is terminal for a pending request. An approved authorization may later be revoked or expire.

## Quorum

Each authorization stores a positive integer approval quorum.

When a list of eligible approver principals is configured, only those principals may decide the request, and the quorum may not exceed the number of eligible approvers.

The optional `approvalAuthority` field is a domain-neutral label for the authority under which approval is being exercised. Role-based enforcement will be expanded during the later RBAC milestone.

## Scope and conditions

The authorization stores explicit JSON `scope` and `conditions`. Approval applies to that exact scope and those conditions. Changing them requires a new authorization rather than silently changing what existing reviewers approved.

## Emergency authorization

An emergency authorization may become temporarily effective at request time, but only if it has:

- a finite `validUntil`; and
- an `emergencyReviewDueAt` that occurs before or at `validUntil`.

It remains subject to the normal approval quorum. If formal review is not completed by the review deadline, the engine treats the authorization as ineffective immediately and the expiration worker transitions it to `revoked`.

A denial during emergency review revokes the emergency authorization.

## Audit atomicity

Authorization state changes and their audit events are written in the same PostgreSQL transaction. This avoids a state in which an approval, denial, revocation, or expiration commits without its corresponding tamper-evident history.

## Expiration

The authorization service exposes an expiration processor. The worker invokes it periodically to transition expired approvals and overdue unreviewed emergency authorizations.
