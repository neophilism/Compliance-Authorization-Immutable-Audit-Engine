# ADR 0006: Bounded exceptions and waivers

**Status:** Accepted

Exceptions and waivers share one controlled lifecycle but retain an explicit `kind` so downstream applications can distinguish the legal or policy meaning of each.

## Scope

Every record targets:

- one organization;
- one resource;
- optionally one enabled rule;
- explicit JSON scope;
- explicit JSON conditions.

An approved exception or waiver does not implicitly apply beyond those targets.

## Mandatory expiration

Every request requires a finite `validUntil`. The engine will not create an unbounded exception or waiver.

`validFrom` may be specified in advance. If omitted, it becomes the time at which the approval quorum is reached.

## Approval

Reviewer decisions are durable records. Each principal may decide once.

A configurable approval quorum determines when the request becomes approved. When eligible approvers are configured, only those principals may decide or revoke the record.

Any denial terminates a pending request.

## Expiration

Both requested and approved records expire when `validUntil` passes. This prevents stale pending requests from later becoming active after their intended window.

The background worker persists expiration, but callers must use the effectiveness check before relying on an approved record because the effectiveness calculation honors the validity window immediately.

## Audit atomicity

Requests, decisions, approvals, denials, revocations, and expirations commit in the same transaction as their tamper-evident audit events.
