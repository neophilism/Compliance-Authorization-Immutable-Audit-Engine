# Deadline engine and typed SDK lifecycle

The master engine owns domain-neutral deadline and statutory-clock machinery. Policy-specific applications decide which obligations exist, what event anchors a clock, and what legal or operational date is due.

## Generic deadline model

A deadline can be associated with an optional resource and a generic subject. It records:

- `subjectType` and `subjectId`;
- a policy-neutral `deadlineType`;
- either an absolute `dueAt` or an `anchorAt` plus `dueAfterSeconds`;
- optional warning and grace windows;
- optional recurrence limits;
- optional escalation thresholds;
- generic metadata and correlation identifiers.

The deadline service preserves immutable audit events for creation, clock transitions, satisfaction, recurring-cycle advancement, and cancellation. Completed occurrences retain their due time, satisfaction time, actor, and on-time or late outcome.

The worker advances active deadlines through scheduled, warning, due, and overdue states and applies configured escalation thresholds.

## SDK boundary

Thin applications must use `@caiae/sdk` rather than importing `@caiae/deadlines`, database repositories, or API internals.

The typed SDK exposes:

- `createDeadline()`;
- `getDeadline()`;
- `getDeadlineStatus()`;
- `listDeadlinesBySubject()`;
- `satisfyDeadline()`;
- `cancelDeadline()`.

The SDK binds the configured organization identifier when a deadline is created and otherwise maps directly to the existing deadline HTTP API.

## Policy-specific clocks stay downstream

The engine does not know what "enactment", "annual certification", "quarterly update", "GAO evaluation", or any other statutory phrase means.

A downstream application is responsible for:

1. establishing the authoritative anchor event or explicit due date;
2. applying the policy's date-calculation semantics;
3. assigning policy-specific subject and deadline identifiers;
4. deciding whether a deadline may recur, be replaced, or be cancelled;
5. supplying policy-specific metadata and authority references.

This separation is especially important for legal periods expressed as calendar years, calendar months, or a date selected by another authority. A thin application may calculate an exact `dueAt` and persist that date through the generic engine rather than forcing a policy meaning into a fixed-second recurrence.

## No duplicate lifecycle

SDK support is an access-layer abstraction only. It does not duplicate the deadline service, database model, clock calculation, recurrence behavior, audit ledger, or worker sweep. Those remain owned by the existing deadline package and API.
