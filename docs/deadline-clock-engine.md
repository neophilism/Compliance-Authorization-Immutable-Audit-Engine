# Deadline and statutory clock engine

The deadlines package provides a generic clock for statutory, regulatory, review, remediation, authorization, case, and certification workflows.

## Create a clock

A deadline identifies:

- organization;
- optional resource;
- generic subject type and subject ID;
- deadline type;
- absolute due time or relative anchor + offset;
- warning window;
- grace period;
- optional recurrence;
- optional escalation thresholds.

The engine does not require the subject to belong to a particular application table. A thin app may use subject types such as `authorization`, `finding`, `case`, or a domain-specific record type.

## Status queries

`DeadlineService.statusAt(id, time)` calculates the state at an arbitrary time:

- `scheduled`
- `warning`
- `due`
- `overdue`

This is independent of worker timing.

## Worker sweep

`DeadlineService.sweep(time)` persists forward-only state changes and escalation levels. The shared worker calls it on `DEADLINE_SWEEP_MS`.

## Completion

Satisfying a deadline records:

- cycle number;
- scheduled due time;
- actual satisfaction time;
- principal;
- on-time/late outcome.

For recurring clocks, satisfaction advances the deadline to the next due date while retaining the completed cycle as a separate occurrence record.

## Escalation

`escalationAfterSeconds` is an ordered set of overdue-age thresholds.

For example:

```json
[0, 3600, 86400]
```

means escalation level 1 begins immediately on becoming overdue, level 2 after one hour overdue, and level 3 after one day overdue.

## Audit history

Clock events include:

- `deadline.created`
- `deadline.warning`
- `deadline.due`
- `deadline.overdue`
- `deadline.escalated`
- `deadline.satisfied`
- `deadline.cycle_advanced`
- `deadline.cancelled`

These use the existing tamper-evident audit chain.
