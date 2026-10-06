# ADR 0008: Time-derived deadline and statutory clock state

**Status:** Accepted

Deadline state is calculated from explicit timestamps and durations before it is persisted by a worker.

## Clock boundaries

For a deadline with due time `D`:

- warning begins at `D - warningWindowSeconds`;
- due begins at `D`;
- overdue begins at `D + gracePeriodSeconds`.

This produces:

```
scheduled -> warning -> due -> overdue
```

A caller can calculate the state for any supplied time without waiting for a background job.

## Persistence

The worker periodically persists clock advancement and writes tamper-evident events.

If a worker wakes after multiple thresholds have passed, the engine records every crossed state with the timestamp of that threshold. It does not fabricate a history in which only the final observed state existed.

Clock persistence never moves backward.

## Absolute and relative deadlines

An absolute deadline supplies `dueAt`.

A relative deadline supplies `dueAfterSeconds` and may supply `anchorAt`. If the anchor is omitted, creation time is used. The engine stores the resolved due time together with the anchor and offset so the calculation remains explainable.

## Grace periods and escalation

Grace time delays the transition from `due` to `overdue`.

Escalation thresholds are nonnegative seconds measured from the overdue boundary. Each crossed threshold increases the escalation level and creates an audit event.

## Recurrence

A recurring deadline advances from the prior scheduled due time, not from the time it was satisfied. This avoids schedule drift.

Each completed cycle is written to `deadline_occurrences`. A recurring deadline advances only when the current cycle is satisfied.

Optional `maxOccurrences` and `recurrenceEndAt` bound recurrence.

## Terminal states

`satisfied` and `cancelled` are terminal for the current deadline record. Once terminal, the clock worker does not advance it.
