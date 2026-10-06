# Automated compliance evaluations

The evaluations package turns declarative rules, resource state, and valid evidence into persisted compliance checks.

## Manual check

A manual check supplies:

- organization;
- resource;
- declarative ruleset;
- optional facts;
- optional requesting principal.

The engine creates a check, transitions it through `pending` and `running`, evaluates it, then persists `passed`, `failed`, `unknown`, or `error`.

## Reproducibility

Each completed check stores:

- normalized ruleset snapshot;
- evaluation context snapshot;
- valid evidence trace;
- ruleset evaluation result;
- evaluation timestamp.

Later changes do not rewrite those fields.

## Event-triggered check

`runEvent()` adds an event type and structured event object to the check trigger details and executes the same evaluation flow.

## Batch check

`runBatch()` creates an independent check for each unique resource ID. Each check gets its own audit chain and snapshots.

## Scheduled checks

A schedule may target:

- one explicit resource; or
- every non-archived resource of one resource type in the organization.

Schedules define:

- normalized ruleset snapshot;
- optional facts;
- interval;
- next run time.

`runDueSchedules()` claims due schedules and creates normal `scheduled` checks.

The worker invokes this through `EVALUATION_SWEEP_MS`.

## Audit events

Checks emit:

- `check.created`
- `check.started`
- `check.completed`
- `check.error`

Schedules emit creation and activation-state events.

The check history is protected by the engine's existing tamper-evident audit ledger.
