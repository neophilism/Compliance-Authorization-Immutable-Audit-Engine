# ADR 0009: Reproducible automated compliance evaluations

**Status:** Accepted

Automated checks must remain explainable after resources, evidence, or policy configuration change.

## Single execution path

Manual, event-triggered, batch, and scheduled evaluations all call the same evaluation execution path.

This prevents trigger-specific differences in:

- evidence selection;
- rule evaluation;
- status mapping;
- snapshots;
- audit events.

## Ruleset snapshot

Every check stores the normalized declarative ruleset object actually supplied to the deterministic rules evaluator.

The snapshot contains the ruleset ID and version but does not depend on the current state of a mutable policy record.

## Context snapshot

Every completed check stores the resource state and facts used to evaluate the rules.

The check therefore answers what the evaluator saw at evaluation time rather than reconstructing it from the current resource.

## Evidence trace

Every completed check stores the valid evidence records made available to the rules engine, including:

- evidence ID;
- evidence type;
- source/reference;
- checksum information;
- capture time;
- validity window.

The rules evaluator consumes evidence types, while the persisted trace explains which evidence records supplied those types.

## Status mapping

Rule-set results map to persisted check states:

- `pass` -> `passed`
- `fail` -> `failed`
- `unknown` -> `unknown`

Execution failures are stored as `error`.

## Schedules

Evaluation schedules store their own normalized ruleset snapshot and facts.

A schedule targets exactly one resource or one resource type.

Workers claim a due schedule occurrence by conditionally advancing `nextRunAt`. Only the worker that successfully changes the expected prior timestamp may create checks for that occurrence.

The next run is advanced from the prior schedule, skipping elapsed intervals when necessary so worker delay does not create schedule drift or duplicate catch-up storms.

## Events

Event-triggered checks preserve the event type and structured event payload in `triggerDetail`, but otherwise use the same evaluator as manual checks.
