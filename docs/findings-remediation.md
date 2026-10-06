# Findings and remediation

The findings package turns failed compliance rules into actionable corrective-work records.

## Automatic findings

After a failed check completes, each failed rule becomes one finding.

Synchronization is idempotent. Re-running synchronization for the same check does not duplicate findings.

Each finding preserves the failed rule result and the ruleset ID/version used by the original check.

## Operator workflow

A finding can be:

- assigned to an owner;
- acknowledged;
- disputed;
- resolved through dispute review;
- remediated;
- resolved after verification;
- closed;
- reopened.

## Remediation workflow

Create a remediation with a plan and optional owner/due date.

Then:

```
planned
-> in_progress
-> ready_for_verification
-> verified
```

Verification marks the parent finding resolved.

If verification fails, the remediation becomes `rejected` and a replacement remediation can be created.

Active remediations may also be cancelled.

## Deadlines

When `dueAt` is present, the remediation automatically receives a deadline from the shared deadline engine.

This means remediation work inherits:

- warning windows;
- grace periods;
- escalation thresholds;
- worker-driven overdue transitions;
- tamper-evident deadline history.

## Audit events

Finding events include:

- `finding.opened`
- `finding.owner_assigned`
- `finding.acknowledged`
- `finding.disputed`
- `finding.dispute_resolved`
- `finding.remediation_started`
- `finding.resolved`
- `finding.closed`
- `finding.reopened`

Remediation events include:

- `remediation.created`
- `remediation.started`
- `remediation.submitted_for_verification`
- `remediation.verified`
- `remediation.rejected`
- `remediation.cancelled`

All use the existing tamper-evident audit ledger.
