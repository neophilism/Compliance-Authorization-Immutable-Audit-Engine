# ADR 0010: Findings and remediation lifecycle

**Status:** Accepted

Compliance findings are durable records derived from failed rule results, not mutable annotations on a check.

## Automatic finding creation

When a completed check is `failed`, the evaluation service asks the findings service to synchronize findings.

Each rule result with status `fail` produces one finding identified by:

```
check_id + rule_key
```

A partial unique index makes synchronization idempotent.

Passing, unknown, and not-applicable rules do not create findings.

## Declarative rule identity

Declarative rule IDs are application-level strings, while the older `rules.id` database field is a UUID foreign key.

Automatically generated findings therefore preserve:

- `ruleKey`;
- `ruleSetKey`;
- `ruleSetVersion`;
- the complete failed rule-result snapshot.

The optional UUID `ruleId` remains available for applications that use persisted rule rows.

## Check/finding failure isolation

A failure to synchronize findings must not rewrite a successfully completed compliance check as `error`.

The evaluator preserves the check result and records `check.finding_sync_error` when synchronization fails.

## Finding states

```
open
  -> acknowledged
  -> disputed
  -> remediating
  -> resolved
  -> closed
```

Not every path visits every state. A dismissed dispute may close a finding without remediation. A resolved or closed finding may be reopened.

## Disputes

Open or acknowledged findings may be disputed.

Dispute resolution has two outcomes:

- `uphold`: return the finding to `acknowledged`;
- `dismiss`: resolve and close the finding without corrective action.

The original dispute reason remains on the record and the resolution rationale is written to the audit history.

## Remediation

Remediation is a separate durable aggregate with:

- creator;
- owner;
- corrective-action plan;
- due time;
- lifecycle timestamps;
- verifier or rejection actor;
- verification/rejection notes;
- optional linked deadline.

The lifecycle is:

```
planned
  -> in_progress
  -> ready_for_verification
  -> verified

ready_for_verification -> rejected
planned/in_progress/ready_for_verification -> cancelled
```

A rejected remediation is historical. A new remediation may then be created.

## Verification and closure

Successful remediation verification marks the finding `resolved`.

Closure is a separate explicit action so systems can distinguish technical verification from administrative closure.

Reopening a resolved or closed finding returns it to `open` while retaining the prior audit history and remediation records.

## Deadline integration

A remediation with `dueAt` gets a normal PR 8 deadline:

```
subjectType: remediation
subjectId: <remediation id>
deadlineType: remediation-completion
```

Verification satisfies that deadline.

Rejection or cancellation cancels the old remediation deadline. A replacement remediation receives its own deadline.
