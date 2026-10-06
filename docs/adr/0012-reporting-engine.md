# ADR 0012: Canonical compliance reporting read model

**Status:** Accepted

The reporting engine is a read model over authoritative compliance records. It does not copy current compliance state into a new reporting table.

## Canonical report

Every report is first compiled into one canonical object containing:

- scope and organization/resource identity;
- summary metrics;
- compliance checks;
- exceptions and waivers;
- deadlines;
- findings;
- remediations;
- certifications;
- audit-chain verification results;
- audit events.

JSON, CSV, and human-readable output are renderings of this same object.

This prevents different report formats from developing different compliance semantics.

## Organization and resource scopes

Reports can cover:

- an entire organization; or
- one resource inside that organization.

A resource-scoped report includes only the selected resource's checks, exceptions, deadlines, findings, remediations, certifications, and the audit chains for those aggregates.

Organization reports include every organization audit event.

## Time-derived state

Some lifecycle state can become stale between worker sweeps.

The report therefore derives effective state at its `asOf` timestamp for:

- exceptions/waivers;
- deadlines;
- certifications.

For example, a deadline stored as `scheduled` can report effective status `overdue` after its due/grace threshold even before the deadline worker persists the transition.

Stored and effective status are both preserved in report records.

## Audit integrity

Audit events are grouped by aggregate and verified with the existing PR 3 hash-chain verifier.

The report exposes:

- event count;
- chain count;
- invalid-chain count;
- all-chains-valid summary;
- per-chain verification results;
- underlying events.

Reporting never rewrites or repairs audit history.

## CSV

CSV is a normalized cross-section export.

Every row includes common fields such as section, resource, entity type/ID, stored/effective status, severity, key/title, dates, and a JSON details column for section-specific fields.

## Human-readable output

The human-readable format is Markdown-compatible text with:

- executive summary;
- checks;
- exceptions/waivers;
- deadlines;
- findings;
- remediation;
- certifications;
- audit integrity.

## Historical limitation

`asOf` controls time-derived effective status. It does not reconstruct arbitrary past mutable database state after later lifecycle actions have already been persisted.

Historical reproduction of policy/ruleset decisions remains a separate concern from report rendering.
