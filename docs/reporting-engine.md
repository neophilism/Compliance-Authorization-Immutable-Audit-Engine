# Reporting engine

The reporting package compiles current compliance records into a single canonical report and renders that report as JSON, CSV, or human-readable Markdown.

## API

Organization report:

```
GET /v1/reports/organizations/:organizationId/compliance
```

Resource report:

```
GET /v1/reports/organizations/:organizationId/resources/:resourceId/compliance
```

Query parameters:

- `format=json` — default structured report;
- `format=csv` — normalized CSV export;
- `format=text` — human-readable Markdown;
- `asOf=<ISO date-time>` — evaluate time-sensitive effective state at that time.

## Summary

The report calculates:

- resources by status;
- checks by status and latest completion;
- active exceptions/waivers;
- deadlines by effective state and overdue count;
- findings by status/severity;
- unresolved and unresolved high/critical findings;
- remediation status and overdue count;
- certifications by effective state and valid count;
- audit event/chain counts and chain-integrity result.

## Worker-independent effective state

Reports derive effective deadline and certification status from timestamps rather than trusting worker persistence alone.

This makes reporting accurate between scheduled worker sweeps.

The original stored lifecycle status is still included.

## Audit history

Organization reports include all audit chains in the organization.

Resource reports include audit chains belonging to the selected resource and the checks, exceptions, deadlines, findings, remediations, and certifications included in that report.

Each included chain is verified before the report is returned.

## Formats

All formats come from the same canonical report object.

CSV is designed for spreadsheet/analytics workflows. Markdown is designed for review packets, administrative briefings, and direct human reading.
