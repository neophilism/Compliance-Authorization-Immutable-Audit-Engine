# Architecture

## Core lifecycle

The engine models:

`rule -> authorization -> action/event -> evidence -> deadline -> review -> finding -> remediation -> certification/report`

## Boundaries

The core engine remains policy-domain neutral. Bill-specific concepts belong in downstream application schemas and configuration.

## Services

- **API** — command/query boundary and integration surface.
- **Worker** — scheduled checks, deadlines, escalations, and asynchronous jobs.
- **Web** — reference administration interface.
- **Core package** — shared types and domain primitives.
- **PostgreSQL** — authoritative transactional store.

## Audit principle

The platform will use append-only, tamper-evident audit events. Corrections are subsequent events; historical events are never silently edited.

## Inter-engine contract

This engine will expose stable IDs, event types, and APIs so Registry/Transparency and Case Workflow applications can consume compliance status without sharing internal database tables.
