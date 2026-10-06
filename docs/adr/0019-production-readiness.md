# ADR 0019: Production operating boundary

## Status

Accepted.

## Context

The engine had complete domain, API, publication, security, traceability, and SDK layers, but local-development assumptions still leaked into process startup:

- API and worker processes always ran migrations on startup;
- CORS was open by default at the API layer;
- the integration layer could fall back to a development webhook secret;
- the API had only a liveness endpoint;
- API shutdown was not coordinated;
- the worker did not wait for active sweeps during shutdown;
- no reusable container/recovery convention existed.

These are deployment concerns shared by every downstream thin application and therefore belong upstream.

## Decision

Add a domain-neutral `@caiae/runtime` package for validated process configuration.

Production runtime rules are fail-closed:

- legacy API security is forbidden;
- wildcard CORS is forbidden;
- a strong webhook master secret is required;
- migrations default off for long-lived processes;
- reverse-proxy trust, request timeout, body limit, release identity, and shutdown grace are explicit settings.

Keep `/health` as process liveness and add `/ready` for PostgreSQL-backed readiness.

API and worker processes perform bounded graceful shutdown.

Provide one multi-target container definition plus a provider-neutral deployment example and backup/restore/rollback runbook.

Do not claim distributed worker scheduling. Production deployments use one active worker replica until a later architecture explicitly adds distributed leadership.

## Consequences

- application startup no longer needs schema mutation privileges in normal production operation;
- deploy systems can separate migration failures from application rollout failures;
- public/browser network exposure is explicit;
- orchestrators can distinguish a live process from a ready database-backed API;
- deployment termination is less likely to interrupt in-flight compliance work;
- downstream thin apps inherit one production convention;
- the first thin app can focus on policy configuration rather than reinventing operations.
