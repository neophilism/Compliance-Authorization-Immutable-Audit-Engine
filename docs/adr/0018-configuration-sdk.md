# ADR 0018: API-first thin-app configuration SDK

## Status

Accepted.

## Context

The engine had reached a point where downstream applications could call its API, but there was no reusable package defining how a thin app should configure itself or consume that API. Without a shared SDK, the first thin app would likely duplicate URL handling, authentication headers, error decoding, configuration validation, and common DTO assumptions.

Directly exporting internal services or database repositories would undermine the architectural rule that downstream applications remain thin and isolated from the engine's persistence model.

## Decision

Create a standalone `@caiae/sdk` package with two responsibilities:

1. validate domain-neutral thin-app configuration;
2. provide API clients for public, operator, and service boundaries.

Runtime credentials are kept separate from public app configuration. The SDK recognizes PR 16's distinct operator/service token families and refuses to interchange them.

The client uses standard HTTP/fetch and accepts an injectable transport. Convenience methods cover common engine operations, while a typed generic request method keeps the package extensible without forcing every API route into the first SDK release.

The SDK does not expose PostgreSQL, repositories, Fastify instances, domain services, or worker internals.

## Consequences

- Thin apps share one configuration and API-client convention.
- Downstream domain terminology lives in configuration rather than the master engine.
- Operator/service authentication semantics remain consistent across applications.
- SDK consumers stay insulated from database migrations and internal package refactors.
- The first thin app in PR 20 can reveal missing abstractions through real SDK usage.
- PR 19 can focus on deployment/operations rather than inventing downstream integration conventions.
