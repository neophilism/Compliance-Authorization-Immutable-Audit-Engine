# Configuration SDK

PR 18 adds the reusable `@caiae/sdk` package for downstream thin applications.

The SDK is deliberately separated from PostgreSQL and from the engine's internal service classes. Thin applications communicate through the same stable API boundary used by external clients.

## Thin-app configuration

A thin app configuration uses schema version `1`:

```json
{
  "schemaVersion": "1",
  "appId": "example-compliance-app",
  "displayName": "Example Compliance App",
  "engine": {
    "apiBaseUrl": "https://engine.example",
    "organizationId": "11111111-1111-4111-8111-111111111111",
    "requestTimeoutMs": 30000
  },
  "features": {
    "resources": true,
    "checks": true,
    "reporting": true
  },
  "resourceTypes": {
    "example-resource": {
      "label": "Example Resource"
    }
  }
}
```

Configuration stays domain-neutral. A downstream application may define domain-specific resource labels and metadata, but those values remain outside the master engine.

## Secrets

Runtime secrets are intentionally separate from public configuration:

```ts
const runtime = createThinAppRuntime({
  config,
  secrets: {
    operatorToken: process.env.CAIAE_OPERATOR_TOKEN,
    serviceToken: process.env.CAIAE_SERVICE_TOKEN
  }
});
```

`toPublicThinAppConfig(...)` returns only validated non-secret configuration.

Operator and service credentials remain distinct:

- `caiau_...` — human/operator API;
- `caiae_...` — service/integration API.

The SDK refuses to mix the token families.

## Clients

The package exposes:

```ts
createPublicClient(...)
createOperatorClient(...)
createServiceClient(...)
new ComplianceEngineClient(...)
```

All clients use the engine's HTTP API. No SDK method reaches into PostgreSQL.

Common helpers cover:

- organization lookup;
- resource listing/creation;
- compliance check execution;
- registered ruleset listing/resolution;
- compliance reports;
- Registry compliance projections;
- integration resource pagination;
- public certification verification;
- public publication reads.

The generic `request<T>()` method remains available for APIs that do not yet have convenience wrappers.

## Registered and ad-hoc rules

`runCheck()` uses a discriminated input:

```ts
await client.runCheck({
  resourceId,
  registeredRuleSetId
});
```

or:

```ts
await client.runCheck({
  resourceId,
  ruleSet
});
```

This mirrors PR 17 and prevents a downstream caller from accidentally supplying both.

## Transport portability

The SDK accepts an injectable `fetch` implementation. This supports:

- browsers;
- Node 20+;
- server frameworks;
- test harnesses;
- downstream applications that need custom network instrumentation.

## Example

See:

```
examples/sdk/thin-app.config.json
```

The next milestones should consume this package rather than importing engine internals directly.
