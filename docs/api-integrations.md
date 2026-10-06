# API and integration layer

## OpenAPI

The complete route inventory is available from:

```
GET /openapi.json
```

## Create a service credential

Control-plane endpoint:

```
POST /v1/integration/service-accounts
```

The response contains the bearer token once. Store it securely.

Execution requests use:

```
Authorization: Bearer caiae_...
```

Available scopes include:

- `resources:read`
- `resources:write`
- `checks:run`
- `events:read`
- `webhooks:read`
- `webhooks:write`
- `imports:write`
- `exports:read`
- `adapters:read`
- `*`

## Idempotent writes

These integration operations require:

```
Idempotency-Key: <client-generated key>
```

Current idempotent routes:

- create resource;
- run compliance check;
- import resources.

A replay returns the prior response with:

```
Idempotency-Replayed: true
```

Using the same key for different request content returns HTTP 409.

## Pagination

Resources and integration events use:

```
?limit=50&cursor=<opaque cursor>
```

The response is:

```json
{
  "items": [],
  "nextCursor": null
}
```

Additional filters:

- resources: `resourceType`, `status`;
- events: `eventType`.

## Webhooks

Create a subscription with an HTTPS URL and optional event-type list.

If no event types are supplied, `*` is used.

Every audit event becomes a durable integration event. Matching subscriptions get queued deliveries.

The worker signs deliveries using:

- `X-CAIAE-Event-Id`
- `X-CAIAE-Timestamp`
- `X-CAIAE-Signature: sha256=<hex>`

Verify the signature over:

```
<timestamp>.<raw request body>
```

using the signing secret returned at subscription creation.

## Import/export

Resource import:

```
POST /v1/integration/import/resources
```

Resource export:

```
GET /v1/integration/export/resources
```

Imports are mapped by source/external ID and update their existing mapped resource on later imports.

## Registry adapter

```
GET /v1/integration/resources/:resourceId/registry-projection
```

Returns a compact compliance projection suitable for the Registry/Transparency engine.

## Case Workflow adapter

```
GET /v1/integration/case-triggers
```

Returns generic human-review triggers for disputed/material findings and overdue remediation.
