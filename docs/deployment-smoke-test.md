# Deployment verification (PR 34)

This is an API acceptance test using only GET requests. It creates or changes no
compliance business records; normal authentication still updates the credential's
last-used timestamp. Run after independently configuring API, worker,
administration frontend, and PostgreSQL, and after one-shot database migration.

Supply the following through your secured deployment environment (never commit credentials):

    CAIAE_SMOKE_API_URL=https://your-api.example
    CAIAE_SMOKE_OPERATOR_TOKEN=your-operator-credential
    CAIAE_SMOKE_EXPECTED_RELEASE=your-deployed-commit-sha
    node scripts/verify-deployment.mjs --require-auth

Checks: HTTPS (except local), API liveness, database/schema readiness, matching release identity, OpenAPI, anonymous operator denial, public certification verification and authenticated operator identity.

Authenticated acceptance now requires the expected full 40-character commit SHA
before any network request. Both health endpoints must identify the API service,
the same full commit and a named schema revision (for example,
`0014_worker_activity`, as emitted from the server's migration contract), not an
invented numeric version. A null release is not evidence of
the intended deployment. An optional `CAIAE_SMOKE_EXPECTED_ORGANIZATION_ID`
pins the intended tenant; supplying it requires an operator token.

The actual `/v1/security/me` contract is `AuthenticatedOperator`: it contains
`principal.organizationId` and `credential.organizationId`, **not** a top-level
`organization` object. The check requires active principal and credential,
matching principal/organization associations and role/permission arrays. This
proves only the returned credential's scope, not general cross-tenant isolation.

The nonexistent-certification probe must return `found: false`, `valid: false`,
null certificate/artifact fields and a parseable check time. HTTP 200 with an
error object, an arbitrary JSON body or an invented valid certificate fails.
OpenAPI must declare the required GET operations in a version 3 document.

All requests are GET with no redirects, ambient cookies or caching. The operator
token is sent only to the final identity request on the configured origin.
Requests have a 10-second deadline covering headers **and** body reads; JSON is
limited to 1 MiB of actual received/decompressed bytes per response, with early
rejection of oversized declared length, malformed JSON, invalid UTF-8 and wrong
media types. Failed bodies are cancelled. No transport exception, provider body,
redirect destination, credential or authenticated identity is included in the
result/error output. The success receipt includes only origin, commit and an
authenticated boolean. This does not substitute for an operator-approved target
origin or platform egress controls.

Run the credential-free checker tests with:

    node --test scripts/verify-deployment.test.mjs

CI runs this same suite. It includes real loopback HTTP requests using only a
synthetic token, proving that an authenticated redirect does not reach its
destination, plus fixtures for the real identity shape, tenant mismatches,
inactive credentials, malformed responses, byte limits and stalled streams.
Fixture success is not a live production acceptance result.

The existing API security integration test also invokes this checker against
the real Fastify handlers, generated OpenAPI and PostgreSQL-backed authentication
in CI's isolated test database. It must accept the actual operator response and
reject a different expected tenant. This prevents the mocked identity shape
from silently drifting away from the server contract again. That test requires
`DATABASE_URL`; a local scaffold-only run does not establish database integration.

This check alone does not prove the worker is sweeping, the web browser interface is usable, webhook deliveries succeed, audit chains are externally anchored, or database backups are restorable. Verify each separately before labeling production operational.

