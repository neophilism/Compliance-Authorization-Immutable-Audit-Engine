# ADR 0016: Operator credentials and organization-scoped RBAC

## Status

Accepted.

## Context

Before PR 16, the reference administration UI selected an active principal and sent that principal ID in workflow requests. Domain services validated many principal relationships, but the API did not authenticate the human caller. A caller able to reach an internal route could therefore present another valid principal ID. Internal ID-addressed reads also needed a uniform organization boundary.

PR 13 already established a separate hashed bearer-credential system for machine integrations. That service-principal model should remain independent because service scopes and human/operator permissions are different security concerns.

## Decision

Introduce a dedicated `@caiae/security` package and operator credential family.

Operator credentials use a distinct `caiau_` token prefix, are returned once, and are stored only as SHA-256 hashes. Credentials bind to active user principals and organizations and support expiry, last-use tracking, and revocation.

Human authorization uses organization-scoped roles. Roles contain generic permission strings; a principal's effective permissions are the union of assigned roles. `*` and namespace wildcards such as `resources.*` are supported.

Fastify applies one centralized pre-handler to all operator-classified routes. The handler:

1. authenticates the operator token;
2. checks the permission derived from the route contract;
3. resolves and enforces organization ownership;
4. rejects caller-supplied workflow actor IDs that do not match the authenticated principal.

Public routes bypass operator authentication intentionally. Integration routes continue to use PR 13 service credentials/scopes and cannot be authenticated with operator tokens.

A deployment bootstrap secret is the break-glass mechanism used to provision an administrator credential for an existing active user principal.

## Consequences

- The reference UI can no longer impersonate arbitrary principals.
- Internal routes have a consistent authentication and organization-isolation boundary.
- Domain services keep explicit actor IDs and existing audit semantics.
- Operator and service credentials remain separate and purpose-specific.
- Downstream thin applications can reuse the same roles/permission package.
- PR 17 can add ruleset/legal traceability without needing to redesign identity.
- Historical API tests use an explicit legacy-mode test harness; dedicated PR 16 tests exercise enforcement mode.
