# Security and permission hardening

PR 16 replaces the reference console's caller-selected acting-principal boundary with authenticated operator credentials and organization-scoped RBAC.

## Authentication boundaries

The API now has three explicit route classes:

- **public** — health, OpenAPI, bootstrap, public certification verification, and published projection reads;
- **operator** — internal human/operator APIs protected by `caiau_...` bearer credentials;
- **service** — PR 13 integration APIs protected independently by `caiae_...` service credentials and service scopes.

Operator and service credentials are intentionally different token families and are not interchangeable.

## Operator credentials

Operator credentials:

- are returned only when issued;
- store only a SHA-256 token hash;
- belong to one active user principal and one organization;
- can expire;
- can be revoked;
- record last use;
- are audited when issued/revoked.

The reference administration UI stores the operator token only in tab-scoped `sessionStorage`.

## Bootstrap

Set a strong deployment secret:

```
CAIAE_BOOTSTRAP_SECRET=<random secret of at least 16 characters>
```

Then bootstrap an active user principal:

```
POST /v1/security/bootstrap
X-CAIAE-Bootstrap-Secret: <secret>
```

Body:

```json
{
  "organizationId": "...",
  "principalId": "...",
  "credentialName": "primary-admin"
}
```

Bootstrap ensures an organization-local `administrator` role with `*` permission, assigns it to the principal, issues an operator credential, and appends an audit event.

Rotate or disable the deployment bootstrap secret after provisioning according to the deployment environment's secret-management policy.

## Roles and permissions

Permissions use generic capability names such as:

```
resources.read
resources.write
authorizations.read
authorizations.write
publication.*
security.*
*
```

A role contains a set of permissions. Principals may have multiple roles; their effective permissions are the union of those roles.

The security package exports standard policy-neutral role templates for administrator, operator, reviewer, publisher, and auditor use. Organizations may create additional roles.

## Organization isolation

For internal routes, the API resolves the organization from:

- explicit organization parameters/body fields; or
- the referenced aggregate for ID-addressed routes.

The authenticated operator's organization must match before the request reaches the domain handler.

## Anti-impersonation

Existing domain services retain their explicit actor-principal parameters for audit compatibility, but PR 16 binds those actor fields to the authenticated operator at the API boundary.

A caller can no longer authenticate as principal A and submit principal B as the requester, issuer, reviewer, or other workflow actor.

Target-principal fields used by security administration (role assignment and credential issuance) are intentionally not treated as actor fields.

## Reference console

The PR 14 console now:

1. asks for an operator credential;
2. calls `GET /v1/security/me`;
3. derives the organization and acting principal from the authenticated identity;
4. sends the bearer token with API calls;
5. no longer offers an acting-principal selector.

## Test compatibility

Production `buildApp()` defaults to security enforcement.

The legacy API regression suite runs with an explicit test-only `CAIAE_API_SECURITY_MODE=legacy` harness so pre-PR-16 domain tests continue testing their original contracts without rewriting every historical fixture. Dedicated PR 16 tests instantiate `buildApp({ securityMode: "enforce" })` and verify the security boundary end to end.
