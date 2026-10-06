# ADR 0014: Reference administration UI

**Status:** Accepted

PR 14 adds a policy-neutral operator console over the existing compliance engine API.

## API-only operator boundary

The web application does not connect to PostgreSQL.

Every read and mutation goes through the Fastify API, preserving the same validation, audit-event generation, lifecycle rules, and error semantics as other clients.

A Next.js rewrite exposes the API to the browser at a same-origin `/engine-api/*` path. The upstream API address is configured with `CAIAE_API_BASE_URL`.

## Minimal new read surface

The compliance report already provides organization-wide resources, checks, exceptions, deadlines, findings, remediation, certifications, and audit-chain state.

Only two additional collection reads were needed:

- active/inactive principals, optionally filtered by kind;
- organization authorization queue, optionally filtered by status/resource.

No separate admin database or duplicated reporting model is introduced.

## Operator context

The console carries three explicit pieces of context:

- organization;
- acting principal;
- selected resource.

Until PR 16 authentication/RBAC hardening, the selected principal is sent explicitly to workflow endpoints. The interface labels this limitation.

## Workflow coverage

The console provides UI operations for:

- resource registration and selection;
- declarative ruleset editing and compliance checks;
- authorization requests, decisions, and revocation;
- exception/waiver requests, decisions, and revocation;
- deadline creation, satisfaction, and cancellation;
- evidence creation, attestation, and revocation;
- finding acknowledgement/dispute/dispute resolution;
- remediation creation/start/submission/verification/rejection/cancellation;
- certification issuance/suspension/reinstatement/renewal/revocation;
- audit-chain inspection;
- JSON/CSV/Markdown compliance report export.

## Source of truth

After every mutation, the console refreshes authoritative API state.

The UI does not synthesize lifecycle state or optimistically mark workflow steps complete.

## Rulesets

PR 14 intentionally treats the ruleset editor as a configuration surface. It sends declarative JSON to the PR 9 evaluation API, which stores the exact ruleset snapshot used by each check.

A future bill-specific application may provide curated/versioned ruleset libraries without changing the reference console architecture.
