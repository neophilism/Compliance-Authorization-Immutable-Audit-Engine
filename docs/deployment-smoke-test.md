# Deployment verification (PR 34)

This is a read-only API acceptance test. Run after independently configuring API, worker, administration frontend, and PostgreSQL, and after one-shot database migration.

Supply the following through your secured deployment environment (never commit credentials):

    CAIAE_SMOKE_API_URL=https://your-api.example
    CAIAE_SMOKE_OPERATOR_TOKEN=your-operator-credential
    CAIAE_SMOKE_EXPECTED_RELEASE=your-deployed-commit-sha
    node scripts/verify-deployment.mjs --require-auth

Checks: HTTPS (except local), API liveness, database/schema readiness, matching release identity, OpenAPI, anonymous operator denial, public certification verification and authenticated operator identity. These checks do not mutate live records.

CI validates the checker itself using mocked HTTP responses.

This check alone does not prove the worker is sweeping, the web browser interface is usable, webhook deliveries succeed, audit chains are externally anchored, or database backups are restorable. Verify each separately before labeling production operational.
