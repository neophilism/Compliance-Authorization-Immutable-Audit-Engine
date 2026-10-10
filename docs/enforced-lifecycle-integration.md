# PR 33: Enforced end-to-end integration regression

The test at apps/api/test/full-lifecycle-api.test.ts exercises the authenticated API with a real PostgreSQL database. It verifies operator bootstrap, cross-tenant rejection, evidence registration, failed control evaluation, finding generation, compliance reporting, private-by-default publication, safe publishing and withdrawal, and audit-chain verification.

The test uses unique identities and a canary metadata value that must never appear in public projections. It runs in the existing database-backed CI suite with npm test.

This is not a browser test, independent security audit, or evidence that the service is deployed.
