# Reference administration UI

## Start the API

The Fastify API defaults to port 4000.

```bash
npm run dev -w @caiae/api
```

## Start the web console

The Next.js application proxies `/engine-api/*` to the API.

The default upstream is:

```
http://localhost:4000
```

Override it with:

```
CAIAE_API_BASE_URL=https://your-api.example
```

Start the console:

```bash
npm run dev -w @caiae/web
```

Open the web application and enter a `caiau_...` operator credential. The console authenticates that credential with `GET /v1/security/me`, derives the operator's organization and principal, and binds workflow actor identity to that authenticated principal.

## Navigation

### Overview

Shows the live compliance posture:

- resource/check totals;
- pending authorizations;
- overdue deadlines;
- unresolved high/critical findings;
- valid certifications;
- urgent workflow items;
- audit-chain integrity.

### Resources

Browse resources and register new domain-neutral resources.

### Rules & Checks

Edit a declarative ruleset JSON document and execute it against the selected resource.

Each check is persisted with the exact ruleset/context/evidence snapshots produced by the engine.

### Authorizations

Browse the organization authorization queue, submit new requests, approve/deny reviews, and revoke approved authorizations.

### Exceptions

Browse report-derived exception/waiver state and administer request/decision/revocation workflows.

### Deadlines

Create deadline clocks and satisfy/cancel existing deadlines. Effective status in the table comes from the reporting engine's shared PR 8 clock calculation.

### Evidence

For the selected resource, create evidence records, add attestations, and revoke active evidence.

### Findings

Operate the full finding/remediation lifecycle: acknowledge, dispute, resolve disputes, create remediation, start work, submit for verification, verify/reject, cancel, close, and reopen.

### Certifications

Issue credentials from passing checks and operate suspension, reinstatement, renewal, and revocation.

### Audit & Reports

Inspect aggregate audit-chain verification and open the same canonical report in JSON, CSV, or Markdown.

## Security boundary

PR 16 protects the reference console with operator authentication, organization isolation, and role-derived permissions.

The browser no longer chooses an acting principal. It stores the operator bearer credential in tab-scoped `sessionStorage`, sends it to internal APIs, and uses the authenticated principal returned by `GET /v1/security/me` for audited workflow actor fields.

Machine integration routes continue to use the separate `caiae_...` service credential family and PR 13 scopes.
