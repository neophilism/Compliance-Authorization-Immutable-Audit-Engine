# Production readiness

PR 19 defines the reusable production operating boundary for the Compliance, Authorization & Immutable Audit Engine.

The guidance is provider-neutral. A downstream thin application may deploy to containers, virtual machines, or a managed platform as long as it preserves the same process and database boundaries.

## Processes

A production deployment has three independently deployable processes:

- **API** — Fastify HTTP API.
- **Worker** — scheduled compliance, deadline, certification, authorization, exception, and webhook sweeps.
- **Web** — reference Next.js administration console.

PostgreSQL remains the authoritative transactional store.

## Build

The root `Dockerfile` exposes three targets:

```bash
docker build --target api -t caiae-api .
docker build --target worker -t caiae-worker .
docker build \
  --target web \
  --build-arg CAIAE_API_BASE_URL=https://engine.example.gov \
  -t caiae-web .
```

The web proxy destination is a build-time Next.js rewrite setting. Supply the production API URL when building the web target.

`docker-compose.production.example.yml` is an example topology, not a prescribed hosting provider.

## Required production configuration

Long-lived production processes require:

```
NODE_ENV=production
DATABASE_URL=postgresql://...
CAIAE_WEBHOOK_MASTER_SECRET=<unique random value of at least 32 characters>
CAIAE_RUN_MIGRATIONS=false
```

Production rejects:

- `CAIAE_API_SECURITY_MODE=legacy`;
- wildcard CORS (`CAIAE_CORS_ORIGINS=*`);
- the development webhook secret;
- webhook secrets shorter than 32 characters.

If cross-origin browser access is needed, provide an explicit comma-separated allowlist:

```
CAIAE_CORS_ORIGINS=https://admin.example.gov,https://program.example.gov
```

If the web console and API share an origin through a reverse proxy, use:

```
CAIAE_CORS_ORIGINS=none
```

## Secret handling

The deployment platform's secret store should hold at least:

- `DATABASE_URL`;
- `CAIAE_WEBHOOK_MASTER_SECRET`;
- `CAIAE_BOOTSTRAP_SECRET` while initial operator bootstrap is required.

Do not expose operator credentials (`caiau_...`) or service credentials (`caiae_...`) as public web configuration.

After the first administrator credential has been bootstrapped, remove `CAIAE_BOOTSTRAP_SECRET` from the long-lived API environment unless another bootstrap operation is deliberately required.

## Release sequence

Use this release order:

1. Build and test one immutable release artifact.
2. Back up PostgreSQL.
3. Run database migrations as a **one-shot release task**.
4. Start or roll the API.
5. Confirm `GET /health` and `GET /ready`.
6. Start or roll the worker.
7. Start or roll the web application.
8. Run a smoke test through the public and authenticated API boundaries.
9. Record the deployed commit in `CAIAE_RELEASE_SHA`.

Long-lived API and worker replicas should normally use:

```
CAIAE_RUN_MIGRATIONS=false
```

Run the migration task explicitly:

```bash
DATABASE_URL=... npm run db:migrate
```

For an intentional single-process local or ephemeral deployment, `CAIAE_RUN_MIGRATIONS=true` remains supported.

## Health probes

### Liveness

```
GET /health
```

Liveness only proves the API process can serve requests. It does not prove PostgreSQL is reachable.

### Readiness

```
GET /ready
```

Readiness runs a database query. It returns HTTP 200 only when the API can reach PostgreSQL and HTTP 503 otherwise.

Load balancers should use `/ready` for traffic admission.

## Graceful shutdown

The API handles `SIGTERM` and `SIGINT`, stops accepting traffic through Fastify shutdown, closes PostgreSQL, and enforces `CAIAE_SHUTDOWN_GRACE_MS`.

The worker stops scheduling new sweeps, waits for active sweeps to finish up to the same grace period, then closes PostgreSQL.

Default:

```
CAIAE_SHUTDOWN_GRACE_MS=15000
```

## Worker replica count

PR 19 does **not** introduce a distributed scheduler-leader protocol.

Deploy the scheduler worker as **one active replica**. API and web processes may scale independently.

A future change may add database-backed worker leadership or per-job distributed claims, but production readiness must not assume that capability before it exists.

## Database backup and restore

Use provider-native PostgreSQL backups where available and periodically test restore.

A portable logical backup is:

```bash
pg_dump \
  --format=custom \
  --no-owner \
  --file=caiae.dump \
  "$DATABASE_URL"
```

Restore into an empty recovery database:

```bash
pg_restore \
  --no-owner \
  --dbname="$RECOVERY_DATABASE_URL" \
  caiae.dump
```

After restore:

1. run `npm run db:migrate` against the recovery database if required;
2. verify application reads;
3. verify tamper-evident audit chains with `npm run audit:verify -- ...` for representative or required aggregates;
4. confirm public certification/publication projections do not expose private state.

Backup files contain sensitive compliance data and must be encrypted and access-controlled by the deployment operator.

## Rollback

Application rollback is safe only while the database schema remains compatible with the older release.

Because migrations are forward-applied, do not automatically reverse a production migration. If a release must be rolled back:

1. stop the affected worker;
2. decide whether the previous application version is compatible with the migrated schema;
3. if compatible, redeploy the previous application artifact;
4. if incompatible, restore the pre-migration backup into a recovery environment and follow the incident-specific recovery plan.

Never silently delete or rewrite audit events to make a rollback succeed.

## Observability

The API uses Fastify structured logs and the worker emits JSON lifecycle/sweep events.

At minimum, production log aggregation should retain and alert on:

- process crashes and unhandled rejections;
- repeated readiness failures;
- failed worker sweeps;
- webhook delivery failures;
- audit-chain verification failures;
- authentication/authorization anomalies at the platform boundary.

`CAIAE_RELEASE_SHA` is returned by health/readiness probes and should identify the deployed commit or release.

## Capacity and safety controls

Defaults:

```
CAIAE_BODY_LIMIT_BYTES=1048576
CAIAE_REQUEST_TIMEOUT_MS=30000
CAIAE_TRUST_PROXY=true
```

Adjust them only with an explicit deployment reason.

The engine stores evidence metadata and references; downstream applications should not assume arbitrarily large binary uploads belong in the API request body.

## Production smoke test

After deployment verify:

1. `/health` returns 200;
2. `/ready` returns 200;
3. anonymous internal API access is rejected;
4. an operator credential can call `/v1/security/me`;
5. a service credential can access only its service scopes;
6. a known public certification/publication endpoint works without credentials;
7. a representative resource/report query succeeds;
8. the worker emits successful sweep events.
