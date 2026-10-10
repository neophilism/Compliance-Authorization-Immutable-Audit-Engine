# Render deployment topology (PR 36)

The deploy/render.blueprint.example.yaml file is **an example, not an active Blueprint**. It is intentionally not stored at repository root as render.yaml, to prevent accidental billable service provisioning while the intended Render workspace and spending approval remain unresolved.

The example defines three services: paid API web service, one active background worker, and paid Next.js admin web service. The API uses a one-shot migration pre-deploy hook with the direct Neon PostgreSQL connection. Normal API and worker database traffic use the pooled Neon connection. The API checks /ready and the worker intentionally has exactly one active replica. Build and deploy are gated on successful GitHub checks.

The admin frontend uses a server-side Next.js rewrite to the API origin, obtained from the API service's Render-assigned external URL. Production API CORS can therefore remain disabled. A generated webhook secret is shared by the API and worker through a Render environment group. The bootstrap secret is initially supplied to the API only, then removed after secure provisioning.

## Deployment order and credentials

1. Confirm the intended Render workspace and paid service plans. Do not accidentally apply the example to another workspace.
2. Supply pooled DATABASE_URL and direct DATABASE_URL_UNPOOLED for the preexisting Neon project. Do not commit either.
3. Create the API first, run migrations using its pre-deploy hook, and confirm /ready is 200.
4. Provision the first organization and user principal intentionally; never run the demonstration db:seed script as a substitute for a production tenant. Bootstrap the first operator only over an authenticated administrative channel.
5. Add the one-active-replica worker and inspect all six sweep logs; add the admin frontend and verify authenticated browser functionality.
6. Set GitHub monitor variables and scoped Engine Room telemetry secrets from docs/engine-room-monitoring.md only after the deployment is live.
7. Run the authenticated read-only production smoke test from docs/deployment-smoke-test.md, test backup/restore in an isolated recovery database and verify audit chains.

Render automatically exposes RENDER_GIT_COMMIT on Git-backed services. If CAIAE_RELEASE_SHA is unset, API and worker now report the Render commit in their health and startup metadata. Explicit CAIAE_RELEASE_SHA always wins.

## Important limitations

The three starter services have ongoing costs; the example is not authorized for automatic provisioning and may exceed the current budget. Render's free web tier is not equivalent to reliable continuously running production infrastructure, and a worker does not have a free compute plan. No live deployment, workspace selection, production tenant creation, data migration, backup or Engine Room ingestion is claimed by this PR. Validate the Blueprint using Render CLI before applying it.
