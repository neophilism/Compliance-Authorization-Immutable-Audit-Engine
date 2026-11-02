# Production acceptance workflow (PR 43)

The manually dispatched GitHub workflow Production Acceptance (manual) runs a fail-closed production health and monitoring check. It is not scheduled, does not deploy services, and does not provision resources.

Before dispatching it from the default branch, configure:
- GitHub repository variable CAIAE_MONITOR_ENABLED=true;
- GitHub repository variable CAIAE_MONITOR_API_URL with the live HTTPS API origin;
- GitHub repository variable ENGINE_ROOM_BASE_URL with the authorized live Engine Room HTTPS origin;
- GitHub Actions secret CAIAE_SMOKE_OPERATOR_TOKEN containing a limited live operator credential;
- GitHub Actions secrets ENGINE_ROOM_TELEMETRY_KEY_ID and ENGINE_ROOM_TELEMETRY_SECRET matching a metric-only, production-scoped signed-telemetry key registered in Engine Room.

The job rejects an unconfigured production monitor. It verifies actual API/database/schema health; denies anonymous operator access; authenticates a real operator; verifies that the deployed commit equals the workflow's main-branch commit; and probes worker-inclusive readiness. Only then does it send signed, measured availability, error and latency metrics to Engine Room.

The API checker follows the real `AuthenticatedOperator` response contract, checks
active credential/principal scope consistency, refuses redirects and bounds JSON
response bytes and header/body wait time. See [deployment-smoke-test.md](deployment-smoke-test.md)
for the exact checks and the optional expected-organization setting. The current
manual workflow already supplies the required full expected commit; no workflow
activation, new schedule or credential is introduced by this checker correction.

## CAIAE-001 implementation handoff — October 17, 2026

The canonical approved plan is `registry/prs.json` (12 CAIAE units). This work is
a deployment-acceptance follow-up under CAIAE-001, not a new approved unit or a
claim to finish the historical 21 milestones. No open PR existed when this unit
was claimed; implementation started from immutable main
`facf3915cbea0fa1fc51c5ba51c0115291109546`. Preserve existing SDK/security and
recovery work rather than rewriting those merged slices.

The old checker incorrectly required `identity.organization.id`; the server
returns organization association inside principal/credential instead. Its old
mock repeated that invented shape, so a mocked pass could not establish that a
real login would pass. The corrected fixture mirrors the server/types and tests
both valid and invalid associations. Previously the public verification probe
accepted any HTTP-200 JSON, and fetch followed redirects by default; both are
now fail-closed. No live API, database, user, certificate or telemetry mutation
was performed while developing this change.

Remaining acceptance: inspect exact-head CI and native merge gates; deploy the
accepted immutable release using existing authorized infrastructure; configure
the scoped operator credential and service origins privately if absent; run the
existing manual production-acceptance workflow at that same deployed commit;
retain actual endpoint and worker/Engine Room evidence. Do not reuse local test
results as production evidence. Browser login/accessibility, real isolated
restore, external audit anchoring, webhook egress and alert delivery remain
separate requirements; independent human review is deferred under AGENTS.md,
not a routine development prerequisite.

A green manual run means that the above checks passed **at the time of the run**. It is not equivalent to full production signoff. Independent outstanding requirements are browser acceptance with live login, real backup and isolated restore, published externally retained audit anchors, worker job replay/failover exercise, webhook egress controls, alert delivery testing, dependency/security review, accessibility, and measured reliability over time.

The workflow deliberately uses explicit service URLs and scoped secrets and has no Render workspace creation or write permission. Do not mark the repository operational until at least one real configured acceptance run passes and the Engine Room dashboard displays the matching project and measurements.

