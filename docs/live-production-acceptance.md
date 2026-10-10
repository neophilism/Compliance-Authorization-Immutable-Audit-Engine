# Production acceptance workflow (PR 43)

The manually dispatched GitHub workflow Production Acceptance (manual) runs a fail-closed production health and monitoring check. It is not scheduled, does not deploy services, and does not provision resources.

Before dispatching it from the default branch, configure:
- GitHub repository variable CAIAE_MONITOR_ENABLED=true;
- GitHub repository variable CAIAE_MONITOR_API_URL with the live HTTPS API origin;
- GitHub repository variable ENGINE_ROOM_BASE_URL with the authorized live Engine Room HTTPS origin;
- GitHub Actions secret CAIAE_SMOKE_OPERATOR_TOKEN containing a limited live operator credential;
- GitHub Actions secrets ENGINE_ROOM_TELEMETRY_KEY_ID and ENGINE_ROOM_TELEMETRY_SECRET matching a metric-only, production-scoped signed-telemetry key registered in Engine Room.

The job rejects an unconfigured production monitor. It verifies actual API/database/schema health; denies anonymous operator access; authenticates a real operator; verifies that the deployed commit equals the workflow's main-branch commit; and probes worker-inclusive readiness. Only then does it send signed, measured availability, error and latency metrics to Engine Room.

A green manual run means that the above checks passed **at the time of the run**. It is not equivalent to full production signoff. Independent outstanding requirements are browser acceptance with live login, real backup and isolated restore, published externally retained audit anchors, worker job replay/failover exercise, webhook egress controls, alert delivery testing, dependency/security review, accessibility, and measured reliability over time.

The workflow deliberately uses explicit service URLs and scoped secrets and has no Render workspace creation or write permission. Do not mark the repository operational until at least one real configured acceptance run passes and the Engine Room dashboard displays the matching project and measurements.
