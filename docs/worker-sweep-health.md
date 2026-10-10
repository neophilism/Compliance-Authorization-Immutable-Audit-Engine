# Worker sweep health (PR 39)

Migration 0014 creates a singleton scheduler activity record containing the worker instance ID, release, and latest status/timestamp for all six sweep families: authorization, exception, deadline, evaluation, certification and webhook.

At startup the worker resets the previous instance's status. After every sweep it records success or failure, updating activity timestamps in PostgreSQL. The optional public endpoint GET /ready?includeWorker=true fails with HTTP 503 unless every sweep reports recent success and the worker release matches the API release. The basic GET /ready remains API/database-only, so a worker problem does not automatically make the administration web console unreachable.

Engine Room five-minute monitor now samples the full-system readiness endpoint, not just API/database health. A degraded worker results in a failed monitor action and measured reduced availability.

This is only observability. It is NOT leader election, job claiming or distributed worker coordination: production must still use one active worker replica. Test coverage includes missing, failed, stale, release-mismatched and healthy worker states. Full readiness does not assert backup recoverability or audit anchoring.
