# Engine Room operational integration

This repository has an approved 12-PR hardening roadmap in .exechub/project.yml for Engine Room project registration. Existing core milestones are completed; the 12 units cover proposed PRs 33-44. Map these approved roadmap units to actual merged GitHub PR numbers in Engine Room. Do not infer progress from ordinal matches.

## Automated production telemetry

A GitHub Actions workflow (Engine Room Production Monitor) is scheduled every five minutes and can be manually dispatched. It is disabled until the repository variable CAIAE_MONITOR_ENABLED is set to true.

Configure the following repository variables:
- CAIAE_MONITOR_API_URL: production HTTPS API origin
- ENGINE_ROOM_BASE_URL: production Engine Room HTTPS origin
- CAIAE_MONITOR_ENABLED: true ONLY after endpoints and credentials are configured

Configure these GitHub Actions secrets:
- ENGINE_ROOM_TELEMETRY_KEY_ID
- ENGINE_ROOM_TELEMETRY_SECRET

In the Engine Room application, configure ENGINE_ROOM_TELEMETRY_KEYS with a scoped credential whose ID and secret match the GitHub secrets, whose projectId is the registered CAIAE project UUID, with environment production, source github-actions-caiae, adapter engine-room-v1, and capabilities containing only metric.

The script sends a signed, HMAC-authenticated envelope (version 1) with **measured** availability, error rate and successful-request P95 latency from five actual database-readiness probes. If every probe fails, latency is omitted rather than fabricated. The workflow fails if any readiness probe fails or if Engine Room rejects the signed delivery.

## Limitations and acceptance

Github scheduled runs are best effort, can be delayed, and cannot substitute for an always-on service monitor. Five individual ready checks are a short-window sample, not 30-day availability. No worker health, job backlog, domain correctness, finances or audit integrity are asserted by this telemetry. Do not label production operational until the actual API, worker and web console are deployed, backend migrations complete, and Engine Room has accepted and displayed a signed delivery. Never commit telemetry keys.

Run local no-network tests: node --test scripts/engine-room-monitor.test.mjs
