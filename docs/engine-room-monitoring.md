# Engine Room operational integration

The canonical approved plan is `registry/prs.json`, with 12 CAIAE work units.
`.exechub/project.yml` and the historical 21-item plan preserve lineage; their
ordinals are not GitHub PR numbers. Map actual PR/head/test/deployment evidence
without inferring completion from source presence or old proposed PR ranges.

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

### Probe and delivery boundaries

Each probe requests `/ready?includeWorker=true` on the configured HTTPS origin.
HTTP 200 is insufficient: JSON must identify service `api`, status `ready`, a
full 40-character release SHA, a named migration revision such as
`0014_worker_activity`, and a timestamp no older than 60 seconds or more than
30 seconds ahead of the monitor. Hosts need synchronized clocks. Successful
samples must agree on release and schema; a rolling mixed-release result is
degraded rather than 100-percent healthy.

Optional `CAIAE_MONITOR_EXPECTED_RELEASE` pins an intended full commit. The
existing **Production Acceptance (manual)** workflow automatically uses its
inherited `GITHUB_SHA` when no explicit pin is supplied. This closes the gap
between its earlier smoke test and the later worker probes without editing or
activating either workflow. Ordinary recurring monitoring does not assume the
latest main commit is deployed; it still rejects mixed-release samples. If the
manual workflow is renamed, supply the explicit expected-release setting and
update the workflow-name contract before calling it acceptance.

Readiness probes have a 10-second header-and-body deadline and a 64-KiB actual
JSON byte limit, including decompressed bytes. Invalid lengths, media types,
UTF-8, JSON, stale or unexpected payloads count as failed samples. Failed bodies
are cancelled. Requests never follow redirects, use ambient cookies or reuse
cached responses. Origin parsing rejects credentials, paths, queries, fragments,
whitespace and backslash/parser normalization ambiguity. Target origins remain
operator-controlled; this does not replace network egress policy.

Signed telemetry uses exactly one POST to the configured Engine Room origin,
with redirects forbidden and no automatic retry after an ambiguous response.
The original exact body/HMAC contract is preserved. Unneeded response bodies
are cancelled rather than parsed or logged. HTTP 200/202 is a transport-level
acknowledgement only; it does not prove durable ingestion, project association
or dashboard display. Check those separately. Any other status or transport
failure rejects delivery; provider error text, redirect URLs, signatures and
secrets are not included in the failure receipt.

Invalid sample counts, impossible success totals, malformed observations or
fabricated outage latency cannot be turned into a metric envelope. Degraded
runs may deliver their truthful reduced availability and then exit with failure;
they never print a success receipt. Credential/configuration preflight performs
no requests and does not construct invented success metrics.

## Limitations and acceptance

Github scheduled runs are best effort, can be delayed, and cannot substitute for an always-on service monitor. Five individual ready checks are a short-window sample, not 30-day availability. They reflect the API's worker-inclusive readiness verdict at sample time, not independent proof of job correctness, backlog, leader election, finances, recoverability or audit integrity. Do not label production operational until the actual API, worker and web console are deployed, backend migrations complete, and Engine Room has accepted and displayed a signed delivery. Never commit telemetry keys.

Run local no-network tests: node --test scripts/engine-room-monitor.test.mjs

The focused suite also includes a real loopback HTTP transport fixture with a
synthetic signing key: a redirected signed POST never reaches its destination
and is not retried. A test-only URL translation reaches that fixture; production
continues to require HTTPS, with no TLS bypass. CI's existing worker-readiness
test runs the monitor against actual Fastify/PostgreSQL responses before six
successful sweeps, after them, and after a failed sweep. A scaffold-only local
run does not establish that database integration or live production acceptance.

