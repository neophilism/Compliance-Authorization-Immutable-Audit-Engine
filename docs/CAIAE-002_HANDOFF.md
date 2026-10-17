# CAIAE-002 — monitoring acceptance handoff

October 17, 2026. This is implementation evidence, not production signoff.

## Approved scope and collision review

The canonical `registry/prs.json` retains 12 approved CAIAE units. This change
is the second integration/deployment acceptance slice, not an added unit or a
claim to complete the historical 21 milestones. Immutable starting main:
`facf3915cbea0fa1fc51c5ba51c0115291109546`.

The existing CAIAE-001 follow-up is PR48 at
`4aece8477d89276a64b165514bd45ce5f06d1df7`, still open when reviewed. It fixes
the separate deployment smoke checker and identity contract. Preserve it; this
change touches the monitor and worker-monitor integration, not those files.
The shared transport could be consolidated later only with equivalent tests.
Do not merge an older version over either set of safeguards.

## Implemented boundary

- Strict HTTPS origins and no redirected readiness or signed telemetry.
- Fresh API/service/release/named-schema readiness, consistent across samples;
  manual production acceptance pins its workflow commit. Worker-inclusive
  readiness is exercised against real handlers in the existing CI database test.
- Bounded headers/body waits and JSON size; invalid or stale responses count as
  failures without fabricated latency or exposed provider/body/credential data.
- One signed POST, exact-body HMAC retained, no automatic ambiguous retry, and
  transport acknowledgement distinct from durable ingestion/display.
- Credential/config preflight before probes; invalid metric evidence rejected;
  degraded measured telemetry is delivered honestly and acceptance still fails.

## Verification and operational gates

Run `node --test scripts/engine-room-monitor.test.mjs` and
`node scripts/validate-pr-registry.mjs`. Full CI runs workspace tests (including
the real API/worker test), existing script suites, typechecks, migrations/seed,
rules evaluation and build. The PR/checkpoint must record actual current-head
results; this document does not pre-assert a CI pass. Local scaffold tests do not
prove a database or production deployment is operational.

No live telemetry, service/database change, deployment, new schedule, dependency,
permission, credential extraction or spending was performed during development.
The existing monitor opt-in remains unchanged. Existing protected workflow files
were read, not edited or dispatched.

Before acceptance: resolve every native merge/protection/approval gate, verify
the accepted commit is deployed, configure existing scoped telemetry credentials
privately if absent, run the existing manual acceptance workflow against that
release, and observe the matching signed delivery on the correct Engine Room
project. A HTTP 200/202 receipt alone is not durable dashboard evidence.

Browser login/accessibility, real isolated restore, external audit anchors,
worker replay/failover, network egress, alert delivery and measured reliability
remain separate gates. Do not claim general security conformance, regulatory
compliance, distributed worker exclusion or full project completion here.
