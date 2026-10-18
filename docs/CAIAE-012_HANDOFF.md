# CAIAE-012 performance and release assurance

The mapped draft PR adds bounded synthetic operation sampling and loopback HTTP sampling. The API test now starts the real Fastify service on an ephemeral loopback port, sends 20 HTTP GET requests to `/ready`, and records p50/p95/p99 latency, success and failure counts. Under CI, `/ready` checks a real isolated PostgreSQL database and migration state. The first response must identify the expected test release. A failed response or unavailable database fails the test.

The diagnostic is a small, sequential, single-process test-environment sample. It is useful for detecting a broken API/database path and for obtaining a reproducible measurement method. It is not production throughput, a concurrency limit, a latency SLO, a representative workload, or evidence of disaster recovery. CI timing is variable and no latency threshold is asserted.

Release acceptance still requires measurements from an authorized representative deployment with its actual database and traffic profile, documented target thresholds and repeatable results, an isolated restore rehearsal, and the production smoke/monitoring gates. Keep the PR draft until the software implementation and applicable evidence are complete. No live account, credential, service or production data is used by this test.
