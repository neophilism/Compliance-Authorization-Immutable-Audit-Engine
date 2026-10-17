# CAIAE-011: bounded audit-prefix fetches

This approved performance/release-assurance slice replaces whole-prefix buffering
with ascending keyset pages of at most 256 events. Both checkpoint collection and
signed-prefix verification reuse it; their existing read-only snapshot ownership
and checkpoint format are unchanged. Each row still requires the exact sequence,
previous hash, canonical event hash and signed terminal hash. No hash checks are sampled.

Regression coverage includes lengths 1, 255, 256, 257 and 513; missing history,
altered payload/hash/link on both sides of page boundaries; invalid signatures
before queries; legitimate appended suffixes; and actual PostgreSQL pagination
of a 257-event chain under a repeatable-read/read-only transaction.

The row-count bound is deterministic, not a measured throughput or latency claim.
Single event payload size, checkpoint chain-head collection, signed manifest size,
total scan CPU/query count and total runtime are not bounded by this change.
Long chains incur additional round trips. No production scale/SLO, restore or
deployment acceptance is asserted. The existing unique chain/sequence index
supports the keyset predicate; representative deployment query plans, workload
benchmarks and owner-only live acceptance remain follow-up work.

Run `npm run typecheck`, `npm test` (with isolated PostgreSQL for database cases),
the existing script tests and `npm run build` through actual CI at the committed
SHA. Local syntax checks alone are not a typecheck or passing integration test.
