# CAIAE-010 recovery verification follow-up

October 17, 2026. The canonical `registry/prs.json` still contains 12 approved
CAIAE units. This is the remaining monitoring/recovery/downstream slice, not
an additional unit or completion of all historical 21 milestones.

## Source and integration boundaries

Implementation starts from immutable main
`facf3915cbea0fa1fc51c5ba51c0115291109546`. Existing recovery verification and
signed checkpoint work is preserved and extended, not replaced. Open PR48
(CAIAE-001, head `4aece8477d89276a64b165514bd45ce5f06d1df7`) and PR49
(CAIAE-002, head `edea903b94fc82744c64e9383b22b676183c317f`) remain independent
smoke/monitor follow-ups when inspected. Their files are not overwritten here.

Previously the recovery verifier checked schema/counts via pooled queries,
external anchor prefixes in one transaction and all restored chains in another.
The combined report therefore had no single-snapshot guarantee. It now owns
one server-confirmed repeatable-read read-only transaction on one client for
all evidence and returns a success report only after commit. SELECT-only
composition helpers preserve existing standalone audit helper APIs.

Default-port/host-case/encoded-name/common pooler and loopback aliases are
compared before connecting; query parameters cannot silently override the
chosen destination/session. This is not proof against arbitrary provider/DNS
aliases. Operator confirmation of an actually independent recovery environment
remains required. No restore or provider resource is created by the verifier.

## Verification and remaining work

Focused local tests cover URL aliases, transaction wiring, failures/rollback,
pre-connection rejection, secret-free counts/errors and bounded regular-file
inputs. They use mock DB wiring, not production. Actual CI must also pass the
new PostgreSQL integration: signed anchor, write rejection, concurrent append
on a different connection and stable original-snapshot report counts. Record
current remote PR/head/CI evidence in the PR and Boardroom checkpoint; do not
infer a pass from this handoff text.

Preserve all configured native merge/protection/approval gates. After acceptance,
perform a deliberate real isolated provider restore with independently retained
checkpoint/public key and scoped credentials. Then exercise real API/worker/web
flows and measure restore/recovery objectives. A checker pass alone does not
prove encrypted-object recovery, all business data completeness, downstream
application integration, external anchoring retention or operational signoff.

No live database/provider/credential, deployment, restore, infrastructure,
schedule, workflow dispatch, new dependency, spending or permission expansion
was used while implementing this follow-up. Do not run it against a guessed
or unverified production endpoint. Large full-history scans and connection
establishment still need operator/runtime resource limits; query timeouts are
not a complete program deadline.
