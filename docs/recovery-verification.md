# Independent recovery verification (PR 41)

Production data restoration must be tested on an isolated recovery database, never directly over the source production database. The verifier in scripts/verify-recovery.mjs does not create or restore databases and performs read-only queries. Run it only after a deliberate restore from a provider snapshot or backup.

1. Obtain a direct (non-pooled) connection to an isolated recovery branch/database, and verify that it is separate from your live DATABASE_URL.
2. Restore a captured PostgreSQL backup to that recovery database using pg_restore or a provider-native recovery workflow. This is an operator-administered operation.
3. Obtain a previously exported, independently retained Ed25519-signed audit checkpoint and the verifying public key. Never pull this reference checkpoint from the recovered database itself.
4. Configure RECOVERY_DATABASE_URL, CAIAE_RECOVERY_CHECKPOINT_FILE, CAIAE_AUDIT_VERIFYING_KEY_FILE, and CAIAE_RECOVERY_CONFIRM=VERIFY_ISOLATED_RECOVERY; optionally provide DATABASE_URL solely to detect accidental verification against the source endpoint.
5. After building the repository, run node scripts/verify-recovery.mjs.

The verifier requires the schema migration for the current release, verifies every anchored historical event against the external signature, verifies all audit chains present in the restored database, and reports only aggregate counts. It fails if an anchor is empty, a signature is invalid, a chain is modified or missing, or the schema version is incompatible.

## One consistent read-only report

The verifier checks the external signature before acquiring a database client.
It then uses exactly one checked-out client and one `REPEATABLE READ READ ONLY`
transaction for schema, anchored prefixes, every restored chain and all reported
counts. The server's actual transaction modes must confirm that isolation and
read-only access. No internal checkpoint helper may acquire another client or
commit a nested transaction. Existing standalone audit helpers retain their own
transaction behavior; new `WithClient` helpers are SELECT-only composition APIs
whose caller owns the transaction and client lifecycle.

Statement timeout is 30 seconds, lock wait is 5 seconds and idle-in-transaction
timeout is 60 seconds. A timeout, invalid evidence or failed commit produces no
success report. Errors roll back; rollback failure discards the client rather
than returning a potentially poisoned transaction to the pool. Connection
establishment and large in-process cryptographic scans still depend on driver
and operator/runtime limits; this is not a total wall-clock bound.

Endpoint comparison normalizes default PostgreSQL port 5432, host case/trailing
dot, decoded database names, common loopback aliases and known Neon pooler/direct
aliases. Recovery pooler hosts are rejected. Query-string destination, credential
or session overrides and duplicate parameters are refused. Allowed connection
parameters are `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `channel_binding`,
`application_name`, and `connect_timeout`; TLS settings are preserved, not
disabled or rewritten. Unsupported provider options must be reviewed, not
silently passed through. URLs and driver errors never enter the report.

These comparisons catch common accidental aliases, **not** arbitrary DNS,
network-proxy or provider branch identity aliases. Independently verify the
recovery branch/database through the provider before supplying confirmation.
Omitting source `DATABASE_URL` cannot establish physical separation; read-only
verification is not a provider restore operation or proof of isolation.

Checkpoint input is limited to a 16-MiB regular UTF-8 file and the public key to
16 KiB, with bounded reads even if a file grows during reading. JSON/driver/file
errors are summarized without values, checkpoint contents, PEM data or paths.

Focused tests: `node --test scripts/verify-recovery.test.mjs`. They include URL
aliases, transaction wiring/failure/rollback fixtures and bounded file inputs.
The database package's actual PostgreSQL integration additionally verifies a
signed anchor, rejects a write inside the read-only transaction, commits an
audit append on another connection and proves the final counts remain from the
original snapshot. Local wiring fixtures alone do not prove these DB properties.

Implementation references: [node-postgres transactions](https://node-postgres.com/features/transactions)
and [PostgreSQL transaction modes](https://www.postgresql.org/docs/current/sql-set-transaction.html).

A successful report establishes only those checks. It does not establish application-level restoration of encrypted blobs, correct policy configuration, data completeness beyond the checkpoint, or a measured RTO/RPO. Exercise full API/worker/web workflows in the recovery environment before declaring disaster recovery ready.

Source and recovery database connection credentials must never be committed. This PR is NOT evidence that a real backup restore has occurred.

