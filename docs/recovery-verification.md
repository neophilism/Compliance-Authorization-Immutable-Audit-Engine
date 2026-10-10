# Independent recovery verification (PR 41)

Production data restoration must be tested on an isolated recovery database, never directly over the source production database. The verifier in scripts/verify-recovery.mjs does not create or restore databases and performs read-only queries. Run it only after a deliberate restore from a provider snapshot or backup.

1. Obtain a direct (non-pooled) connection to an isolated recovery branch/database, and verify that it is separate from your live DATABASE_URL.
2. Restore a captured PostgreSQL backup to that recovery database using pg_restore or a provider-native recovery workflow. This is an operator-administered operation.
3. Obtain a previously exported, independently retained Ed25519-signed audit checkpoint and the verifying public key. Never pull this reference checkpoint from the recovered database itself.
4. Configure RECOVERY_DATABASE_URL, CAIAE_RECOVERY_CHECKPOINT_FILE, CAIAE_AUDIT_VERIFYING_KEY_FILE, and CAIAE_RECOVERY_CONFIRM=VERIFY_ISOLATED_RECOVERY; optionally provide DATABASE_URL solely to detect accidental verification against the source endpoint.
5. After building the repository, run node scripts/verify-recovery.mjs.

The verifier requires the schema migration for the current release, verifies every anchored historical event against the external signature, verifies all audit chains present in the restored database, and reports only aggregate counts. It fails if an anchor is empty, a signature is invalid, a chain is modified or missing, or the schema version is incompatible.

A successful report establishes only those checks. It does not establish application-level restoration of encrypted blobs, correct policy configuration, data completeness beyond the checkpoint, or a measured RTO/RPO. Exercise full API/worker/web workflows in the recovery environment before declaring disaster recovery ready.

Source and recovery database connection credentials must never be committed. This PR is NOT evidence that a real backup restore has occurred.
