# Signed audit checkpoints (PR 38)

The existing per-aggregate SHA-256 audit chains detect ordinary changes and prevent UPDATE or DELETE from application/database roles subject to the append-only trigger. A sufficiently privileged database operator could replace and recompute an entire chain. An independently retained Ed25519-signed checkpoint closes that gap only for events anchored by that checkpoint, provided the signing key and independent copy cannot be controlled by the database operator.

## Issuing a checkpoint

1. Generate an Ed25519 private/public keypair in an offline, access-controlled environment (for example using OpenSSL). Store the private key away from the database and application host.
2. Use a direct, read-only PostgreSQL database connection in DATABASE_URL_UNPOOLED. The tool reads and verifies every existing audit aggregate under one repeatable-read database snapshot; this is an offline operation, not a request handler.
3. Set CAIAE_AUDIT_SIGNING_KEY_FILE and CAIAE_AUDIT_KEY_ID, then run:

    node scripts/audit-anchor.mjs create /secure-external-volume/audit-2026-10-09.json

The tool refuses to overwrite an existing checkpoint, creates a mode-0600 file outside the Git checkout, and never outputs signing keys. It does not upload checkpoints automatically.

4. Copy the signed JSON to a truly independent append-only/immutable storage location under separate credentials and retention controls. A local file in the same trust domain as the database is **not** an external anchor.

## Independent verification

Set CAIAE_AUDIT_VERIFYING_KEY_FILE to the trusted public-key file and use the direct read-only database URL:

    node scripts/audit-anchor.mjs verify /secure-external-volume/audit-2026-10-09.json

Verification rejects invalid signatures, missing chains, missing historical events, changed chained content and altered anchored hashes. Chains that gained legitimate events after the checkpoint remain valid because the complete anchored historical prefix is verified. The verifier intentionally does not claim that unanchored later events are protected. Produce and independently retain regular new checkpoints.

Operational considerations: the checkpoint contains organization and aggregate identifiers and is sensitive; limit access, preserve key rotation history, and do not put private keys or checkpoint files into GitHub. Large deployments should replace the current offline full-history verification scan with a bounded, independently reviewed streaming or incremental strategy before scheduling high-frequency anchoring.
