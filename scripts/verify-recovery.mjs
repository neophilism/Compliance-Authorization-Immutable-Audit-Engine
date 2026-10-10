import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import {
  createPool,
  LATEST_SCHEMA_VERSION,
  collectAuditCheckpoint,
  verifyAuditCheckpointAgainstDatabase,
} from "@caiae/db";

export function validateRecoveryTarget(recoveryUrl, sourceUrl) {
  let target;
  try { target = new URL(recoveryUrl); }
  catch { throw new Error("A valid RECOVERY_DATABASE_URL is required"); }
  if (!["postgres:", "postgresql:"].includes(target.protocol) ||
      !target.hostname || !target.pathname || target.pathname === "/") {
    throw new Error("RECOVERY_DATABASE_URL must address a PostgreSQL database");
  }
  if (target.hostname.includes("-pooler")) {
    throw new Error("Recovery verification requires a direct, non-pooled database connection");
  }
  if (sourceUrl) {
    let source;
    try { source = new URL(sourceUrl); }
    catch { throw new Error("Configured source DATABASE_URL is invalid"); }
    if (source.hostname === target.hostname &&
        source.port === target.port && source.pathname === target.pathname) {
      throw new Error("Recovery database must not be the production/source database");
    }
  }
  return recoveryUrl;
}

export async function verifyRecovery(pool, checkpoint, publicKey) {
  if (!checkpoint || !Array.isArray(checkpoint.checkpoint?.chainHeads) ||
      checkpoint.checkpoint.chainHeads.length === 0) {
    throw new Error("A nonempty externally retained audit checkpoint is required");
  }
  const migration = await pool.query(
    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1) AS current",
    [LATEST_SCHEMA_VERSION],
  );
  if (migration.rows[0]?.current !== true) {
    throw new Error("Recovery schema does not match this application release");
  }
  const anchored = await verifyAuditCheckpointAgainstDatabase(pool, checkpoint, publicKey);
  if (!anchored.valid) {
    throw new Error("Restored audit history does not match the externally retained checkpoint");
  }
  // This additional pass checks every restored chain, including newer unanchored chains.
  const collected = await collectAuditCheckpoint(pool);
  const totals = await pool.query(
    "SELECT (SELECT count(*) FROM organizations)::integer AS organizations, " +
    "(SELECT count(*) FROM resources)::integer AS resources, " +
    "(SELECT count(*) FROM audit_events)::integer AS audit_events",
  );
  return {
    schemaVersion: LATEST_SCHEMA_VERSION,
    anchoredChainsVerified: anchored.checkedChains,
    allRestoredChainsVerified: collected.chainHeads.length,
    ...totals.rows[0],
  };
}

async function main() {
  if (process.env.CAIAE_RECOVERY_CONFIRM !== "VERIFY_ISOLATED_RECOVERY") {
    throw new Error("Set CAIAE_RECOVERY_CONFIRM=VERIFY_ISOLATED_RECOVERY");
  }
  const url = validateRecoveryTarget(
    process.env.RECOVERY_DATABASE_URL,
    process.env.DATABASE_URL,
  );
  if (!process.env.CAIAE_RECOVERY_CHECKPOINT_FILE ||
      !process.env.CAIAE_AUDIT_VERIFYING_KEY_FILE) {
    throw new Error("Externally retained checkpoint and verifying public key file are required");
  }
  const checkpoint = JSON.parse(
    await readFile(process.env.CAIAE_RECOVERY_CHECKPOINT_FILE, "utf8"),
  );
  const publicKey = await readFile(process.env.CAIAE_AUDIT_VERIFYING_KEY_FILE, "utf8");
  const pool = createPool(url);
  try {
    const report = await verifyRecovery(pool, checkpoint, publicKey);
    console.log(JSON.stringify({ recoveryVerified: true, ...report }));
  } finally { await pool.end(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error("Recovery verification failed: " +
      (error instanceof Error ? error.message : "unknown error"));
    process.exitCode = 1;
  });
}
