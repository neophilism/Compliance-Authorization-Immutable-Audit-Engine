import { open } from "node:fs/promises";
import { constants } from "node:fs";
import { pathToFileURL } from "node:url";

class RecoveryError extends Error {}

function targetIdentity(raw, label, direct) {
  let url;
  try {
    if (typeof raw !== "string" || /[\x00-\x20\x7f\\#]/.test(raw)) throw new Error();
    url = new URL(raw);
  } catch { throw new RecoveryError("A valid " + label + " PostgreSQL database URL is required"); }
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname ||
      url.hostname.includes("%") || !url.pathname || url.pathname === "/") {
    throw new RecoveryError(label + " must address a PostgreSQL database");
  }
  let database;
  try { database = decodeURIComponent(url.pathname.slice(1)); }
  catch { throw new RecoveryError(label + " has an invalid database name"); }
  if (!database || /[\x00-\x1f\x7f/]/.test(database) || Buffer.byteLength(database) > 63) {
    throw new RecoveryError(label + " has an invalid database name");
  }
  const allowed = new Set(["sslmode", "sslrootcert", "sslcert", "sslkey", "channel_binding", "application_name", "connect_timeout"]);
  const seen = new Set();
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key) || seen.has(key)) {
      throw new RecoveryError(label + " contains ambiguous or unsupported connection parameters");
    }
    seen.add(key);
  }
  let host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (direct && host.includes("-pooler")) {
    throw new RecoveryError("Recovery verification requires a direct, non-pooled database connection");
  }
  host = host.replace(/-pooler(?=\.)/, "");
  if (["localhost", "127.0.0.1", "[::1]"].includes(host)) host = "loopback";
  return { host, port: url.port || "5432", database };
}

export function validateRecoveryTarget(recoveryUrl, sourceUrl) {
  const target = targetIdentity(recoveryUrl, "RECOVERY_DATABASE_URL", true);
  if (sourceUrl !== undefined) {
    const source = targetIdentity(sourceUrl, "source DATABASE_URL", false);
    if (source.host === target.host && source.port === target.port && source.database === target.database) {
      throw new RecoveryError("Recovery database must not be the production/source database");
    }
  }
  return recoveryUrl;
}

export async function verifyRecovery(pool, checkpoint, publicKey, { database } = {}) {
  if (!checkpoint || !Array.isArray(checkpoint.checkpoint?.chainHeads) ||
      checkpoint.checkpoint.chainHeads.length === 0) {
    throw new RecoveryError("A nonempty externally retained audit checkpoint is required");
  }
  const db = database ?? await import("@caiae/db");
  if (!db.verifyAuditCheckpointSignature(checkpoint, publicKey)) {
    throw new RecoveryError("External audit checkpoint signature is invalid");
  }
  let client;
  let discard = false;
  try {
    client = await pool.connect();
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout = '30000ms'");
    await client.query("SET LOCAL lock_timeout = '5000ms'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '60000ms'");
    const mode = await client.query("SELECT current_setting('transaction_isolation') AS isolation, current_setting('transaction_read_only') AS read_only");
    if (mode.rows[0]?.isolation !== "repeatable read" || mode.rows[0]?.read_only !== "on") {
      throw new RecoveryError("Recovery transaction must be repeatable-read and read-only");
    }
    const migration = await client.query(
      "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1) AS current",
      [db.LATEST_SCHEMA_VERSION],
    );
    if (migration.rows[0]?.current !== true) {
      throw new RecoveryError("Recovery schema does not match this application release");
    }
    const anchored = await db.verifyAuditCheckpointAgainstDatabaseWithClient(client, checkpoint, publicKey);
    if (!anchored.valid || anchored.checkedChains !== checkpoint.checkpoint.chainHeads.length) {
      throw new RecoveryError("Restored audit history does not match the externally retained checkpoint");
    }
    // Include every restored chain, including newer unanchored chains.
    const collected = await db.collectAuditCheckpointWithClient(client);
    if (!Array.isArray(collected.chainHeads) || collected.chainHeads.length < anchored.checkedChains) {
      throw new RecoveryError("Incomplete restored audit chain evidence");
    }
    const totals = await client.query(
      "SELECT (SELECT count(*) FROM organizations)::integer AS organizations, " +
      "(SELECT count(*) FROM resources)::integer AS resources, " +
      "(SELECT count(*) FROM audit_events)::integer AS audit_events",
    );
    const counts = {};
    for (const key of ["organizations", "resources", "audit_events"]) {
      const value = totals.rows[0]?.[key];
      if (!Number.isSafeInteger(value) || value < 0) throw new RecoveryError("Invalid recovery count evidence");
      counts[key] = value;
    }
    const report = {
      schemaVersion: db.LATEST_SCHEMA_VERSION,
      anchoredChainsVerified: anchored.checkedChains,
      allRestoredChainsVerified: collected.chainHeads.length,
      ...counts,
      snapshotIsolation: "repeatable read",
      readOnly: true,
    };
    await client.query("COMMIT");
    return report;
  } catch (error) {
    if (client) {
      try { await client.query("ROLLBACK"); } catch { discard = true; }
    }
    throw new RecoveryError(error instanceof RecoveryError ? error.message : "Recovery snapshot verification failed");
  } finally { if (client) client.release(discard); }
}

export async function readRecoveryInput(path, limit) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 16777216) {
    throw new RecoveryError("Invalid recovery input byte limit");
  }
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error();
    const bytes = Buffer.alloc(limit + 1);
    let size = 0;
    while (size <= limit) {
      const { bytesRead } = await file.read(bytes, size, bytes.length - size, null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    if (size > limit) throw new Error();
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size));
  } catch { throw new RecoveryError("Recovery input must be a bounded UTF-8 regular file"); }
  finally { if (file) await file.close(); }
}

async function main() {
  if (process.env.CAIAE_RECOVERY_CONFIRM !== "VERIFY_ISOLATED_RECOVERY") {
    throw new RecoveryError("Set CAIAE_RECOVERY_CONFIRM=VERIFY_ISOLATED_RECOVERY");
  }
  const url = validateRecoveryTarget(
    process.env.RECOVERY_DATABASE_URL,
    process.env.DATABASE_URL,
  );
  if (!process.env.CAIAE_RECOVERY_CHECKPOINT_FILE ||
      !process.env.CAIAE_AUDIT_VERIFYING_KEY_FILE) {
    throw new RecoveryError("Externally retained checkpoint and verifying public key file are required");
  }
  let checkpoint;
  try { checkpoint = JSON.parse(await readRecoveryInput(process.env.CAIAE_RECOVERY_CHECKPOINT_FILE, 16777216)); }
  catch { throw new RecoveryError("External recovery checkpoint is unreadable or invalid"); }
  const publicKey = await readRecoveryInput(process.env.CAIAE_AUDIT_VERIFYING_KEY_FILE, 16384);
  const { createPool } = await import("@caiae/db");
  const pool = createPool(url);
  try {
    const report = await verifyRecovery(pool, checkpoint, publicKey);
    console.log(JSON.stringify({ recoveryVerified: true, ...report }));
  } finally { await pool.end(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error("Recovery verification failed: " +
      (error instanceof RecoveryError ? error.message : "verification could not complete"));
    process.exitCode = 1;
  });
}

