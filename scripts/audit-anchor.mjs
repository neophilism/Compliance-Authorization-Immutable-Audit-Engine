import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { createPool, collectAuditCheckpoint, signAuditCheckpoint,
  verifyAuditCheckpointAgainstDatabase } from "@caiae/db";

function exportPath(raw) {
  if (!raw || !path.isAbsolute(raw)) {
    throw new Error("An absolute checkpoint file path is required");
  }
  const resolved = path.resolve(raw);
  const inCheckout = path.relative(process.cwd(), resolved);
  if (!inCheckout.startsWith("..") && !path.isAbsolute(inCheckout)) {
    throw new Error("Checkpoint file must be outside the Git checkout");
  }
  return resolved;
}

async function main() {
  const [command, rawFile] = process.argv.slice(2);
  if (command !== "create" && command !== "verify") {
    throw new Error("Usage: node scripts/audit-anchor.mjs create|verify /absolute/external/path.json");
  }
  const file = exportPath(rawFile);
  const databaseUrl = process.env.DATABASE_URL_UNPOOLED;
  if (!databaseUrl) throw new Error("DATABASE_URL_UNPOOLED is required");
  const pool = createPool(databaseUrl);
  try {
    if (command === "create") {
      if (!process.env.CAIAE_AUDIT_SIGNING_KEY_FILE || !process.env.CAIAE_AUDIT_KEY_ID) {
        throw new Error("CAIAE_AUDIT_SIGNING_KEY_FILE and CAIAE_AUDIT_KEY_ID are required");
      }
      const signingKey = await readFile(process.env.CAIAE_AUDIT_SIGNING_KEY_FILE, "utf8");
      const checkpoint = await collectAuditCheckpoint(pool);
      const signed = signAuditCheckpoint(checkpoint, signingKey, process.env.CAIAE_AUDIT_KEY_ID);
      await writeFile(file, JSON.stringify(signed, null, 2) + "\n", { flag: "wx", mode: 0o600 });
      console.log(JSON.stringify({ created: true, chains: checkpoint.chainHeads.length, file }));
    } else {
      if (!process.env.CAIAE_AUDIT_VERIFYING_KEY_FILE) {
        throw new Error("CAIAE_AUDIT_VERIFYING_KEY_FILE is required");
      }
      const key = await readFile(process.env.CAIAE_AUDIT_VERIFYING_KEY_FILE, "utf8");
      const signed = JSON.parse(await readFile(file, "utf8"));
      const verdict = await verifyAuditCheckpointAgainstDatabase(pool, signed, key);
      console.log(JSON.stringify({ file, ...verdict }));
      if (!verdict.valid) process.exitCode = 1;
    }
  } finally {
    await pool.end();
  }
}

main().catch(error => {
  console.error("Audit anchoring failed: " + (error instanceof Error ? error.message : "unknown error"));
  process.exitCode = 1;
});
