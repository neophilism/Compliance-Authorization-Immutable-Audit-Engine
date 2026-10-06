import { AuditLedger } from "./audit.js";
import { createPool } from "./client.js";
import { runMigrations } from "./migrations.js";

const [organizationId, aggregateType, aggregateId] = process.argv.slice(2);

if (!organizationId || !aggregateType || !aggregateId) {
  console.error(
    "usage: npm run audit:verify -w @caiae/db -- <organizationId> <aggregateType> <aggregateId>",
  );
  process.exitCode = 2;
} else {
  const pool = createPool();
  try {
    await runMigrations(pool);
    const result = await new AuditLedger(pool).verify(
      organizationId,
      aggregateType,
      aggregateId,
    );

    console.log(JSON.stringify(result, null, 2));
    if (!result.valid) {
      process.exitCode = 1;
    }
  } finally {
    await pool.end();
  }
}
