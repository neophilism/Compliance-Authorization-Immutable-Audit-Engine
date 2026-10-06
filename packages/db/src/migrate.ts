import { createPool } from "./client.js";
import { runMigrations } from "./migrations.js";

const pool = createPool();

try {
  await runMigrations(pool);
  console.log("database migrations complete");
} finally {
  await pool.end();
}
