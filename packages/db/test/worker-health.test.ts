import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool, runMigrations, WORKER_SWEEP_NAMES,
  startWorkerActivity, recordWorkerSweep, assessWorkerHealth,
} from "../src/index.js";

test("worker heartbeats require fresh results from all six sweeps", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  try {
    await runMigrations(pool);
    const instanceId = randomUUID();
    await startWorkerActivity(pool, instanceId, "commit-1");
    assert.deepEqual(await assessWorkerHealth(pool, 180000, "commit-1"), { healthy: false, reason: "incomplete" });
    for (const name of WORKER_SWEEP_NAMES) {
      await recordWorkerSweep(pool, { instanceId, name, succeeded: true });
    }
    assert.deepEqual(await assessWorkerHealth(pool, 180000, "commit-1"), { healthy: true });
    assert.deepEqual(await assessWorkerHealth(pool, 180000, "commit-2"), { healthy: false, reason: "release_mismatch" });
    await recordWorkerSweep(pool, { instanceId, name: "deadline", succeeded: false });
    assert.deepEqual(await assessWorkerHealth(pool, 180000, "commit-1"), { healthy: false, reason: "failed" });
    await recordWorkerSweep(pool, { instanceId, name: "deadline", succeeded: true });
    await pool.query("UPDATE worker_activity SET last_seen_at = now() - interval '10 minutes'");
    assert.deepEqual(await assessWorkerHealth(pool, 180000, "commit-1"), { healthy: false, reason: "stale" });
    await startWorkerActivity(pool, randomUUID(), "commit-2");
    await assert.rejects(
      recordWorkerSweep(pool, { instanceId, name: "webhook", succeeded: true }),
      /no longer owns/,
    );
  } finally { await pool.end(); }
});
