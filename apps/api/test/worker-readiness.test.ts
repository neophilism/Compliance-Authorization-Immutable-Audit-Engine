import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool, runMigrations, WORKER_SWEEP_NAMES,
  startWorkerActivity, recordWorkerSweep,
} from "@caiae/db";
import { buildApp } from "../src/app.js";

test("full readiness fails closed when scheduled worker is unhealthy", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  await runMigrations(pool);
  const app = await buildApp({ securityMode: "enforce", runMigrations: false, releaseSha: "api-test-sha" });
  const instanceId = randomUUID();
  try {
    await startWorkerActivity(pool, instanceId, "api-test-sha");
    const basic = await app.inject({ method: "GET", url: "/ready" });
    assert.equal(basic.statusCode, 200, basic.body);
    const incomplete = await app.inject({ method: "GET", url: "/ready?includeWorker=true" });
    assert.equal(incomplete.statusCode, 503, incomplete.body);
    assert.equal(incomplete.json().reason, "worker_unhealthy");
    for (const name of WORKER_SWEEP_NAMES) {
      await recordWorkerSweep(pool, { instanceId, name, succeeded: true });
    }
    const ready = await app.inject({ method: "GET", url: "/ready?includeWorker=true" });
    assert.equal(ready.statusCode, 200, ready.body);
    await recordWorkerSweep(pool, { instanceId, name: "webhook", succeeded: false });
    const failed = await app.inject({ method: "GET", url: "/ready?includeWorker=true" });
    assert.equal(failed.statusCode, 503, failed.body);
    assert.equal(failed.json().reason, "worker_unhealthy");
    assert.equal((await app.inject({ method: "GET", url: "/ready" })).statusCode, 200);
  } finally { await app.close(); await pool.end(); }
});
