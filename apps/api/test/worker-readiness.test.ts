import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  createPool, runMigrations, WORKER_SWEEP_NAMES,
  startWorkerActivity, recordWorkerSweep,
} from "@caiae/db";
import { buildApp } from "../src/app.js";

test("full readiness and production monitor fail closed when scheduled worker is unhealthy", async () => {
  if (!process.env.DATABASE_URL) return;
  const pool = createPool();
  await runMigrations(pool);
  const releaseSha = "a".repeat(40);
  const app = await buildApp({ securityMode: "enforce", runMigrations: false, releaseSha });
  const instanceId = randomUUID();
  try {
    const monitorUrl = new URL("../../../scripts/engine-room-monitor.mjs", import.meta.url);
    const { probeApi } = await import(monitorUrl.href);
    const sampleWorker = () => probeApi("https://isolated-api.example", {
      count: 1, expectedRelease: releaseSha,
      fetchImpl: async (raw: string) => {
        const url = new URL(raw);
        assert.equal(url.pathname + url.search, "/ready?includeWorker=true");
        const response = await app.inject({ method: "GET", url: url.pathname + url.search });
        return new Response(response.body, { status: response.statusCode,
          headers: { "content-type": String(response.headers["content-type"]) } });
      },
    });
    await startWorkerActivity(pool, instanceId, releaseSha);
    const basic = await app.inject({ method: "GET", url: "/ready" });
    assert.equal(basic.statusCode, 200, basic.body);
    const incomplete = await app.inject({ method: "GET", url: "/ready?includeWorker=true" });
    assert.equal(incomplete.statusCode, 503, incomplete.body);
    assert.equal(incomplete.json().reason, "worker_unhealthy");
    assert.equal((await sampleWorker()).success, 0);
    for (const name of WORKER_SWEEP_NAMES) {
      await recordWorkerSweep(pool, { instanceId, name, succeeded: true });
    }
    const ready = await app.inject({ method: "GET", url: "/ready?includeWorker=true" });
    assert.equal(ready.statusCode, 200, ready.body);
    const healthySample = await sampleWorker();
    assert.equal(healthySample.success, 1);
    assert.equal(healthySample.release, releaseSha);
    await recordWorkerSweep(pool, { instanceId, name: "webhook", succeeded: false });
    const failed = await app.inject({ method: "GET", url: "/ready?includeWorker=true" });
    assert.equal(failed.statusCode, 503, failed.body);
    assert.equal(failed.json().reason, "worker_unhealthy");
    assert.equal((await sampleWorker()).success, 0);
    assert.equal((await app.inject({ method: "GET", url: "/ready" })).statusCode, 200);
  } finally { await app.close(); await pool.end(); }
});

