import assert from "node:assert/strict";
import test from "node:test";
import { buildApp } from "../src/app.js";
import { benchmarkLoopbackHttp } from "../../../scripts/benchmark-loopback.mjs";

test("isolated HTTP readiness benchmark traverses the real API and PostgreSQL", async (t) => {
  if (!process.env.DATABASE_URL) {
    t.skip("isolated PostgreSQL is required");
    return;
  }

  const app = await buildApp({
    securityMode: "enforce",
    runMigrations: false,
    corsOrigins: false,
    releaseSha: "isolated-benchmark",
  });

  try {
    const origin = await app.listen({ host: "127.0.0.1", port: 0 });
    const ready = await fetch(new URL("/ready", origin), {
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(ready.status, 200);
    const body = await ready.json() as { status?: string; release?: string };
    assert.equal(body.status, "ready");
    assert.equal(body.release, "isolated-benchmark");

    const result = await benchmarkLoopbackHttp(
      new URL("/ready", origin).href,
      { iterations: 20 },
    );
    assert.equal(result.kind, "isolated-loopback-http");
    assert.equal(result.requests, 20);
    assert.equal(result.successes, 20);
    assert.equal(result.failures, 0);
    assert.equal(result.productionSloVerified, false);
    assert.ok(result.p50Ms <= result.p95Ms);
    assert.ok(result.p95Ms <= result.p99Ms);
    t.diagnostic(JSON.stringify({
      environment: "isolated-ci-api-postgresql",
      path: "/ready",
      release: "isolated-benchmark",
      ...result,
    }));

    const publicUrl = new URL("/v1/public/certifications/verify/not-a-real-code", origin);
    const publicResponse = await fetch(publicUrl, {
      redirect: "error", signal: AbortSignal.timeout(5000),
    });
    assert.equal(publicResponse.status, 200);
    await publicResponse.body?.cancel();
    const publicResult = await benchmarkLoopbackHttp(publicUrl.href, { iterations: 20 });
    assert.equal(publicResult.requests, 20);
    assert.equal(publicResult.successes, 20);
    assert.equal(publicResult.failures, 0);
    assert.equal(publicResult.productionSloVerified, false);
    t.diagnostic(JSON.stringify({
      environment: "isolated-ci-api-postgresql",
      path: publicUrl.pathname,
      release: "isolated-benchmark",
      ...publicResult,
    }));
  } finally {
    await app.close();
  }
});
