import test from "node:test";
import assert from "node:assert/strict";
import { sampleReleaseReadiness } from "./benchmark-release.mjs";

const sha = "a".repeat(40);
const ready = release => new Response(JSON.stringify({
  status: "ready", release,
}), { status: 200, headers: { "content-type": "application/json" } });

test("release pinned samples require exact SHA and omit credentials", async () => {
  const requests = [];
  const report = await sampleReleaseReadiness({
    baseUrl: "https://api.example.gov",
    expectedRelease: sha,
    iterations: 3,
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return ready(sha);
    },
  });
  assert.equal(report.successes, 3);
  assert.equal(report.failures, 0);
  assert.equal(report.productionSloVerified, false);
  assert.ok(report.p50Ms <= report.p95Ms && report.p95Ms <= report.p99Ms);
  assert.equal(requests.length, 3);
  for (const request of requests) {
    assert.equal(request.url, "https://api.example.gov/ready");
    assert.equal(request.options.method, "GET");
    assert.equal(request.options.redirect, "error");
    assert.equal(request.options.credentials, "omit");
    assert.equal(request.options.headers.authorization, undefined);
  }
});

test("wrong release, unavailable readiness and oversized body count as failures", async () => {
  let count = 0;
  const report = await sampleReleaseReadiness({
    baseUrl: "http://127.0.0.1:3000",
    expectedRelease: sha,
    iterations: 3,
    fetchImpl: async () => {
      count++;
      if (count === 1) return ready("b".repeat(40));
      if (count === 2) return new Response("unavailable", { status: 503 });
      return new Response("x".repeat(16385), { status: 200 });
    },
  });
  assert.equal(report.successes, 0);
  assert.equal(report.failures, 3);
});

test("invalid target, release identity and sample count fail before requests", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return ready(sha); };
  for (const input of [
    { baseUrl: "http://api.example.gov", expectedRelease: sha },
    { baseUrl: "https://user:secret@api.example.gov", expectedRelease: sha },
    { baseUrl: "https://api.example.gov", expectedRelease: "short" },
    { baseUrl: "https://api.example.gov", expectedRelease: sha, iterations: 21 },
  ]) {
    await assert.rejects(() => sampleReleaseReadiness({ ...input, fetchImpl }));
  }
  assert.equal(calls, 0);
});
