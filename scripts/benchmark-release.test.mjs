import test from "node:test";
import assert from "node:assert/strict";
import { sampleReleaseReadiness, sampleReleasePublicLookup } from "./benchmark-release.mjs";

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
test("benchmark cancels stalled headers and body reads", async () => {
  const options = { baseUrl: "https://api.example.gov", expectedRelease: sha,
    iterations: 1, timeoutMs: 20 };
  const start = Date.now();
  const pending = await sampleReleaseReadiness({
    ...options, fetchImpl: () => new Promise(() => {}),
  });
  assert.equal(pending.failures, 1);
  let cancelled = false;
  const stream = new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancelled = true; },
  });
  const stalled = await sampleReleaseReadiness({ ...options,
    fetchImpl: async () => new Response(stream, { status: 200 }),
  });
  assert.equal(stalled.failures, 1);
  assert.equal(cancelled, true);
  assert.ok(Date.now() - start < 3000);
});

test("benchmark rejects substituted response locations", async () => {
  const response = ready(sha);
  Object.defineProperty(response, "url", { value: "https://other.example.gov/ready" });
  const report = await sampleReleaseReadiness({
    baseUrl: "https://api.example.gov", expectedRelease: sha,
    iterations: 1, fetchImpl: async () => response,
  });
  assert.equal(report.failures, 1);
});

test("non-JSON or excessive length cannot count as readiness", async () => {
  const invalid = await sampleReleaseReadiness({
    baseUrl: "https://api.example.gov", expectedRelease: sha, iterations: 2,
    fetchImpl: async (_url, options) => {
      if (options.signal.aborted) throw new Error("aborted");
      return new Response(JSON.stringify({ status: "ready", release: sha }), {
        status: 200, headers: { "content-type": "text/html", "content-length": "50000" },
      });
    },
  });
  assert.equal(invalid.successes, 0);
  assert.equal(invalid.failures, 2);
});

test("public database read is pinned by readiness before and after", async () => {
 const urls = [];
 const report = await sampleReleasePublicLookup({
  baseUrl:"https://api.example.gov",expectedRelease:sha,iterations:2,
  fetchImpl:async url=>{
   urls.push(url);
   if(url.endsWith("/ready")) return ready(sha);
   return new Response(JSON.stringify({
    found:false,valid:false,certificationId:null,publicArtifact:null
   }),{status:200,headers:{"content-type":"application/json"}});
  }
 });
 assert.equal(urls.length,4);
 assert.ok(urls[0].endsWith("/ready")&&urls[3].endsWith("/ready"));
 assert.ok(urls[1].includes("/v1/public/certifications/verify/benchmark-"));
 assert.equal(report.successes,2);assert.equal(report.failures,0);
 assert.equal(report.productionSloVerified,false);
});
test("public lookup fails on changed release or unexpectedly found certificate",async()=>{
 let count=0;
 await assert.rejects(()=>sampleReleasePublicLookup({
  baseUrl:"https://api.example.gov",expectedRelease:sha,iterations:1,
  fetchImpl:async url=>{
   count++;
   if(url.endsWith("/ready"))return ready(count===3?"b".repeat(40):sha);
   return new Response(JSON.stringify({
    found:false,valid:false,certificationId:null,publicArtifact:null
   }),{status:200,headers:{"content-type":"application/json"}});
  }
 }),/postflight/);
 const report=await sampleReleasePublicLookup({
  baseUrl:"https://api.example.gov",expectedRelease:sha,iterations:1,
  fetchImpl:async url=>url.endsWith("/ready")?ready(sha):
   new Response(JSON.stringify({found:true,valid:true,certificationId:"unexpected",publicArtifact:{}}),
    {status:200}),
 });
 assert.equal(report.successes,0);assert.equal(report.failures,1);
});
