import { performance } from "node:perf_hooks";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { deploymentBaseUrl } from "./verify-deployment.mjs";

async function boundedWait(promise, signal) {
  if (signal.aborted) throw new Error("Benchmark request timed out");
  let onAbort;
  const abort = new Promise((_, reject) => {
    onAbort = () => reject(new Error("Benchmark request timed out"));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try { return await Promise.race([promise, abort]); }
  finally { signal.removeEventListener("abort", onAbort); }
}

async function boundedJson(response, signal) {
  const mediaType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase();
  if (!mediaType || !/^application\\/(?:json|[a-z0-9!#async function boundedJson(response, signal) {
  if (!response.body) throw new Error("Missing response body");^_.+-]+\\+json)$/u.test(mediaType)) {
    throw new Error("Expected JSON benchmark response");
  }
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\\d+$/u.test(length) ||
      !Number.isSafeInteger(Number(length)) || Number(length) > 16384)) {
    throw new Error("Invalid benchmark content length");
  }
  if (!response.body) throw new Error("Missing response body");
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await boundedWait(reader.read(), signal);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 16384) throw new Error("Response body exceeds limit");
      chunks.push(value);
    }
  } finally {
    if (bytes > 16384 || signal.aborted) void reader.cancel().catch(() => {});
    try { reader.releaseLock(); } catch { /* pending read cancelled */ }
  }
  const data = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
}

/** Low-volume deployment readiness sample, never a production SLO verdict. */
export async function sampleReleaseReadiness({
  baseUrl, expectedRelease, iterations = 10, timeoutMs = 5000, fetchImpl = fetch,
}) {
  const origin = deploymentBaseUrl(baseUrl);
  if (typeof expectedRelease !== "string" || !/^[0-9a-f]{40}$/i.test(expectedRelease)) {
    throw new Error("A full expected release commit SHA is required");
  }
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 20) {
    throw new Error("Iterations must be 1-20");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) {
    throw new Error("Invalid benchmark timeout");
  }
  const samples = [];
  let successes = 0, failures = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    try {
      const signal = AbortSignal.timeout(timeoutMs);
      const requestUrl = origin + "/ready";
      const response = await boundedWait(fetchImpl(requestUrl, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        signal,
      }), signal);
      if (response.redirected || (response.url && response.url !== requestUrl)) {
        throw new Error("Redirected benchmark response");
      }
      if (response.status !== 200) {
        await response.body?.cancel?.();
        failures++;
      } else {
        const payload = await boundedJson(response, signal);
        if (payload?.status === "ready" && payload?.release === expectedRelease) {
          successes++;
        } else {
          failures++;
        }
      }
    } catch {
      failures++;
    }
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  const percentile = fraction => samples[Math.ceil(fraction * samples.length) - 1];
  return Object.freeze({
    kind: "release-pinned-readiness-sample",
    origin, expectedRelease, requests: iterations, successes, failures,
    p50Ms: percentile(.5), p95Ms: percentile(.95), p99Ms: percentile(.99),
    productionSloVerified: false,
  });
}

/** Low-volume public database lookup with release identity checked before and after. */
export async function sampleReleasePublicLookup({
  baseUrl, expectedRelease, iterations = 10, timeoutMs = 5000, fetchImpl = fetch,
}) {
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 20) {
    throw new Error("Iterations must be 1-20");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) {
    throw new Error("Invalid benchmark timeout");
  }
  const before = await sampleReleaseReadiness({
    baseUrl, expectedRelease, iterations: 1, timeoutMs, fetchImpl,
  });
  if (before.failures) throw new Error("Release readiness preflight failed");
  const path = "/v1/public/certifications/verify/benchmark-" + randomUUID();
  const samples = [];
  let successes = 0, failures = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    try {
      const signal = AbortSignal.timeout(timeoutMs);
      const requestUrl = before.origin + path;
      const response = await boundedWait(fetchImpl(requestUrl, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        signal,
      }), signal);
      if (response.redirected || (response.url && response.url !== requestUrl)) {
        throw new Error("Redirected benchmark response");
      }
      if (response.status !== 200) {
        await response.body?.cancel?.();
        failures++;
      } else {
        const payload = await boundedJson(response, signal);
        if (payload?.found === false && payload?.valid === false &&
            payload?.certificationId === null && payload?.publicArtifact === null) {
          successes++;
        } else {
          failures++;
        }
      }
    } catch {
      failures++;
    }
    samples.push(performance.now() - start);
  }
  const after = await sampleReleaseReadiness({
    baseUrl, expectedRelease, iterations: 1, timeoutMs, fetchImpl,
  });
  if (after.failures) throw new Error("Release readiness postflight failed");
  samples.sort((a, b) => a - b);
  const percentile = fraction => samples[Math.ceil(fraction * samples.length) - 1];
  return Object.freeze({
    kind: "release-pinned-public-db-sample",
    origin: before.origin, expectedRelease, requests: iterations,
    successes, failures, p50Ms: percentile(.5), p95Ms: percentile(.95),
    p99Ms: percentile(.99), productionSloVerified: false,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const workload = process.env.CAIAE_BENCH_WORKLOAD ?? "ready";
  if (!["ready", "public-db"].includes(workload)) {
    console.error("CAIAE_BENCH_WORKLOAD must be ready or public-db");
    process.exitCode = 1;
  }
  const sampler = workload === "public-db"
    ? sampleReleasePublicLookup : sampleReleaseReadiness;
  if (process.exitCode !== 1) sampler({
    baseUrl: process.env.CAIAE_BENCH_API_URL,
    expectedRelease: process.env.CAIAE_BENCH_EXPECTED_RELEASE,
    iterations: process.env.CAIAE_BENCH_ITERATIONS === undefined
      ? 10 : Number(process.env.CAIAE_BENCH_ITERATIONS),
  }).then(report => {
    console.log(JSON.stringify(report));
    if (report.failures) process.exitCode = 1;
  }).catch(error => {
    console.error(error instanceof Error ? error.message : "Readiness sampling failed");
    process.exitCode = 1;
  });
}
