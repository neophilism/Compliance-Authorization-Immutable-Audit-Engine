import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { deploymentBaseUrl } from "./verify-deployment.mjs";

async function boundedJson(response) {
  if (!response.body) throw new Error("Missing response body");
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 16384) throw new Error("Response body exceeds limit");
      chunks.push(value);
    }
  } finally {
    if (bytes > 16384) await reader.cancel().catch(() => {});
    reader.releaseLock();
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
  baseUrl, expectedRelease, iterations = 10, fetchImpl = fetch,
}) {
  const origin = deploymentBaseUrl(baseUrl);
  if (typeof expectedRelease !== "string" || !/^[0-9a-f]{40}$/i.test(expectedRelease)) {
    throw new Error("A full expected release commit SHA is required");
  }
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 20) {
    throw new Error("Iterations must be 1-20");
  }
  const samples = [];
  let successes = 0, failures = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    try {
      const response = await fetchImpl(origin + "/ready", {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        signal: AbortSignal.timeout(5000),
      });
      if (response.status !== 200) {
        await response.body?.cancel?.();
        failures++;
      } else {
        const payload = await boundedJson(response);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  sampleReleaseReadiness({
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
