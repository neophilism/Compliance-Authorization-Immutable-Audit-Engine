import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
/** Bounded, credential-free loopback probe; never a production SLO claim. */
export async function benchmarkLoopbackHttp(urlText, options = {}) {
  const url = new URL(urlText);
  if (url.protocol !== "http:" ||
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      url.username || url.password || url.hash) {
    throw new Error("Benchmark requires credential-free HTTP loopback target");
  }
  const iterations = options.iterations ?? 10;
  const concurrency = options.concurrency ?? 1;
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 100) {
    throw new Error("Iterations must be 1-100");
  }
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 ||
      concurrency > 8 || concurrency > iterations) {
    throw new Error("Concurrency must be 1-8 and no more than iterations");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const samples = [];
  let successes = 0, failures = 0, next = 0;
  const sample = async () => {
    if (options.signal?.aborted) throw new Error("Benchmark aborted");
    const begin = performance.now();
    try {
      const signal = options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(2000)])
        : AbortSignal.timeout(2000);
      const response = await fetchImpl(url, {
        method: "GET", redirect: "error", signal,
      });
      await response.body?.cancel?.();
      if (response.status >= 200 && response.status < 300) successes++;
      else failures++;
    } catch {
      if (options.signal?.aborted) throw new Error("Benchmark aborted");
      failures++;
    }
    if (options.signal?.aborted) throw new Error("Benchmark aborted");
    samples.push(performance.now() - begin);
  };
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next < iterations) {
      next++;
      await sample();
    }
  }));
  samples.sort((a, b) => a - b);
  const percentile = fraction => samples[Math.ceil(fraction * samples.length) - 1];
  return Object.freeze({
    kind: "isolated-loopback-http", requests: iterations, concurrency,
    successes, failures, p50Ms: percentile(.5), p95Ms: percentile(.95),
    p99Ms: percentile(.99), productionSloVerified: false,
  });
}

// Explicit opt-in, loopback-only CLI; argument values never become request headers.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [url, iterations, concurrency] = process.argv.slice(2);
  benchmarkLoopbackHttp(url, {
    iterations: iterations === undefined ? undefined : Number(iterations),
    concurrency: concurrency === undefined ? undefined : Number(concurrency),
  }).then(report => console.log(JSON.stringify(report))).catch(error => {
    console.error(error instanceof Error ? error.message : "Benchmark failed");
    process.exitCode = 1;
  });
}
