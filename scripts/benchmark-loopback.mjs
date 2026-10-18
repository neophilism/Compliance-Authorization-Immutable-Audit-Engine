import { performance } from "node:perf_hooks";
/** Isolated loopback HTTP performance probe only; never a production stress tool. */
export async function benchmarkLoopbackHttp(urlText, options = {}) {
  const url = new URL(urlText);
  if (url.protocol !== "http:" || !["localhost","127.0.0.1","[::1]"].includes(url.hostname) ||
      url.username || url.password || url.hash) {
    throw new Error("Benchmark requires credential-free HTTP loopback target");
  }
  const iterations = options.iterations ?? 10;
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 100) {
    throw new Error("Iterations must be 1-100");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const samples = [];
  let successes=0, failures=0;
  for (let i=0;i<iterations;i++) {
    if (options.signal?.aborted) throw new Error("Benchmark aborted");
    const begin=performance.now();
    try {
      const response=await fetchImpl(url, {
        method:"GET", redirect:"error", signal:AbortSignal.timeout(2000)
      });
      await response.body?.cancel?.();
      if (response.status>=200 && response.status<400) successes++;
      else failures++;
    } catch {
      failures++;
    }
    samples.push(performance.now()-begin);
  }
  samples.sort((a,b)=>a-b);
  const percentile = fraction => samples[Math.ceil(fraction*samples.length)-1];
  return Object.freeze({kind:"isolated-loopback-http",requests:iterations,
    successes,failures,p50Ms:percentile(.5),p95Ms:percentile(.95),
    p99Ms:percentile(.99),productionSloVerified:false});
}
