import { performance } from 'node:perf_hooks';
import { writeFileSync } from 'node:fs';

/**
 * Repeatable local workload harness, NOT production latency evidence.
 * CI should compare saved observations over time rather than assuming
 * these synthetic numbers are measured customer SLOs.
 */
export function benchmarkSync(operation, {iterations = 500, warmup = 50} = {}) {
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 100000 ||
      !Number.isSafeInteger(warmup) || warmup < 0 || warmup > 100000) {
    throw new TypeError('Invalid benchmark repetitions');
  }
  for (let i = 0; i < warmup; i++) operation();
  const durations = [];
  for (let i = 0; i < iterations; i++) {
    const before = performance.now();
    operation();
    durations.push(performance.now() - before);
  }
  durations.sort((a, b) => a - b);
  const quantile = p => durations[Math.min(durations.length - 1, Math.ceil(p * durations.length) - 1)];
  return {sampleCount: iterations, p50Ms: quantile(0.50), p95Ms: quantile(0.95), p99Ms: quantile(0.99), maxMs: durations.at(-1)};
}

if (process.argv[1]?.endsWith('benchmark-local.mjs')) {
  const result = benchmarkSync(() => {
    const x = JSON.stringify({component: 'CAIAE', action: 'local-json-roundtrip', version: 1});
    JSON.parse(x);
  });
  process.stdout.write(JSON.stringify({kind: 'synthetic-local', workload: 'JSON roundtrip (not database or API)', ...result}) + '\n');
}
