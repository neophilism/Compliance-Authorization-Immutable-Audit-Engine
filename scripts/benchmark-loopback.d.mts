export interface LoopbackBenchmarkResult {
  readonly kind: "isolated-loopback-http";
  readonly requests: number;
  readonly concurrency: number;
  readonly successes: number;
  readonly failures: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly productionSloVerified: false;
}
export function benchmarkLoopbackHttp(
  urlText: string,
  options?: { iterations?: number; concurrency?: number; signal?: AbortSignal; fetchImpl?: typeof fetch },
): Promise<LoopbackBenchmarkResult>;
