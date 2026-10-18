import test from 'node:test';
import assert from 'node:assert/strict';
import {benchmarkSync} from './benchmark-local.mjs';

test('quantiles are ordered and sample size is exact', () => {
  let calls = 0;
  const result = benchmarkSync(() => { calls++; }, {iterations: 10, warmup: 3});
  assert.equal(calls, 13);
  assert.equal(result.sampleCount, 10);
  assert.ok(0 <= result.p50Ms && result.p50Ms <= result.p95Ms && result.p95Ms <= result.p99Ms);
  assert.ok(result.p99Ms <= result.maxMs);
});
test('invalid benchmark repetition limits fail closed', () => {
  for (const iterations of [0, -1, 100001, 1.5, NaN]) {
    assert.throws(() => benchmarkSync(() => {}, {iterations}), TypeError);
  }
});
