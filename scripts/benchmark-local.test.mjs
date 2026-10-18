import test from 'node:test';
import assert from 'node:assert/strict';
import {benchmarkSync,benchmarkAsync} from './benchmark-local.mjs';
test('sync reports ordered quantiles and exact invocations',()=>{
 let calls=0;const r=benchmarkSync(()=>calls++,{iterations:10,warmup:3});
 assert.equal(calls,13);assert.equal(r.sampleCount,10);
 assert.ok(r.p50Ms<=r.p95Ms&&r.p95Ms<=r.p99Ms&&r.p99Ms<=r.maxMs);
 assert.ok(Object.isFrozen(r));
});
test('async measures completed awaited sequential operations',async()=>{
 let concurrent=0,maximum=0,calls=0;
 const r=await benchmarkAsync(async()=>{concurrent++;maximum=Math.max(maximum,concurrent);
   await Promise.resolve();calls++;concurrent--;},{iterations:7,warmup:2});
 assert.equal(calls,9);assert.equal(maximum,1);assert.equal(r.sampleCount,7);
 assert.ok(r.p50Ms<=r.p95Ms&&r.p95Ms<=r.p99Ms);
});
test('invalid repetition bounds and operations fail closed',async()=>{
 for(const iterations of [0,-1,100001,1.5,NaN]) {
  assert.throws(()=>benchmarkSync(()=>{},{iterations}),TypeError);
  await assert.rejects(benchmarkAsync(async()=>{},{iterations}),TypeError);
 }
 assert.throws(()=>benchmarkSync(null),TypeError);
 await assert.rejects(benchmarkAsync(null),TypeError);
});
test('aborted async benchmark does not produce a misleading result',async()=>{
 const controller=new AbortController();let calls=0;
 await assert.rejects(benchmarkAsync(async()=>{calls++;controller.abort();},
   {iterations:3,warmup:0,signal:controller.signal}),/aborted/);
 assert.equal(calls,1);
});
