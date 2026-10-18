import test from "node:test";
import assert from "node:assert/strict";
import { benchmarkLoopbackHttp } from "./benchmark-loopback.mjs";
test("loopback-only bounded status sampling returns actual failure count",async()=>{
 let count=0;const result=await benchmarkLoopbackHttp("http://127.0.0.1:3000/health",{
  iterations:5,fetchImpl:async()=>({status:++count===3?503:200,body:{cancel:async()=>{}}})
 });
 assert.equal(result.successes,4);assert.equal(result.failures,1);
 assert.equal(result.productionSloVerified,false);
 assert.ok(result.p50Ms<=result.p95Ms&&result.p95Ms<=result.p99Ms);
});
test("external and credential-bearing targets fail closed",async()=>{
 for(const url of ["https://example.gov","http://example.gov","http://user:secret@localhost:3000"]) {
  await assert.rejects(()=>benchmarkLoopbackHttp(url),/loopback/);
 }
 await assert.rejects(()=>benchmarkLoopbackHttp("http://localhost:3000",{iterations:101}),/1-100/);
});
test("redirect status never counts as a successful sample",async()=>{
 const result=await benchmarkLoopbackHttp("http://localhost:3000/health",{
  iterations:1,fetchImpl:async()=>({status:302,body:{cancel:async()=>{}}})
 });
 assert.equal(result.successes,0);assert.equal(result.failures,1);
});
test("abort during final request cannot return a misleading successful report",async()=>{
 const controller=new AbortController();
 await assert.rejects(()=>benchmarkLoopbackHttp("http://127.0.0.1:3000/health",{
  iterations:1,signal:controller.signal,fetchImpl:async()=>{controller.abort();throw new Error("aborted");}
 }),/Benchmark aborted/);
});
