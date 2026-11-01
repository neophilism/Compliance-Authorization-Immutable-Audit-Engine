import test from "node:test";
import { createServer } from "node:http";
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
test("bounded concurrency never exceeds configured active requests",async()=>{
 let active=0,peak=0;
 const result=await benchmarkLoopbackHttp("http://127.0.0.1:3000/ready",{
  iterations:12,concurrency:3,fetchImpl:async()=>{
   active++;peak=Math.max(peak,active);
   await new Promise(resolve=>setImmediate(resolve));
   active--;return {status:200,body:{cancel:async()=>{}}};
  }
 });
 assert.equal(peak,3);assert.equal(result.concurrency,3);
 assert.equal(result.requests,12);assert.equal(result.successes,12);
 await assert.rejects(()=>benchmarkLoopbackHttp("http://localhost:3000",{
  iterations:2,concurrency:3
 }),/Concurrency/);
});
test("real loopback transport counts redirect and server errors without following",async()=>{
 let calls=0;
 const server=createServer((_request,response)=>{
  calls++;
  if(calls===1) {response.writeHead(302,{location:"https://example.invalid/"});response.end();return;}
  response.writeHead(calls===3?503:200,{"content-type":"application/json"});
  response.end("{}");
 });
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 try {
  const address=server.address();
  assert.ok(address && typeof address!=="string");
  const result=await benchmarkLoopbackHttp(
   `http://127.0.0.1:${address.port}/ready`,{iterations:3}
  );
  assert.equal(calls,3);
  assert.equal(result.successes,1);
  assert.equal(result.failures,2);
 } finally {
  server.closeAllConnections();
  await new Promise(resolve=>server.close(resolve));
 }
});
