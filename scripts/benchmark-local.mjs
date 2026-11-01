import { performance } from 'node:perf_hooks';
/** Local-only measurements, never evidence of API/database production SLOs. */
function validate(iterations,warmup) {
  if (![iterations,warmup].every(Number.isSafeInteger) || iterations < 1 ||
      iterations > 100000 || warmup < 0 || warmup > 100000)
    throw new TypeError('Invalid benchmark repetitions');
}
function report(durations) {
  durations.sort((a,b)=>a-b);
  const quantile = p => durations[Math.min(durations.length-1,Math.ceil(p*durations.length)-1)];
  return Object.freeze({sampleCount:durations.length,p50Ms:quantile(.5),p95Ms:quantile(.95),
    p99Ms:quantile(.99),maxMs:durations.at(-1)});
}
export function benchmarkSync(operation,{iterations=500,warmup=50}={}) {
  if(typeof operation!=='function') throw new TypeError('Operation must be a function');
  validate(iterations,warmup);
  for(let i=0;i<warmup;i++) operation();
  const durations=[];
  for(let i=0;i<iterations;i++) {const t=performance.now();operation();durations.push(performance.now()-t);}
  return report(durations);
}
/** Sequential awaited workload isolates service duration from concurrent load. */
export async function benchmarkAsync(operation,{iterations=100,warmup=10,signal}={}) {
  if(typeof operation!=='function') throw new TypeError('Operation must be a function');
  validate(iterations,warmup);
  const run=async()=>{if(signal?.aborted)throw new Error('Benchmark aborted');await operation();};
  for(let i=0;i<warmup;i++)await run();
  const durations=[];
  for(let i=0;i<iterations;i++){if(signal?.aborted)throw new Error('Benchmark aborted');
    const t=performance.now();await operation();durations.push(performance.now()-t);}
  return report(durations);
}
if(process.argv[1]?.endsWith('benchmark-local.mjs')) {
  const result=benchmarkSync(()=>JSON.parse(JSON.stringify({component:'CAIAE',version:1})));
  process.stdout.write(JSON.stringify({kind:'synthetic-local',workload:'JSON roundtrip (not database or API)',...result})+'\n');
}
