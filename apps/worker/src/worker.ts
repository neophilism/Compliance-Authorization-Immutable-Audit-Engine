const intervalMs = Number(process.env.WORKER_HEARTBEAT_MS ?? 30000);

console.log("compliance worker started");

setInterval(() => {
  console.log(JSON.stringify({ event: "worker.heartbeat", at: new Date().toISOString() }));
}, intervalMs);
