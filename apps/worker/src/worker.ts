import { AuthorizationService } from "@caiae/authorization";
import { createPool, runMigrations } from "@caiae/db";

const intervalMs = Number(
  process.env.AUTHORIZATION_SWEEP_MS ?? 30_000,
);

if (!Number.isFinite(intervalMs) || intervalMs < 1_000) {
  throw new Error(
    "AUTHORIZATION_SWEEP_MS must be a number of at least 1000",
  );
}

const pool = createPool();
await runMigrations(pool);
const authorizations = new AuthorizationService(pool);
let sweepRunning = false;

async function sweep(): Promise<void> {
  if (sweepRunning) return;
  sweepRunning = true;

  try {
    const result = await authorizations.expireDue(new Date());

    console.log(
      JSON.stringify({
        event: "authorization.expiration_sweep",
        at: new Date().toISOString(),
        ...result,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "authorization.expiration_sweep_failed",
        at: new Date().toISOString(),
        message:
          error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    sweepRunning = false;
  }
}

console.log(
  JSON.stringify({
    event: "compliance_worker.started",
    at: new Date().toISOString(),
    authorizationSweepMs: intervalMs,
  }),
);

await sweep();
const timer = setInterval(() => {
  void sweep();
}, intervalMs);

async function shutdown(signal: string): Promise<void> {
  clearInterval(timer);
  console.log(
    JSON.stringify({
      event: "compliance_worker.stopping",
      signal,
      at: new Date().toISOString(),
    }),
  );
  await pool.end();
  process.exit(0);
}

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});
