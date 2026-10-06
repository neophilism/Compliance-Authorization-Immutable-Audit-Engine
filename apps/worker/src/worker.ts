import { AuthorizationService } from "@caiae/authorization";
import { createPool, runMigrations } from "@caiae/db";
import { ExceptionService } from "@caiae/exceptions";

const authorizationSweepMs = Number(
  process.env.AUTHORIZATION_SWEEP_MS ?? 30_000,
);
const exceptionSweepMs = Number(
  process.env.EXCEPTION_SWEEP_MS ?? 30_000,
);

for (const [name, value] of [
  ["AUTHORIZATION_SWEEP_MS", authorizationSweepMs],
  ["EXCEPTION_SWEEP_MS", exceptionSweepMs],
] as const) {
  if (!Number.isFinite(value) || value < 1_000) {
    throw new Error(
      `${name} must be a number of at least 1000`,
    );
  }
}

const pool = createPool();
await runMigrations(pool);

const authorizations = new AuthorizationService(pool);
const exceptions = new ExceptionService(pool);

let authorizationSweepRunning = false;
let exceptionSweepRunning = false;

async function sweepAuthorizations(): Promise<void> {
  if (authorizationSweepRunning) return;
  authorizationSweepRunning = true;

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
    authorizationSweepRunning = false;
  }
}

async function sweepExceptions(): Promise<void> {
  if (exceptionSweepRunning) return;
  exceptionSweepRunning = true;

  try {
    const result = await exceptions.expireDue(new Date());

    console.log(
      JSON.stringify({
        event: "exception.expiration_sweep",
        at: new Date().toISOString(),
        ...result,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "exception.expiration_sweep_failed",
        at: new Date().toISOString(),
        message:
          error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    exceptionSweepRunning = false;
  }
}

console.log(
  JSON.stringify({
    event: "compliance_worker.started",
    at: new Date().toISOString(),
    authorizationSweepMs,
    exceptionSweepMs,
  }),
);

await Promise.all([
  sweepAuthorizations(),
  sweepExceptions(),
]);

const authorizationTimer = setInterval(() => {
  void sweepAuthorizations();
}, authorizationSweepMs);

const exceptionTimer = setInterval(() => {
  void sweepExceptions();
}, exceptionSweepMs);

async function shutdown(signal: string): Promise<void> {
  clearInterval(authorizationTimer);
  clearInterval(exceptionTimer);

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
