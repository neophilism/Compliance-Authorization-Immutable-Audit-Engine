import { AuthorizationService } from "@caiae/authorization";
import { CertificationService } from "@caiae/certifications";
import { createPool, runMigrations } from "@caiae/db";
import { DeadlineService } from "@caiae/deadlines";
import { EvaluationService } from "@caiae/evaluations";
import { IntegrationService } from "@caiae/integrations";
import { ExceptionService } from "@caiae/exceptions";

const authorizationSweepMs = Number(
  process.env.AUTHORIZATION_SWEEP_MS ?? 30_000,
);
const exceptionSweepMs = Number(
  process.env.EXCEPTION_SWEEP_MS ?? 30_000,
);
const deadlineSweepMs = Number(
  process.env.DEADLINE_SWEEP_MS ?? 30_000,
);
const evaluationSweepMs = Number(
  process.env.EVALUATION_SWEEP_MS ?? 30_000,
);
const certificationSweepMs = Number(
  process.env.CERTIFICATION_SWEEP_MS ?? 30_000,
);
const webhookSweepMs = Number(
  process.env.WEBHOOK_SWEEP_MS ?? 30_000,
);

for (const [name, value] of [
  ["AUTHORIZATION_SWEEP_MS", authorizationSweepMs],
  ["EXCEPTION_SWEEP_MS", exceptionSweepMs],
  ["DEADLINE_SWEEP_MS", deadlineSweepMs],
  ["EVALUATION_SWEEP_MS", evaluationSweepMs],
  ["CERTIFICATION_SWEEP_MS", certificationSweepMs],
  ["WEBHOOK_SWEEP_MS", webhookSweepMs],
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
const deadlines = new DeadlineService(pool);
const evaluations = new EvaluationService(pool);
const certifications = new CertificationService(pool);
const integrations = new IntegrationService(pool);

let authorizationSweepRunning = false;
let exceptionSweepRunning = false;
let deadlineSweepRunning = false;
let evaluationSweepRunning = false;
let certificationSweepRunning = false;
let webhookSweepRunning = false;

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

async function sweepDeadlines(): Promise<void> {
  if (deadlineSweepRunning) return;
  deadlineSweepRunning = true;

  try {
    const result = await deadlines.sweep(new Date());

    console.log(
      JSON.stringify({
        event: "deadline.clock_sweep",
        at: new Date().toISOString(),
        ...result,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "deadline.clock_sweep_failed",
        at: new Date().toISOString(),
        message:
          error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    deadlineSweepRunning = false;
  }
}

async function sweepEvaluations(): Promise<void> {
  if (evaluationSweepRunning) return;
  evaluationSweepRunning = true;

  try {
    const result = await evaluations.runDueSchedules(new Date());

    console.log(
      JSON.stringify({
        event: "evaluation.schedule_sweep",
        at: new Date().toISOString(),
        ...result,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "evaluation.schedule_sweep_failed",
        at: new Date().toISOString(),
        message:
          error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    evaluationSweepRunning = false;
  }
}

async function sweepCertifications(): Promise<void> {
  if (certificationSweepRunning) return;
  certificationSweepRunning = true;

  try {
    const result = await certifications.sweep(new Date());

    console.log(
      JSON.stringify({
        event: "certification.lifecycle_sweep",
        at: new Date().toISOString(),
        ...result,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "certification.lifecycle_sweep_failed",
        at: new Date().toISOString(),
        message:
          error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    certificationSweepRunning = false;
  }
}

async function sweepWebhooks(): Promise<void> {
  if (webhookSweepRunning) return;
  webhookSweepRunning = true;

  try {
    const result = await integrations.deliverPendingWebhooks(50);

    console.log(
      JSON.stringify({
        event: "integration.webhook_sweep",
        at: new Date().toISOString(),
        ...result,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "integration.webhook_sweep_failed",
        at: new Date().toISOString(),
        message:
          error instanceof Error ? error.message : "unknown error",
      }),
    );
  } finally {
    webhookSweepRunning = false;
  }
}

console.log(
  JSON.stringify({
    event: "compliance_worker.started",
    at: new Date().toISOString(),
    authorizationSweepMs,
    exceptionSweepMs,
    deadlineSweepMs,
    evaluationSweepMs,
    certificationSweepMs,
    webhookSweepMs,
  }),
);

await Promise.all([
  sweepAuthorizations(),
  sweepExceptions(),
  sweepDeadlines(),
  sweepEvaluations(),
  sweepCertifications(),
  sweepWebhooks(),
]);

const authorizationTimer = setInterval(() => {
  void sweepAuthorizations();
}, authorizationSweepMs);

const exceptionTimer = setInterval(() => {
  void sweepExceptions();
}, exceptionSweepMs);

const deadlineTimer = setInterval(() => {
  void sweepDeadlines();
}, deadlineSweepMs);

const evaluationTimer = setInterval(() => {
  void sweepEvaluations();
}, evaluationSweepMs);

const certificationTimer = setInterval(() => {
  void sweepCertifications();
}, certificationSweepMs);

const webhookTimer = setInterval(() => {
  void sweepWebhooks();
}, webhookSweepMs);

async function shutdown(signal: string): Promise<void> {
  clearInterval(authorizationTimer);
  clearInterval(exceptionTimer);
  clearInterval(deadlineTimer);
  clearInterval(evaluationTimer);
  clearInterval(certificationTimer);
  clearInterval(webhookTimer);

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
