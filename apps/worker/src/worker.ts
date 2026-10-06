import { AuthorizationService } from "@caiae/authorization";
import { CertificationService } from "@caiae/certifications";
import { createPool, runMigrations } from "@caiae/db";
import { DeadlineService } from "@caiae/deadlines";
import { EvaluationService } from "@caiae/evaluations";
import { IntegrationService } from "@caiae/integrations";
import { ExceptionService } from "@caiae/exceptions";
import {
  readWorkerRuntimeConfig,
} from "@caiae/runtime";

const runtime =
  readWorkerRuntimeConfig();

const {
  authorizationSweepMs,
  exceptionSweepMs,
  deadlineSweepMs,
  evaluationSweepMs,
  certificationSweepMs,
  webhookSweepMs,
} = runtime;

const pool = createPool();

if (runtime.runMigrations) {
  await runMigrations(pool);
}

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
    release:
      runtime.releaseSha,
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

let shuttingDown = false;

function anySweepRunning(): boolean {
  return (
    authorizationSweepRunning ||
    exceptionSweepRunning ||
    deadlineSweepRunning ||
    evaluationSweepRunning ||
    certificationSweepRunning ||
    webhookSweepRunning
  );
}

async function waitForSweeps(): Promise<boolean> {
  const deadline =
    Date.now() +
    runtime.shutdownGraceMs;

  while (
    anySweepRunning() &&
    Date.now() < deadline
  ) {
    await new Promise<void>(
      (resolve) => {
        setTimeout(resolve, 50);
      },
    );
  }

  return !anySweepRunning();
}

async function shutdown(
  signal: string,
  exitCode = 0,
): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;

  clearInterval(authorizationTimer);
  clearInterval(exceptionTimer);
  clearInterval(deadlineTimer);
  clearInterval(evaluationTimer);
  clearInterval(certificationTimer);
  clearInterval(webhookTimer);

  console.log(
    JSON.stringify({
      event:
        "compliance_worker.stopping",
      signal,
      at:
        new Date().toISOString(),
      release:
        runtime.releaseSha,
    }),
  );

  const drained =
    await waitForSweeps();

  if (!drained) {
    console.error(
      JSON.stringify({
        event:
          "compliance_worker.shutdown_grace_exceeded",
        signal,
        graceMs:
          runtime.shutdownGraceMs,
        at:
          new Date().toISOString(),
      }),
    );
    process.exitCode = 1;
  } else {
    process.exitCode =
      exitCode;
  }

  await pool.end();
}

process.once("SIGTERM", () => {
  void shutdown("SIGTERM");
});

process.once("SIGINT", () => {
  void shutdown("SIGINT");
});

process.once(
  "uncaughtException",
  (error) => {
    console.error(
      JSON.stringify({
        event:
          "compliance_worker.uncaught_exception",
        at:
          new Date().toISOString(),
        message:
          error.message,
      }),
    );
    void shutdown(
      "uncaughtException",
      1,
    );
  },
);

process.once(
  "unhandledRejection",
  (reason) => {
    console.error(
      JSON.stringify({
        event:
          "compliance_worker.unhandled_rejection",
        at:
          new Date().toISOString(),
        message:
          reason instanceof Error
            ? reason.message
            : String(reason),
      }),
    );
    void shutdown(
      "unhandledRejection",
      1,
    );
  },
);
