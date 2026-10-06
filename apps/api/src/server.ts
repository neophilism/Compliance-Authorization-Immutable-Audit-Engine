import {
  readApiRuntimeConfig,
} from "@caiae/runtime";
import { buildApp } from "./app.js";

const runtime =
  readApiRuntimeConfig();

const app =
  await buildApp({
    runMigrations:
      runtime.runMigrations,
    corsOrigins:
      runtime.corsOrigins,
    trustProxy:
      runtime.trustProxy,
    bodyLimitBytes:
      runtime.bodyLimitBytes,
    requestTimeoutMs:
      runtime.requestTimeoutMs,
    releaseSha:
      runtime.releaseSha,
  });

await app.listen({
  port: runtime.port,
  host: runtime.host,
});

let shuttingDown = false;

async function shutdown(
  signal: string,
  exitCode = 0,
): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;

  app.log.info(
    {
      signal,
      release:
        runtime.releaseSha,
    },
    "api shutdown started",
  );

  const forceTimer =
    setTimeout(() => {
      app.log.error(
        {
          signal,
          graceMs:
            runtime.shutdownGraceMs,
        },
        "api shutdown grace period exceeded",
      );
      process.exit(1);
    }, runtime.shutdownGraceMs);

  forceTimer.unref();

  try {
    await app.close();
    clearTimeout(forceTimer);
    process.exitCode =
      exitCode;
  } catch (error) {
    clearTimeout(forceTimer);
    app.log.error(
      error,
      "api shutdown failed",
    );
    process.exitCode = 1;
  }
}

process.once(
  "SIGTERM",
  () => {
    void shutdown("SIGTERM");
  },
);

process.once(
  "SIGINT",
  () => {
    void shutdown("SIGINT");
  },
);

process.once(
  "uncaughtException",
  (error) => {
    app.log.error(
      error,
      "uncaught exception",
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
    app.log.error(
      { reason },
      "unhandled rejection",
    );
    void shutdown(
      "unhandledRejection",
      1,
    );
  },
);
