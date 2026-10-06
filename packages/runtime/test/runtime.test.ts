import assert from "node:assert/strict";
import test from "node:test";
import {
  readApiRuntimeConfig,
  readWorkerRuntimeConfig,
} from "../src/index.js";

const DATABASE_URL =
  "postgresql://user:pass@db.example/caiae";

test("development runtime keeps local-friendly defaults", () => {
  const config =
    readApiRuntimeConfig({
      NODE_ENV: "development",
      DATABASE_URL,
    });

  assert.equal(
    config.runMigrations,
    true,
  );
  assert.equal(
    config.corsOrigins,
    true,
  );
  assert.equal(
    config.trustProxy,
    false,
  );
  assert.equal(
    config.bodyLimitBytes,
    1_048_576,
  );
});

test("production runtime is secure by default", () => {
  const config =
    readApiRuntimeConfig({
      NODE_ENV: "production",
      DATABASE_URL,
      CAIAE_WEBHOOK_MASTER_SECRET:
        "x".repeat(64),
    });

  assert.equal(
    config.runMigrations,
    false,
  );
  assert.equal(
    config.corsOrigins,
    false,
  );
  assert.equal(
    config.trustProxy,
    true,
  );

  const bootstrapDisabled =
    readApiRuntimeConfig({
      NODE_ENV: "production",
      DATABASE_URL,
      CAIAE_WEBHOOK_MASTER_SECRET:
        "x".repeat(64),
      CAIAE_BOOTSTRAP_SECRET: "",
    });

  assert.equal(
    bootstrapDisabled.environment,
    "production",
  );
});

test("production rejects legacy security, wildcard CORS, and weak secrets", () => {
  assert.throws(
    () =>
      readApiRuntimeConfig({
        NODE_ENV:
          "production",
        DATABASE_URL,
        CAIAE_API_SECURITY_MODE:
          "legacy",
        CAIAE_WEBHOOK_MASTER_SECRET:
          "x".repeat(64),
      }),
    /forbidden in production/,
  );

  assert.throws(
    () =>
      readApiRuntimeConfig({
        NODE_ENV:
          "production",
        DATABASE_URL,
        CAIAE_WEBHOOK_MASTER_SECRET:
          "x".repeat(64),
        CAIAE_CORS_ORIGINS:
          "*",
      }),
    /CORS_ORIGINS=\*/,
  );

  assert.throws(
    () =>
      readApiRuntimeConfig({
        NODE_ENV:
          "production",
        DATABASE_URL,
        CAIAE_WEBHOOK_MASTER_SECRET:
          "short",
      }),
    /at least 32/,
  );
});

test("production accepts explicit CORS origins and migration override", () => {
  const config =
    readApiRuntimeConfig({
      NODE_ENV: "production",
      DATABASE_URL,
      CAIAE_WEBHOOK_MASTER_SECRET:
        "x".repeat(64),
      CAIAE_CORS_ORIGINS:
        "https://one.example, https://two.example/",
      CAIAE_RUN_MIGRATIONS:
        "true",
      CAIAE_TRUST_PROXY:
        "false",
    });

  assert.deepEqual(
    config.corsOrigins,
    [
      "https://one.example",
      "https://two.example",
    ],
  );
  assert.equal(
    config.runMigrations,
    true,
  );
  assert.equal(
    config.trustProxy,
    false,
  );
});

test("worker validates sweep cadence and shares production secret checks", () => {
  const config =
    readWorkerRuntimeConfig({
      NODE_ENV:
        "production",
      DATABASE_URL,
      CAIAE_WEBHOOK_MASTER_SECRET:
        "x".repeat(64),
      EVALUATION_SWEEP_MS:
        "60000",
    });

  assert.equal(
    config.evaluationSweepMs,
    60_000,
  );
  assert.equal(
    config.runMigrations,
    false,
  );

  assert.throws(
    () =>
      readWorkerRuntimeConfig({
        NODE_ENV:
          "development",
        DATABASE_URL,
        DEADLINE_SWEEP_MS:
          "500",
      }),
    /between 1000/,
  );
});
