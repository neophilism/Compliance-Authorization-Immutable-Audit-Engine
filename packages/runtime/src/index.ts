export type RuntimeEnvironment =
  | "development"
  | "test"
  | "production";

export type ApiRuntimeConfig = {
  environment: RuntimeEnvironment;
  host: string;
  port: number;
  runMigrations: boolean;
  corsOrigins: true | false | string[];
  trustProxy: boolean;
  bodyLimitBytes: number;
  requestTimeoutMs: number;
  shutdownGraceMs: number;
  releaseSha: string | null;
};

export type WorkerRuntimeConfig = {
  environment: RuntimeEnvironment;
  runMigrations: boolean;
  shutdownGraceMs: number;
  authorizationSweepMs: number;
  exceptionSweepMs: number;
  deadlineSweepMs: number;
  evaluationSweepMs: number;
  certificationSweepMs: number;
  webhookSweepMs: number;
  releaseSha: string | null;
};

export function readApiRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
): ApiRuntimeConfig {
  const environment =
    runtimeEnvironment(env.NODE_ENV);

  assertDatabaseUrl(env);
  assertProductionSecurity(env, environment);

  return {
    environment,
    host:
      nonEmpty(
        env.HOST,
      ) ?? "0.0.0.0",
    port:
      integer(
        env.PORT,
        "PORT",
        4000,
        1,
        65535,
      ),
    runMigrations:
      booleanValue(
        env.CAIAE_RUN_MIGRATIONS,
        "CAIAE_RUN_MIGRATIONS",
        environment !==
          "production",
      ),
    corsOrigins:
      corsOrigins(
        env.CAIAE_CORS_ORIGINS,
        environment,
      ),
    trustProxy:
      booleanValue(
        env.CAIAE_TRUST_PROXY,
        "CAIAE_TRUST_PROXY",
        environment ===
          "production",
      ),
    bodyLimitBytes:
      integer(
        env.CAIAE_BODY_LIMIT_BYTES,
        "CAIAE_BODY_LIMIT_BYTES",
        1_048_576,
        16_384,
        20_971_520,
      ),
    requestTimeoutMs:
      integer(
        env.CAIAE_REQUEST_TIMEOUT_MS,
        "CAIAE_REQUEST_TIMEOUT_MS",
        30_000,
        1_000,
        300_000,
      ),
    shutdownGraceMs:
      integer(
        env.CAIAE_SHUTDOWN_GRACE_MS,
        "CAIAE_SHUTDOWN_GRACE_MS",
        15_000,
        1_000,
        120_000,
      ),
    releaseSha:
      nonEmpty(
        env.CAIAE_RELEASE_SHA,
      ) ?? nonEmpty(env.RENDER_GIT_COMMIT),
  };
}

export function readWorkerRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
): WorkerRuntimeConfig {
  const environment =
    runtimeEnvironment(env.NODE_ENV);

  assertDatabaseUrl(env);
  assertProductionSecurity(env, environment);

  return {
    environment,
    runMigrations:
      booleanValue(
        env.CAIAE_RUN_MIGRATIONS,
        "CAIAE_RUN_MIGRATIONS",
        environment !==
          "production",
      ),
    shutdownGraceMs:
      integer(
        env.CAIAE_SHUTDOWN_GRACE_MS,
        "CAIAE_SHUTDOWN_GRACE_MS",
        15_000,
        1_000,
        120_000,
      ),
    authorizationSweepMs:
      sweep(
        env.AUTHORIZATION_SWEEP_MS,
        "AUTHORIZATION_SWEEP_MS",
      ),
    exceptionSweepMs:
      sweep(
        env.EXCEPTION_SWEEP_MS,
        "EXCEPTION_SWEEP_MS",
      ),
    deadlineSweepMs:
      sweep(
        env.DEADLINE_SWEEP_MS,
        "DEADLINE_SWEEP_MS",
      ),
    evaluationSweepMs:
      sweep(
        env.EVALUATION_SWEEP_MS,
        "EVALUATION_SWEEP_MS",
      ),
    certificationSweepMs:
      sweep(
        env.CERTIFICATION_SWEEP_MS,
        "CERTIFICATION_SWEEP_MS",
      ),
    webhookSweepMs:
      sweep(
        env.WEBHOOK_SWEEP_MS,
        "WEBHOOK_SWEEP_MS",
      ),
    releaseSha:
      nonEmpty(
        env.CAIAE_RELEASE_SHA,
      ) ?? nonEmpty(env.RENDER_GIT_COMMIT),
  };
}

export function assertProductionSecurity(
  env: NodeJS.ProcessEnv,
  environment:
    RuntimeEnvironment,
): void {
  if (
    environment !==
    "production"
  ) {
    return;
  }

  if (
    env.CAIAE_API_SECURITY_MODE ===
    "legacy"
  ) {
    throw new Error(
      "CAIAE_API_SECURITY_MODE=legacy is forbidden in production",
    );
  }

  secret(
    env.CAIAE_WEBHOOK_MASTER_SECRET,
    "CAIAE_WEBHOOK_MASTER_SECRET",
    true,
  );

  if (
    nonEmpty(
      env.CAIAE_BOOTSTRAP_SECRET,
    )
  ) {
    secret(
      env.CAIAE_BOOTSTRAP_SECRET,
      "CAIAE_BOOTSTRAP_SECRET",
      true,
    );
  }
}

function runtimeEnvironment(
  value: string | undefined,
): RuntimeEnvironment {
  const normalized =
    value?.trim() ||
    "development";

  if (
    normalized !==
      "development" &&
    normalized !==
      "test" &&
    normalized !==
      "production"
  ) {
    throw new Error(
      "NODE_ENV must be development, test, or production",
    );
  }

  return normalized;
}

function assertDatabaseUrl(
  env: NodeJS.ProcessEnv,
): void {
  const value =
    nonEmpty(
      env.DATABASE_URL,
    );

  if (!value) {
    throw new Error(
      "DATABASE_URL is required",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(
      "DATABASE_URL must be a valid PostgreSQL URL",
    );
  }

  if (
    parsed.protocol !==
      "postgres:" &&
    parsed.protocol !==
      "postgresql:"
  ) {
    throw new Error(
      "DATABASE_URL must use postgres or postgresql",
    );
  }
}

function corsOrigins(
  value: string | undefined,
  environment:
    RuntimeEnvironment,
): true | false | string[] {
  const normalized =
    nonEmpty(value);

  if (!normalized) {
    return environment ===
      "production"
      ? false
      : true;
  }

  if (
    normalized === "*"
  ) {
    if (
      environment ===
      "production"
    ) {
      throw new Error(
        "CAIAE_CORS_ORIGINS=* is forbidden in production",
      );
    }
    return true;
  }

  if (
    normalized.toLowerCase() ===
    "none"
  ) {
    return false;
  }

  const origins =
    normalized
      .split(",")
      .map((item) =>
        item.trim(),
      )
      .filter(Boolean);

  if (
    origins.length === 0
  ) {
    throw new Error(
      "CAIAE_CORS_ORIGINS must contain at least one origin, none, or *",
    );
  }

  for (
    const origin of origins
  ) {
    let parsed: URL;
    try {
      parsed =
        new URL(origin);
    } catch {
      throw new Error(
        `invalid CORS origin: ${origin}`,
      );
    }

    if (
      parsed.protocol !==
        "http:" &&
      parsed.protocol !==
        "https:"
    ) {
      throw new Error(
        `CORS origin must use http or https: ${origin}`,
      );
    }

    if (
      parsed.pathname !==
        "/" ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error(
        `CORS origin must not include path, query, or fragment: ${origin}`,
      );
    }
  }

  return origins.map(
    (origin) =>
      origin.replace(
        /\/$/,
        "",
      ),
  );
}

function sweep(
  value: string | undefined,
  name: string,
): number {
  return integer(
    value,
    name,
    30_000,
    1_000,
    86_400_000,
  );
}

function booleanValue(
  value: string | undefined,
  name: string,
  defaultValue: boolean,
): boolean {
  if (
    value === undefined ||
    value.trim() === ""
  ) {
    return defaultValue;
  }

  const normalized =
    value.trim().toLowerCase();

  if (
    normalized === "true" ||
    normalized === "1" ||
    normalized === "yes"
  ) {
    return true;
  }

  if (
    normalized === "false" ||
    normalized === "0" ||
    normalized === "no"
  ) {
    return false;
  }

  throw new Error(
    `${name} must be true or false`,
  );
}

function integer(
  value: string | undefined,
  name: string,
  defaultValue: number,
  min: number,
  max: number,
): number {
  if (
    value === undefined ||
    value.trim() === ""
  ) {
    return defaultValue;
  }

  const parsed =
    Number(value);

  if (
    !Number.isSafeInteger(
      parsed,
    ) ||
    parsed < min ||
    parsed > max
  ) {
    throw new Error(
      `${name} must be an integer between ${min} and ${max}`,
    );
  }

  return parsed;
}

function secret(
  value: string | undefined,
  name: string,
  required: boolean,
): string | null {
  const normalized =
    nonEmpty(value);

  if (!normalized) {
    if (required) {
      throw new Error(
        `${name} is required in production`,
      );
    }
    return null;
  }

  if (
    normalized.length < 32
  ) {
    throw new Error(
      `${name} must contain at least 32 characters`,
    );
  }

  if (
    normalized.includes(
      "replace-with",
    ) ||
    normalized ===
      "caiae-development-webhook-secret"
  ) {
    throw new Error(
      `${name} must not use a development placeholder`,
    );
  }

  return normalized;
}

function nonEmpty(
  value: string | undefined,
): string | null {
  if (
    value === undefined
  ) {
    return null;
  }
  const normalized =
    value.trim();
  return normalized === ""
    ? null
    : normalized;
}
