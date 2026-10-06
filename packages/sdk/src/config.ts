import type {
  JsonObject,
} from "@caiae/core";
import type {
  PublicThinAppConfig,
  ThinAppConfig,
  ThinAppRuntimeConfig,
} from "./types.js";

const FEATURE_KEYS = new Set([
  "rulesets",
  "resources",
  "checks",
  "authorizations",
  "exceptions",
  "evidence",
  "deadlines",
  "findings",
  "remediations",
  "certifications",
  "reporting",
  "publication",
  "integrations",
  "security",
]);

export function parseThinAppConfig(
  input: unknown,
): ThinAppConfig {
  const source = object(
    input,
    "config",
  );

  if (
    source.schemaVersion !==
    "1"
  ) {
    throw new Error(
      'config.schemaVersion must be "1"',
    );
  }

  const appId =
    identifier(
      source.appId,
      "config.appId",
    );
  const displayName =
    nonEmptyString(
      source.displayName,
      "config.displayName",
    );
  const description =
    optionalString(
      source.description,
      "config.description",
    );
  const engineSource =
    object(
      source.engine,
      "config.engine",
    );
  const apiBaseUrl =
    absoluteHttpUrl(
      engineSource.apiBaseUrl,
      "config.engine.apiBaseUrl",
    );
  const organizationId =
    optionalUuid(
      engineSource.organizationId,
      "config.engine.organizationId",
    );
  const requestTimeoutMs =
    optionalPositiveInteger(
      engineSource.requestTimeoutMs,
      "config.engine.requestTimeoutMs",
      30000,
    );
  const features =
    source.features ===
    undefined
      ? undefined
      : parseFeatures(
          source.features,
        );
  const resourceTypes =
    source.resourceTypes ===
    undefined
      ? undefined
      : parseResourceTypes(
          source.resourceTypes,
        );
  const metadata =
    source.metadata ===
    undefined
      ? undefined
      : jsonObject(
          source.metadata,
          "config.metadata",
        );

  return {
    schemaVersion: "1",
    appId,
    displayName,
    ...(description
      ? { description }
      : {}),
    engine: {
      apiBaseUrl,
      ...(organizationId
        ? { organizationId }
        : {}),
      requestTimeoutMs,
    },
    ...(features
      ? { features }
      : {}),
    ...(resourceTypes
      ? { resourceTypes }
      : {}),
    ...(metadata
      ? { metadata }
      : {}),
  };
}

export function parseThinAppRuntimeConfig(
  input: unknown,
): ThinAppRuntimeConfig {
  const source = object(
    input,
    "runtime",
  );
  const config =
    parseThinAppConfig(
      source.config,
    );

  if (
    source.secrets ===
    undefined
  ) {
    return { config };
  }

  const secretsSource =
    object(
      source.secrets,
      "runtime.secrets",
    );
  const operatorToken =
    optionalToken(
      secretsSource.operatorToken,
      "runtime.secrets.operatorToken",
      "caiau_",
    );
  const serviceToken =
    optionalToken(
      secretsSource.serviceToken,
      "runtime.secrets.serviceToken",
      "caiae_",
    );

  return {
    config,
    secrets: {
      ...(operatorToken
        ? { operatorToken }
        : {}),
      ...(serviceToken
        ? { serviceToken }
        : {}),
    },
  };
}

export function toPublicThinAppConfig(
  runtime:
    | ThinAppRuntimeConfig
    | ThinAppConfig,
): PublicThinAppConfig {
  const config =
    "config" in runtime
      ? runtime.config
      : runtime;
  return parseThinAppConfig(
    config,
  );
}

function parseFeatures(
  value: unknown,
): ThinAppConfig["features"] {
  const source =
    object(
      value,
      "config.features",
    );
  const result:
    Record<string, boolean> = {};

  for (
    const [key, item] of
    Object.entries(source)
  ) {
    if (!FEATURE_KEYS.has(key)) {
      throw new Error(
        `config.features.${key} is not a recognized feature flag`,
      );
    }
    if (
      typeof item !==
      "boolean"
    ) {
      throw new Error(
        `config.features.${key} must be boolean`,
      );
    }
    result[key] = item;
  }

  return result;
}

function parseResourceTypes(
  value: unknown,
): ThinAppConfig["resourceTypes"] {
  const source =
    object(
      value,
      "config.resourceTypes",
    );
  const result:
    NonNullable<
      ThinAppConfig["resourceTypes"]
    > = {};

  for (
    const [key, item] of
    Object.entries(source)
  ) {
    identifier(
      key,
      `config.resourceTypes.${key}`,
    );
    const entry =
      object(
        item,
        `config.resourceTypes.${key}`,
      );
    const description =
      optionalString(
        entry.description,
        `config.resourceTypes.${key}.description`,
      );
    const metadata =
      entry.metadata ===
      undefined
        ? undefined
        : jsonObject(
            entry.metadata,
            `config.resourceTypes.${key}.metadata`,
          );

    result[key] = {
      label:
        nonEmptyString(
          entry.label,
          `config.resourceTypes.${key}.label`,
        ),
      ...(description
        ? { description }
        : {}),
      ...(metadata
        ? { metadata }
        : {}),
    };
  }

  return result;
}

function object(
  value: unknown,
  path: string,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !==
      "object" ||
    Array.isArray(value)
  ) {
    throw new Error(
      `${path} must be an object`,
    );
  }
  return value as Record<
    string,
    unknown
  >;
}

function jsonObject(
  value: unknown,
  path: string,
): JsonObject {
  const source =
    object(value, path);
  return JSON.parse(
    JSON.stringify(source),
  ) as JsonObject;
}

function nonEmptyString(
  value: unknown,
  path: string,
): string {
  if (
    typeof value !==
      "string" ||
    value.trim() === ""
  ) {
    throw new Error(
      `${path} must be a non-empty string`,
    );
  }
  return value.trim();
}

function optionalString(
  value: unknown,
  path: string,
): string | undefined {
  return value ===
    undefined
    ? undefined
    : nonEmptyString(
        value,
        path,
      );
}

function identifier(
  value: unknown,
  path: string,
): string {
  const normalized =
    nonEmptyString(
      value,
      path,
    );

  if (
    !/^[a-z0-9][a-z0-9._:-]*$/i.test(
      normalized,
    )
  ) {
    throw new Error(
      `${path} must be an identifier`,
    );
  }

  return normalized;
}

function optionalUuid(
  value: unknown,
  path: string,
): string | undefined {
  if (
    value === undefined
  ) {
    return undefined;
  }
  const normalized =
    nonEmptyString(
      value,
      path,
    );
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      normalized,
    )
  ) {
    throw new Error(
      `${path} must be a UUID`,
    );
  }
  return normalized;
}

function optionalPositiveInteger(
  value: unknown,
  path: string,
  defaultValue: number,
): number {
  if (
    value === undefined
  ) {
    return defaultValue;
  }
  if (
    typeof value !==
      "number" ||
    !Number.isSafeInteger(
      value,
    ) ||
    value < 1 ||
    value > 300000
  ) {
    throw new Error(
      `${path} must be an integer between 1 and 300000`,
    );
  }
  return value;
}

function absoluteHttpUrl(
  value: unknown,
  path: string,
): string {
  const normalized =
    nonEmptyString(
      value,
      path,
    );
  let url: URL;
  try {
    url = new URL(
      normalized,
    );
  } catch {
    throw new Error(
      `${path} must be an absolute URL`,
    );
  }
  if (
    url.protocol !==
      "http:" &&
    url.protocol !==
      "https:"
  ) {
    throw new Error(
      `${path} must use http or https`,
    );
  }
  return url
    .toString()
    .replace(/\/$/, "");
}

function optionalToken(
  value: unknown,
  path: string,
  prefix: string,
): string | undefined {
  if (
    value === undefined
  ) {
    return undefined;
  }
  const token =
    nonEmptyString(
      value,
      path,
    );
  if (
    !token.startsWith(prefix)
  ) {
    throw new Error(
      `${path} must begin with ${prefix}`,
    );
  }
  return token;
}
