import type {
  JsonObject,
  JsonValue,
} from "@caiae/core";
import {
  PublicationError,
  type NormalizedPublicationPolicy,
  type PublicationPolicy,
} from "./types.js";

const PATH_SEGMENT =
  /^[A-Za-z0-9_-]+$/;

const FORBIDDEN_SEGMENTS =
  new Set([
    "__proto__",
    "prototype",
    "constructor",
  ]);

export function normalizePublicationPolicy(
  policy: PublicationPolicy | undefined,
): NormalizedPublicationPolicy {
  const omitPaths =
    normalizePaths(
      policy?.omitPaths ?? [],
      "omitPaths",
    );

  const replacements =
    policy?.replacements ?? {};

  if (
    replacements === null ||
    typeof replacements !== "object" ||
    Array.isArray(replacements)
  ) {
    throw new PublicationError(
      "validation",
      "replacements must be an object",
    );
  }

  const normalizedReplacements:
    Record<string, JsonValue> = {};

  for (
    const [path, value] of
    Object.entries(replacements)
  ) {
    validatePath(path, "replacements");
    normalizedReplacements[path] =
      cloneJson(value);
  }

  return {
    omitPaths:
      [...new Set(omitPaths)].sort(),
    replacements:
      Object.fromEntries(
        Object.entries(
          normalizedReplacements,
        ).sort(([a], [b]) =>
          a.localeCompare(b),
        ),
      ),
  };
}

export function applyPublicationPolicy(
  source: JsonObject,
  policy: NormalizedPublicationPolicy,
): JsonObject {
  const result =
    cloneJson(source) as JsonObject;

  for (const path of policy.omitPaths) {
    deletePath(result, path);
  }

  for (
    const [path, value] of
    Object.entries(
      policy.replacements,
    )
  ) {
    setPath(
      result,
      path,
      cloneJson(value),
    );
  }

  return result;
}

function normalizePaths(
  value: string[],
  field: string,
): string[] {
  if (!Array.isArray(value)) {
    throw new PublicationError(
      "validation",
      `${field} must be an array of paths`,
    );
  }

  return value.map(
    (path, index) => {
      if (
        typeof path !== "string" ||
        path.trim() === ""
      ) {
        throw new PublicationError(
          "validation",
          `${field}[${index}] must be a non-empty path`,
        );
      }
      const normalized =
        path.trim();
      validatePath(
        normalized,
        field,
      );
      return normalized;
    },
  );
}

function validatePath(
  path: string,
  field: string,
): void {
  const segments =
    path.split(".");

  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        !PATH_SEGMENT.test(segment) ||
        FORBIDDEN_SEGMENTS.has(
          segment,
        ),
    )
  ) {
    throw new PublicationError(
      "validation",
      `${field} contains an invalid path: ${path}`,
    );
  }
}

function deletePath(
  target: JsonObject,
  path: string,
): void {
  const segments =
    path.split(".");
  const key =
    segments.pop()!;
  let current:
    Record<string, JsonValue> =
      target;

  for (const segment of segments) {
    const next =
      current[segment];

    if (
      next === null ||
      Array.isArray(next) ||
      typeof next !== "object"
    ) {
      return;
    }

    current =
      next as Record<
        string,
        JsonValue
      >;
  }

  delete current[key];
}

function setPath(
  target: JsonObject,
  path: string,
  value: JsonValue,
): void {
  const segments =
    path.split(".");
  const key =
    segments.pop()!;
  let current:
    Record<string, JsonValue> =
      target;

  for (const segment of segments) {
    const existing =
      current[segment];

    if (
      existing === null ||
      Array.isArray(existing) ||
      typeof existing !== "object"
    ) {
      current[segment] = {};
    }

    current =
      current[segment] as Record<
        string,
        JsonValue
      >;
  }

  current[key] = value;
}

function cloneJson(
  value: JsonValue,
): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    if (
      typeof value === "number" &&
      !Number.isFinite(value)
    ) {
      throw new PublicationError(
        "validation",
        "publication policy cannot contain non-finite numbers",
      );
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(cloneJson);
  }

  const output:
    Record<string, JsonValue> = {};

  for (
    const key of Object.keys(
      value,
    ).sort()
  ) {
    if (
      FORBIDDEN_SEGMENTS.has(key)
    ) {
      throw new PublicationError(
        "validation",
        "publication policy contains a forbidden object key",
      );
    }
    output[key] =
      cloneJson(value[key]!);
  }

  return output;
}
