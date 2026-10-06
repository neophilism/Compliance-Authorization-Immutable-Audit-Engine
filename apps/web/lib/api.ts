export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly payload: unknown,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function api<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(
    `/engine-api${path}`,
    {
      ...init,
      headers: {
        "content-type": "application/json",
        ...(init?.headers ?? {}),
      },
    },
  );

  const contentType =
    response.headers.get("content-type") ?? "";
  const payload =
    contentType.includes("application/json")
      ? await response.json()
      : await response.text();

  if (!response.ok) {
    const message =
      typeof payload === "object" &&
      payload !== null &&
      "message" in payload &&
      typeof (payload as { message?: unknown }).message === "string"
        ? String((payload as { message: string }).message)
        : `Request failed with HTTP ${response.status}`;

    throw new ApiError(
      response.status,
      payload,
      message,
    );
  }

  return payload as T;
}

export function post<T>(
  path: string,
  body: unknown,
): Promise<T> {
  return api<T>(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function parseJsonObject(
  value: string,
  label: string,
): Record<string, unknown> {
  const trimmed = value.trim();
  if (!trimmed) return {};

  const parsed = JSON.parse(trimmed) as unknown;
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    throw new Error(
      `${label} must be a JSON object`,
    );
  }

  return parsed as Record<string, unknown>;
}
