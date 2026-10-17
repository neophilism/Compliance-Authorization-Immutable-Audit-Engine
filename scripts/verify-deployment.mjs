import { pathToFileURL } from "node:url";

export function deploymentBaseUrl(raw) {
  if (typeof raw !== "string" || !raw.trim()) {
    throw new Error("CAIAE_SMOKE_API_URL is required");
  }
  if (/[\s\\]/u.test(raw)) {
    throw new Error("API URL must be an unambiguous origin without whitespace or backslashes");
  }
  let url;
  try { url = new URL(raw); } catch { throw new Error("Invalid API URL"); }
  if (url.username || url.password || url.search || url.hash ||
      (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("API URL must be an origin without credentials, query, fragment or path");
  }
  if (!/^[a-z]+:\/\/[^/?#]+\/?$/i.test(raw)) {
    throw new Error("API URL must be an unambiguous origin");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error("Remote deployment URL must use HTTPS");
  }
  return url.origin;
}

class CheckError extends Error {}

function nonEmptyId(value) {
  return typeof value === "string" && value.length <= 256 &&
    value.length > 0 && !/[\s\x00-\x1f\x7f]/u.test(value);
}

// Apply the same deadline to headers AND the response stream. Some fetch mocks
// and broken upstreams do not reject a pending read when a signal is aborted.
async function boundedWait(promise, signal) {
  if (signal.aborted) throw new CheckError("request timed out");
  let abort;
  const interrupted = new Promise((_, reject) => {
    abort = () => reject(new CheckError("request timed out"));
    signal.addEventListener("abort", abort, { once: true });
  });
  try { return await Promise.race([promise, interrupted]); }
  finally { signal.removeEventListener("abort", abort); }
}

export async function verifyDeployment({
  baseUrl,
  operatorToken,
  requireAuth = false,
  expectedRelease,
  expectedOrganizationId,
  timeoutMs = 10000,
  maxResponseBytes = 1048576,
  fetchImpl = fetch,
}) {
  const origin = deploymentBaseUrl(baseUrl);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 ||
      !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 ||
      maxResponseBytes > 4194304) {
    throw new Error("Invalid deployment check resource limits");
  }
  if (operatorToken !== undefined && operatorToken !== null &&
      (typeof operatorToken !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(operatorToken))) {
    throw new Error("Invalid operator token format");
  }
  if (requireAuth && !operatorToken) {
    throw new Error("An operator token is required for the authenticated production smoke test");
  }
  if (expectedRelease !== undefined &&
      (typeof expectedRelease !== "string" || !/^[a-f0-9]{40}$/i.test(expectedRelease))) {
    throw new Error("Expected release must be a full 40-character commit SHA");
  }
  if (requireAuth && !expectedRelease) {
    throw new Error("An expected commit SHA is required for authenticated production acceptance");
  }
  if (expectedOrganizationId !== undefined && !nonEmptyId(expectedOrganizationId)) {
    throw new Error("Invalid expected organization ID");
  }
  if (expectedOrganizationId && !operatorToken) {
    throw new Error("An operator token is required to verify an expected organization");
  }
  async function expectJson(path, status, token, readJson = true) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    let reader;
    try {
      const requestUrl = origin + path;
      response = await boundedWait(fetchImpl(requestUrl, {
        method: "GET",
        headers: {
          accept: "application/json",
          ...(token ? { authorization: "Bearer " + token } : {}),
        },
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
      }), controller.signal);
      if (response.redirected || (response.url && response.url !== requestUrl)) {
        throw new CheckError("redirected response is forbidden");
      }
      if (response.status !== status) {
        throw new CheckError("unexpected HTTP status");
      }
      if (!readJson) return null;
      const mediaType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase();
      if (!mediaType || !/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/.test(mediaType)) {
        throw new CheckError("expected a JSON content type");
      }
      const length = response.headers.get("content-length");
      if (length !== null && (!/^\d+$/.test(length) ||
          !Number.isSafeInteger(Number(length)) || Number(length) > maxResponseBytes)) {
        throw new CheckError("response exceeds byte limit or has invalid length");
      }
      if (!response.body) throw new CheckError("missing JSON response body");
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      while (true) {
        const { value, done } = await boundedWait(reader.read(), controller.signal);
        if (done) break;
        size += value.byteLength;
        if (size > maxResponseBytes) throw new CheckError("response exceeds byte limit");
        chunks.push(value);
      }
      let body;
      try {
        body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size)));
      } catch { throw new CheckError("invalid JSON response"); }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        throw new CheckError("expected a JSON object");
      }
      return body;
    } catch (error) {
      // Upstream URLs, exception messages and bodies can contain credentials.
      throw new Error(path + ": " +
        (error instanceof CheckError ? error.message : "request failed"));
    } finally {
      clearTimeout(timer);
      controller.abort();
      // Do not await cleanup of an uncooperative remote stream.
      if (reader) {
        void reader.cancel().catch(() => {});
        try { reader.releaseLock(); } catch { /* pending read was cancelled */ }
      } else if (response?.body) {
        void response.body.cancel().catch(() => {});
      }
    }
  }
  const health = await expectJson("/health", 200);
  if (health.status !== "ok" || health.service !== "api" ||
      typeof health.release !== "string" || !/^[a-f0-9]{40}$/i.test(health.release)) {
    throw new Error("/health: unexpected liveness or release payload");
  }
  const ready = await expectJson("/ready", 200);
  if (ready.status !== "ready" || ready.service !== "api" ||
      typeof ready.schemaVersion !== "string" || ready.schemaVersion.length > 128 ||
      !/^\d{4}_[a-z][a-z0-9_]*$/.test(ready.schemaVersion)) {
    throw new Error("/ready: database/schema not ready");
  }
  if (health.release !== ready.release) throw new Error("Health/readiness release mismatch");
  if (expectedRelease && ready.release !== expectedRelease) {
    throw new Error("Deployed release does not match expected commit");
  }
  const schema = await expectJson("/openapi.json", 200);
  const routes = ["/health", "/ready", "/v1/security/me", "/v1/public/certifications/verify/{code}"];
  if (typeof schema.openapi !== "string" || !/^3\./.test(schema.openapi) ||
      routes.some(path => !schema.paths?.[path]?.get ||
        typeof schema.paths[path].get !== "object" || Array.isArray(schema.paths[path].get))) {
    throw new Error("OpenAPI is missing required routes");
  }
  await expectJson("/v1/security/me", 401, undefined, false);
  const absent = await expectJson("/v1/public/certifications/verify/does-not-exist", 200);
  if (absent.found !== false || absent.valid !== false ||
      ["certificationId", "certificateNumber", "storedStatus", "effectiveStatus", "publicArtifact"]
        .some(key => absent[key] !== null) || typeof absent.checkedAt !== "string" ||
      !Number.isFinite(Date.parse(absent.checkedAt))) {
    throw new Error("Public verification did not reject the nonexistent certification");
  }
  let authenticated = false;
  if (operatorToken) {
    const identity = await expectJson("/v1/security/me", 200, operatorToken);
    // AuthenticatedOperator has principal.organizationId and credential scope;
    // there is deliberately no top-level organization object in the real API.
    const { principal, credential } = identity;
    if (!nonEmptyId(principal?.id) || !nonEmptyId(principal?.organizationId) ||
        principal.status !== "active" || !nonEmptyId(credential?.id) ||
        credential.status !== "active" || credential.principalId !== principal.id ||
        credential.organizationId !== principal.organizationId ||
        !Array.isArray(identity.roles) || !Array.isArray(identity.permissions) ||
        !identity.permissions.every(value => typeof value === "string")) {
      throw new Error("Authenticated identity response is incomplete");
    }
    if (expectedOrganizationId && principal.organizationId !== expectedOrganizationId) {
      throw new Error("Authenticated identity does not match expected organization");
    }
    authenticated = true;
  }
  return { apiOrigin: origin, release: ready.release ?? null, authenticated };
}

async function main() {
  const required = process.argv.includes("--require-auth");
  const result = await verifyDeployment({
    baseUrl: process.env.CAIAE_SMOKE_API_URL,
    operatorToken: process.env.CAIAE_SMOKE_OPERATOR_TOKEN,
    requireAuth: required,
    expectedRelease: process.env.CAIAE_SMOKE_EXPECTED_RELEASE,
    expectedOrganizationId: process.env.CAIAE_SMOKE_EXPECTED_ORGANIZATION_ID,
  });
  console.log(JSON.stringify({ status: "passed", ...result }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error("Deployment smoke check failed: " +
      (error instanceof Error ? error.message : "unknown error"));
    process.exitCode = 1;
  });
}

