import { pathToFileURL } from "node:url";

export function deploymentBaseUrl(raw) {
  if (typeof raw !== "string" || !raw.trim()) {
    throw new Error("CAIAE_SMOKE_API_URL is required");
  }
  let url;
  try { url = new URL(raw); } catch { throw new Error("Invalid API URL"); }
  if (url.username || url.password || url.search || url.hash ||
      (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("API URL must be an origin without credentials, query, fragment or path");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error("Remote deployment URL must use HTTPS");
  }
  return url.origin;
}

export async function verifyDeployment({
  baseUrl,
  operatorToken,
  requireAuth = false,
  expectedRelease,
  fetchImpl = fetch,
}) {
  const origin = deploymentBaseUrl(baseUrl);
  if (requireAuth && !operatorToken) {
    throw new Error("An operator token is required for the authenticated production smoke test");
  }
  async function request(path, token) {
    return fetchImpl(origin + path, {
      headers: {
        accept: "application/json",
        ...(token ? { authorization: "Bearer " + token } : {}),
      },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
  }
  async function expectJson(path, status, token) {
    const response = await request(path, token);
    if (response.status !== status) {
      throw new Error(path + ": expected HTTP " + status + ", got " + response.status);
    }
    try { return await response.json(); }
    catch { throw new Error(path + ": invalid JSON response"); }
  }
  const health = await expectJson("/health", 200);
  if (health?.status !== "ok") throw new Error("/health: unexpected liveness payload");
  const ready = await expectJson("/ready", 200);
  if (ready?.status !== "ready") throw new Error("/ready: database/schema not ready");
  if (health.release !== ready.release) throw new Error("Health/readiness release mismatch");
  if (expectedRelease && ready.release !== expectedRelease) {
    throw new Error("Deployed release does not match expected commit");
  }
  const schema = await expectJson("/openapi.json", 200);
  if (!schema?.paths?.["/v1/security/me"] || !schema?.paths?.["/ready"]) {
    throw new Error("OpenAPI is missing required routes");
  }
  const anonymous = await request("/v1/security/me");
  if (anonymous.status !== 401) {
    throw new Error("Internal operator identity endpoint is not rejecting anonymous access");
  }
  await expectJson("/v1/public/certifications/verify/does-not-exist", 200);
  let authenticated = false;
  if (operatorToken) {
    const identity = await expectJson("/v1/security/me", 200, operatorToken);
    if (!identity?.principal?.id || !identity?.organization?.id) {
      throw new Error("Authenticated identity response is incomplete");
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
