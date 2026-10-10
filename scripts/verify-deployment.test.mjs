import assert from "node:assert/strict";
import test from "node:test";
import { deploymentBaseUrl, verifyDeployment } from "./verify-deployment.mjs";

function mockedApi({ anonymousStatus = 401, release = "abc123" } = {}) {
  const seen = [];
  const fetchImpl = async (raw, options = {}) => {
    const url = new URL(raw);
    seen.push({ path: url.pathname, headers: options.headers });
    const token = options.headers?.authorization;
    let status = 200;
    let body = {};
    if (url.pathname === "/health") body = { status: "ok", release };
    else if (url.pathname === "/ready") body = { status: "ready", release };
    else if (url.pathname === "/openapi.json") {
      body = { paths: { "/v1/security/me": {}, "/ready": {} } };
    } else if (url.pathname === "/v1/security/me") {
      status = token ? 200 : anonymousStatus;
      body = token ? { principal: { id: "p" }, organization: { id: "o" } } : { error: "unauthorized" };
    } else if (url.pathname.includes("/public/certifications/verify/")) {
      body = { valid: false };
    } else {
      status = 404;
    }
    return new Response(JSON.stringify(body), {
      status, headers: { "content-type": "application/json" },
    });
  };
  return { fetchImpl, seen };
}

test("requires TLS for non-loopback deploy URLs", () => {
  assert.equal(deploymentBaseUrl("https://engine.example/"), "https://engine.example");
  assert.equal(deploymentBaseUrl("http://127.0.0.1:4000"), "http://127.0.0.1:4000");
  assert.throws(() => deploymentBaseUrl("http://engine.example"), /HTTPS/);
  assert.throws(() => deploymentBaseUrl("https://user:pass@engine.example"), /credentials/);
  assert.throws(() => deploymentBaseUrl("https://engine.example/path"), /origin/);
});

test("checks live release, readiness, authorization, public endpoint and OpenAPI", async () => {
  const { fetchImpl, seen } = mockedApi();
  const result = await verifyDeployment({
    baseUrl: "https://engine.example",
    operatorToken: "private-test-token",
    requireAuth: true,
    expectedRelease: "abc123",
    fetchImpl,
  });
  assert.deepEqual(result, {
    apiOrigin: "https://engine.example",
    release: "abc123",
    authenticated: true,
  });
  assert.ok(seen.some(v => v.path === "/v1/security/me" && !v.headers.authorization));
  assert.ok(seen.some(v => v.path === "/v1/security/me" && v.headers.authorization));
  assert.equal(JSON.stringify(result).includes("private-test-token"), false);
});

test("authenticated production check refuses missing operator credentials", async () => {
  await assert.rejects(
    verifyDeployment({
      baseUrl: "https://engine.example",
      requireAuth: true,
      fetchImpl: mockedApi().fetchImpl,
    }),
    /operator token is required/,
  );
});

test("fails closed when an internal route is anonymously accessible", async () => {
  await assert.rejects(
    verifyDeployment({ baseUrl: "https://engine.example", fetchImpl: mockedApi({ anonymousStatus: 200 }).fetchImpl }),
    /not rejecting anonymous/,
  );
});

test("fails when deployed commit does not match expected release", async () => {
  await assert.rejects(
    verifyDeployment({
      baseUrl: "https://engine.example",
      expectedRelease: "other",
      fetchImpl: mockedApi().fetchImpl,
    }),
    /does not match expected commit/,
  );
});
