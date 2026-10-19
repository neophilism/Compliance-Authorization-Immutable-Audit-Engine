import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { deploymentBaseUrl, verifyDeployment } from "./verify-deployment.mjs";

const RELEASE = "a".repeat(40);
const OPTIONS = { baseUrl: "https://engine.example", expectedRelease: RELEASE };

function mockBody(path, token, release) {
  if (path === "/health") return { status: "ok", service: "api", release };
  if (path === "/ready") return { status: "ready", service: "api", schemaVersion: "0014_worker_activity", release };
  if (path === "/openapi.json") return {
    openapi: "3.1.0", paths: Object.fromEntries([
      "/health", "/ready", "/v1/security/me", "/v1/public/certifications/verify/{code}",
    ].map(path => [path, { get: {} }])),
  };
  if (path === "/v1/security/me") return token ? {
    principal: { id: "p", organizationId: "o", status: "active" },
    credential: { id: "c", organizationId: "o", principalId: "p", status: "active" },
    roles: [], permissions: [],
  } : { error: "unauthorized" };
  if (path.includes("/public/certifications/verify/")) return {
    found: false, valid: false, certificationId: null, certificateNumber: null,
    storedStatus: null, effectiveStatus: null, publicArtifact: null,
    checkedAt: new Date().toISOString(),
  };
  return {};
}

function mockedApi({ anonymousStatus = 401, release = RELEASE, change = body => body } = {}) {
  const seen = [];
  const fetchImpl = async (raw, options = {}) => {
    const url = new URL(raw);
    seen.push({ path: url.pathname, ...options });
    const token = options.headers?.authorization;
    let status = 200;
    let body = mockBody(url.pathname, token, release);
    if (url.pathname === "/v1/security/me") {
      status = token ? 200 : anonymousStatus;
    } else if (!["/health", "/ready", "/openapi.json"].includes(url.pathname) &&
        !url.pathname.includes("/public/certifications/verify/")) {
      status = 404;
    }
    body = change(body, url.pathname, options);
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
    expectedRelease: RELEASE,
    expectedOrganizationId: "o",
    fetchImpl,
  });
  assert.deepEqual(result, {
    apiOrigin: "https://engine.example",
    release: RELEASE,
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
    /unexpected HTTP status/,
  );
});

test("fails when deployed commit does not match expected release", async () => {
  await assert.rejects(
    verifyDeployment({
      baseUrl: "https://engine.example",
      expectedRelease: "b".repeat(40),
      fetchImpl: mockedApi().fetchImpl,
    }),
    /does not match expected commit/,
  );
});

test("all requests are read-only, bounded and credential-isolated", async () => {
  const { fetchImpl, seen } = mockedApi();
  await verifyDeployment({ ...OPTIONS, operatorToken: "test-token", requireAuth: true, fetchImpl });
  assert.equal(seen.length, 6);
  for (const item of seen) {
    assert.equal(item.method, "GET");
    assert.equal(item.redirect, "error");
    assert.equal(item.credentials, "omit");
    assert.equal(item.cache, "no-store");
    assert.ok(item.signal instanceof AbortSignal);
  }
  assert.equal(seen.filter(item => item.headers.authorization).length, 1);
  assert.equal(seen.at(-1).path, "/v1/security/me");
});

test("validates credentials, full expected SHA and tenant before making any request", async () => {
  for (const options of [
    { operatorToken: "test", requireAuth: true },
    { operatorToken: "test", expectedRelease: "abc123" },
    { operatorToken: "test", expectedRelease: null },
    { operatorToken: "test", expectedRelease: " " },
    { operatorToken: "test\nsecret" },
    { operatorToken: "two words" },
    { operatorToken: "" },
    { operatorToken: {} },
    { expectedOrganizationId: "o" },
    { expectedOrganizationId: " " },
    { timeoutMs: 0 }, { timeoutMs: Infinity }, { maxResponseBytes: 0 },
  ]) {
    let called = false;
    await assert.rejects(verifyDeployment({
      baseUrl: OPTIONS.baseUrl, ...options,
      fetchImpl: async () => { called = true; throw new Error("should not run"); },
    }));
    assert.equal(called, false);
  }
});

test("rejects URL parser normalization and empty query/fragment ambiguity", () => {
  for (const raw of [
    " https://engine.example", "https://engine.example\n", "https://engine.example/one/..",
    "https://engine.example?", "https://engine.example#", "https:\\engine.example",
    "https:engine.example", "https://engine.example\\anything", "http://localhost.evil",
    "ftp://localhost", "https://user:pass@engine.example",
  ]) assert.throws(() => deploymentBaseUrl(raw));
  for (const raw of [
    "https://10.0.0.1", "https://172.16.0.1", "https://192.168.1.2",
    "https://169.254.169.254", "https://127.0.0.2",
    "https://100.64.0.1", "https://[fc00::1]", "https://8.8.8.8",
  ]) assert.throws(() => deploymentBaseUrl(raw), /forbidden/);
  assert.equal(deploymentBaseUrl("http://[::1]:4000/"), "http://[::1]:4000");
});

for (const [name, change] of [
  ["missing release", (body, path) => path === "/health" ? { ...body, release: null } : body],
  ["mismatched release", (body, path) => path === "/ready" ? { ...body, release: "b".repeat(40) } : body],
  ["wrong service", (body, path) => path === "/health" ? { ...body, service: "unrelated" } : body],
  ["missing schema version", (body, path) => path === "/ready" ? { ...body, schemaVersion: null } : body],
  ["fractional schema version", (body, path) => path === "/ready" ? { ...body, schemaVersion: 1.5 } : body],
  ["error JSON with HTTP200", (body, path) => path.includes("/verify/") ? { error: "database unavailable" } : body],
  ["nonexistent certification marked valid", (body, path) => path.includes("/verify/") ? { ...body, valid: true } : body],
  ["private artifact in nonexistent result", (body, path) => path.includes("/verify/") ? { ...body, publicArtifact: {} } : body],
  ["stale public verification timestamp", (body, path) => path.includes("/verify/") ? { ...body, checkedAt: "2020-01-01T00:00:00Z" } : body],
  ["timezone-unqualified public verification timestamp", (body, path) => path.includes("/verify/") ? { ...body, checkedAt: "2026-10-19T00:00:00" } : body],
  ["future public verification timestamp", (body, path) => path.includes("/verify/") ? { ...body, checkedAt: "2099-01-01T00:00:00Z" } : body],
  ["wrong OpenAPI version", (body, path) => path === "/openapi.json" ? { ...body, openapi: "2.0" } : body],
  ["missing GET route", (body, path) => path === "/openapi.json" ? { ...body, paths: { "/ready": {} } } : body],
  ["legacy invented identity shape", (body, path, options) => path === "/v1/security/me" && options.headers.authorization ? { principal: { id: "p" }, organization: { id: "o" } } : body],
  ["cross-tenant credential", (body, path, options) => path === "/v1/security/me" && options.headers.authorization ? { ...body, credential: { ...body.credential, organizationId: "other" } } : body],
  ["wrong credential principal", (body, path, options) => path === "/v1/security/me" && options.headers.authorization ? { ...body, credential: { ...body.credential, principalId: "other" } } : body],
  ["revoked credential", (body, path, options) => path === "/v1/security/me" && options.headers.authorization ? { ...body, credential: { ...body.credential, status: "revoked" } } : body],
  ["inactive principal", (body, path, options) => path === "/v1/security/me" && options.headers.authorization ? { ...body, principal: { ...body.principal, status: "inactive" } } : body],
]) {
  test("rejects " + name, async () => {
    await assert.rejects(verifyDeployment({
      ...OPTIONS, operatorToken: "test-token", requireAuth: true,
      fetchImpl: mockedApi({ change }).fetchImpl,
    }));
  });
}

test("rejects a valid identity belonging to a different expected organization", async () => {
  await assert.rejects(verifyDeployment({
    ...OPTIONS, operatorToken: "test-token", expectedOrganizationId: "other",
    fetchImpl: mockedApi().fetchImpl,
  }), /expected organization/);
});

test("rejects followed responses even when an injected fetch ignores redirect:error", async () => {
  const response = new Response("{}", { headers: { "content-type": "application/json" } });
  Object.defineProperty(response, "redirected", { value: true });
  await assert.rejects(verifyDeployment({ ...OPTIONS, fetchImpl: async () => response }), /redirected/);
});

test("rejects response URL substitution", async () => {
  const response = new Response("{}", { headers: { "content-type": "application/json" } });
  Object.defineProperty(response, "url", { value: "https://other.example/health" });
  await assert.rejects(verifyDeployment({ ...OPTIONS, fetchImpl: async () => response }), /redirected/);
});

test("never includes provider errors, response bodies or credentials in thrown errors", async () => {
  const secret = "DO-NOT-LOG-test-token";
  const normal = mockedApi().fetchImpl;
  await assert.rejects(verifyDeployment({
    ...OPTIONS, operatorToken: secret,
    fetchImpl: async (url, options) => {
      if (options.headers.authorization) throw new Error(secret + " https://user:password@host/?key=secret");
      return normal(url, options);
    },
  }), error => {
    assert.equal(error.message, "/v1/security/me: request failed");
    assert.equal(error.cause, undefined);
    assert.equal(String(error).includes(secret), false);
    return true;
  });
});

for (const [name, body, headers, maxResponseBytes] of [
  ["non-JSON media", "{}", { "content-type": "text/html" }, 1024],
  ["malformed JSON", "not-json-private-content", { "content-type": "application/json" }, 1024],
  ["JSON primitive", "true", { "content-type": "application/json" }, 1024],
  ["JSON array", "[]", { "content-type": "application/json" }, 1024],
  ["oversized declared body", "{}", { "content-type": "application/json", "content-length": "5000" }, 1024],
  ["invalid length", "{}", { "content-type": "application/json", "content-length": "NaN" }, 1024],
  ["oversized actual body", " ".repeat(1025), { "content-type": "application/json" }, 1024],
  ["lying content length", " ".repeat(1025), { "content-type": "application/json", "content-length": "1" }, 1024],
  ["invalid UTF8", new Uint8Array([0xff, 0xfe]), { "content-type": "application/json" }, 1024],
]) {
  test("bounds and rejects " + name, async () => {
    await assert.rejects(verifyDeployment({ ...OPTIONS, maxResponseBytes,
      fetchImpl: async () => new Response(body, { headers }),
    }));
  });
}

test("bounds header and body waits even for an uncooperative fetch or reader", async () => {
  await assert.rejects(verifyDeployment({ ...OPTIONS, timeoutMs: 20,
    fetchImpl: () => new Promise(() => {}),
  }), /timed out/);
  let cancelled = false;
  const stream = new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { cancelled = true; } });
  await assert.rejects(verifyDeployment({ ...OPTIONS, timeoutMs: 20,
    fetchImpl: async () => new Response(stream, { headers: { "content-type": "application/json" } }),
  }), /timed out/);
  assert.equal(cancelled, true);
});

test("cancels a chunked oversized response", async () => {
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(600)); },
    cancel() { cancelled = true; },
  });
  await assert.rejects(verifyDeployment({ ...OPTIONS, maxResponseBytes: 1024,
    fetchImpl: async () => new Response(stream, { headers: { "content-type": "application/json" } }),
  }), /byte limit/);
  assert.equal(cancelled, true);
});

test("real HTTP fixture verifies the actual operator contract and stops authenticated redirects", async (t) => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push({ path: req.url, token: req.headers.authorization, method: req.method });
    if (req.url === "/v1/security/me" && req.headers.authorization && seen.redirectAuth) {
      res.writeHead(302, { location: "/credential-sink" }); res.end(); return;
    }
    res.writeHead(req.url === "/v1/security/me" && !req.headers.authorization ? 401 : 200,
      { "content-type": "application/json" });
    res.end(JSON.stringify(mockBody(req.url, req.headers.authorization, RELEASE)));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const baseUrl = "http://127.0.0.1:" + server.address().port;
  const options = { baseUrl, expectedRelease: RELEASE, requireAuth: true, operatorToken: "synthetic-fixture-token" };
  assert.equal((await verifyDeployment(options)).authenticated, true);
  seen.redirectAuth = true;
  await assert.rejects(verifyDeployment(options), /request failed/);
  assert.equal(seen.some(item => item.path === "/credential-sink"), false);
  assert.equal(seen.filter(item => item.token).every(item => item.path === "/v1/security/me"), true);
  assert.equal(seen.every(item => item.method === "GET"), true);
});

