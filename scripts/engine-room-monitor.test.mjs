import assert from "node:assert/strict";
import test from "node:test";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";
import { httpsOrigin, p95, probeApi, metricEnvelope, signedTelemetry, sendTelemetry, monitorExpectedRelease, runMonitor } from "./engine-room-monitor.mjs";

const RELEASE = "a".repeat(40);
const SECRET = "synthetic-only-minimum-32-byte-hmac-key";
const ENV = {
  CAIAE_MONITOR_API_URL: "https://api.example",
  ENGINE_ROOM_BASE_URL: "https://room.example",
  ENGINE_ROOM_TELEMETRY_KEY_ID: "fixture-key",
  ENGINE_ROOM_TELEMETRY_SECRET: SECRET,
};
const ready = (patch = {}) => ({ status: "ready", service: "api", release: RELEASE,
  schemaVersion: "0014_worker_activity", timestamp: new Date().toISOString(), ...patch });
const json = body => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });

test("production monitoring requires HTTPS origins with no embedded credentials", () => {
  assert.equal(httpsOrigin("https://engine.example/", "API"), "https://engine.example");
  assert.throws(() => httpsOrigin("http://engine.example", "API"), /HTTPS/);
  assert.throws(() => httpsOrigin("https://name:secret@engine.example", "API"), /origin/);
  assert.throws(() => httpsOrigin("https://engine.example/hidden", "API"), /origin/);
});

test("p95 uses observed samples, never a fabricated latency on outage", () => {
  assert.equal(p95([]), null);
  assert.equal(p95([10, 20, 30, 40, 50]), 50);
});

test("readiness sampling records actual success and failed probes", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    if (calls === 2) throw new Error("simulated outage");
    return new Response(JSON.stringify(ready({ status: calls === 3 ? "unavailable" : "ready" })), {
      status: calls === 3 ? 503 : 200,
      headers: { "content-type": "application/json" },
    });
  };
  const probe = await probeApi("https://engine.example", { count: 5, fetchImpl });
  assert.equal(probe.count, 5);
  assert.equal(probe.success, 3);
  const envelope = metricEnvelope(probe, "delivery-example");
  assert.equal(envelope.records[0].value, 60);
  assert.equal(envelope.records[1].value, 40);
  assert.ok(envelope.records[2].value >= 0);
  assert.equal(envelope.records[2].metric, "latency-p95-ms");
});

test("rejects ambiguous URLs before network access", () => {
  for (const raw of [undefined, {}, " https://api.example", "https://api.example\n",
    "https:\\api.example", "https:api.example", "https://api.example?", "https://api.example#",
    "https://api.example/a/..", "https://api.example\\path"]) {
    assert.throws(() => httpsOrigin(raw, "API"));
  }
});

test("manual acceptance automatically pins the workflow commit, ordinary monitoring does not guess it", () => {
  assert.equal(monitorExpectedRelease({ GITHUB_WORKFLOW: "Production Acceptance (manual)", GITHUB_SHA: RELEASE }), RELEASE);
  assert.equal(monitorExpectedRelease({ GITHUB_WORKFLOW: "Engine Room Production Monitor", GITHUB_SHA: RELEASE }), undefined);
  assert.equal(monitorExpectedRelease({ CAIAE_MONITOR_EXPECTED_RELEASE: RELEASE }), RELEASE);
  for (const env of [{ GITHUB_WORKFLOW: "Production Acceptance (manual)" },
    { CAIAE_MONITOR_EXPECTED_RELEASE: "abc123" }, { CAIAE_MONITOR_EXPECTED_RELEASE: "" }]) {
    assert.throws(() => monitorExpectedRelease(env));
  }
});

test("probe sends only bounded anonymous GETs to full worker readiness", async () => {
  let calls = 0;
  const probe = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 2, expectedRelease: RELEASE,
    fetchImpl: async (url, options) => {
      calls++;
      assert.equal(url, "https://api.example/ready?includeWorker=true");
      assert.equal(options.method, "GET");
      assert.equal(options.redirect, "error");
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.headers.authorization, undefined);
      assert.ok(options.signal instanceof AbortSignal);
      return json(ready());
    },
  });
  assert.equal(calls, 2);
  assert.equal(probe.success, 2);
  assert.equal(probe.release, RELEASE);
});

for (const [name, patch] of [
  ["minimal ready object", null], ["wrong service", { service: "other" }],
  ["no release", { release: null }], ["short release", { release: "abc123" }],
  ["numeric schema", { schemaVersion: 14 }], ["no schema", { schemaVersion: null }],
  ["no timestamp", { timestamp: null }], ["stale timestamp", { timestamp: "2000-01-01T00:00:00Z" }],
  ["future timestamp", { timestamp: "2999-01-01T00:00:00Z" }],
  ["not ready", { status: "not_ready" }],
]) {
  test("does not count " + name + " as healthy", async () => {
    const probe = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 1,
      fetchImpl: async () => json(patch === null ? { status: "ready" } : ready(patch)),
    });
    assert.equal(probe.success, 0);
    assert.equal(probe.latencyP95Ms, null);
    assert.equal(probe.release, null);
  });
}

test("mismatched expected release and mixed-release/schema samples cannot produce 100 percent", async () => {
  const wrong = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 1,
    expectedRelease: "b".repeat(40), fetchImpl: async () => json(ready()) });
  assert.equal(wrong.success, 0);
  let calls = 0;
  const mixed = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 3, fetchImpl: async () => {
    calls++;
    return json(ready(calls === 2 ? { release: "b".repeat(40) } :
      calls === 3 ? { schemaVersion: "0015_other_revision" } : {}));
  } });
  assert.equal(mixed.success, 1);
  assert.equal(metricEnvelope(mixed).records[0].value, 33.33);
});

test("redirected and substituted response URLs count as failed probes", async () => {
  for (const prop of ["redirected", "url"]) {
    const response = json(ready());
    Object.defineProperty(response, prop, { value: prop === "url" ? "https://other.example/ready" : true });
    const probe = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 1, fetchImpl: async () => response });
    assert.equal(probe.success, 0);
  }
});

for (const [name, body, headers] of [
  ["HTML", "{}", { "content-type": "text/html" }],
  ["invalid JSON", "not-json-sensitive-error", { "content-type": "application/json" }],
  ["JSON array", "[]", { "content-type": "application/json" }],
  ["bad UTF8", new Uint8Array([0xff]), { "content-type": "application/json" }],
  ["oversized length", "{}", { "content-type": "application/json", "content-length": "5000" }],
  ["invalid length", "{}", { "content-type": "application/json", "content-length": "NaN" }],
  ["oversized body", " ".repeat(1025), { "content-type": "application/json" }],
  ["lying length", " ".repeat(1025), { "content-type": "application/json", "content-length": "1" }],
]) {
  test("counts " + name + " as failed without leaking body data", async () => {
    const probe = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 1, maxResponseBytes: 1024,
      fetchImpl: async () => new Response(body, { headers }) });
    assert.equal(probe.success, 0);
    assert.equal(probe.latencyP95Ms, null);
    assert.equal(JSON.stringify(probe).includes("sensitive-error"), false);
  });
}

test("timeouts cover headers and stalled bodies; streams are cancelled", async () => {
  let cancelled = false;
  const fetches = [() => new Promise(() => {}), async () => new Response(new ReadableStream({
    pull() { return new Promise(() => {}); }, cancel() { cancelled = true; },
  }), { headers: { "content-type": "application/json" } })];
  for (const fetchImpl of fetches) {
    const probe = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 1, timeoutMs: 20, fetchImpl });
    assert.equal(probe.success, 0);
  }
  assert.equal(cancelled, true);
});

test("oversized chunked responses are cancelled", async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(600)); },
    cancel() { cancelled = true; },
  }), { headers: { "content-type": "application/json" } });
  const probe = await probeApi(ENV.CAIAE_MONITOR_API_URL, { count: 1, maxResponseBytes: 1024,
    fetchImpl: async () => response });
  assert.equal(probe.success, 0);
  assert.equal(cancelled, true);
});

test("invalid probe arguments fail before requests", async () => {
  for (const options of [{ count: 0 }, { count: 21 }, { timeoutMs: 0 },
    { maxResponseBytes: Infinity }, { expectedRelease: "short" }]) {
    let called = false;
    await assert.rejects(probeApi(ENV.CAIAE_MONITOR_API_URL, { ...options,
      fetchImpl: async () => { called = true; return json(ready()); } }));
    assert.equal(called, false);
  }
});

test("invalid measurements and fabricated latency are rejected before signing", () => {
  const valid = { count: 5, success: 5, observedAt: new Date().toISOString(), latencyP95Ms: 1 };
  for (const patch of [{ count: 0 }, { count: NaN }, { success: 6 }, { success: -1 },
    { observedAt: "bad" }, { latencyP95Ms: NaN }, { latencyP95Ms: -1 },
    { success: 0, latencyP95Ms: 1 }, { success: 1, latencyP95Ms: null }]) {
    assert.throws(() => metricEnvelope({ ...valid, ...patch }));
  }
  assert.throws(() => metricEnvelope(valid, "invalid delivery\n"));
  for (const samples of [[NaN], [-1], [Infinity], "not samples"]) assert.throws(() => p95(samples));
  assert.throws(() => signedTelemetry({}, "bad\nkey", SECRET));
  assert.throws(() => signedTelemetry({}, "key", SECRET, NaN));
});

test("monitor validates endpoints, credentials and acceptance SHA before probing", async () => {
  for (const patch of [{ ENGINE_ROOM_TELEMETRY_SECRET: "short" },
    { ENGINE_ROOM_BASE_URL: "http://room.example" }, { ENGINE_ROOM_TELEMETRY_KEY_ID: "bad\nkey" },
    { GITHUB_WORKFLOW: "Production Acceptance (manual)" }]) {
    let called = false;
    await assert.rejects(runMonitor({ env: { ...ENV, ...patch }, fetchImpl: async () => { called = true; } }));
    assert.equal(called, false);
  }
});

test("orchestration posts only actual measured metrics and a secret-free success receipt", async () => {
  const calls = [];
  const receipt = await runMonitor({ env: { ...ENV, GITHUB_WORKFLOW: "Production Acceptance (manual)", GITHUB_SHA: RELEASE },
    fetchImpl: async (url, options) => {
      calls.push({ url, ...options });
      if (options.method === "GET") return json(ready());
      const signature = createHmac("sha256", SECRET).update(options.headers["x-engine-room-timestamp"] + ".").update(options.body).digest("hex");
      assert.equal(options.headers["x-engine-room-signature"], "sha256=" + signature);
      const envelope = JSON.parse(options.body);
      assert.equal(envelope.records[0].value, 100);
      assert.equal(envelope.records[1].value, 0);
      return new Response(null, { status: 202 });
    },
  });
  assert.equal(calls.length, 6);
  assert.equal(calls.filter(item => item.method === "POST").length, 1);
  assert.equal(calls.at(-1).url, "https://room.example/api/telemetry");
  assert.equal(calls.at(-1).redirect, "error");
  assert.equal(calls.slice(0, 5).some(item => item.headers["x-engine-room-signature"]), false);
  assert.equal(receipt.release, RELEASE);
  assert.equal(JSON.stringify(receipt).includes(SECRET), false);
});

test("degraded and total-outage runs deliver honest percentages then fail acceptance", async () => {
  for (const successes of [0, 3]) {
    let gets = 0;
    let posted;
    await assert.rejects(runMonitor({ env: ENV, fetchImpl: async (_url, options) => {
      if (options.method === "GET") { gets++; return gets <= successes ? json(ready()) : new Response(null, { status: 503 }); }
      posted = JSON.parse(options.body);
      return new Response(null, { status: 202 });
    } }), /readiness is degraded/);
    assert.equal(posted.records[0].value, successes * 20);
    assert.equal(posted.records[1].value, 100 - successes * 20);
    assert.equal(posted.records.length, successes ? 3 : 2);
  }
});

test("signed POST transport errors and followed redirects fail without leaking signature or URL", async () => {
  const signed = signedTelemetry(metricEnvelope({ count: 1, success: 0,
    observedAt: new Date().toISOString(), latencyP95Ms: null }), "fixture-key", SECRET);
  for (const fetchImpl of [
    async () => { throw new Error(SECRET + signed.headers["x-engine-room-signature"] + " https://user:password@host/"); },
    async () => { const response = new Response(null, { status: 202 }); Object.defineProperty(response, "redirected", { value: true }); return response; },
    () => new Promise(() => {}),
  ]) {
    await assert.rejects(sendTelemetry(ENV.ENGINE_ROOM_BASE_URL, signed, fetchImpl, { timeoutMs: 20 }), error => {
      assert.equal(error.message, "Monitoring request failed or exceeded its limits");
      assert.equal(error.cause, undefined);
      return true;
    });
  }
});

test("real loopback HTTP transport never forwards a signed redirect or retries an ambiguous POST", async (t) => {
  const seen = [];
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    seen.push({ path: req.url, headers: req.headers, body });
    res.writeHead(307, { location: "/signature-sink" }); res.end();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const signed = signedTelemetry(metricEnvelope({ count: 1, success: 0,
    observedAt: new Date().toISOString(), latencyP95Ms: null }), "fixture-key", SECRET);
  // Test-only translation to a loopback fixture; production accepts HTTPS only.
  const fetchImpl = (url, options) => {
    assert.equal(url, "https://room.example/api/telemetry");
    return fetch("http://127.0.0.1:" + server.address().port + "/api/telemetry", options);
  };
  await assert.rejects(sendTelemetry(ENV.ENGINE_ROOM_BASE_URL, signed, fetchImpl), /Monitoring request failed/);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].path, "/api/telemetry");
  assert.equal(seen[0].body, signed.body);
  assert.equal(seen[0].headers["x-engine-room-signature"], signed.headers["x-engine-room-signature"]);
});

test("total outages omit latency instead of reporting zero", () => {
  const envelope = metricEnvelope({
    count: 5, success: 0, observedAt: "2026-10-09T00:00:00.000Z", latencyP95Ms: null,
  }, "outage");
  assert.equal(envelope.records.length, 2);
  assert.equal(envelope.records[0].value, 0);
  assert.equal(envelope.records[1].value, 100);
});

test("signed delivery authenticates the exact HTTP body and is not logged", async () => {
  const secret = "minimum-32-byte-test-secret-for-hmac-testing";
  const envelope = metricEnvelope({
    count: 5, success: 5, observedAt: "2026-10-09T00:00:00.000Z", latencyP95Ms: 8,
  }, "probe-123");
  const signed = signedTelemetry(envelope, "caiae-test", secret, 1791500000000);
  const expected = createHmac("sha256", secret)
    .update("1791500000000.").update(signed.body).digest("hex");
  assert.equal(signed.headers["x-engine-room-signature"], "sha256=" + expected);
  let posted = false;
  const status = await sendTelemetry("https://room.example", signed, async (url, init) => {
    posted = true;
    assert.equal(url, "https://room.example/api/telemetry");
    assert.equal(init.body, signed.body);
    return { status: 202 };
  });
  assert.equal(status, 202);
  assert.equal(posted, true);
  await assert.rejects(
    sendTelemetry("https://room.example", signed, async () => ({ status: 401 })),
    /HTTP 401/,
  );
});

