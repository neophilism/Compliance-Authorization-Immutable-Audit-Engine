import assert from "node:assert/strict";
import test from "node:test";
import { createHmac } from "node:crypto";
import { httpsOrigin, p95, probeApi, metricEnvelope, signedTelemetry, sendTelemetry } from "./engine-room-monitor.mjs";

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
    return new Response(JSON.stringify({ status: calls === 3 ? "unavailable" : "ready" }), {
      status: calls === 3 ? 503 : 200,
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
