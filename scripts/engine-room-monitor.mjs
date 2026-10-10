import { createHmac, randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

export function httpsOrigin(raw, label) {
  if (!raw) throw new Error(label + " is required");
  let url;
  try { url = new URL(raw); } catch { throw new Error(label + " is not a valid URL"); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error(label + " must contain only an origin");
  }
  if (url.protocol !== "https:") throw new Error(label + " must use HTTPS");
  return url.origin;
}

export function p95(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round(sorted[Math.ceil(sorted.length * 0.95) - 1] * 100) / 100;
}

export async function probeApi(origin, { count = 5, fetchImpl = fetch } = {}) {
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new Error("Invalid probe count");
  const url = httpsOrigin(origin, "CAIAE_MONITOR_API_URL") + "/ready";
  let success = 0;
  const latencies = [];
  for (let i = 0; i < count; i++) {
    const start = performance.now();
    try {
      const response = await fetchImpl(url, {
        method: "GET",
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: AbortSignal.timeout(10000),
      });
      if (response.status !== 200) continue;
      const body = await response.json();
      if (body?.status !== "ready") continue;
      success += 1;
      latencies.push(performance.now() - start);
    } catch {
      // A failed response, network outage, or timeout counts as unavailable.
    }
  }
  return { count, success, latencyP95Ms: p95(latencies), observedAt: new Date().toISOString() };
}

export function metricEnvelope(probe, id = randomUUID()) {
  const stamp = probe.observedAt;
  const availability = Math.round(10000 * probe.success / probe.count) / 100;
  const records = [
    { kind: "metric", externalId: id + "-availability", metric: "availability-percent", value: availability, observedAt: stamp },
    { kind: "metric", externalId: id + "-errors", metric: "error-rate-percent", value: 100 - availability, observedAt: stamp },
  ];
  if (probe.latencyP95Ms !== null) {
    records.push({
      kind: "metric", externalId: id + "-latency", metric: "latency-p95-ms",
      value: probe.latencyP95Ms, observedAt: stamp,
    });
  }
  return { version: 1, deliveryId: id, records };
}

export function signedTelemetry(envelope, keyId, secret, timestamp = Date.now()) {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId || "")) throw new Error("Invalid telemetry key ID");
  if (typeof secret !== "string" || Buffer.byteLength(secret) < 32 ||
      Buffer.byteLength(secret) > 1024) throw new Error("Telemetry secret is missing or too short");
  const body = JSON.stringify(envelope);
  if (Buffer.byteLength(body) > 65536) throw new Error("Telemetry payload exceeds 64 KiB");
  const value = String(timestamp);
  const signature = createHmac("sha256", secret).update(value + ".").update(body).digest("hex");
  return {
    body,
    headers: {
      "content-type": "application/json",
      "x-engine-room-key": keyId,
      "x-engine-room-timestamp": value,
      "x-engine-room-signature": "sha256=" + signature,
    },
  };
}

export async function sendTelemetry(origin, signed, fetchImpl = fetch) {
  const url = httpsOrigin(origin, "ENGINE_ROOM_BASE_URL") + "/api/telemetry";
  const response = await fetchImpl(url, {
    method: "POST",
    headers: signed.headers,
    body: signed.body,
    signal: AbortSignal.timeout(10000),
  });
  if (response.status !== 200 && response.status !== 202) {
    throw new Error("Engine Room telemetry rejected the delivery (HTTP " + response.status + ")");
  }
  return response.status;
}

async function main() {
  // Validate both endpoints and the signing credential before the probes begin.
  const apiOrigin = httpsOrigin(process.env.CAIAE_MONITOR_API_URL, "CAIAE_MONITOR_API_URL");
  const roomOrigin = httpsOrigin(process.env.ENGINE_ROOM_BASE_URL, "ENGINE_ROOM_BASE_URL");
  const keyId = process.env.ENGINE_ROOM_TELEMETRY_KEY_ID;
  const secret = process.env.ENGINE_ROOM_TELEMETRY_SECRET;
  signedTelemetry(metricEnvelope({
    count: 1, success: 1, observedAt: new Date().toISOString(), latencyP95Ms: 1,
  }), keyId, secret);

  const probe = await probeApi(apiOrigin);
  const envelope = metricEnvelope(probe);
  await sendTelemetry(roomOrigin, signedTelemetry(envelope, keyId, secret));
  console.log(JSON.stringify({
    delivery: "accepted", samples: probe.count, successes: probe.success,
    availabilityPercent: envelope.records[0].value, latencyP95Ms: probe.latencyP95Ms,
  }));
  if (probe.success !== probe.count) {
    throw new Error("CAIAE API readiness is degraded (" + probe.success + "/" + probe.count + ")");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error("CAIAE monitoring failed: " + (error instanceof Error ? error.message : "unknown error"));
    process.exitCode = 1;
  });
}
