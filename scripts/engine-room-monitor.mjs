import { createHmac, randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { isIP } from "node:net";

export function httpsOrigin(raw, label) {
  if (typeof raw !== "string" || !raw) throw new Error(label + " is required");
  if (/[\s\\]/u.test(raw) || !/^[a-z]+:\/\/[^/?#]+\/?$/i.test(raw)) {
    throw new Error(label + " must contain only an unambiguous origin");
  }
  let url;
  try { url = new URL(raw); } catch { throw new Error(label + " is not a valid URL"); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error(label + " must contain only an origin");
  }
  if (url.protocol !== "https:") throw new Error(label + " must use HTTPS");
  const hostname = url.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost") ||
      isIP(hostname.replace(/^\\[|\\]$/g, ""))) {
    throw new Error(label + " must use a named public HTTPS service");
  }
  return url.origin;
}

export function p95(values) {
  if (!Array.isArray(values) || values.length > 20 ||
      values.some(value => !Number.isFinite(value) || value < 0)) {
    throw new Error("Invalid latency samples");
  }
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round(sorted[Math.ceil(sorted.length * 0.95) - 1] * 100) / 100;
}

function commitSha(raw) {
  if (typeof raw !== "string" || !/^[a-f0-9]{40}$/i.test(raw)) {
    throw new Error("Expected monitoring release must be a full commit SHA");
  }
  return raw;
}

export function monitorExpectedRelease(env = process.env) {
  // The existing manual acceptance step already inherits these GitHub values.
  // Ordinary monitoring need not assume that every main commit is deployed.
  const acceptance = env.GITHUB_WORKFLOW === "Production Acceptance (manual)" ||
    (typeof env.GITHUB_WORKFLOW_REF === "string" &&
      /\/\.github\/workflows\/production-acceptance\.yml@/.test(env.GITHUB_WORKFLOW_REF));
  if (acceptance) {
    const workflowRelease = commitSha(env.GITHUB_SHA);
    if (env.CAIAE_MONITOR_EXPECTED_RELEASE !== undefined &&
        commitSha(env.CAIAE_MONITOR_EXPECTED_RELEASE) !== workflowRelease) {
      throw new Error("Monitoring release pin conflicts with the acceptance workflow commit");
    }
    return workflowRelease;
  }
  if (env.CAIAE_MONITOR_EXPECTED_RELEASE !== undefined) return commitSha(env.CAIAE_MONITOR_EXPECTED_RELEASE);
  return undefined;
}

function requestLimits(timeoutMs, maxResponseBytes) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 ||
      !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 ||
      maxResponseBytes > 1048576) throw new Error("Invalid monitoring resource limits");
}

async function untilAbort(promise, signal) {
  if (signal.aborted) throw new Error("Monitoring request timed out");
  let abort;
  const interrupted = new Promise((_, reject) => {
    abort = () => reject(new Error("Monitoring request timed out"));
    signal.addEventListener("abort", abort, { once: true });
  });
  try { return await Promise.race([promise, interrupted]); }
  finally { signal.removeEventListener("abort", abort); }
}

async function exchange(url, init, { fetchImpl, timeoutMs, maxResponseBytes, json }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  let reader;
  try {
    response = await untilAbort(fetchImpl(url, {
      ...init, redirect: "error", credentials: "omit", cache: "no-store",
      signal: controller.signal,
    }), controller.signal);
    if (response.redirected || (response.url && response.url !== url)) {
      throw new Error("Redirected response is forbidden");
    }
    if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
      throw new Error("Invalid response status");
    }
    if (!json) return { status: response.status };
    if (response.status !== 200) throw new Error("Readiness request rejected");
    const mediaType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase();
    if (!mediaType || !/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/.test(mediaType)) {
      throw new Error("Expected JSON readiness response");
    }
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) ||
        !Number.isSafeInteger(Number(length)) || Number(length) > maxResponseBytes)) {
      throw new Error("Invalid response length");
    }
    if (!response.body) throw new Error("Missing readiness body");
    reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await untilAbort(reader.read(), controller.signal);
      if (done) break;
      size += value.byteLength;
      if (size > maxResponseBytes) throw new Error("Readiness body exceeds byte limit");
      chunks.push(value);
    }
    const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size)));
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid readiness object");
    return { status: response.status, body };
  } catch {
    // Transport errors/redirect destinations/body text can contain signed data.
    throw new Error("Monitoring request failed or exceeded its limits");
  } finally {
    clearTimeout(timer);
    controller.abort();
    if (reader) {
      void reader.cancel().catch(() => {});
      try { reader.releaseLock(); } catch { /* pending read cancelled */ }
    } else if (response?.body) {
      void response.body.cancel().catch(() => {});
    }
  }
}

export async function probeApi(origin, {
  count = 5, fetchImpl = fetch, expectedRelease,
  timeoutMs = 10000, maxResponseBytes = 65536,
} = {}) {
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new Error("Invalid probe count");
  requestLimits(timeoutMs, maxResponseBytes);
  if (expectedRelease !== undefined) commitSha(expectedRelease);
  const url = httpsOrigin(origin, "CAIAE_MONITOR_API_URL") + "/ready?includeWorker=true";
  let success = 0;
  let sampledRelease = null;
  let sampledSchema = null;
  const latencies = [];
  for (let i = 0; i < count; i++) {
    const start = performance.now();
    try {
      const { body } = await exchange(url, {
        method: "GET",
        headers: { accept: "application/json" },
      }, { fetchImpl, timeoutMs, maxResponseBytes, json: true });
      if (body.status !== "ready" || body.service !== "api" ||
          typeof body.schemaVersion !== "string" || body.schemaVersion.length > 128 ||
          !/^\d{4}_[a-z][a-z0-9_]*$/.test(body.schemaVersion)) continue;
      commitSha(body.release);
      if (expectedRelease && body.release !== expectedRelease) continue;
      const stamp = typeof body.timestamp === "string" ? Date.parse(body.timestamp) : NaN;
      const age = Date.now() - stamp;
      if (!Number.isFinite(stamp) || age < -30000 || age > 60000) continue;
      if (sampledRelease && (body.release !== sampledRelease || body.schemaVersion !== sampledSchema)) continue;
      sampledRelease = body.release;
      sampledSchema = body.schemaVersion;
      success += 1;
      latencies.push(performance.now() - start);
    } catch {
      // A failed response, network outage, or timeout counts as unavailable.
    }
  }
  return { count, success, latencyP95Ms: p95(latencies), observedAt: new Date().toISOString(), release: sampledRelease };
}

export function metricEnvelope(probe, id = randomUUID()) {
  if (!probe || !Number.isInteger(probe.count) || probe.count < 1 || probe.count > 20 ||
      !Number.isInteger(probe.success) || probe.success < 0 || probe.success > probe.count ||
      typeof probe.observedAt !== "string" || !Number.isFinite(Date.parse(probe.observedAt)) ||
      (probe.success === 0 ? probe.latencyP95Ms !== null :
        !Number.isFinite(probe.latencyP95Ms) || probe.latencyP95Ms < 0) ||
      typeof id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(id)) {
    throw new Error("Invalid measured monitoring evidence");
  }
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

function signingInputs(keyId, secret, timestamp) {
  if (typeof keyId !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) throw new Error("Invalid telemetry key ID");
  if (typeof secret !== "string" || Buffer.byteLength(secret) < 32 ||
      Buffer.byteLength(secret) > 1024) throw new Error("Telemetry secret is missing or too short");
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error("Invalid telemetry timestamp");
}

export function signedTelemetry(envelope, keyId, secret, timestamp = Date.now()) {
  signingInputs(keyId, secret, timestamp);
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

export async function sendTelemetry(origin, signed, fetchImpl = fetch, { timeoutMs = 10000 } = {}) {
  requestLimits(timeoutMs, 65536);
  const url = httpsOrigin(origin, "ENGINE_ROOM_BASE_URL") + "/api/telemetry";
  const response = await exchange(url, {
    method: "POST",
    headers: signed.headers,
    body: signed.body,
  }, { fetchImpl, timeoutMs, maxResponseBytes: 65536, json: false });
  if (response.status !== 200 && response.status !== 202) {
    throw new Error("Engine Room telemetry rejected the delivery (HTTP " + response.status + ")");
  }
  return response.status;
}

export async function runMonitor({ env = process.env, fetchImpl = fetch } = {}) {
  // Validate both endpoints and the signing credential before the probes begin.
  const apiOrigin = httpsOrigin(env.CAIAE_MONITOR_API_URL, "CAIAE_MONITOR_API_URL");
  const roomOrigin = httpsOrigin(env.ENGINE_ROOM_BASE_URL, "ENGINE_ROOM_BASE_URL");
  const keyId = env.ENGINE_ROOM_TELEMETRY_KEY_ID;
  const secret = env.ENGINE_ROOM_TELEMETRY_SECRET;
  const expectedRelease = monitorExpectedRelease(env);
  signingInputs(keyId, secret, Date.now());

  const probe = await probeApi(apiOrigin, { fetchImpl, expectedRelease });
  const envelope = metricEnvelope(probe);
  await sendTelemetry(roomOrigin, signedTelemetry(envelope, keyId, secret), fetchImpl);
  const receipt = {
    delivery: "accepted", samples: probe.count, successes: probe.success,
    availabilityPercent: envelope.records[0].value, latencyP95Ms: probe.latencyP95Ms,
    release: probe.release,
  };
  if (probe.success !== probe.count) {
    throw new Error("CAIAE API readiness is degraded (" + probe.success + "/" + probe.count + ")");
  }
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runMonitor().then(receipt => console.log(JSON.stringify(receipt))).catch(error => {
    console.error("CAIAE monitoring failed: " + (error instanceof Error ? error.message : "unknown error"));
    process.exitCode = 1;
  });
}

