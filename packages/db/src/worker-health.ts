import type { Pool } from "pg";

export const WORKER_SWEEP_NAMES = ["authorization", "exception", "deadline", "evaluation", "certification", "webhook"] as const;
export type WorkerSweepName = (typeof WORKER_SWEEP_NAMES)[number];

export async function startWorkerActivity(pool: Pool, instanceId: string, releaseSha: string | null): Promise<void> {
  await pool.query(
    "INSERT INTO worker_activity(worker_name, instance_id, release_sha, last_seen_at, sweeps) " +
    "VALUES ('scheduler', $1::uuid, $2, now(), '{}'::jsonb) " +
    "ON CONFLICT(worker_name) DO UPDATE SET instance_id=EXCLUDED.instance_id, " +
    "release_sha=EXCLUDED.release_sha, last_seen_at=now(), sweeps='{}'::jsonb",
    [instanceId, releaseSha],
  );
}

export async function recordWorkerSweep(
  pool: Pool,
  input: { instanceId: string; name: WorkerSweepName; succeeded: boolean },
): Promise<void> {
  if (!WORKER_SWEEP_NAMES.includes(input.name)) throw new Error("Unknown worker sweep");
  const at = new Date().toISOString();
  const result = await pool.query(
    "UPDATE worker_activity SET " +
    "sweeps=jsonb_set(sweeps, ARRAY[$2::text], jsonb_build_object('status', $3::text, 'at', $4::text), true), " +
    "last_seen_at=$4::timestamptz " +
    "WHERE worker_name='scheduler' AND instance_id=$1::uuid",
    [input.instanceId, input.name, input.succeeded ? "ok" : "failed", at],
  );
  if (result.rowCount !== 1) throw new Error("Worker instance no longer owns the heartbeat");
}

export type WorkerHealthVerdict =
  | { healthy: true }
  | { healthy: false; reason: "missing" | "stale" | "incomplete" | "failed" | "release_mismatch" };

export async function assessWorkerHealth(
  pool: Pool,
  maxAgeMs = 180_000,
  expectedRelease: string | null = null,
  now = new Date(),
): Promise<WorkerHealthVerdict> {
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1000) throw new Error("Invalid worker freshness window");
  const result = await pool.query(
    "SELECT release_sha, last_seen_at, sweeps FROM worker_activity WHERE worker_name='scheduler'",
  );
  const row = result.rows[0];
  if (!row) return { healthy: false, reason: "missing" };
  if (expectedRelease && row.release_sha !== expectedRelease) return { healthy: false, reason: "release_mismatch" };
  const fresh = (date: unknown) => {
    const when = new Date(date as string | number).getTime();
    const age = now.getTime() - when;
    return Number.isFinite(when) && age >= -30_000 && age <= maxAgeMs;
  };
  if (!fresh(row.last_seen_at)) return { healthy: false, reason: "stale" };
  const sweeps = row.sweeps as Record<string, { status?: string; at?: string }> | null;
  if (!sweeps || typeof sweeps !== "object" || Array.isArray(sweeps)) {
    return { healthy: false, reason: "incomplete" };
  }
  for (const name of WORKER_SWEEP_NAMES) {
    const status = sweeps[name];
    if (!status || typeof status !== "object") return { healthy: false, reason: "incomplete" };
    if (status.status === "failed") return { healthy: false, reason: "failed" };
    if (status.status !== "ok") return { healthy: false, reason: "incomplete" };
    if (!fresh(status.at)) return { healthy: false, reason: "stale" };
  }
  return { healthy: true };
}
