export { createPool } from "./client.js";
export { DomainRepository } from "./repository.js";
export type {
  UpdateResourceInput,
  UpdateResourceResult,
} from "./repository.js";
export {
  LATEST_SCHEMA_VERSION,
  runMigrations,
} from "./migrations.js";
export {
  AuditLedger,
  appendAuditEventWithClient,
  canonicalJson,
  hashAuditEvent,
  verifyAuditChain,
} from "./audit.js";
export type {
  AppendAuditEventInput,
  AuditVerificationResult,
} from "./audit.js";
export {
  collectAuditCheckpoint,
  signAuditCheckpoint,
  verifyAuditCheckpointSignature,
  verifyAuditCheckpointAgainstDatabase,
} from "./audit-anchor.js";
export type {
  AuditCheckpoint,
  AuditChainHead,
  SignedAuditCheckpoint,
  CheckpointVerification,
} from "./audit-anchor.js";
export {
  WORKER_SWEEP_NAMES, startWorkerActivity, recordWorkerSweep, assessWorkerHealth,
} from "./worker-health.js";
export type { WorkerSweepName, WorkerHealthVerdict } from "./worker-health.js";
