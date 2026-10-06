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
