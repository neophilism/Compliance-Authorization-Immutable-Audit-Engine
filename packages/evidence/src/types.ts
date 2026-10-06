import type {
  Evidence,
  EvidenceAttestation,
  JsonObject,
} from "@caiae/core";
import type { EvaluationContext } from "@caiae/rules";

export type EvidenceErrorCode =
  | "validation"
  | "not_found"
  | "invalid_state";

export class EvidenceError extends Error {
  constructor(
    public readonly code: EvidenceErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "EvidenceError";
  }
}

export type CreateEvidenceInput = {
  organizationId: string;
  resourceId: string;
  evidenceType: string;
  title: string;
  submittedByPrincipalId?: string | null;
  source?: string | null;
  uri?: string | null;
  mediaType?: string | null;
  fileName?: string | null;
  checksumAlgorithm?: string | null;
  checksum?: string | null;
  capturedAt?: string | null;
  validFrom?: string | null;
  validUntil?: string | null;
  provenance?: JsonObject;
  supersedesEvidenceId?: string | null;
  attributes?: JsonObject;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type AddAttestationInput = {
  evidenceId: string;
  principalId: string;
  attestationType: string;
  statement: string;
  claims?: JsonObject;
  attestedAt?: string;
  validUntil?: string | null;
  metadata?: JsonObject;
  correlationId?: string | null;
};

export type RevokeEvidenceInput = {
  evidenceId: string;
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type RevokeAttestationInput = {
  attestationId: string;
  principalId: string;
  reason: string;
  correlationId?: string | null;
};

export type EvidenceView = {
  evidence: Evidence;
  attestations: EvidenceAttestation[];
};

export type EvidenceValidity =
  | { valid: true; reason: "active" }
  | {
      valid: false;
      reason:
        | "superseded"
        | "revoked"
        | "not_yet_valid"
        | "expired";
    };

export type RuleEvaluationContextInput = Omit<
  EvaluationContext,
  "evidenceTypes"
>;
