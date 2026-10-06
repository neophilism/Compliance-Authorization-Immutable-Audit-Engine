import type { JsonObject } from "@caiae/core";

export type SecurityErrorCode =
  | "validation"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict";

export class SecurityError extends Error {
  constructor(
    public readonly code: SecurityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "SecurityError";
  }
}

export type SecurityRole = {
  id: string;
  organizationId: string;
  key: string;
  name: string;
  permissions: string[];
  system: boolean;
  metadata: JsonObject;
  createdAt: string;
  updatedAt: string;
};

export type PrincipalRoleAssignment = {
  id: string;
  organizationId: string;
  principalId: string;
  roleId: string;
  assignedByPrincipalId: string | null;
  createdAt: string;
};

export type OperatorCredential = {
  id: string;
  organizationId: string;
  principalId: string;
  name: string;
  tokenPrefix: string;
  status: "active" | "revoked";
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdByPrincipalId: string | null;
  revokedAt: string | null;
  metadata: JsonObject;
  createdAt: string;
  updatedAt: string;
};

export type AuthenticatedOperator = {
  credential: OperatorCredential;
  principal: {
    id: string;
    organizationId: string;
    displayName: string;
    externalRef: string | null;
    status: "active";
  };
  roles: Array<{
    id: string;
    key: string;
    name: string;
  }>;
  permissions: string[];
};

export type IssuedOperatorCredential = {
  credential: OperatorCredential;
  token: string;
};

export type BootstrapInput = {
  organizationId: string;
  principalId: string;
  credentialName?: string;
};

export type CreateRoleInput = {
  organizationId: string;
  key: string;
  name: string;
  permissions: string[];
  metadata?: JsonObject;
};

export type AssignRoleInput = {
  organizationId: string;
  principalId: string;
  roleId: string;
};

export type IssueOperatorCredentialInput = {
  organizationId: string;
  principalId: string;
  name: string;
  expiresAt?: string | null;
  metadata?: JsonObject;
};

export type RevokeOperatorCredentialInput = {
  credentialId: string;
  reason: string;
};

export type SecurityServiceOptions = {
  now?: () => Date;
  bootstrapSecret?: string | null;
};
