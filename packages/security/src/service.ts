import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { JsonObject } from "@caiae/core";
import { appendAuditEventWithClient } from "@caiae/db";
import {
  SecurityError,
  type AssignRoleInput,
  type AuthenticatedOperator,
  type BootstrapInput,
  type CreateRoleInput,
  type IssuedOperatorCredential,
  type IssueOperatorCredentialInput,
  type OperatorCredential,
  type PrincipalRoleAssignment,
  type RevokeOperatorCredentialInput,
  type SecurityRole,
  type SecurityServiceOptions,
} from "./types.js";

export const STANDARD_ROLE_TEMPLATES = {
  administrator: {
    name: "Administrator",
    permissions: ["*"],
  },
  operator: {
    name: "Operator",
    permissions: [
      "organizations.read",
      "policies.*",
      "resources.*",
      "checks.*",
      "evidence.*",
      "deadlines.*",
      "findings.*",
      "remediations.*",
      "certifications.read",
      "reports.read",
    ],
  },
  reviewer: {
    name: "Reviewer",
    permissions: [
      "organizations.read",
      "resources.read",
      "checks.read",
      "authorizations.*",
      "exceptions.*",
      "findings.*",
      "remediations.*",
      "certifications.*",
      "reports.read",
    ],
  },
  publisher: {
    name: "Publisher",
    permissions: [
      "organizations.read",
      "resources.read",
      "findings.read",
      "certifications.read",
      "reports.read",
      "publication.*",
    ],
  },
  auditor: {
    name: "Auditor",
    permissions: [
      "organizations.read",
      "policies.read",
      "resources.read",
      "checks.read",
      "authorizations.read",
      "exceptions.read",
      "evidence.read",
      "deadlines.read",
      "findings.read",
      "remediations.read",
      "certifications.read",
      "reports.read",
      "publication.read",
    ],
  },
} as const;

export class SecurityService {
  private readonly now: () => Date;
  private readonly bootstrapSecret: string | null;

  constructor(
    private readonly pool: Pool,
    options: SecurityServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.bootstrapSecret =
      options.bootstrapSecret ??
      process.env.CAIAE_BOOTSTRAP_SECRET ??
      null;
  }

  async authenticate(
    token: string,
  ): Promise<AuthenticatedOperator> {
    if (
      typeof token !== "string" ||
      !token.startsWith("caiau_")
    ) {
      throw new SecurityError(
        "unauthorized",
        "invalid operator credential",
      );
    }

    const tokenHash = hashToken(token);
    const at = this.now().toISOString();
    const result = await this.pool.query(
      `SELECT
         c.*,
         p.display_name,
         p.external_ref,
         p.status AS principal_status
       FROM operator_credentials AS c
       INNER JOIN principals AS p
         ON p.id = c.principal_id
       WHERE c.token_hash = $1`,
      [tokenHash],
    );

    const row = result.rows[0];
    if (
      !row ||
      row.status !== "active" ||
      row.principal_status !== "active" ||
      (
        row.expires_at !== null &&
        new Date(row.expires_at).getTime() <=
          this.now().getTime()
      )
    ) {
      throw new SecurityError(
        "unauthorized",
        "operator credential is inactive or expired",
      );
    }

    const rolesResult = await this.pool.query(
      `SELECT
         r.id,
         r.key,
         r.name,
         r.permissions
       FROM principal_role_assignments AS a
       INNER JOIN security_roles AS r
         ON r.id = a.role_id
       WHERE a.organization_id = $1
         AND a.principal_id = $2
       ORDER BY r.key ASC`,
      [row.organization_id, row.principal_id],
    );

    const roles = rolesResult.rows.map((role) => ({
      id: role.id,
      key: role.key,
      name: role.name,
    }));
    const permissions = [
      ...new Set(
        rolesResult.rows.flatMap((role) =>
          normalizePermissions(role.permissions),
        ),
      ),
    ].sort();

    await this.pool.query(
      `UPDATE operator_credentials
       SET last_used_at = $2,
           updated_at = $2
       WHERE id = $1`,
      [row.id, at],
    );

    return {
      credential: mapCredential({
        ...row,
        last_used_at: at,
        updated_at: at,
      }),
      principal: {
        id: row.principal_id,
        organizationId: row.organization_id,
        displayName: row.display_name,
        externalRef: row.external_ref ?? null,
        status: "active",
      },
      roles,
      permissions,
    };
  }

  assertPermission(
    auth: AuthenticatedOperator,
    required: string | null,
  ): void {
    if (required === null) return;
    if (
      auth.permissions.some((granted) =>
        permissionAllows(granted, required),
      )
    ) {
      return;
    }

    throw new SecurityError(
      "forbidden",
      `missing required permission: ${required}`,
    );
  }

  assertOrganization(
    auth: AuthenticatedOperator,
    organizationId: string,
  ): void {
    if (
      auth.principal.organizationId !==
      organizationId
    ) {
      throw new SecurityError(
        "forbidden",
        "cross-organization access is forbidden",
      );
    }
  }

  assertActor(
    auth: AuthenticatedOperator,
    actorPrincipalId:
      | string
      | null
      | undefined,
    field: string,
  ): void {
    if (
      actorPrincipalId === null ||
      actorPrincipalId === undefined
    ) {
      return;
    }
    if (
      actorPrincipalId !==
      auth.principal.id
    ) {
      throw new SecurityError(
        "forbidden",
        `${field} must match the authenticated operator`,
      );
    }
  }

  verifyBootstrapSecret(
    supplied: string,
  ): void {
    if (
      this.bootstrapSecret === null ||
      this.bootstrapSecret.length < 16
    ) {
      throw new SecurityError(
        "forbidden",
        "operator bootstrap is disabled until CAIAE_BOOTSTRAP_SECRET is configured",
      );
    }
    if (
      typeof supplied !== "string" ||
      !safeEqual(
        supplied,
        this.bootstrapSecret,
      )
    ) {
      throw new SecurityError(
        "unauthorized",
        "invalid bootstrap secret",
      );
    }
  }

  async bootstrap(
    suppliedSecret: string,
    input: BootstrapInput,
  ): Promise<IssuedOperatorCredential> {
    this.verifyBootstrapSecret(
      suppliedSecret,
    );
    const organizationId = requiredUuid(
      input.organizationId,
      "organizationId",
    );
    const principalId = requiredUuid(
      input.principalId,
      "principalId",
    );
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertActiveUserPrincipal(
        client,
        organizationId,
        principalId,
      );

      const roleId = await ensureAdministratorRole(
        client,
        organizationId,
      );
      await ensureRoleAssignment(
        client,
        organizationId,
        principalId,
        roleId,
        null,
      );

      const issued =
        await issueCredentialWithClient(
          client,
          {
            organizationId,
            principalId,
            name:
              input.credentialName?.trim() ||
              "bootstrap-operator",
            expiresAt: null,
            metadata: {
              source: "bootstrap",
            },
          },
          null,
          this.now,
        );

      await appendAuditEventWithClient(
        client,
        {
          organizationId,
          aggregateType: "principal",
          aggregateId: principalId,
          eventType: "security.bootstrap",
          actorPrincipalId:
            principalId,
          occurredAt:
            this.now().toISOString(),
          payload: {
            roleId,
            credentialId:
              issued.credential.id,
          },
        },
      );

      await client.query("COMMIT");
      return issued;
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async listRoles(
    auth: AuthenticatedOperator,
  ): Promise<SecurityRole[]> {
    this.assertPermission(
      auth,
      "security.read",
    );
    const result = await this.pool.query(
      `SELECT *
       FROM security_roles
       WHERE organization_id = $1
       ORDER BY key ASC`,
      [
        auth.principal.organizationId,
      ],
    );
    return result.rows.map(mapRole);
  }

  async createRole(
    auth: AuthenticatedOperator,
    input: CreateRoleInput,
  ): Promise<SecurityRole> {
    this.assertPermission(
      auth,
      "security.write",
    );
    this.assertOrganization(
      auth,
      requiredUuid(
        input.organizationId,
        "organizationId",
      ),
    );
    const key = requiredKey(
      input.key,
      "key",
    );
    const name = requiredString(
      input.name,
      "name",
    );
    const permissions =
      validatePermissions(
        input.permissions,
      );
    const id = randomUUID();

    try {
      await this.pool.query(
        `INSERT INTO security_roles(
           id,
           organization_id,
           key,
           name,
           permissions,
           system,
           metadata
         ) VALUES (
           $1, $2, $3, $4,
           $5::jsonb, false, $6::jsonb
         )`,
        [
          id,
          auth.principal.organizationId,
          key,
          name,
          JSON.stringify(permissions),
          JSON.stringify(
            input.metadata ?? {},
          ),
        ],
      );
    } catch (error) {
      throw normalizeError(error);
    }

    return (
      await this.pool.query(
        `SELECT *
         FROM security_roles
         WHERE id = $1`,
        [id],
      )
    ).rows.map(mapRole)[0]!;
  }

  async assignRole(
    auth: AuthenticatedOperator,
    input: AssignRoleInput,
  ): Promise<PrincipalRoleAssignment> {
    this.assertPermission(
      auth,
      "security.write",
    );
    const organizationId = requiredUuid(
      input.organizationId,
      "organizationId",
    );
    this.assertOrganization(
      auth,
      organizationId,
    );
    const principalId = requiredUuid(
      input.principalId,
      "principalId",
    );
    const roleId = requiredUuid(
      input.roleId,
      "roleId",
    );
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertActiveUserPrincipal(
        client,
        organizationId,
        principalId,
      );
      await assertRole(
        client,
        organizationId,
        roleId,
      );

      const assignment =
        await ensureRoleAssignment(
          client,
          organizationId,
          principalId,
          roleId,
          auth.principal.id,
        );

      await appendAuditEventWithClient(
        client,
        {
          organizationId,
          aggregateType: "principal",
          aggregateId:
            principalId,
          eventType:
            "security.role_assigned",
          actorPrincipalId:
            auth.principal.id,
          occurredAt:
            this.now().toISOString(),
          payload: {
            roleId,
            assignmentId:
              assignment.id,
          },
        },
      );

      await client.query("COMMIT");
      return assignment;
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async issueCredential(
    auth: AuthenticatedOperator,
    input: IssueOperatorCredentialInput,
  ): Promise<IssuedOperatorCredential> {
    this.assertPermission(
      auth,
      "security.write",
    );
    const organizationId = requiredUuid(
      input.organizationId,
      "organizationId",
    );
    this.assertOrganization(
      auth,
      organizationId,
    );
    const principalId = requiredUuid(
      input.principalId,
      "principalId",
    );
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertActiveUserPrincipal(
        client,
        organizationId,
        principalId,
      );

      const roles = await client.query(
        `SELECT 1
         FROM principal_role_assignments
         WHERE organization_id = $1
           AND principal_id = $2
         LIMIT 1`,
        [organizationId, principalId],
      );
      if (!roles.rows[0]) {
        throw new SecurityError(
          "validation",
          "principal must have at least one role before a credential can be issued",
        );
      }

      const issued =
        await issueCredentialWithClient(
          client,
          input,
          auth.principal.id,
          this.now,
        );

      await appendAuditEventWithClient(
        client,
        {
          organizationId,
          aggregateType:
            "operator_credential",
          aggregateId:
            issued.credential.id,
          eventType:
            "security.credential_issued",
          actorPrincipalId:
            auth.principal.id,
          occurredAt:
            this.now().toISOString(),
          payload: {
            principalId,
            name:
              issued.credential.name,
            expiresAt:
              issued.credential.expiresAt,
          },
        },
      );

      await client.query("COMMIT");
      return issued;
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async listCredentials(
    auth: AuthenticatedOperator,
  ): Promise<OperatorCredential[]> {
    this.assertPermission(
      auth,
      "security.read",
    );
    const result = await this.pool.query(
      `SELECT *
       FROM operator_credentials
       WHERE organization_id = $1
       ORDER BY created_at ASC, id ASC`,
      [
        auth.principal.organizationId,
      ],
    );
    return result.rows.map(
      mapCredential,
    );
  }

  async revokeCredential(
    auth: AuthenticatedOperator,
    input: RevokeOperatorCredentialInput,
  ): Promise<OperatorCredential> {
    this.assertPermission(
      auth,
      "security.write",
    );
    const credentialId =
      requiredUuid(
        input.credentialId,
        "credentialId",
      );
    const reason = requiredString(
      input.reason,
      "reason",
    );
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const result = await client.query(
        `SELECT *
         FROM operator_credentials
         WHERE id = $1
         FOR UPDATE`,
        [credentialId],
      );
      if (!result.rows[0]) {
        throw new SecurityError(
          "not_found",
          "operator credential not found",
        );
      }
      const credential =
        mapCredential(
          result.rows[0],
        );
      this.assertOrganization(
        auth,
        credential.organizationId,
      );
      if (
        credential.status ===
        "revoked"
      ) {
        throw new SecurityError(
          "conflict",
          "operator credential is already revoked",
        );
      }

      const revokedAt =
        this.now().toISOString();
      await client.query(
        `UPDATE operator_credentials
         SET status = 'revoked',
             revoked_at = $2,
             updated_at = $2
         WHERE id = $1`,
        [
          credential.id,
          revokedAt,
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            credential.organizationId,
          aggregateType:
            "operator_credential",
          aggregateId:
            credential.id,
          eventType:
            "security.credential_revoked",
          actorPrincipalId:
            auth.principal.id,
          occurredAt: revokedAt,
          payload: {
            reason,
            principalId:
              credential.principalId,
          },
        },
      );

      await client.query("COMMIT");
      return mapCredential({
        ...result.rows[0],
        status: "revoked",
        revoked_at: revokedAt,
        updated_at: revokedAt,
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }
}

export function permissionAllows(
  granted: string,
  required: string,
): boolean {
  if (
    granted === "*" ||
    granted === required
  ) {
    return true;
  }

  if (
    granted.endsWith(".*")
  ) {
    const prefix =
      granted.slice(0, -1);
    return required.startsWith(
      prefix,
    );
  }

  return false;
}

async function issueCredentialWithClient(
  client: PoolClient,
  input: IssueOperatorCredentialInput,
  createdByPrincipalId: string | null,
  now: () => Date,
): Promise<IssuedOperatorCredential> {
  const organizationId =
    requiredUuid(
      input.organizationId,
      "organizationId",
    );
  const principalId =
    requiredUuid(
      input.principalId,
      "principalId",
    );
  const name = requiredString(
    input.name,
    "name",
  );
  const expiresAt =
    normalizeOptionalDate(
      input.expiresAt,
      "expiresAt",
    );

  if (
    expiresAt !== null &&
    new Date(expiresAt).getTime() <=
      now().getTime()
  ) {
    throw new SecurityError(
      "validation",
      "expiresAt must be in the future",
    );
  }

  const id = randomUUID();
  const tokenPrefix =
    randomBytes(5).toString("hex");
  const tokenSecret =
    randomBytes(32).toString(
      "base64url",
    );
  const token =
    `caiau_${tokenPrefix}_${tokenSecret}`;
  const tokenHash =
    hashToken(token);

  try {
    await client.query(
      `INSERT INTO operator_credentials(
         id,
         organization_id,
         principal_id,
         name,
         token_prefix,
         token_hash,
         status,
         expires_at,
         created_by_principal_id,
         metadata
       ) VALUES (
         $1, $2, $3, $4, $5, $6,
         'active', $7, $8, $9::jsonb
       )`,
      [
        id,
        organizationId,
        principalId,
        name,
        tokenPrefix,
        tokenHash,
        expiresAt,
        createdByPrincipalId,
        JSON.stringify(
          input.metadata ?? {},
        ),
      ],
    );
  } catch (error) {
    throw normalizeError(error);
  }

  const row = (
    await client.query(
      `SELECT *
       FROM operator_credentials
       WHERE id = $1`,
      [id],
    )
  ).rows[0];

  return {
    credential:
      mapCredential(row),
    token,
  };
}

async function ensureAdministratorRole(
  client: PoolClient,
  organizationId: string,
): Promise<string> {
  const existing = await client.query(
    `SELECT id
     FROM security_roles
     WHERE organization_id = $1
       AND key = 'administrator'`,
    [organizationId],
  );
  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const id = randomUUID();
  await client.query(
    `INSERT INTO security_roles(
       id,
       organization_id,
       key,
       name,
       permissions,
       system
     ) VALUES (
       $1, $2, 'administrator',
       'Administrator',
       '["*"]'::jsonb,
       true
     )`,
    [id, organizationId],
  );
  return id;
}

async function ensureRoleAssignment(
  client: PoolClient,
  organizationId: string,
  principalId: string,
  roleId: string,
  assignedByPrincipalId: string | null,
): Promise<PrincipalRoleAssignment> {
  const existing =
    await client.query(
      `SELECT *
       FROM principal_role_assignments
       WHERE organization_id = $1
         AND principal_id = $2
         AND role_id = $3`,
      [
        organizationId,
        principalId,
        roleId,
      ],
    );
  if (existing.rows[0]) {
    return mapAssignment(
      existing.rows[0],
    );
  }

  const id = randomUUID();
  await client.query(
    `INSERT INTO principal_role_assignments(
       id,
       organization_id,
       principal_id,
       role_id,
       assigned_by_principal_id
     ) VALUES (
       $1, $2, $3, $4, $5
     )`,
    [
      id,
      organizationId,
      principalId,
      roleId,
      assignedByPrincipalId,
    ],
  );

  return {
    id,
    organizationId,
    principalId,
    roleId,
    assignedByPrincipalId,
    createdAt:
      new Date().toISOString(),
  };
}

async function assertActiveUserPrincipal(
  client: PoolClient,
  organizationId: string,
  principalId: string,
): Promise<void> {
  const result = await client.query(
    `SELECT 1
     FROM principals
     WHERE id = $1
       AND organization_id = $2
       AND kind = 'user'
       AND status = 'active'`,
    [
      principalId,
      organizationId,
    ],
  );
  if (!result.rows[0]) {
    throw new SecurityError(
      "not_found",
      "active user principal not found",
    );
  }
}

async function assertRole(
  client: PoolClient,
  organizationId: string,
  roleId: string,
): Promise<void> {
  const result = await client.query(
    `SELECT 1
     FROM security_roles
     WHERE id = $1
       AND organization_id = $2`,
    [roleId, organizationId],
  );
  if (!result.rows[0]) {
    throw new SecurityError(
      "not_found",
      "security role not found",
    );
  }
}

function mapRole(row: any): SecurityRole {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    key: row.key,
    name: row.name,
    permissions:
      normalizePermissions(
        row.permissions,
      ),
    system:
      Boolean(row.system),
    metadata:
      objectOrEmpty(
        row.metadata,
      ),
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function mapAssignment(
  row: any,
): PrincipalRoleAssignment {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    principalId:
      row.principal_id,
    roleId:
      row.role_id,
    assignedByPrincipalId:
      row.assigned_by_principal_id ??
      null,
    createdAt:
      iso(row.created_at),
  };
}

function mapCredential(
  row: any,
): OperatorCredential {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    principalId:
      row.principal_id,
    name: row.name,
    tokenPrefix:
      row.token_prefix,
    status: row.status,
    expiresAt:
      nullableIso(row.expires_at),
    lastUsedAt:
      nullableIso(row.last_used_at),
    createdByPrincipalId:
      row.created_by_principal_id ??
      null,
    revokedAt:
      nullableIso(row.revoked_at),
    metadata:
      objectOrEmpty(
        row.metadata,
      ),
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function validatePermissions(
  permissions: string[],
): string[] {
  if (
    !Array.isArray(permissions) ||
    permissions.length === 0
  ) {
    throw new SecurityError(
      "validation",
      "permissions must contain at least one permission",
    );
  }

  return [
    ...new Set(
      permissions.map(
        (permission, index) => {
          if (
            typeof permission !==
              "string" ||
            !/^\*$|^[a-z0-9-]+\.(?:[a-z0-9-]+|\*)$/.test(
              permission.trim(),
            )
          ) {
            throw new SecurityError(
              "validation",
              `permissions[${index}] is invalid`,
            );
          }
          return permission.trim();
        },
      ),
    ),
  ].sort();
}

function normalizePermissions(
  value: unknown,
): string[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is string =>
          typeof item === "string",
      )
    : [];
}

function requiredString(
  value: string,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new SecurityError(
      "validation",
      `${field} is required`,
    );
  }
  return value.trim();
}

function requiredKey(
  value: string,
  field: string,
): string {
  const normalized =
    requiredString(
      value,
      field,
    );
  if (
    !/^[a-z0-9][a-z0-9._-]*$/.test(
      normalized,
    )
  ) {
    throw new SecurityError(
      "validation",
      `${field} is invalid`,
    );
  }
  return normalized;
}

function requiredUuid(
  value: string,
  field: string,
): string {
  const normalized =
    requiredString(
      value,
      field,
    );
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      normalized,
    )
  ) {
    throw new SecurityError(
      "validation",
      `${field} must be a UUID`,
    );
  }
  return normalized;
}

function normalizeOptionalDate(
  value:
    | string
    | null
    | undefined,
  field: string,
): string | null {
  if (
    value === undefined ||
    value === null
  ) {
    return null;
  }

  const date = new Date(value);
  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    throw new SecurityError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
}

function objectOrEmpty(
  value: unknown,
): JsonObject {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  )
    ? value as JsonObject
    : {};
}

function hashToken(
  token: string,
): string {
  return createHash("sha256")
    .update(token, "utf8")
    .digest("hex");
}

function safeEqual(
  a: string,
  b: string,
): boolean {
  const left =
    Buffer.from(a, "utf8");
  const right =
    Buffer.from(b, "utf8");

  if (
    left.length !== right.length
  ) {
    return false;
  }
  return timingSafeEqual(
    left,
    right,
  );
}

function iso(
  value: Date | string,
): string {
  return (
    value instanceof Date
      ? value
      : new Date(value)
  ).toISOString();
}

function nullableIso(
  value:
    | Date
    | string
    | null
    | undefined,
): string | null {
  return value === null ||
    value === undefined
    ? null
    : iso(value);
}

function normalizeError(
  error: unknown,
): Error {
  if (
    error instanceof SecurityError
  ) {
    return error;
  }

  if (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (
      error as {
        code?: string;
      }
    ).code === "23505"
  ) {
    return new SecurityError(
      "conflict",
      "record already exists",
    );
  }

  return error instanceof Error
    ? error
    : new Error(
        String(error),
      );
}
