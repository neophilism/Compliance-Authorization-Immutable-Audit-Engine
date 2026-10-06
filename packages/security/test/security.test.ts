import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  createPool,
  runMigrations,
} from "@caiae/db";
import {
  SecurityError,
  SecurityService,
} from "../src/index.js";

const BOOTSTRAP_SECRET =
  "test-bootstrap-secret-123456789";

async function fixture() {
  const pool = createPool();
  await runMigrations(pool);

  const organizationId = randomUUID();
  const adminId = randomUUID();
  const operatorId = randomUUID();

  await pool.query(
    `INSERT INTO organizations(
       id, name, slug, status
     ) VALUES (
       $1, 'Security Test Organization',
       $2, 'active'
     )`,
    [
      organizationId,
      `security-test-${organizationId}`,
    ],
  );

  for (const [id, name] of [
    [adminId, "Security Admin"],
    [operatorId, "Limited Operator"],
  ]) {
    await pool.query(
      `INSERT INTO principals(
         id,
         organization_id,
         kind,
         display_name,
         status
       ) VALUES (
         $1, $2, 'user', $3, 'active'
       )`,
      [id, organizationId, name],
    );
  }

  return {
    pool,
    organizationId,
    adminId,
    operatorId,
    service:
      new SecurityService(pool, {
        bootstrapSecret:
          BOOTSTRAP_SECRET,
      }),
  };
}

test("bootstrap returns a one-time operator token, stores only its hash, and authenticates administrator permissions", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    await assert.rejects(
      f.service.bootstrap(
        "wrong-secret",
        {
          organizationId:
            f.organizationId,
          principalId: f.adminId,
        },
      ),
      (error: unknown) =>
        error instanceof
          SecurityError &&
        error.code ===
          "unauthorized",
    );

    const issued =
      await f.service.bootstrap(
        BOOTSTRAP_SECRET,
        {
          organizationId:
            f.organizationId,
          principalId: f.adminId,
          credentialName:
            "primary-admin",
        },
      );

    assert.match(
      issued.token,
      /^caiau_[0-9a-f]{10}_[A-Za-z0-9_-]+$/,
    );

    const stored =
      await f.pool.query(
        `SELECT token_hash
         FROM operator_credentials
         WHERE id = $1`,
        [issued.credential.id],
      );

    assert.notEqual(
      stored.rows[0]?.token_hash,
      issued.token,
    );
    assert.equal(
      String(
        stored.rows[0]?.token_hash,
      ).length,
      64,
    );

    const auth =
      await f.service.authenticate(
        issued.token,
      );

    assert.equal(
      auth.principal.id,
      f.adminId,
    );
    assert.equal(
      auth.principal.organizationId,
      f.organizationId,
    );
    assert.deepEqual(
      auth.permissions,
      ["*"],
    );
    f.service.assertPermission(
      auth,
      "security.write",
    );

    const ledger =
      new AuditLedger(f.pool);
    const events =
      await ledger.list(
        f.organizationId,
        "principal",
        f.adminId,
      );
    assert.equal(
      events.some(
        (event) =>
          event.eventType ===
          "security.bootstrap",
      ),
      true,
    );
  } finally {
    await f.pool.end();
  }
});

test("role permissions are organization-scoped and revoked credentials stop authenticating", async () => {
  if (!process.env.DATABASE_URL) return;
  const f = await fixture();

  try {
    const bootstrap =
      await f.service.bootstrap(
        BOOTSTRAP_SECRET,
        {
          organizationId:
            f.organizationId,
          principalId: f.adminId,
          credentialName:
            "rbac-admin",
        },
      );
    const admin =
      await f.service.authenticate(
        bootstrap.token,
      );

    const role =
      await f.service.createRole(
        admin,
        {
          organizationId:
            f.organizationId,
          key: "resource-reader",
          name: "Resource Reader",
          permissions: [
            "resources.read",
          ],
        },
      );

    const assignment =
      await f.service.assignRole(
        admin,
        {
          organizationId:
            f.organizationId,
          principalId:
            f.operatorId,
          roleId: role.id,
        },
      );
    assert.equal(
      assignment.principalId,
      f.operatorId,
    );

    const issued =
      await f.service.issueCredential(
        admin,
        {
          organizationId:
            f.organizationId,
          principalId:
            f.operatorId,
          name: "limited-reader",
        },
      );
    const limited =
      await f.service.authenticate(
        issued.token,
      );

    f.service.assertPermission(
      limited,
      "resources.read",
    );
    await assert.rejects(
      async () =>
        f.service.assertPermission(
          limited,
          "resources.write",
        ),
      (error: unknown) =>
        error instanceof
          SecurityError &&
        error.code ===
          "forbidden",
    );

    const otherOrg =
      randomUUID();
    await assert.rejects(
      async () =>
        f.service.assertOrganization(
          limited,
          otherOrg,
        ),
      (error: unknown) =>
        error instanceof
          SecurityError &&
        error.code ===
          "forbidden",
    );

    await f.service.revokeCredential(
      admin,
      {
        credentialId:
          issued.credential.id,
        reason: "rotation",
      },
    );

    await assert.rejects(
      f.service.authenticate(
        issued.token,
      ),
      (error: unknown) =>
        error instanceof
          SecurityError &&
        error.code ===
          "unauthorized",
    );
  } finally {
    await f.pool.end();
  }
});
