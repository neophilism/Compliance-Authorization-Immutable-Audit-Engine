import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
} from "node:crypto";
import type {
  Pool,
  PoolClient,
} from "pg";
import type {
  JsonObject,
  Resource,
} from "@caiae/core";
import {
  appendAuditEventWithClient,
  canonicalJson,
} from "@caiae/db";
import {
  EvaluationService,
} from "@caiae/evaluations";
import type {
  CaseWorkflowIntegrationAdapter,
  RegistryIntegrationAdapter,
} from "./adapters.js";
import {
  IntegrationError,
  type ApiCredential,
  type AuthenticatedService,
  type CaseWorkflowTrigger,
  type CreateServiceAccountInput,
  type CreatedWebhookSubscription,
  type EventListOptions,
  type IdempotencyResult,
  type IntegrationEvent,
  type IntegrationServiceOptions,
  type IssuedServiceCredential,
  type Paginated,
  type RegistryComplianceProjection,
  type ResourceExportBundle,
  type ResourceImportBundle,
  type ResourceImportResult,
  type ResourceListOptions,
  type ServiceScope,
  type WebhookDeliverySweep,
  type WebhookSubscription,
} from "./types.js";

const SUPPORTED_SCOPES: ServiceScope[] = [
  "*",
  "resources:read",
  "resources:write",
  "checks:run",
  "events:read",
  "webhooks:read",
  "webhooks:write",
  "imports:write",
  "exports:read",
  "adapters:read",
];

const DEFAULT_IDEMPOTENCY_TTL_SECONDS = 86_400;
const DEFAULT_WEBHOOK_MASTER_SECRET =
  "caiae-development-webhook-secret";
const DEFAULT_MAX_WEBHOOK_ATTEMPTS = 8;

export class IntegrationService
  implements
    RegistryIntegrationAdapter,
    CaseWorkflowIntegrationAdapter
{
  private readonly evaluations: EvaluationService;
  private readonly webhookMasterSecret: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;
  private readonly maxWebhookAttempts: number;

  constructor(
    private readonly pool: Pool,
    options: IntegrationServiceOptions = {},
  ) {
    this.evaluations =
      new EvaluationService(pool);
    this.webhookMasterSecret =
      options.webhookMasterSecret ??
      process.env.CAIAE_WEBHOOK_MASTER_SECRET ??
      DEFAULT_WEBHOOK_MASTER_SECRET;
    this.fetchImpl =
      options.fetchImpl ?? fetch;
    this.now =
      options.now ?? (() => new Date());
    this.maxWebhookAttempts =
      options.maxWebhookAttempts ??
      DEFAULT_MAX_WEBHOOK_ATTEMPTS;
  }

  async createServiceAccount(
    input: CreateServiceAccountInput,
  ): Promise<IssuedServiceCredential> {
    validateServiceAccountInput(input);

    const client =
      await this.pool.connect();
    const principalId = randomUUID();
    const credentialId = randomUUID();
    const issuedAt =
      this.now().toISOString();
    const tokenPrefix =
      randomBytes(5).toString("hex");
    const tokenSecret =
      randomBytes(32).toString(
        "base64url",
      );
    const token =
      `caiae_${tokenPrefix}_${tokenSecret}`;
    const tokenHash =
      hashToken(token);
    const expiresAt =
      normalizeOptionalDate(
        input.expiresAt,
        "expiresAt",
      );
    const scopes =
      normalizeScopes(input.scopes);

    if (
      expiresAt !== null &&
      new Date(expiresAt).getTime() <=
        this.now().getTime()
    ) {
      throw new IntegrationError(
        "validation",
        "expiresAt must be in the future",
      );
    }

    try {
      await client.query("BEGIN");

      await assertOrganization(
        client,
        input.organizationId,
      );
      await assertActivePrincipal(
        client,
        input.organizationId,
        input.createdByPrincipalId,
      );

      await client.query(
        `INSERT INTO principals(
           id,
           organization_id,
           kind,
           display_name,
           external_ref,
           status,
           metadata
         ) VALUES (
           $1, $2, 'service', $3, $4,
           'active', $5::jsonb
         )`,
        [
          principalId,
          input.organizationId,
          input.displayName.trim(),
          normalizeNullableString(
            input.externalRef,
          ),
          JSON.stringify(
            input.metadata ?? {},
          ),
        ],
      );

      await client.query(
        `INSERT INTO api_credentials(
           id,
           organization_id,
           principal_id,
           name,
           token_prefix,
           token_hash,
           scopes,
           status,
           expires_at,
           created_by_principal_id,
           metadata,
           created_at,
           updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7::jsonb, 'active', $8, $9,
           $10::jsonb, $11, $11
         )`,
        [
          credentialId,
          input.organizationId,
          principalId,
          input.credentialName.trim(),
          tokenPrefix,
          tokenHash,
          JSON.stringify(scopes),
          expiresAt,
          input.createdByPrincipalId,
          JSON.stringify(
            input.metadata ?? {},
          ),
          issuedAt,
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            input.organizationId,
          aggregateType:
            "api_credential",
          aggregateId: credentialId,
          eventType:
            "api_credential.issued",
          actorPrincipalId:
            input.createdByPrincipalId,
          occurredAt: issuedAt,
          correlationId:
            input.correlationId ?? null,
          payload: {
            principalId,
            name:
              input.credentialName.trim(),
            tokenPrefix,
            scopes,
            expiresAt,
          },
        },
      );

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeDatabaseError(error);
    } finally {
      client.release();
    }

    const credential =
      await this.getCredential(
        credentialId,
      );

    return {
      principal: {
        id: principalId,
        organizationId:
          input.organizationId,
        displayName:
          input.displayName.trim(),
        externalRef:
          normalizeNullableString(
            input.externalRef,
          ),
        status: "active",
      },
      credential,
      token,
    };
  }

  async getCredential(
    credentialId: string,
  ): Promise<ApiCredential> {
    const result =
      await this.pool.query(
        `SELECT *
         FROM api_credentials
         WHERE id = $1`,
        [credentialId],
      );

    if (!result.rows[0]) {
      throw new IntegrationError(
        "not_found",
        "API credential not found",
      );
    }

    return mapCredential(
      result.rows[0],
    );
  }

  async listCredentials(
    organizationId: string,
  ): Promise<ApiCredential[]> {
    const result =
      await this.pool.query(
        `SELECT *
         FROM api_credentials
         WHERE organization_id = $1
         ORDER BY created_at DESC, id DESC`,
        [organizationId],
      );

    return result.rows.map(
      mapCredential,
    );
  }

  async revokeCredential(input: {
    credentialId: string;
    principalId: string;
    reason: string;
    correlationId?: string | null;
  }): Promise<ApiCredential> {
    const reason =
      requiredString(
        input.reason,
        "reason",
      );
    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");

      const result =
        await client.query(
          `SELECT *
           FROM api_credentials
           WHERE id = $1
           FOR UPDATE`,
          [input.credentialId],
        );

      if (!result.rows[0]) {
        throw new IntegrationError(
          "not_found",
          "API credential not found",
        );
      }

      const credential =
        mapCredential(
          result.rows[0],
        );

      await assertActivePrincipal(
        client,
        credential.organizationId,
        input.principalId,
      );

      if (
        credential.status ===
        "revoked"
      ) {
        await client.query(
          "COMMIT",
        );
        return credential;
      }

      const revokedAt =
        this.now().toISOString();

      await client.query(
        `UPDATE api_credentials
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
            "api_credential",
          aggregateId:
            credential.id,
          eventType:
            "api_credential.revoked",
          actorPrincipalId:
            input.principalId,
          occurredAt: revokedAt,
          correlationId:
            input.correlationId ?? null,
          payload: {
            reason,
            principalId:
              credential.principalId,
          },
        },
      );

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeDatabaseError(error);
    } finally {
      client.release();
    }

    return this.getCredential(
      input.credentialId,
    );
  }

  async authenticate(
    token: string,
    requiredScopes: ServiceScope[] = [],
  ): Promise<AuthenticatedService> {
    if (
      typeof token !== "string" ||
      !token.startsWith("caiae_")
    ) {
      throw new IntegrationError(
        "unauthorized",
        "invalid API credential",
      );
    }

    const tokenHash =
      hashToken(token);
    const now =
      this.now().toISOString();

    const result =
      await this.pool.query(
        `SELECT
           c.*,
           p.display_name,
           p.external_ref,
           p.status AS principal_status,
           p.kind AS principal_kind,
           o.status AS organization_status
         FROM api_credentials AS c
         INNER JOIN principals AS p
           ON p.id = c.principal_id
         INNER JOIN organizations AS o
           ON o.id = c.organization_id
         WHERE c.token_hash = $1`,
        [tokenHash],
      );

    if (!result.rows[0]) {
      throw new IntegrationError(
        "unauthorized",
        "invalid API credential",
      );
    }

    const row = result.rows[0];
    const credential =
      mapCredential(row);

    if (
      credential.status !== "active" ||
      row.principal_kind !==
        "service" ||
      row.principal_status !==
        "active" ||
      row.organization_status !==
        "active" ||
      (
        credential.expiresAt !==
          null &&
        new Date(
          credential.expiresAt,
        ).getTime() <=
          this.now().getTime()
      )
    ) {
      throw new IntegrationError(
        "unauthorized",
        "API credential is inactive or expired",
      );
    }

    assertScopes(
      credential.scopes,
      requiredScopes,
    );

    await this.pool.query(
      `UPDATE api_credentials
       SET last_used_at = $2,
           updated_at = now()
       WHERE id = $1`,
      [
        credential.id,
        now,
      ],
    );

    return {
      credential: {
        ...credential,
        lastUsedAt: now,
      },
      principal: {
        id: credential.principalId,
        organizationId:
          credential.organizationId,
        displayName:
          row.display_name,
        externalRef:
          row.external_ref,
        status: "active",
      },
    };
  }

  async executeIdempotent<T>(
    auth: AuthenticatedService,
    input: {
      key: string;
      method: string;
      route: string;
      body: unknown;
      statusCode: number;
      contentType?: string;
      ttlSeconds?: number;
    },
    execute: () => Promise<T>,
  ): Promise<IdempotencyResult<T>> {
    const key =
      requiredString(
        input.key,
        "idempotency key",
      );

    if (key.length > 200) {
      throw new IntegrationError(
        "validation",
        "idempotency key cannot exceed 200 characters",
      );
    }

    const requestHash =
      hashRequest(
        input.method,
        input.route,
        input.body,
      );
    const recordId =
      randomUUID();
    const ttl =
      input.ttlSeconds ??
      DEFAULT_IDEMPOTENCY_TTL_SECONDS;

    if (
      !Number.isSafeInteger(ttl) ||
      ttl <= 0
    ) {
      throw new IntegrationError(
        "validation",
        "idempotency TTL must be a positive integer",
      );
    }

    const expiresAt =
      new Date(
        this.now().getTime() +
          ttl * 1_000,
      ).toISOString();

    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [
          `${auth.credential.id}:${key}`,
        ],
      );

      const existing =
        await client.query(
          `SELECT *
           FROM idempotency_records
           WHERE credential_id = $1
             AND idempotency_key = $2
           FOR UPDATE`,
          [
            auth.credential.id,
            key,
          ],
        );

      if (existing.rows[0]) {
        const row =
          existing.rows[0];

        if (
          new Date(
            row.expires_at,
          ).getTime() <=
          this.now().getTime()
        ) {
          await client.query(
            `DELETE FROM idempotency_records
             WHERE id = $1`,
            [row.id],
          );
        } else {
          if (
            row.request_hash !==
              requestHash ||
            row.method !==
              input.method.toUpperCase() ||
            row.route !==
              input.route
          ) {
            throw new IntegrationError(
              "conflict",
              "idempotency key was already used for a different request",
            );
          }

          if (
            row.state ===
            "completed"
          ) {
            await client.query(
              "COMMIT",
            );

            return {
              replayed: true,
              statusCode:
                Number(
                  row.response_status,
                ),
              body:
                row.response_body as T,
              contentType:
                row.content_type ??
                "application/json",
            };
          }

          throw new IntegrationError(
            "conflict",
            "request with this idempotency key is already in progress",
          );
        }
      }

      await client.query(
        `INSERT INTO idempotency_records(
           id,
           organization_id,
           credential_id,
           idempotency_key,
           method,
           route,
           request_hash,
           state,
           expires_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, 'pending', $8
         )`,
        [
          recordId,
          auth.credential.organizationId,
          auth.credential.id,
          key,
          input.method.toUpperCase(),
          input.route,
          requestHash,
          expiresAt,
        ],
      );

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeDatabaseError(error);
    } finally {
      client.release();
    }

    try {
      const body =
        await execute();
      const jsonBody =
        toJsonValue(body);

      await this.pool.query(
        `UPDATE idempotency_records
         SET state = 'completed',
             response_status = $2,
             response_body = $3::jsonb,
             content_type = $4,
             completed_at = $5
         WHERE id = $1`,
        [
          recordId,
          input.statusCode,
          JSON.stringify(jsonBody),
          input.contentType ??
            "application/json",
          this.now().toISOString(),
        ],
      );

      return {
        replayed: false,
        statusCode:
          input.statusCode,
        body,
        contentType:
          input.contentType ??
          "application/json",
      };
    } catch (error) {
      await this.pool.query(
        `DELETE FROM idempotency_records
         WHERE id = $1
           AND state = 'pending'`,
        [recordId],
      );
      throw error;
    }
  }

  async createResource(
    auth: AuthenticatedService,
    idempotencyKey: string,
    input: {
      resourceType: string;
      name: string;
      externalRef?: string | null;
      status?: Resource["status"];
      attributes?: JsonObject;
      metadata?: JsonObject;
      correlationId?: string | null;
    },
  ): Promise<
    IdempotencyResult<Resource>
  > {
    assertScopes(
      auth.credential.scopes,
      ["resources:write"],
    );

    const resourceType =
      requiredString(
        input.resourceType,
        "resourceType",
      );
    const name =
      requiredString(
        input.name,
        "name",
      );
    const status =
      normalizeResourceStatus(
        input.status,
      );

    return this.executeIdempotent(
      auth,
      {
        key: idempotencyKey,
        method: "POST",
        route:
          "/v1/integration/resources",
        body: input,
        statusCode: 201,
      },
      async () => {
        const client =
          await this.pool.connect();
        const id = randomUUID();

        try {
          await client.query("BEGIN");

          const result =
            await client.query(
              `INSERT INTO resources(
                 id,
                 organization_id,
                 resource_type,
                 name,
                 external_ref,
                 status,
                 attributes,
                 metadata
               ) VALUES (
                 $1, $2, $3, $4, $5, $6,
                 $7::jsonb, $8::jsonb
               )
               RETURNING *`,
              [
                id,
                auth.credential.organizationId,
                resourceType,
                name,
                normalizeNullableString(
                  input.externalRef,
                ),
                status,
                JSON.stringify(
                  input.attributes ?? {},
                ),
                JSON.stringify(
                  input.metadata ?? {},
                ),
              ],
            );

          await appendAuditEventWithClient(
            client,
            {
              organizationId:
                auth.credential.organizationId,
              aggregateType:
                "resource",
              aggregateId: id,
              eventType:
                "resource.created",
              actorPrincipalId:
                auth.principal.id,
              correlationId:
                input.correlationId ??
                null,
              payload: {
                resourceType,
                name,
                externalRef:
                  normalizeNullableString(
                    input.externalRef,
                  ),
                status,
                source:
                  "integration_api",
              },
            },
          );

          await client.query(
            "COMMIT",
          );

          return mapResource(
            result.rows[0],
          );
        } catch (error) {
          await client.query(
            "ROLLBACK",
          );
          throw normalizeDatabaseError(
            error,
          );
        } finally {
          client.release();
        }
      },
    );
  }

  async listResources(
    auth: AuthenticatedService,
    options: ResourceListOptions = {},
  ): Promise<Paginated<Resource>> {
    assertScopes(
      auth.credential.scopes,
      ["resources:read"],
    );

    const limit =
      normalizeLimit(
        options.limit,
      );
    const cursor =
      decodeCursor(
        options.cursor,
      );
    const resourceType =
      normalizeNullableString(
        options.resourceType,
      );
    const status =
      options.status ?? null;

    if (
      status !== null &&
      status !== "active" &&
      status !== "inactive" &&
      status !== "archived"
    ) {
      throw new IntegrationError(
        "validation",
        "status is invalid",
      );
    }

    const result =
      await this.pool.query(
        `SELECT *
         FROM resources
         WHERE organization_id = $1
           AND (
             $2::text IS NULL
             OR resource_type = $2::text
           )
           AND (
             $3::text IS NULL
             OR status = $3::text
           )
           AND (
             $4::timestamptz IS NULL
             OR (
               date_trunc('milliseconds', created_at),
               id
             ) >
                ($4::timestamptz, $5::uuid)
           )
         ORDER BY
           date_trunc('milliseconds', created_at) ASC,
           id ASC
         LIMIT $6`,
        [
          auth.credential.organizationId,
          resourceType,
          status,
          cursor?.createdAt ?? null,
          cursor?.id ??
            "00000000-0000-0000-0000-000000000000",
          limit + 1,
        ],
      );

    const hasMore =
      result.rows.length > limit;
    const rows =
      hasMore
        ? result.rows.slice(0, limit)
        : result.rows;
    const items =
      rows.map(mapResource);
    const last =
      rows.at(-1);

    return {
      items,
      nextCursor:
        hasMore && last
          ? encodeCursor({
              createdAt:
                iso(last.created_at),
              id: last.id,
            })
          : null,
    };
  }

  async runCheck(
    auth: AuthenticatedService,
    idempotencyKey: string,
    input: {
      resourceId: string;
      ruleSet: unknown;
      facts?: JsonObject;
      evaluatedAt?: string;
      metadata?: JsonObject;
      correlationId?: string | null;
    },
  ): Promise<
    IdempotencyResult<unknown>
  > {
    assertScopes(
      auth.credential.scopes,
      ["checks:run"],
    );

    return this.executeIdempotent(
      auth,
      {
        key: idempotencyKey,
        method: "POST",
        route:
          "/v1/integration/checks/run",
        body: input,
        statusCode: 201,
      },
      async () =>
        this.evaluations.run({
          organizationId:
            auth.credential.organizationId,
          resourceId:
            requiredString(
              input.resourceId,
              "resourceId",
            ),
          ruleSet: input.ruleSet,
          requestedByPrincipalId:
            auth.principal.id,
          facts: input.facts,
          evaluatedAt:
            input.evaluatedAt,
          metadata:
            input.metadata,
          correlationId:
            input.correlationId ??
            null,
        }),
    );
  }

  async createWebhookSubscription(
    auth: AuthenticatedService,
    input: {
      name: string;
      url: string;
      eventTypes?: string[];
      metadata?: JsonObject;
      correlationId?: string | null;
    },
  ): Promise<CreatedWebhookSubscription> {
    assertScopes(
      auth.credential.scopes,
      ["webhooks:write"],
    );

    const name =
      requiredString(
        input.name,
        "name",
      );
    const url =
      validateWebhookUrl(
        input.url,
      );
    const eventTypes =
      normalizeEventTypes(
        input.eventTypes,
      );
    const id = randomUUID();
    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");

      const result =
        await client.query(
          `INSERT INTO webhook_subscriptions(
             id,
             organization_id,
             name,
             url,
             event_types,
             status,
             created_by_principal_id,
             metadata
           ) VALUES (
             $1, $2, $3, $4,
             $5::jsonb, 'active',
             $6, $7::jsonb
           )
           RETURNING *`,
          [
            id,
            auth.credential.organizationId,
            name,
            url,
            JSON.stringify(eventTypes),
            auth.principal.id,
            JSON.stringify(
              input.metadata ?? {},
            ),
          ],
        );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            auth.credential.organizationId,
          aggregateType:
            "webhook_subscription",
          aggregateId: id,
          eventType:
            "webhook_subscription.created",
          actorPrincipalId:
            auth.principal.id,
          correlationId:
            input.correlationId ?? null,
          payload: {
            name,
            url,
            eventTypes,
          },
        },
      );

      await client.query("COMMIT");

      return {
        subscription:
          mapWebhookSubscription(
            result.rows[0],
          ),
        signingSecret:
          this.webhookSecret(id),
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeDatabaseError(error);
    } finally {
      client.release();
    }
  }

  async listWebhookSubscriptions(
    auth: AuthenticatedService,
  ): Promise<WebhookSubscription[]> {
    assertScopes(
      auth.credential.scopes,
      ["webhooks:read"],
    );

    const result =
      await this.pool.query(
        `SELECT *
         FROM webhook_subscriptions
         WHERE organization_id = $1
         ORDER BY created_at DESC, id DESC`,
        [
          auth.credential.organizationId,
        ],
      );

    return result.rows.map(
      mapWebhookSubscription,
    );
  }

  async setWebhookActive(
    auth: AuthenticatedService,
    subscriptionId: string,
    active: boolean,
    correlationId?: string | null,
  ): Promise<WebhookSubscription> {
    assertScopes(
      auth.credential.scopes,
      ["webhooks:write"],
    );

    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");
      const result =
        await client.query(
          `SELECT *
           FROM webhook_subscriptions
           WHERE id = $1
             AND organization_id = $2
           FOR UPDATE`,
          [
            subscriptionId,
            auth.credential.organizationId,
          ],
        );

      if (!result.rows[0]) {
        throw new IntegrationError(
          "not_found",
          "webhook subscription not found",
        );
      }

      const status =
        active
          ? "active"
          : "inactive";

      const updated =
        await client.query(
          `UPDATE webhook_subscriptions
           SET status = $2,
               updated_at = now()
           WHERE id = $1
           RETURNING *`,
          [
            subscriptionId,
            status,
          ],
        );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            auth.credential.organizationId,
          aggregateType:
            "webhook_subscription",
          aggregateId:
            subscriptionId,
          eventType:
            active
              ? "webhook_subscription.activated"
              : "webhook_subscription.deactivated",
          actorPrincipalId:
            auth.principal.id,
          correlationId:
            correlationId ?? null,
          payload: { active },
        },
      );

      await client.query("COMMIT");

      return mapWebhookSubscription(
        updated.rows[0],
      );
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeDatabaseError(error);
    } finally {
      client.release();
    }
  }

  async listEvents(
    auth: AuthenticatedService,
    options: EventListOptions = {},
  ): Promise<Paginated<IntegrationEvent>> {
    assertScopes(
      auth.credential.scopes,
      ["events:read"],
    );

    const limit =
      normalizeLimit(
        options.limit,
      );
    const cursor =
      decodeCursor(
        options.cursor,
      );
    const eventType =
      normalizeNullableString(
        options.eventType,
      );

    const result =
      await this.pool.query(
        `SELECT *
         FROM integration_events
         WHERE organization_id = $1
           AND (
             $2::text IS NULL
             OR event_type = $2::text
           )
           AND (
             $3::timestamptz IS NULL
             OR (
               date_trunc('milliseconds', created_at),
               id
             ) >
                ($3::timestamptz, $4::uuid)
           )
         ORDER BY
           date_trunc('milliseconds', created_at) ASC,
           id ASC
         LIMIT $5`,
        [
          auth.credential.organizationId,
          eventType,
          cursor?.createdAt ?? null,
          cursor?.id ??
            "00000000-0000-0000-0000-000000000000",
          limit + 1,
        ],
      );

    const hasMore =
      result.rows.length > limit;
    const rows =
      hasMore
        ? result.rows.slice(0, limit)
        : result.rows;
    const items =
      rows.map(mapIntegrationEvent);
    const last =
      rows.at(-1);

    return {
      items,
      nextCursor:
        hasMore && last
          ? encodeCursor({
              createdAt:
                iso(last.created_at),
              id: last.id,
            })
          : null,
    };
  }

  async deliverPendingWebhooks(
    limit = 50,
  ): Promise<WebhookDeliverySweep> {
    const normalizedLimit =
      normalizeLimit(
        limit,
        100,
      );
    const client =
      await this.pool.connect();
    let rows: any[] = [];

    try {
      await client.query("BEGIN");

      const claimed =
        await client.query(
          `SELECT
             d.*,
             s.url,
             s.status AS subscription_status,
             e.organization_id AS event_organization_id,
             e.event_type,
             e.aggregate_type,
             e.aggregate_id,
             e.payload AS event_payload,
             e.occurred_at
           FROM webhook_deliveries AS d
           INNER JOIN webhook_subscriptions AS s
             ON s.id = d.subscription_id
           INNER JOIN integration_events AS e
             ON e.id = d.event_id
           WHERE d.status IN ('pending', 'failed')
             AND d.attempts < $1
             AND d.next_attempt_at <= $2
             AND s.status = 'active'
           ORDER BY
             d.next_attempt_at ASC,
             d.created_at ASC,
             d.id ASC
           FOR UPDATE OF d SKIP LOCKED
           LIMIT $3`,
          [
            this.maxWebhookAttempts,
            this.now().toISOString(),
            normalizedLimit,
          ],
        );

      rows = claimed.rows;

      for (const row of rows) {
        await client.query(
          `UPDATE webhook_deliveries
           SET attempts = attempts + 1,
               last_attempt_at = $2,
               next_attempt_at = $3,
               updated_at = $2
           WHERE id = $1`,
          [
            row.id,
            this.now().toISOString(),
            new Date(
              this.now().getTime() +
                300_000,
            ).toISOString(),
          ],
        );
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeDatabaseError(error);
    } finally {
      client.release();
    }

    let succeeded = 0;
    let failed = 0;

    for (const row of rows) {
      const event =
        webhookEnvelope(row);
      const body =
        JSON.stringify(event);
      const timestamp =
        this.now().toISOString();
      const secret =
        this.webhookSecret(
          row.subscription_id,
        );
      const signature =
        createHmac(
          "sha256",
          secret,
        )
          .update(
            `${timestamp}.${body}`,
            "utf8",
          )
          .digest("hex");

      try {
        const response =
          await this.fetchImpl(
            row.url,
            {
              method: "POST",
              headers: {
                "content-type":
                  "application/json",
                "x-caiae-event-id":
                  row.event_id,
                "x-caiae-timestamp":
                  timestamp,
                "x-caiae-signature":
                  `sha256=${signature}`,
              },
              body,
            },
          );

        if (
          response.status >= 200 &&
          response.status < 300
        ) {
          succeeded += 1;
          await this.pool.query(
            `UPDATE webhook_deliveries
             SET status = 'succeeded',
                 delivered_at = $2,
                 response_status = $3,
                 last_error = NULL,
                 updated_at = $2
             WHERE id = $1`,
            [
              row.id,
              this.now().toISOString(),
              response.status,
            ],
          );
        } else {
          failed += 1;
          await this.markWebhookFailure(
            row,
            `HTTP ${response.status}`,
            response.status,
          );
        }
      } catch (error) {
        failed += 1;
        await this.markWebhookFailure(
          row,
          error instanceof Error
            ? error.message
            : "webhook delivery failed",
          null,
        );
      }
    }

    return {
      claimed: rows.length,
      succeeded,
      failed,
    };
  }

  async importResources(
    auth: AuthenticatedService,
    idempotencyKey: string,
    bundle: ResourceImportBundle,
    correlationId?: string | null,
  ): Promise<
    IdempotencyResult<ResourceImportResult>
  > {
    assertScopes(
      auth.credential.scopes,
      ["imports:write"],
    );
    validateImportBundle(bundle);

    return this.executeIdempotent(
      auth,
      {
        key: idempotencyKey,
        method: "POST",
        route:
          "/v1/integration/import/resources",
        body: bundle,
        statusCode: 200,
      },
      async () => {
        const client =
          await this.pool.connect();
        let created = 0;
        let updated = 0;
        const resourceIds:
          string[] = [];

        try {
          await client.query("BEGIN");

          for (
            const item of
            bundle.items
          ) {
            const payloadHash =
              hashJson(item);
            const mapping =
              await client.query(
                `SELECT *
                 FROM integration_import_records
                 WHERE organization_id = $1
                   AND source = $2
                   AND entity_type = 'resource'
                   AND external_id = $3
                 FOR UPDATE`,
                [
                  auth.credential.organizationId,
                  bundle.source.trim(),
                  item.externalId.trim(),
                ],
              );

            let resourceId:
              string;
            let eventType:
              string;

            if (
              mapping.rows[0]
            ) {
              resourceId =
                mapping.rows[0].entity_id;

              const exists =
                await client.query(
                  `SELECT id
                   FROM resources
                   WHERE id = $1
                     AND organization_id = $2`,
                  [
                    resourceId,
                    auth.credential.organizationId,
                  ],
                );

              if (!exists.rows[0]) {
                resourceId =
                  randomUUID();
                created += 1;
                eventType =
                  "resource.imported";

                await insertImportedResource(
                  client,
                  auth.credential.organizationId,
                  resourceId,
                  item,
                );
              } else {
                updated += 1;
                eventType =
                  "resource.import_updated";

                await updateImportedResource(
                  client,
                  resourceId,
                  item,
                );
              }

              await client.query(
                `UPDATE integration_import_records
                 SET entity_id = $2,
                     payload_hash = $3,
                     updated_at = now()
                 WHERE id = $1`,
                [
                  mapping.rows[0].id,
                  resourceId,
                  payloadHash,
                ],
              );
            } else {
              resourceId =
                randomUUID();
              created += 1;
              eventType =
                "resource.imported";

              await insertImportedResource(
                client,
                auth.credential.organizationId,
                resourceId,
                item,
              );

              await client.query(
                `INSERT INTO integration_import_records(
                   id,
                   organization_id,
                   source,
                   entity_type,
                   external_id,
                   entity_id,
                   payload_hash
                 ) VALUES (
                   $1, $2, $3, 'resource',
                   $4, $5, $6
                 )`,
                [
                  randomUUID(),
                  auth.credential.organizationId,
                  bundle.source.trim(),
                  item.externalId.trim(),
                  resourceId,
                  payloadHash,
                ],
              );
            }

            resourceIds.push(
              resourceId,
            );

            await appendAuditEventWithClient(
              client,
              {
                organizationId:
                  auth.credential.organizationId,
                aggregateType:
                  "resource",
                aggregateId:
                  resourceId,
                eventType,
                actorPrincipalId:
                  auth.principal.id,
                correlationId:
                  correlationId ??
                  null,
                payload: {
                  source:
                    bundle.source.trim(),
                  externalId:
                    item.externalId.trim(),
                  payloadHash,
                },
              },
            );
          }

          await client.query(
            "COMMIT",
          );
        } catch (error) {
          await client.query(
            "ROLLBACK",
          );
          throw normalizeDatabaseError(
            error,
          );
        } finally {
          client.release();
        }

        return {
          source:
            bundle.source.trim(),
          created,
          updated,
          resourceIds,
        };
      },
    );
  }

  async exportResources(
    auth: AuthenticatedService,
  ): Promise<ResourceExportBundle> {
    assertScopes(
      auth.credential.scopes,
      ["exports:read"],
    );

    const result =
      await this.pool.query(
        `SELECT *
         FROM resources
         WHERE organization_id = $1
         ORDER BY created_at ASC, id ASC`,
        [
          auth.credential.organizationId,
        ],
      );

    return {
      schemaVersion: "1",
      exportedAt:
        this.now().toISOString(),
      organizationId:
        auth.credential.organizationId,
      items:
        result.rows.map((row) => {
          const resource =
            mapResource(row);

          return {
            externalId:
              resource.externalRef ??
              resource.id,
            resource,
          };
        }),
    };
  }

  async getRegistryProjection(
    auth: AuthenticatedService,
    resourceId: string,
  ): Promise<RegistryComplianceProjection> {
    assertScopes(
      auth.credential.scopes,
      ["adapters:read"],
    );

    const resourceResult =
      await this.pool.query(
        `SELECT *
         FROM resources
         WHERE id = $1
           AND organization_id = $2`,
        [
          resourceId,
          auth.credential.organizationId,
        ],
      );

    if (!resourceResult.rows[0]) {
      throw new IntegrationError(
        "not_found",
        "resource not found",
      );
    }

    const [
      checkResult,
      certificationResult,
      findingResult,
    ] = await Promise.all([
      this.pool.query(
        `SELECT *
         FROM checks
         WHERE organization_id = $1
           AND resource_id = $2
         ORDER BY
           COALESCE(
             evaluated_at,
             completed_at,
             created_at
           ) DESC,
           id DESC
         LIMIT 1`,
        [
          auth.credential.organizationId,
          resourceId,
        ],
      ),
      this.pool.query(
        `SELECT
           count(*)::int AS count,
           COALESCE(
             jsonb_agg(
               certificate_number
               ORDER BY certificate_number
             ) FILTER (
               WHERE certificate_number IS NOT NULL
             ),
             '[]'::jsonb
           ) AS certificate_numbers
         FROM certifications
         WHERE organization_id = $1
           AND resource_id = $2
           AND status = 'active'
           AND valid_from <= $3
           AND valid_until > $3`,
        [
          auth.credential.organizationId,
          resourceId,
          this.now().toISOString(),
        ],
      ),
      this.pool.query(
        `SELECT
           count(*) FILTER (
             WHERE status NOT IN ('resolved', 'closed')
           )::int AS unresolved,
           count(*) FILTER (
             WHERE status NOT IN ('resolved', 'closed')
               AND severity IN ('high', 'critical')
           )::int AS unresolved_material
         FROM findings
         WHERE organization_id = $1
           AND resource_id = $2`,
        [
          auth.credential.organizationId,
          resourceId,
        ],
      ),
    ]);

    const resource =
      mapResource(
        resourceResult.rows[0],
      );
    const check =
      checkResult.rows[0];
    const ruleSet =
      check
        ? objectOrEmpty(
            check.rule_set_snapshot,
          )
        : {};

    return {
      organizationId:
        auth.credential.organizationId,
      resource: {
        id: resource.id,
        resourceType:
          resource.resourceType,
        name: resource.name,
        externalRef:
          resource.externalRef,
        status: resource.status,
      },
      latestCheck:
        check
          ? {
              id: check.id,
              status:
                check.status,
              evaluatedAt:
                nullableIso(
                  check.evaluated_at,
                ),
              ruleSetId:
                stringOrNull(
                  ruleSet.id,
                ),
              ruleSetVersion:
                stringOrNull(
                  ruleSet.version,
                ),
            }
          : null,
      certifications: {
        validCount:
          Number(
            certificationResult
              .rows[0]
              ?.count ?? 0,
          ),
        activeCertificateNumbers:
          Array.isArray(
            certificationResult
              .rows[0]
              ?.certificate_numbers,
          )
            ? certificationResult
                .rows[0]
                .certificate_numbers
            : [],
      },
      findings: {
        unresolvedCount:
          Number(
            findingResult.rows[0]
              ?.unresolved ?? 0,
          ),
        unresolvedHighCriticalCount:
          Number(
            findingResult.rows[0]
              ?.unresolved_material ??
              0,
          ),
      },
    };
  }

  async listCaseTriggers(
    auth: AuthenticatedService,
    options: {
      limit?: number;
      severity?: string | null;
    } = {},
  ): Promise<CaseWorkflowTrigger[]> {
    assertScopes(
      auth.credential.scopes,
      ["adapters:read"],
    );

    const limit =
      normalizeLimit(
        options.limit,
        200,
      );
    const severity =
      normalizeNullableString(
        options.severity,
      );

    if (
      severity !== null &&
      ![
        "info",
        "low",
        "medium",
        "high",
        "critical",
      ].includes(severity)
    ) {
      throw new IntegrationError(
        "validation",
        "severity is invalid",
      );
    }

    const findingResult =
      await this.pool.query(
        `SELECT *
         FROM findings
         WHERE organization_id = $1
           AND status NOT IN ('resolved', 'closed')
           AND (
             status = 'disputed'
             OR severity IN ('high', 'critical')
           )
           AND (
             $2::text IS NULL
             OR severity = $2::text
           )
         ORDER BY
           opened_at ASC,
           id ASC
         LIMIT $3`,
        [
          auth.credential.organizationId,
          severity,
          limit,
        ],
      );

    const remediationResult =
      await this.pool.query(
        `SELECT
           r.*,
           f.resource_id,
           f.severity,
           f.title,
           d.status AS deadline_status,
           d.due_at AS deadline_due_at,
           d.grace_period_seconds
         FROM remediations AS r
         INNER JOIN findings AS f
           ON f.id = r.finding_id
         LEFT JOIN deadlines AS d
           ON d.id = r.deadline_id
         WHERE r.organization_id = $1
           AND r.status IN (
             'planned',
             'in_progress',
             'ready_for_verification'
           )
           AND (
             (
               d.id IS NOT NULL
               AND d.status NOT IN ('satisfied', 'cancelled')
               AND (
                 d.due_at +
                 d.grace_period_seconds * interval '1 second'
               ) <= $2
             )
             OR (
               d.id IS NULL
               AND r.due_at IS NOT NULL
               AND r.due_at <= $2
             )
           )
         ORDER BY
           COALESCE(
             d.due_at,
             r.due_at
           ) ASC,
           r.id ASC
         LIMIT $3`,
        [
          auth.credential.organizationId,
          this.now().toISOString(),
          limit,
        ],
      );

    const triggers:
      CaseWorkflowTrigger[] = [];

    for (
      const row of
      findingResult.rows
    ) {
      triggers.push({
        id:
          `finding:${row.id}`,
        organizationId:
          auth.credential.organizationId,
        resourceId:
          row.resource_id,
        triggerType:
          row.status ===
          "disputed"
            ? "finding_disputed"
            : "finding_human_review",
        aggregateType:
          "finding",
        aggregateId: row.id,
        severity: row.severity,
        status: row.status,
        title: row.title,
        dueAt: null,
        occurredAt:
          iso(
            row.opened_at ??
              row.created_at,
          ),
        metadata: {
          ruleKey:
            row.rule_key ??
            null,
          checkId:
            row.check_id ??
            null,
        },
      });
    }

    for (
      const row of
      remediationResult.rows
    ) {
      triggers.push({
        id:
          `remediation:${row.id}`,
        organizationId:
          auth.credential.organizationId,
        resourceId:
          row.resource_id,
        triggerType:
          "remediation_overdue",
        aggregateType:
          "remediation",
        aggregateId: row.id,
        severity:
          row.severity ??
          null,
        status: row.status,
        title:
          row.title ??
          "Overdue remediation",
        dueAt:
          nullableIso(
            row.deadline_due_at ??
              row.due_at,
          ),
        occurredAt:
          nullableIso(
            row.due_at,
          ) ??
          iso(row.created_at),
        metadata: {
          findingId:
            row.finding_id,
          deadlineId:
            row.deadline_id ??
            null,
        },
      });
    }

    return triggers
      .sort((left, right) =>
        left.occurredAt.localeCompare(
          right.occurredAt,
        ),
      )
      .slice(0, limit);
  }

  private webhookSecret(
    subscriptionId: string,
  ): string {
    return createHmac(
      "sha256",
      this.webhookMasterSecret,
    )
      .update(
        subscriptionId,
        "utf8",
      )
      .digest("base64url");
  }

  private async markWebhookFailure(
    row: any,
    message: string,
    responseStatus: number | null,
  ): Promise<void> {
    const attempts =
      Number(row.attempts) + 1;
    const delaySeconds =
      Math.min(
        3_600,
        30 *
          2 **
            Math.max(
              0,
              attempts - 1,
            ),
      );
    const nextAttemptAt =
      new Date(
        this.now().getTime() +
          delaySeconds * 1_000,
      ).toISOString();

    await this.pool.query(
      `UPDATE webhook_deliveries
       SET status = 'failed',
           response_status = $2,
           last_error = $3,
           next_attempt_at = $4,
           updated_at = $5
       WHERE id = $1`,
      [
        row.id,
        responseStatus,
        message.slice(0, 2_000),
        nextAttemptAt,
        this.now().toISOString(),
      ],
    );
  }
}

async function insertImportedResource(
  client: PoolClient,
  organizationId: string,
  resourceId: string,
  item: ResourceImportBundle["items"][number],
): Promise<void> {
  await client.query(
    `INSERT INTO resources(
       id,
       organization_id,
       resource_type,
       name,
       external_ref,
       status,
       attributes,
       metadata
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7::jsonb, $8::jsonb
     )`,
    [
      resourceId,
      organizationId,
      item.resourceType.trim(),
      item.name.trim(),
      normalizeNullableString(
        item.externalRef,
      ),
      normalizeResourceStatus(
        item.status,
      ),
      JSON.stringify(
        item.attributes ?? {},
      ),
      JSON.stringify(
        item.metadata ?? {},
      ),
    ],
  );
}

async function updateImportedResource(
  client: PoolClient,
  resourceId: string,
  item: ResourceImportBundle["items"][number],
): Promise<void> {
  await client.query(
    `UPDATE resources
     SET resource_type = $2,
         name = $3,
         external_ref = $4,
         status = $5,
         attributes = $6::jsonb,
         metadata = $7::jsonb,
         updated_at = now()
     WHERE id = $1`,
    [
      resourceId,
      item.resourceType.trim(),
      item.name.trim(),
      normalizeNullableString(
        item.externalRef,
      ),
      normalizeResourceStatus(
        item.status,
      ),
      JSON.stringify(
        item.attributes ?? {},
      ),
      JSON.stringify(
        item.metadata ?? {},
      ),
    ],
  );
}

function validateServiceAccountInput(
  input: CreateServiceAccountInput,
): void {
  requiredString(
    input.organizationId,
    "organizationId",
  );
  requiredString(
    input.displayName,
    "displayName",
  );
  requiredString(
    input.credentialName,
    "credentialName",
  );
  requiredString(
    input.createdByPrincipalId,
    "createdByPrincipalId",
  );
  normalizeScopes(input.scopes);
}

function normalizeScopes(
  values: ServiceScope[],
): ServiceScope[] {
  if (
    !Array.isArray(values) ||
    values.length === 0
  ) {
    throw new IntegrationError(
      "validation",
      "scopes must contain at least one scope",
    );
  }

  const normalized =
    values.map((value) => {
      if (
        !SUPPORTED_SCOPES.includes(
          value,
        )
      ) {
        throw new IntegrationError(
          "validation",
          `unsupported scope: ${value}`,
        );
      }
      return value;
    });

  return [
    ...new Set(normalized),
  ];
}

function assertScopes(
  granted: ServiceScope[],
  required: ServiceScope[],
): void {
  if (
    granted.includes("*")
  ) {
    return;
  }

  for (const scope of required) {
    if (
      !granted.includes(scope)
    ) {
      throw new IntegrationError(
        "forbidden",
        `missing required scope: ${scope}`,
      );
    }
  }
}

function validateImportBundle(
  bundle: ResourceImportBundle,
): void {
  if (
    bundle.schemaVersion !== "1"
  ) {
    throw new IntegrationError(
      "validation",
      "unsupported import schemaVersion",
    );
  }

  requiredString(
    bundle.source,
    "source",
  );

  if (
    !Array.isArray(bundle.items)
  ) {
    throw new IntegrationError(
      "validation",
      "items must be an array",
    );
  }

  if (
    bundle.items.length > 1_000
  ) {
    throw new IntegrationError(
      "validation",
      "a single import cannot exceed 1000 resources",
    );
  }

  for (
    const [
      index,
      item,
    ] of bundle.items.entries()
  ) {
    requiredString(
      item.externalId,
      `items[${index}].externalId`,
    );
    requiredString(
      item.resourceType,
      `items[${index}].resourceType`,
    );
    requiredString(
      item.name,
      `items[${index}].name`,
    );
    normalizeResourceStatus(
      item.status,
    );
  }
}

function normalizeEventTypes(
  values?: string[],
): string[] {
  if (values === undefined) {
    return ["*"];
  }

  if (
    !Array.isArray(values) ||
    values.length === 0
  ) {
    throw new IntegrationError(
      "validation",
      "eventTypes must contain at least one event type",
    );
  }

  const normalized =
    values.map((value, index) =>
      requiredString(
        value,
        `eventTypes[${index}]`,
      ),
    );

  return [
    ...new Set(normalized),
  ];
}

function validateWebhookUrl(
  value: string,
): string {
  const input =
    requiredString(
      value,
      "url",
    );
  let url: URL;

  try {
    url = new URL(input);
  } catch {
    throw new IntegrationError(
      "validation",
      "webhook URL is invalid",
    );
  }

  if (
    url.protocol !== "https:"
  ) {
    throw new IntegrationError(
      "validation",
      "webhook URL must use HTTPS",
    );
  }

  if (
    url.username ||
    url.password
  ) {
    throw new IntegrationError(
      "validation",
      "webhook URL cannot contain credentials",
    );
  }

  return url.toString();
}

function normalizeLimit(
  value?: number,
  maximum = 100,
): number {
  const normalized =
    value ?? 50;

  if (
    !Number.isSafeInteger(
      normalized,
    ) ||
    normalized <= 0 ||
    normalized > maximum
  ) {
    throw new IntegrationError(
      "validation",
      `limit must be an integer between 1 and ${maximum}`,
    );
  }

  return normalized;
}

function normalizeResourceStatus(
  value?:
    | Resource["status"]
    | null,
): Resource["status"] {
  if (
    value === undefined ||
    value === null
  ) {
    return "active";
  }

  if (
    value !== "active" &&
    value !== "inactive" &&
    value !== "archived"
  ) {
    throw new IntegrationError(
      "validation",
      "resource status is invalid",
    );
  }

  return value;
}

function mapCredential(
  row: any,
): ApiCredential {
  const rawScopes =
    Array.isArray(row.scopes)
      ? row.scopes
      : [];

  return {
    id: row.id,
    organizationId:
      row.organization_id,
    principalId:
      row.principal_id,
    name: row.name,
    tokenPrefix:
      row.token_prefix,
    scopes:
      normalizeScopes(
        rawScopes as ServiceScope[],
      ),
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
      ) as JsonObject,
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function mapResource(
  row: any,
): Resource {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    resourceType:
      row.resource_type,
    name: row.name,
    externalRef:
      row.external_ref,
    status: row.status,
    attributes:
      objectOrEmpty(
        row.attributes,
      ) as JsonObject,
    metadata:
      objectOrEmpty(
        row.metadata,
      ) as JsonObject,
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function mapWebhookSubscription(
  row: any,
): WebhookSubscription {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    name: row.name,
    url: row.url,
    eventTypes:
      Array.isArray(row.event_types)
        ? row.event_types
        : [],
    status: row.status,
    createdByPrincipalId:
      row.created_by_principal_id ??
      null,
    metadata:
      objectOrEmpty(
        row.metadata,
      ) as JsonObject,
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function mapIntegrationEvent(
  row: any,
): IntegrationEvent {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    auditEventId:
      row.audit_event_id,
    eventType:
      row.event_type,
    aggregateType:
      row.aggregate_type,
    aggregateId:
      row.aggregate_id,
    payload:
      objectOrEmpty(
        row.payload,
      ) as JsonObject,
    occurredAt:
      iso(row.occurred_at),
    createdAt:
      iso(row.created_at),
  };
}

function webhookEnvelope(
  row: any,
): JsonObject {
  return {
    id: row.event_id,
    type: row.event_type,
    organizationId:
      row.event_organization_id,
    aggregateType:
      row.aggregate_type,
    aggregateId:
      row.aggregate_id,
    occurredAt:
      iso(row.occurred_at),
    payload:
      objectOrEmpty(
        row.event_payload,
      ) as JsonObject,
  };
}

function hashToken(
  token: string,
): string {
  return createHash("sha256")
    .update(token, "utf8")
    .digest("hex");
}

function hashRequest(
  method: string,
  route: string,
  body: unknown,
): string {
  return createHash("sha256")
    .update(
      canonicalJson({
        method:
          method.toUpperCase(),
        route,
        body:
          toJsonValue(body),
      }),
      "utf8",
    )
    .digest("hex");
}

function hashJson(
  value: unknown,
): string {
  return createHash("sha256")
    .update(
      canonicalJson(
        toJsonValue(value),
      ),
      "utf8",
    )
    .digest("hex");
}

function toJsonValue(
  value: unknown,
): any {
  if (value === undefined) {
    return null;
  }

  return JSON.parse(
    JSON.stringify(value),
  );
}

function encodeCursor(
  value: {
    createdAt: string;
    id: string;
  },
): string {
  return Buffer.from(
    JSON.stringify(value),
    "utf8",
  ).toString("base64url");
}

function decodeCursor(
  value:
    | string
    | null
    | undefined,
): {
  createdAt: string;
  id: string;
} | null {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return null;
  }

  try {
    const decoded =
      JSON.parse(
        Buffer.from(
          value,
          "base64url",
        ).toString("utf8"),
      ) as Record<
        string,
        unknown
      >;

    if (
      typeof decoded.createdAt !==
        "string" ||
      typeof decoded.id !==
        "string"
    ) {
      throw new Error(
        "invalid cursor shape",
      );
    }

    const createdAt =
      normalizeRequiredDate(
        decoded.createdAt,
        "cursor.createdAt",
      );

    if (
      !/^[0-9a-fA-F-]{36}$/.test(
        decoded.id,
      )
    ) {
      throw new Error(
        "invalid cursor id",
      );
    }

    return {
      createdAt,
      id: decoded.id,
    };
  } catch {
    throw new IntegrationError(
      "validation",
      "cursor is invalid",
    );
  }
}

async function assertOrganization(
  client: PoolClient,
  organizationId: string,
): Promise<void> {
  const result =
    await client.query(
      `SELECT 1
       FROM organizations
       WHERE id = $1
         AND status = 'active'`,
      [organizationId],
    );

  if (!result.rows[0]) {
    throw new IntegrationError(
      "not_found",
      "active organization not found",
    );
  }
}

async function assertActivePrincipal(
  client: PoolClient,
  organizationId: string,
  principalId: string,
): Promise<void> {
  const result =
    await client.query(
      `SELECT 1
       FROM principals
       WHERE id = $1
         AND organization_id = $2
         AND status = 'active'`,
      [
        principalId,
        organizationId,
      ],
    );

  if (!result.rows[0]) {
    throw new IntegrationError(
      "not_found",
      "active principal not found",
    );
  }
}

function requiredString(
  value: string,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new IntegrationError(
      "validation",
      `${field} is required`,
    );
  }

  return value.trim();
}

function normalizeNullableString(
  value:
    | string
    | null
    | undefined,
): string | null {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const normalized =
    value.trim();

  return normalized === ""
    ? null
    : normalized;
}

function normalizeOptionalDate(
  value:
    | string
    | null
    | undefined,
  field: string,
): string | null {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  return normalizeRequiredDate(
    value,
    field,
  );
}

function normalizeRequiredDate(
  value: string,
  field: string,
): string {
  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    throw new IntegrationError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }

  return date.toISOString();
}

function objectOrEmpty(
  value: unknown,
): Record<string, any> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    return {};
  }

  return value as Record<
    string,
    any
  >;
}

function stringOrNull(
  value: unknown,
): string | null {
  return typeof value === "string"
    ? value
    : null;
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

function normalizeDatabaseError(
  error: unknown,
): unknown {
  if (
    error instanceof
    IntegrationError
  ) {
    return error;
  }

  if (
    error !== null &&
    typeof error === "object" &&
    "code" in error
  ) {
    const code =
      (
        error as {
          code?: string;
        }
      ).code;

    if (code === "23505") {
      return new IntegrationError(
        "conflict",
        "record already exists",
      );
    }
  }

  return error;
}
