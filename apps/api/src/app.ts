import Fastify from "fastify";
import cors from "@fastify/cors";
import {
  AuthorizationError,
  AuthorizationService,
} from "@caiae/authorization";
import { createPool, DomainRepository, runMigrations } from "@caiae/db";

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} is required`);
  }
  return value.trim();
}

function optionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new AuthorizationError(
      "validation",
      `${field} must be a string`,
    );
  }
  return value.trim();
}

function optionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  if (typeof value !== "string" || value.trim() === "") {
    throw new AuthorizationError(
      "validation",
      `${field} must be a non-empty string or null`,
    );
  }
  return value.trim();
}

function optionalBoolean(
  value: unknown,
  field: string,
): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") {
    throw new AuthorizationError(
      "validation",
      `${field} must be a boolean`,
    );
  }
  return value;
}

function optionalPositiveInteger(
  value: unknown,
  field: string,
): number | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1
  ) {
    throw new AuthorizationError(
      "validation",
      `${field} must be a positive integer`,
    );
  }
  return value;
}

function optionalStringArray(
  value: unknown,
  field: string,
): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new AuthorizationError(
      "validation",
      `${field} must be an array of strings`,
    );
  }

  return value.map((item, index) => {
    if (typeof item !== "string" || item.trim() === "") {
      throw new AuthorizationError(
        "validation",
        `${field}[${index}] must be a non-empty string`,
      );
    }
    return item.trim();
  });
}

function optionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new AuthorizationError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown_error";
}

function authorizationHttpStatus(error: AuthorizationError): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "forbidden_approver":
      return 403;
    case "invalid_state":
    case "duplicate_decision":
      return 409;
  }
}

export async function buildApp() {
  const app = Fastify({ logger: true });
  const pool = createPool();
  await runMigrations(pool);
  const repository = new DomainRepository(pool);
  const authorizations = new AuthorizationService(pool);

  await app.register(cors, { origin: true });

  app.addHook("onClose", async () => {
    await pool.end();
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AuthorizationError) {
      return reply
        .code(authorizationHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    const message = errorMessage(error);

    if (message.endsWith(" is required")) {
      return reply.code(400).send({ error: message });
    }

    app.log.error(error);
    return reply.code(500).send({ error: "internal_error" });
  });

  app.get("/health", async () => ({
    status: "ok",
    service: "api",
    timestamp: new Date().toISOString(),
  }));

  app.post("/v1/organizations", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const organization = await repository.createOrganization({
      name: requiredString(body.name, "name"),
      slug: requiredString(body.slug, "slug"),
    });
    return reply.code(201).send(organization);
  });

  app.get("/v1/organizations/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const organization = await repository.getOrganization(id);
    if (!organization) {
      return reply.code(404).send({ error: "not_found" });
    }
    return organization;
  });

  app.post("/v1/policies", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const policy = await repository.createPolicy({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      key: requiredString(body.key, "key"),
      title: requiredString(body.title, "title"),
      description:
        typeof body.description === "string" ? body.description : "",
      status:
        body.status === "active" ||
        body.status === "retired" ||
        body.status === "draft"
          ? body.status
          : "draft",
    });
    return reply.code(201).send(policy);
  });

  app.get("/v1/policies/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const policy = await repository.getPolicy(id);
    if (!policy) return reply.code(404).send({ error: "not_found" });
    return policy;
  });

  app.post("/v1/resources", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const attributes =
      body.attributes &&
      typeof body.attributes === "object" &&
      !Array.isArray(body.attributes)
        ? (body.attributes as Record<string, any>)
        : {};

    const resource = await repository.createResource({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceType: requiredString(
        body.resourceType,
        "resourceType",
      ),
      name: requiredString(body.name, "name"),
      externalRef:
        typeof body.externalRef === "string" ? body.externalRef : null,
      attributes,
    });
    return reply.code(201).send(resource);
  });

  app.get("/v1/resources/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const resource = await repository.getResource(id);
    if (!resource) return reply.code(404).send({ error: "not_found" });
    return resource;
  });

  app.get(
    "/v1/organizations/:organizationId/resources",
    async (request) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };
      const { resourceType } = request.query as {
        resourceType?: string;
      };
      return repository.listResources(
        organizationId,
        resourceType,
      );
    },
  );

  app.post("/v1/authorizations", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    const record = await authorizations.request({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceId: requiredString(body.resourceId, "resourceId"),
      authorizationType: requiredString(
        body.authorizationType,
        "authorizationType",
      ),
      requestedByPrincipalId: requiredString(
        body.requestedByPrincipalId,
        "requestedByPrincipalId",
      ),
      validFrom: optionalNullableString(body.validFrom, "validFrom"),
      validUntil: optionalNullableString(
        body.validUntil,
        "validUntil",
      ),
      scope: optionalObject(body.scope, "scope"),
      conditions: optionalObject(body.conditions, "conditions"),
      approvalQuorum: optionalPositiveInteger(
        body.approvalQuorum,
        "approvalQuorum",
      ),
      approvalAuthority: optionalNullableString(
        body.approvalAuthority,
        "approvalAuthority",
      ),
      eligibleApproverPrincipalIds: optionalStringArray(
        body.eligibleApproverPrincipalIds,
        "eligibleApproverPrincipalIds",
      ),
      emergency: optionalBoolean(body.emergency, "emergency"),
      emergencyReviewDueAt: optionalNullableString(
        body.emergencyReviewDueAt,
        "emergencyReviewDueAt",
      ),
      metadata: optionalObject(body.metadata, "metadata"),
      correlationId: optionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send(record);
  });

  app.get("/v1/authorizations/:id", async (request) => {
    const { id } = request.params as { id: string };
    return authorizations.get(id);
  });

  app.get(
    "/v1/authorizations/:id/effectiveness",
    async (request) => {
      const { id } = request.params as { id: string };
      const query = request.query as { at?: string };

      if (query.at === undefined) {
        return authorizations.effectiveness(id);
      }

      const at = new Date(query.at);
      if (Number.isNaN(at.getTime())) {
        throw new AuthorizationError(
          "validation",
          "at must be a valid date-time",
        );
      }

      return authorizations.effectiveness(id, at);
    },
  );

  app.post(
    "/v1/authorizations/:id/decisions",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      if (body.decision !== "approve" && body.decision !== "deny") {
        throw new AuthorizationError(
          "validation",
          "decision must be approve or deny",
        );
      }

      return authorizations.recordDecision({
        authorizationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        decision: body.decision,
        rationale: optionalString(body.rationale, "rationale"),
        correlationId: optionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/authorizations/:id/revoke",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return authorizations.revoke({
        authorizationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: optionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  return app;
}
