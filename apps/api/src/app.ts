import Fastify from "fastify";
import cors from "@fastify/cors";
import { createPool, DomainRepository, runMigrations } from "@caiae/db";

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} is required`);
  }
  return value.trim();
}

export async function buildApp() {
  const app = Fastify({ logger: true });
  const pool = createPool();
  await runMigrations(pool);
  const repository = new DomainRepository(pool);

  await app.register(cors, { origin: true });

  app.addHook("onClose", async () => {
    await pool.end();
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error.message.endsWith(" is required")) {
      return reply.code(400).send({ error: error.message });
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
    if (!organization) return reply.code(404).send({ error: "not_found" });
    return organization;
  });

  app.post("/v1/policies", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const policy = await repository.createPolicy({
      organizationId: requiredString(body.organizationId, "organizationId"),
      key: requiredString(body.key, "key"),
      title: requiredString(body.title, "title"),
      description: typeof body.description === "string" ? body.description : "",
      status:
        body.status === "active" || body.status === "retired" || body.status === "draft"
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
      body.attributes && typeof body.attributes === "object" && !Array.isArray(body.attributes)
        ? (body.attributes as Record<string, any>)
        : {};

    const resource = await repository.createResource({
      organizationId: requiredString(body.organizationId, "organizationId"),
      resourceType: requiredString(body.resourceType, "resourceType"),
      name: requiredString(body.name, "name"),
      externalRef: typeof body.externalRef === "string" ? body.externalRef : null,
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

  app.get("/v1/organizations/:organizationId/resources", async (request) => {
    const { organizationId } = request.params as { organizationId: string };
    const { resourceType } = request.query as { resourceType?: string };
    return repository.listResources(organizationId, resourceType);
  });

  return app;
}
