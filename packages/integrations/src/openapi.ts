type HttpMethod =
  | "get"
  | "post"
  | "put"
  | "patch"
  | "delete";

export type ApiRouteManifestEntry = {
  method: HttpMethod;
  path: string;
  tag: string;
  summary: string;
  integrationAuth?: boolean;
  idempotency?: boolean;
};

export const API_ROUTE_MANIFEST: ApiRouteManifestEntry[] = [
  { method: "get", path: "/health", tag: "system", summary: "Health check" },
  { method: "get", path: "/openapi.json", tag: "system", summary: "OpenAPI document" },
  { method: "post", path: "/v1/organizations", tag: "organizations", summary: "Create organization" },
  { method: "get", path: "/v1/organizations/:id", tag: "organizations", summary: "Get organization" },
  { method: "post", path: "/v1/policies", tag: "policies", summary: "Create policy" },
  { method: "get", path: "/v1/policies/:id", tag: "policies", summary: "Get policy" },
  { method: "post", path: "/v1/resources", tag: "resources", summary: "Create resource" },
  { method: "get", path: "/v1/resources/:id", tag: "resources", summary: "Get resource" },
  { method: "get", path: "/v1/organizations/:organizationId/resources", tag: "resources", summary: "List organization resources" },
  { method: "get", path: "/v1/organizations/:organizationId/principals", tag: "organizations", summary: "List organization principals" },
  { method: "get", path: "/v1/organizations/:organizationId/authorizations", tag: "authorizations", summary: "List organization authorizations" },
  { method: "post", path: "/v1/authorizations", tag: "authorizations", summary: "Request authorization" },
  { method: "get", path: "/v1/authorizations/:id", tag: "authorizations", summary: "Get authorization" },
  { method: "get", path: "/v1/authorizations/:id/effectiveness", tag: "authorizations", summary: "Get authorization effectiveness" },
  { method: "post", path: "/v1/authorizations/:id/decisions", tag: "authorizations", summary: "Record authorization decision" },
  { method: "post", path: "/v1/authorizations/:id/revoke", tag: "authorizations", summary: "Revoke authorization" },
  { method: "post", path: "/v1/exceptions", tag: "exceptions", summary: "Request exception or waiver" },
  { method: "get", path: "/v1/exceptions/:id", tag: "exceptions", summary: "Get exception or waiver" },
  { method: "get", path: "/v1/exceptions/:id/effectiveness", tag: "exceptions", summary: "Get exception effectiveness" },
  { method: "post", path: "/v1/exceptions/:id/decisions", tag: "exceptions", summary: "Record exception decision" },
  { method: "post", path: "/v1/exceptions/:id/revoke", tag: "exceptions", summary: "Revoke exception" },
  { method: "post", path: "/v1/evidence", tag: "evidence", summary: "Create evidence" },
  { method: "get", path: "/v1/evidence/:id", tag: "evidence", summary: "Get evidence" },
  { method: "get", path: "/v1/organizations/:organizationId/resources/:resourceId/evidence", tag: "evidence", summary: "List resource evidence" },
  { method: "get", path: "/v1/organizations/:organizationId/resources/:resourceId/evidence-types", tag: "evidence", summary: "List resource evidence types" },
  { method: "post", path: "/v1/evidence/:id/attestations", tag: "evidence", summary: "Create evidence attestation" },
  { method: "post", path: "/v1/evidence/:id/revoke", tag: "evidence", summary: "Revoke evidence" },
  { method: "post", path: "/v1/evidence-attestations/:id/revoke", tag: "evidence", summary: "Revoke evidence attestation" },
  { method: "post", path: "/v1/deadlines", tag: "deadlines", summary: "Create deadline" },
  { method: "get", path: "/v1/deadlines/:id", tag: "deadlines", summary: "Get deadline" },
  { method: "get", path: "/v1/deadlines/:id/status", tag: "deadlines", summary: "Get effective deadline status" },
  { method: "get", path: "/v1/organizations/:organizationId/subjects/:subjectType/:subjectId/deadlines", tag: "deadlines", summary: "List subject deadlines" },
  { method: "post", path: "/v1/deadlines/:id/satisfy", tag: "deadlines", summary: "Satisfy deadline" },
  { method: "post", path: "/v1/deadlines/:id/cancel", tag: "deadlines", summary: "Cancel deadline" },
  { method: "post", path: "/v1/checks/run", tag: "checks", summary: "Run compliance check" },
  { method: "post", path: "/v1/checks/event", tag: "checks", summary: "Run event-triggered compliance check" },
  { method: "post", path: "/v1/checks/batch", tag: "checks", summary: "Run batch compliance checks" },
  { method: "get", path: "/v1/checks/:id", tag: "checks", summary: "Get compliance check" },
  { method: "get", path: "/v1/organizations/:organizationId/resources/:resourceId/checks", tag: "checks", summary: "List resource checks" },
  { method: "post", path: "/v1/evaluation-schedules", tag: "checks", summary: "Create evaluation schedule" },
  { method: "get", path: "/v1/evaluation-schedules/:id", tag: "checks", summary: "Get evaluation schedule" },
  { method: "post", path: "/v1/evaluation-schedules/:id/active", tag: "checks", summary: "Activate or deactivate evaluation schedule" },
  { method: "post", path: "/v1/checks/:id/findings/sync", tag: "findings", summary: "Synchronize findings from a failed check" },
  { method: "get", path: "/v1/findings/:id", tag: "findings", summary: "Get finding" },
  { method: "get", path: "/v1/organizations/:organizationId/resources/:resourceId/findings", tag: "findings", summary: "List resource findings" },
  { method: "post", path: "/v1/findings/:id/owner", tag: "findings", summary: "Assign finding owner" },
  { method: "post", path: "/v1/findings/:id/acknowledge", tag: "findings", summary: "Acknowledge finding" },
  { method: "post", path: "/v1/findings/:id/dispute", tag: "findings", summary: "Dispute finding" },
  { method: "post", path: "/v1/findings/:id/resolve-dispute", tag: "findings", summary: "Resolve finding dispute" },
  { method: "post", path: "/v1/findings/:id/remediations", tag: "remediations", summary: "Create remediation" },
  { method: "post", path: "/v1/remediations/:id/start", tag: "remediations", summary: "Start remediation" },
  { method: "post", path: "/v1/remediations/:id/submit", tag: "remediations", summary: "Submit remediation for verification" },
  { method: "post", path: "/v1/remediations/:id/verify", tag: "remediations", summary: "Verify remediation" },
  { method: "post", path: "/v1/remediations/:id/reject", tag: "remediations", summary: "Reject remediation" },
  { method: "post", path: "/v1/remediations/:id/cancel", tag: "remediations", summary: "Cancel remediation" },
  { method: "post", path: "/v1/findings/:id/close", tag: "findings", summary: "Close finding" },
  { method: "post", path: "/v1/findings/:id/reopen", tag: "findings", summary: "Reopen finding" },
  { method: "post", path: "/v1/certifications", tag: "certifications", summary: "Issue certification" },
  { method: "get", path: "/v1/certifications/:id", tag: "certifications", summary: "Get certification" },
  { method: "get", path: "/v1/organizations/:organizationId/resources/:resourceId/certifications", tag: "certifications", summary: "List resource certifications" },
  { method: "post", path: "/v1/certifications/:id/renew", tag: "certifications", summary: "Renew certification" },
  { method: "post", path: "/v1/certifications/:id/suspend", tag: "certifications", summary: "Suspend certification" },
  { method: "post", path: "/v1/certifications/:id/reinstate", tag: "certifications", summary: "Reinstate certification" },
  { method: "post", path: "/v1/certifications/:id/revoke", tag: "certifications", summary: "Revoke certification" },
  { method: "get", path: "/v1/public/certifications/verify/:code", tag: "certifications", summary: "Publicly verify certification" },
  { method: "get", path: "/v1/reports/organizations/:organizationId/compliance", tag: "reports", summary: "Generate organization compliance report" },
  { method: "get", path: "/v1/reports/organizations/:organizationId/resources/:resourceId/compliance", tag: "reports", summary: "Generate resource compliance report" },

  { method: "post", path: "/v1/integration/service-accounts", tag: "integration-admin", summary: "Create service account and API credential" },
  { method: "get", path: "/v1/integration/organizations/:organizationId/api-credentials", tag: "integration-admin", summary: "List organization API credentials" },
  { method: "post", path: "/v1/integration/api-credentials/:id/revoke", tag: "integration-admin", summary: "Revoke API credential" },

  { method: "post", path: "/v1/integration/resources", tag: "integration", summary: "Create resource through authenticated integration API", integrationAuth: true, idempotency: true },
  { method: "get", path: "/v1/integration/resources", tag: "integration", summary: "List resources with cursor pagination", integrationAuth: true },
  { method: "post", path: "/v1/integration/checks/run", tag: "integration", summary: "Run compliance check as service principal", integrationAuth: true, idempotency: true },
  { method: "post", path: "/v1/integration/webhooks", tag: "integration", summary: "Create webhook subscription", integrationAuth: true },
  { method: "get", path: "/v1/integration/webhooks", tag: "integration", summary: "List webhook subscriptions", integrationAuth: true },
  { method: "post", path: "/v1/integration/webhooks/:id/active", tag: "integration", summary: "Activate or deactivate webhook subscription", integrationAuth: true },
  { method: "get", path: "/v1/integration/events", tag: "integration", summary: "List durable integration events", integrationAuth: true },
  { method: "post", path: "/v1/integration/import/resources", tag: "integration", summary: "Import resources from an external system", integrationAuth: true, idempotency: true },
  { method: "get", path: "/v1/integration/export/resources", tag: "integration", summary: "Export resources as a portable bundle", integrationAuth: true },
  { method: "get", path: "/v1/integration/resources/:resourceId/registry-projection", tag: "adapters", summary: "Get Registry engine compliance projection", integrationAuth: true },
  { method: "get", path: "/v1/integration/case-triggers", tag: "adapters", summary: "List Case Workflow engine triggers", integrationAuth: true },
  { method: "post", path: "/v1/publications/preview", tag: "publication", summary: "Preview a deterministic public-safe projection" },
  { method: "post", path: "/v1/publications/publish", tag: "publication", summary: "Publish a public-safe projection snapshot" },
  { method: "post", path: "/v1/publications/unpublish", tag: "publication", summary: "Remove a publication snapshot from public visibility" },
  { method: "get", path: "/v1/publications/:id", tag: "publication", summary: "Get an internal publication control record" },
  { method: "get", path: "/v1/organizations/:organizationId/publications", tag: "publication", summary: "List organization publication controls" },
  { method: "get", path: "/v1/public/publications/:id", tag: "publication", summary: "Get a published public-safe projection" },
  { method: "get", path: "/v1/public/organizations/:organizationId/publications", tag: "publication", summary: "List published public-safe projections" }
];

export function buildOpenApiDocument(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};

  for (const route of API_ROUTE_MANIFEST) {
    const openApiPath = route.path.replace(
      /:([A-Za-z0-9_]+)/g,
      "{$1}",
    );
    const parameters = pathParameters(
      openApiPath,
    );

    const operation: Record<string, unknown> = {
      tags: [route.tag],
      summary: route.summary,
      operationId: operationId(route),
      parameters,
      responses: {
        "200": {
          description: "Successful response",
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: true,
              },
            },
          },
        },
        "201": {
          description: "Created",
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: true,
              },
            },
          },
        },
        "400": {
          description: "Validation error",
        },
        "404": {
          description: "Not found",
        },
        "409": {
          description: "Conflict",
        },
      },
    };

    if (route.integrationAuth) {
      operation.security = [
        {
          serviceBearer: [],
        },
      ];
      (
        operation.responses as Record<
          string,
          unknown
        >
      )["401"] = {
        description: "Invalid or inactive service credential",
      };
      (
        operation.responses as Record<
          string,
          unknown
        >
      )["403"] = {
        description: "Credential lacks required scope",
      };
    }

    if (route.idempotency) {
      (
        operation.parameters as unknown[]
      ).push({
        name: "Idempotency-Key",
        in: "header",
        required: true,
        schema: {
          type: "string",
          maxLength: 200,
        },
        description:
          "Credential-scoped idempotency key. Reusing a key with a different request returns 409.",
      });
    }

    if (
      route.method === "post" ||
      route.method === "put" ||
      route.method === "patch"
    ) {
      operation.requestBody = {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              additionalProperties: true,
            },
          },
        },
      };
    }

    paths[openApiPath] ??= {};
    paths[openApiPath]![route.method] =
      operation;
  }

  return {
    openapi: "3.1.0",
    info: {
      title:
        "Compliance, Authorization & Immutable Audit Engine API",
      version: "0.1.0",
      description:
        "Route-complete API contract for the reusable compliance engine. Internal domain APIs remain separate from the PR 15 publication boundary, which exposes only deterministic allowlisted publication snapshots and existing public certification verification artifacts.",
    },
    servers: [
      {
        url: "/",
      },
    ],
    tags: [
      { name: "system" },
      { name: "organizations" },
      { name: "policies" },
      { name: "resources" },
      { name: "authorizations" },
      { name: "exceptions" },
      { name: "evidence" },
      { name: "deadlines" },
      { name: "checks" },
      { name: "findings" },
      { name: "remediations" },
      { name: "certifications" },
      { name: "reports" },
      { name: "publication" },
      { name: "integration-admin" },
      { name: "integration" },
      { name: "adapters" },
    ],
    paths,
    components: {
      securitySchemes: {
        serviceBearer: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "CAIAE service API credential",
          description:
            "Token returned once when a service account credential is created. Only its SHA-256 hash is stored.",
        },
      },
      schemas: {
        CursorPage: {
          type: "object",
          required: [
            "items",
            "nextCursor",
          ],
          properties: {
            items: {
              type: "array",
              items: {},
            },
            nextCursor: {
              anyOf: [
                { type: "string" },
                { type: "null" },
              ],
            },
          },
        },
      },
    },
  };
}

function pathParameters(
  path: string,
): Array<Record<string, unknown>> {
  const names =
    [...path.matchAll(
      /\{([^}]+)\}/g,
    )].map(
      (match) => match[1]!,
    );

  return names.map((name) => ({
    name,
    in: "path",
    required: true,
    schema: {
      type: "string",
    },
  }));
}

function operationId(
  route: ApiRouteManifestEntry,
): string {
  const normalizedPath =
    route.path
      .replace(
        /:([A-Za-z0-9_]+)/g,
        " by $1 ",
      )
      .replace(
        /[^A-Za-z0-9]+/g,
        " ",
      )
      .trim()
      .split(/\s+/)
      .map((part, index) =>
        index === 0
          ? part.toLowerCase()
          : part.charAt(0).toUpperCase() +
            part.slice(1),
      )
      .join("");

  return `${route.method}${normalizedPath.charAt(0).toUpperCase()}${normalizedPath.slice(1)}`;
}
