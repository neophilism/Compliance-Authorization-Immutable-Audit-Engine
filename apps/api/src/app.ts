import Fastify from "fastify";
import cors from "@fastify/cors";
import {
  AuthorizationError,
  AuthorizationService,
} from "@caiae/authorization";
import {
  CertificationError,
  CertificationService,
} from "@caiae/certifications";
import {
  createPool,
  DomainRepository,
  LATEST_SCHEMA_VERSION,
  runMigrations,
  assessWorkerHealth,
} from "@caiae/db";
import {
  ExceptionError,
  ExceptionService,
} from "@caiae/exceptions";
import {
  EvidenceError,
  EvidenceService,
} from "@caiae/evidence";
import {
  DeadlineError,
  DeadlineService,
} from "@caiae/deadlines";
import {
  EvaluationError,
  EvaluationService,
} from "@caiae/evaluations";
import {
  FindingError,
  FindingService,
} from "@caiae/findings";
import {
  IntegrationError,
  IntegrationService,
  apiRouteAccess,
  apiRoutePermission,
  buildOpenApiDocument,
  findApiRoute,
  type AuthenticatedService,
  type ServiceScope,
} from "@caiae/integrations";
import {
  ReportingError,
  ReportingService,
  renderComplianceReport,
} from "@caiae/reporting";
import {
  PublicationError,
  PublicationService,
} from "@caiae/publication";
import {
  SecurityError,
  SecurityService,
  type AuthenticatedOperator,
} from "@caiae/security";
import {
  TraceabilityError,
  TraceabilityService,
  type AuthorityReferenceInput,
} from "@caiae/traceability";

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} is required`);
  }
  return value.trim();
}

type BuildAppOptions = {
  securityMode?: "enforce" | "legacy";
  bootstrapSecret?: string | null;
  runMigrations?: boolean;
  corsOrigins?: true | false | string[];
  trustProxy?: boolean;
  bodyLimitBytes?: number;
  requestTimeoutMs?: number;
  releaseSha?: string | null;
};

const ACTOR_FIELDS = [
  "principalId",
  "requestedByPrincipalId",
  "issuedByPrincipalId",
  "createdByPrincipalId",
  "submittedByPrincipalId",
] as const;

function operatorBearerToken(
  authorization: unknown,
): string {
  if (typeof authorization !== "string") {
    throw new SecurityError(
      "unauthorized",
      "Bearer operator credential is required",
    );
  }

  const match = authorization.match(
    /^Bearer\s+(.+)$/i,
  );

  if (!match?.[1]) {
    throw new SecurityError(
      "unauthorized",
      "Bearer operator credential is required",
    );
  }

  return match[1].trim();
}

function securityHeaderString(
  value: unknown,
  field: string,
): string {
  const raw =
    Array.isArray(value)
      ? value[0]
      : value;

  if (
    typeof raw !== "string" ||
    raw.trim() === ""
  ) {
    throw new SecurityError(
      "validation",
      `${field} is required`,
    );
  }

  return raw.trim();
}

function securityStringArray(
  value: unknown,
  field: string,
): string[] {
  if (!Array.isArray(value)) {
    throw new SecurityError(
      "validation",
      `${field} must be an array of strings`,
    );
  }

  return value.map((item, index) => {
    if (
      typeof item !== "string" ||
      item.trim() === ""
    ) {
      throw new SecurityError(
        "validation",
        `${field}[${index}] must be a non-empty string`,
      );
    }
    return item.trim();
  });
}

function securityOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (
    value === undefined ||
    value === null
  ) {
    return value;
  }
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new SecurityError(
      "validation",
      `${field} must be a non-empty string or null`,
    );
  }
  return value.trim();
}

function securityOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new SecurityError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
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

function deadlineOptionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") {
    throw new DeadlineError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function deadlineOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  if (typeof value !== "string" || value.trim() === "") {
    throw new DeadlineError(
      "validation",
      `${field} must be a non-empty string or null`,
    );
  }
  return value.trim();
}

function deadlineOptionalInteger(
  value: unknown,
  field: string,
): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value)) {
    throw new DeadlineError(
      "validation",
      `${field} must be a safe integer`,
    );
  }
  return value as number;
}

function deadlineOptionalNullableInteger(
  value: unknown,
  field: string,
): number | null | undefined {
  if (value === undefined || value === null) return value;
  if (!Number.isSafeInteger(value)) {
    throw new DeadlineError(
      "validation",
      `${field} must be a safe integer or null`,
    );
  }
  return value as number;
}

function deadlineOptionalNumberArray(
  value: unknown,
  field: string,
): number[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new DeadlineError(
      "validation",
      `${field} must be an array of integers`,
    );
  }

  return value.map((item, index) => {
    if (!Number.isSafeInteger(item)) {
      throw new DeadlineError(
        "validation",
        `${field}[${index}] must be a safe integer`,
      );
    }
    return item as number;
  });
}

function deadlineOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new DeadlineError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function evaluationRequiredObject(
  value: unknown,
  field: string,
): Record<string, any> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new EvaluationError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function evaluationOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  return evaluationRequiredObject(value, field);
}

function evaluationOptionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") {
    throw new EvaluationError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function evaluationOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  return evaluationOptionalString(value, field);
}

function evaluationRequiredInteger(
  value: unknown,
  field: string,
): number {
  if (!Number.isSafeInteger(value)) {
    throw new EvaluationError(
      "validation",
      `${field} must be a safe integer`,
    );
  }
  return value as number;
}

function evaluationStringArray(
  value: unknown,
  field: string,
): string[] {
  if (!Array.isArray(value)) {
    throw new EvaluationError(
      "validation",
      `${field} must be an array of strings`,
    );
  }
  return value.map((item, index) => {
    if (typeof item !== "string" || item.trim() === "") {
      throw new EvaluationError(
        "validation",
        `${field}[${index}] must be a non-empty string`,
      );
    }
    return item.trim();
  });
}

function findingOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  if (typeof value !== "string" || value.trim() === "") {
    throw new FindingError(
      "validation",
      `${field} must be a non-empty string or null`,
    );
  }
  return value.trim();
}

function findingOptionalInteger(
  value: unknown,
  field: string,
): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value)) {
    throw new FindingError(
      "validation",
      `${field} must be a safe integer`,
    );
  }
  return value as number;
}

function findingOptionalNumberArray(
  value: unknown,
  field: string,
): number[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new FindingError(
      "validation",
      `${field} must be an array of integers`,
    );
  }
  return value.map((item, index) => {
    if (!Number.isSafeInteger(item)) {
      throw new FindingError(
        "validation",
        `${field}[${index}] must be a safe integer`,
      );
    }
    return item as number;
  });
}

function findingOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new FindingError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function certificationOptionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") {
    throw new CertificationError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function certificationOptionalInteger(
  value: unknown,
  field: string,
): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value)) {
    throw new CertificationError(
      "validation",
      `${field} must be a safe integer`,
    );
  }
  return value as number;
}

function certificationOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new CertificationError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function certificationOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  return certificationOptionalString(value, field);
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
    default:
      return 500;
  }
}

function exceptionHttpStatus(error: ExceptionError): number {
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
    default:
      return 500;
  }
}

function evidenceHttpStatus(error: EvidenceError): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
      return 409;
    default:
      return 500;
  }
}

function deadlineHttpStatus(error: DeadlineError): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
      return 409;
    default:
      return 500;
  }
}

function evaluationHttpStatus(error: EvaluationError): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
      return 409;
    default:
      return 500;
  }
}

function findingHttpStatus(error: FindingError): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
      return 409;
    default:
      return 500;
  }
}

function reportingHttpStatus(error: ReportingError): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    default:
      return 500;
  }
}

function reportFormat(
  value: unknown,
): "json" | "csv" | "text" {
  if (value === undefined) return "json";
  if (
    value === "json" ||
    value === "csv" ||
    value === "text"
  ) {
    return value;
  }

  throw new ReportingError(
    "validation",
    "format must be json, csv, or text",
  );
}

function reportOptionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") {
    throw new ReportingError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function publicationHttpStatus(
  error: PublicationError,
): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
      return 409;
    default:
      return 500;
  }
}

function publicationOptionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new PublicationError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function publicationOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  return publicationOptionalString(value, field);
}

function publicationOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new PublicationError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function traceabilityHttpStatus(
  error: TraceabilityError,
): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
    case "conflict":
      return 409;
    default:
      return 500;
  }
}

function traceabilityAuthorities(
  value: unknown,
): AuthorityReferenceInput[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    throw new TraceabilityError(
      "validation",
      "authorities must be an array",
    );
  }

  return value.map((item, index) => {
    if (
      item === null ||
      typeof item !== "object" ||
      Array.isArray(item)
    ) {
      throw new TraceabilityError(
        "validation",
        `authorities[${index}] must be an object`,
      );
    }

    const source =
      item as Record<string, unknown>;

    return {
      authorityType:
        requiredString(
          source.authorityType,
          `authorities[${index}].authorityType`,
        ),
      citation:
        requiredString(
          source.citation,
          `authorities[${index}].citation`,
        ),
      title:
        typeof source.title === "string"
          ? source.title
          : null,
      uri:
        typeof source.uri === "string"
          ? source.uri
          : null,
      locator:
        typeof source.locator === "string"
          ? source.locator
          : null,
      jurisdiction:
        typeof source.jurisdiction === "string"
          ? source.jurisdiction
          : null,
      effectiveFrom:
        typeof source.effectiveFrom === "string"
          ? source.effectiveFrom
          : null,
      effectiveTo:
        typeof source.effectiveTo === "string"
          ? source.effectiveTo
          : null,
      metadata:
        source.metadata !== null &&
        typeof source.metadata === "object" &&
        !Array.isArray(source.metadata)
          ? source.metadata as Record<string, any>
          : undefined,
    };
  });
}

function securityHttpStatus(
  error: SecurityError,
): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "unauthorized":
      return 401;
    case "forbidden":
      return 403;
    case "not_found":
      return 404;
    case "conflict":
      return 409;
    default:
      return 500;
  }
}

function certificationHttpStatus(
  error: CertificationError,
): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "not_found":
      return 404;
    case "invalid_state":
      return 409;
    default:
      return 500;
  }
}

function integrationHttpStatus(
  error: IntegrationError,
): number {
  switch (error.code) {
    case "validation":
      return 400;
    case "unauthorized":
      return 401;
    case "forbidden":
      return 403;
    case "not_found":
      return 404;
    case "conflict":
      return 409;
    default:
      return 500;
  }
}

function integrationOptionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() === "") {
    throw new IntegrationError(
      "validation",
      `${field} must be a non-empty string`,
    );
  }
  return value.trim();
}

function integrationOptionalNullableString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) return value;
  return integrationOptionalString(value, field);
}

function integrationOptionalInteger(
  value: unknown,
  field: string,
): number | undefined {
  if (value === undefined) return undefined;
  const parsed =
    typeof value === "string"
      ? Number(value)
      : value;

  if (!Number.isSafeInteger(parsed)) {
    throw new IntegrationError(
      "validation",
      `${field} must be a safe integer`,
    );
  }

  return parsed as number;
}

function integrationOptionalObject(
  value: unknown,
  field: string,
): Record<string, any> | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new IntegrationError(
      "validation",
      `${field} must be an object`,
    );
  }
  return value as Record<string, any>;
}

function integrationStringArray(
  value: unknown,
  field: string,
): string[] {
  if (!Array.isArray(value)) {
    throw new IntegrationError(
      "validation",
      `${field} must be an array of strings`,
    );
  }

  return value.map((item, index) => {
    if (typeof item !== "string" || item.trim() === "") {
      throw new IntegrationError(
        "validation",
        `${field}[${index}] must be a non-empty string`,
      );
    }
    return item.trim();
  });
}

function integrationOptionalStringArray(
  value: unknown,
  field: string,
): string[] | undefined {
  if (value === undefined) return undefined;
  return integrationStringArray(value, field);
}

function integrationBoolean(
  value: unknown,
  field: string,
): boolean {
  if (typeof value !== "boolean") {
    throw new IntegrationError(
      "validation",
      `${field} must be a boolean`,
    );
  }
  return value;
}

function integrationBearerToken(
  authorization: unknown,
): string {
  if (typeof authorization !== "string") {
    throw new IntegrationError(
      "unauthorized",
      "Bearer API credential is required",
    );
  }

  const match = authorization.match(
    /^Bearer\s+(.+)$/i,
  );

  if (!match?.[1]) {
    throw new IntegrationError(
      "unauthorized",
      "Bearer API credential is required",
    );
  }

  return match[1].trim();
}

function integrationIdempotencyKey(
  value: unknown,
): string {
  const raw =
    Array.isArray(value)
      ? value[0]
      : value;

  if (typeof raw !== "string" || raw.trim() === "") {
    throw new IntegrationError(
      "validation",
      "Idempotency-Key header is required",
    );
  }

  return raw.trim();
}

export async function buildApp(
  options: BuildAppOptions = {},
) {
  const app = Fastify({
    logger: true,
    trustProxy:
      options.trustProxy ?? false,
    bodyLimit:
      options.bodyLimitBytes ??
      1_048_576,
    requestTimeout:
      options.requestTimeoutMs ??
      30_000,
  });
  const pool = createPool();

  if (
    options.runMigrations ??
    true
  ) {
    await runMigrations(pool);
  }
  const repository = new DomainRepository(pool);
  const authorizations = new AuthorizationService(pool);
  const exceptions = new ExceptionService(pool);
  const evidence = new EvidenceService(pool);
  const deadlines = new DeadlineService(pool);
  const evaluations = new EvaluationService(pool);
  const findings = new FindingService(pool);
  const certifications = new CertificationService(pool);
  const reporting = new ReportingService(pool);
  const publication = new PublicationService(pool);
  const traceability = new TraceabilityService(pool);
  const security = new SecurityService(pool, {
    bootstrapSecret:
      options.bootstrapSecret,
  });
  const integrations = new IntegrationService(pool);
  const securityMode =
    options.securityMode ??
    (
      process.env.CAIAE_API_SECURITY_MODE ===
        "legacy"
        ? "legacy"
        : "enforce"
    );

  await app.register(cors, {
    origin:
      options.corsOrigins ??
      true,
  });

  async function lookupOrganizationById(
    table: string,
    id: string,
  ): Promise<string | null> {
    const allowed = new Set([
      "policies",
      "rule_sets",
      "resources",
      "authorizations",
      "exceptions",
      "evidence",
      "evidence_attestations",
      "deadlines",
      "checks",
      "evaluation_schedules",
      "findings",
      "remediations",
      "certifications",
      "publication_controls",
      "api_credentials",
      "operator_credentials",
    ]);

    if (!allowed.has(table)) {
      throw new Error(
        "unsupported organization lookup table",
      );
    }

    const result = await pool.query(
      `SELECT organization_id
       FROM ${table}
       WHERE id = $1`,
      [id],
    );

    return (
      result.rows[0]
        ?.organization_id ??
      null
    );
  }

  async function resolveRequestOrganization(
    routePath: string,
    params: Record<string, unknown>,
    body: Record<string, unknown>,
  ): Promise<string | null> {
    const direct =
      typeof params.organizationId ===
        "string"
        ? params.organizationId
        : (
            typeof body.organizationId ===
              "string"
              ? body.organizationId
              : null
          );

    if (direct) return direct;

    if (
      routePath ===
        "/v1/organizations/:id" &&
      typeof params.id === "string"
    ) {
      return params.id;
    }

    if (
      typeof params.id !== "string"
    ) {
      return null;
    }

    const id = params.id;
    const prefixes: Array<
      [string, string]
    > = [
      ["/v1/policies/", "policies"],
      ["/v1/rulesets/", "rule_sets"],
      ["/v1/resources/", "resources"],
      ["/v1/authorizations/", "authorizations"],
      ["/v1/exceptions/", "exceptions"],
      ["/v1/evidence-attestations/", "evidence_attestations"],
      ["/v1/evidence/", "evidence"],
      ["/v1/deadlines/", "deadlines"],
      ["/v1/checks/", "checks"],
      ["/v1/evaluation-schedules/", "evaluation_schedules"],
      ["/v1/findings/", "findings"],
      ["/v1/remediations/", "remediations"],
      ["/v1/certifications/", "certifications"],
      ["/v1/publications/", "publication_controls"],
      ["/v1/integration/api-credentials/", "api_credentials"],
      ["/v1/security/operator-credentials/", "operator_credentials"],
    ];

    for (
      const [prefix, table] of prefixes
    ) {
      if (
        routePath.startsWith(prefix)
      ) {
        return lookupOrganizationById(
          table,
          id,
        );
      }
    }

    return null;
  }

  app.addHook(
    "preHandler",
    async (request) => {
      if (
        securityMode === "legacy"
      ) {
        return;
      }

      const routePath =
        request.routeOptions.url;

      if (!routePath) {
        return;
      }

      const route = findApiRoute(
        request.method,
        routePath,
      );

      if (!route) return;

      const access =
        apiRouteAccess(route);

      if (
        access !== "operator"
      ) {
        return;
      }

      const auth =
        await security.authenticate(
          operatorBearerToken(
            request.headers
              .authorization,
          ),
        );

      security.assertPermission(
        auth,
        apiRoutePermission(route),
      );

      const params =
        (
          request.params ??
          {}
        ) as Record<
          string,
          unknown
        >;
      const body =
        (
          request.body ??
          {}
        ) as Record<
          string,
          unknown
        >;
      const organizationId =
        await resolveRequestOrganization(
          routePath,
          params,
          body,
        );

      if (organizationId !== null) {
        security.assertOrganization(
          auth,
          organizationId,
        );
      }

      const principalIdIsTarget =
        routePath ===
          "/v1/security/role-assignments" ||
        routePath ===
          "/v1/security/operator-credentials";

      for (
        const field of
        ACTOR_FIELDS
      ) {
        if (
          field === "principalId" &&
          principalIdIsTarget
        ) {
          continue;
        }

        const value =
          body[field];

        if (
          typeof value ===
            "string"
        ) {
          security.assertActor(
            auth,
            value,
            field,
          );
        }
      }

      (
        request as any
      ).operatorAuth = auth;
    },
  );

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

    if (error instanceof ExceptionError) {
      return reply
        .code(exceptionHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof EvidenceError) {
      return reply
        .code(evidenceHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof DeadlineError) {
      return reply
        .code(deadlineHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof EvaluationError) {
      return reply
        .code(evaluationHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof FindingError) {
      return reply
        .code(findingHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof CertificationError) {
      return reply
        .code(certificationHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof ReportingError) {
      return reply
        .code(reportingHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof PublicationError) {
      return reply
        .code(publicationHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof IntegrationError) {
      return reply
        .code(integrationHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof SecurityError) {
      return reply
        .code(securityHttpStatus(error))
        .send({
          error: error.code,
          message: error.message,
        });
    }

    if (error instanceof TraceabilityError) {
      return reply
        .code(traceabilityHttpStatus(error))
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
    release:
      options.releaseSha ??
      null,
    timestamp: new Date().toISOString(),
  }));

  app.get(
    "/ready",
    async (_request, reply) => {
      try {
        await pool.query("SELECT 1");
        const schema =
          await pool.query(
            `SELECT 1
             FROM schema_migrations
             WHERE version = $1`,
            [
              LATEST_SCHEMA_VERSION,
            ],
          );

        if (!schema.rows[0]) {
          return reply
            .code(503)
            .send({
              status:
                "not_ready",
              reason:
                "schema_out_of_date",
              expectedSchemaVersion:
                LATEST_SCHEMA_VERSION,
              service: "api",
              release:
                options.releaseSha ??
                null,
              timestamp:
                new Date().toISOString(),
            });
        }

        const workerQuery = _request.query as { includeWorker?: string };
        if (workerQuery?.includeWorker === "true") {
          const workerHealth = await assessWorkerHealth(pool, 180_000, options.releaseSha ?? null);
          if (!workerHealth.healthy) {
            return reply.code(503).send({
              status: "not_ready",
              reason: "worker_unhealthy",
              service: "api",
              release: options.releaseSha ?? null,
              timestamp: new Date().toISOString(),
            });
          }
        }

        return {
          status: "ready",
          schemaVersion:
            LATEST_SCHEMA_VERSION,
          service: "api",
          release:
            options.releaseSha ??
            null,
          timestamp:
            new Date().toISOString(),
        };
      } catch (error) {
        app.log.error(
          error,
          "readiness check failed",
        );
        return reply
          .code(503)
          .send({
            status:
              "not_ready",
            service: "api",
            release:
              options.releaseSha ??
              null,
            timestamp:
              new Date().toISOString(),
          });
      }
    },
  );

  app.get("/openapi.json", async () =>
    buildOpenApiDocument(),
  );

  function operatorAuth(
    request: unknown,
  ): AuthenticatedOperator {
    const auth =
      (
        request as {
          operatorAuth?:
            AuthenticatedOperator;
        }
      ).operatorAuth;

    if (!auth) {
      throw new SecurityError(
        "unauthorized",
        "operator authentication is required",
      );
    }

    return auth;
  }

  async function integrationAuth(
    request: { headers: Record<string, unknown> },
    scopes: ServiceScope[],
  ): Promise<AuthenticatedService> {
    return integrations.authenticate(
      integrationBearerToken(
        request.headers.authorization,
      ),
      scopes,
    );
  }

  app.post(
    "/v1/security/bootstrap",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;
      const issued =
        await security.bootstrap(
          securityHeaderString(
            request.headers[
              "x-caiae-bootstrap-secret"
            ],
            "X-CAIAE-Bootstrap-Secret",
          ),
          {
            organizationId:
              requiredString(
                body.organizationId,
                "organizationId",
              ),
            principalId:
              requiredString(
                body.principalId,
                "principalId",
              ),
            credentialName:
              typeof body.credentialName ===
                "string"
                ? body.credentialName
                : undefined,
          },
        );

      return reply
        .code(201)
        .send(issued);
    },
  );

  app.get(
    "/v1/security/me",
    async (request) =>
      operatorAuth(request),
  );

  app.get(
    "/v1/security/roles",
    async (request) =>
      security.listRoles(
        operatorAuth(request),
      ),
  );

  app.post(
    "/v1/security/roles",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;
      const role =
        await security.createRole(
          operatorAuth(request),
          {
            organizationId:
              requiredString(
                body.organizationId,
                "organizationId",
              ),
            key: requiredString(
              body.key,
              "key",
            ),
            name: requiredString(
              body.name,
              "name",
            ),
            permissions:
              securityStringArray(
                body.permissions,
                "permissions",
              ),
            metadata:
              securityOptionalObject(
                body.metadata,
                "metadata",
              ),
          },
        );

      return reply
        .code(201)
        .send(role);
    },
  );

  app.post(
    "/v1/security/role-assignments",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;
      const assignment =
        await security.assignRole(
          operatorAuth(request),
          {
            organizationId:
              requiredString(
                body.organizationId,
                "organizationId",
              ),
            principalId:
              requiredString(
                body.principalId,
                "principalId",
              ),
            roleId:
              requiredString(
                body.roleId,
                "roleId",
              ),
          },
        );

      return reply
        .code(201)
        .send(assignment);
    },
  );

  app.get(
    "/v1/security/operator-credentials",
    async (request) =>
      security.listCredentials(
        operatorAuth(request),
      ),
  );

  app.post(
    "/v1/security/operator-credentials",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;
      const issued =
        await security.issueCredential(
          operatorAuth(request),
          {
            organizationId:
              requiredString(
                body.organizationId,
                "organizationId",
              ),
            principalId:
              requiredString(
                body.principalId,
                "principalId",
              ),
            name: requiredString(
              body.name,
              "name",
            ),
            expiresAt:
              securityOptionalNullableString(
                body.expiresAt,
                "expiresAt",
              ),
            metadata:
              securityOptionalObject(
                body.metadata,
                "metadata",
              ),
          },
        );

      return reply
        .code(201)
        .send(issued);
    },
  );

  app.post(
    "/v1/security/operator-credentials/:id/revoke",
    async (request) => {
      const { id } =
        request.params as {
          id: string;
        };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return security.revokeCredential(
        operatorAuth(request),
        {
          credentialId: id,
          reason: requiredString(
            body.reason,
            "reason",
          ),
        },
      );
    },
  );

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

  app.post(
    "/v1/rulesets",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;
      const auth = operatorAuth(request);
      const registered =
        await traceability.register({
          organizationId:
            requiredString(
              body.organizationId,
              "organizationId",
            ),
          policyId:
            requiredString(
              body.policyId,
              "policyId",
            ),
          key:
            requiredString(
              body.key,
              "key",
            ),
          ruleSet:
            evaluationRequiredObject(
              body.ruleSet,
              "ruleSet",
            ),
          effectiveFrom:
            evaluationOptionalNullableString(
              body.effectiveFrom,
              "effectiveFrom",
            ),
          effectiveTo:
            evaluationOptionalNullableString(
              body.effectiveTo,
              "effectiveTo",
            ),
          supersedesRuleSetId:
            evaluationOptionalNullableString(
              body.supersedesRuleSetId,
              "supersedesRuleSetId",
            ),
          authorities:
            traceabilityAuthorities(
              body.authorities,
            ),
          createdByPrincipalId:
            auth.principal.id,
          metadata:
            evaluationOptionalObject(
              body.metadata,
              "metadata",
            ),
          correlationId:
            evaluationOptionalNullableString(
              body.correlationId,
              "correlationId",
            ),
        });

      return reply
        .code(201)
        .send(registered);
    },
  );

  app.get(
    "/v1/rulesets/:id",
    async (request) => {
      const { id } =
        request.params as {
          id: string;
        };
      return traceability.get(id);
    },
  );

  app.get(
    "/v1/rulesets/:id/traceability",
    async (request) => {
      const { id } =
        request.params as {
          id: string;
        };
      return traceability.traceability(
        id,
      );
    },
  );

  app.post(
    "/v1/rulesets/:id/activate",
    async (request) => {
      const { id } =
        request.params as {
          id: string;
        };
      const body = (request.body ?? {}) as Record<string, unknown>;
      const auth = operatorAuth(request);

      return traceability.activate({
        ruleSetId: id,
        principalId:
          auth.principal.id,
        effectiveFrom:
          evaluationOptionalNullableString(
            body.effectiveFrom,
            "effectiveFrom",
          ),
        correlationId:
          evaluationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
      });
    },
  );

  app.post(
    "/v1/rulesets/:id/retire",
    async (request) => {
      const { id } =
        request.params as {
          id: string;
        };
      const body = (request.body ?? {}) as Record<string, unknown>;
      const auth = operatorAuth(request);

      return traceability.retire({
        ruleSetId: id,
        principalId:
          auth.principal.id,
        effectiveTo:
          evaluationOptionalNullableString(
            body.effectiveTo,
            "effectiveTo",
          ),
        reason:
          evaluationOptionalNullableString(
            body.reason,
            "reason",
          ),
        correlationId:
          evaluationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
      });
    },
  );

  app.get(
    "/v1/organizations/:organizationId/rulesets",
    async (request) => {
      const { organizationId } =
        request.params as {
          organizationId: string;
        };
      const query =
        request.query as {
          key?: string;
          status?: "draft" | "active" | "superseded" | "retired";
        };

      return traceability.list(
        organizationId,
        {
          key: query.key ?? null,
          status:
            query.status ?? null,
        },
      );
    },
  );

  app.get(
    "/v1/organizations/:organizationId/rulesets/resolve/:key",
    async (request) => {
      const {
        organizationId,
        key,
      } = request.params as {
        organizationId: string;
        key: string;
      };
      const query =
        request.query as {
          at?: string;
        };

      return traceability.resolve({
        organizationId,
        key,
        at: query.at,
      });
    },
  );

  app.post("/v1/resources", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const attributes =
      optionalObject(
        body.attributes,
        "attributes",
      ) ?? {};
    const metadata =
      optionalObject(
        body.metadata,
        "metadata",
      ) ?? {};
    const status =
      body.status ===
      undefined
        ? undefined
        : requiredString(
            body.status,
            "status",
          );

    if (
      status !== undefined &&
      status !== "active" &&
      status !== "inactive" &&
      status !== "archived"
    ) {
      return reply
        .code(400)
        .send({
          error:
            "validation",
          message:
            "status must be active, inactive, or archived",
        });
    }

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
        optionalNullableString(
          body.externalRef,
          "externalRef",
        ) ?? null,
      status,
      attributes,
      metadata,
    });
    return reply.code(201).send(resource);
  });

  app.get("/v1/resources/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const resource = await repository.getResource(id);
    if (!resource) return reply.code(404).send({ error: "not_found" });
    return resource;
  });

  app.patch(
    "/v1/resources/:id",
    async (request, reply) => {
      const { id } =
        request.params as {
          id: string;
        };
      const body =
        (
          request.body ??
          {}
        ) as Record<
          string,
          unknown
        >;

      const expectedUpdatedAt =
        requiredString(
          body.expectedUpdatedAt,
          "expectedUpdatedAt",
        );

      if (
        Number.isNaN(
          new Date(
            expectedUpdatedAt,
          ).getTime(),
        )
      ) {
        return reply
          .code(400)
          .send({
            error:
              "validation",
            message:
              "expectedUpdatedAt must be a valid date-time",
          });
      }

      const mutableFields = [
        "name",
        "externalRef",
        "status",
        "attributes",
        "metadata",
      ];

      if (
        !mutableFields.some(
          (field) =>
            Object.prototype.hasOwnProperty.call(
              body,
              field,
            ),
        )
      ) {
        return reply
          .code(400)
          .send({
            error:
              "validation",
            message:
              "at least one mutable resource field is required",
          });
      }

      const name =
        body.name ===
        undefined
          ? undefined
          : requiredString(
              body.name,
              "name",
            );
      const externalRef =
        optionalNullableString(
          body.externalRef,
          "externalRef",
        );
      const status =
        body.status ===
        undefined
          ? undefined
          : requiredString(
              body.status,
              "status",
            );

      if (
        status !==
          undefined &&
        status !== "active" &&
        status !==
          "inactive" &&
        status !==
          "archived"
      ) {
        return reply
          .code(400)
          .send({
            error:
              "validation",
            message:
              "status must be active, inactive, or archived",
          });
      }

      const attributes =
        optionalObject(
          body.attributes,
          "attributes",
        );
      const metadata =
        optionalObject(
          body.metadata,
          "metadata",
        );

      const auth =
        (
          request as {
            operatorAuth?:
              AuthenticatedOperator;
          }
        ).operatorAuth;

      const result =
        await repository.updateResource({
          resourceId: id,
          expectedUpdatedAt,
          name,
          externalRef,
          status,
          attributes,
          metadata,
          actorPrincipalId:
            auth?.principal.id ??
            null,
          correlationId:
            optionalNullableString(
              body.correlationId,
              "correlationId",
            ),
        });

      if (
        result.status ===
        "not_found"
      ) {
        return reply
          .code(404)
          .send({
            error:
              "not_found",
            message:
              "resource not found",
          });
      }

      if (
        result.status ===
        "conflict"
      ) {
        return reply
          .code(409)
          .send({
            error:
              "conflict",
            message:
              "resource changed since expectedUpdatedAt",
            current:
              result.current,
          });
      }

      return result.resource;
    },
  );

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

  app.get(
    "/v1/organizations/:organizationId/principals",
    async (request) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };
      const query = request.query as {
        status?: string;
        kind?: string;
      };

      if (
        query.status !== undefined &&
        query.status !== "active" &&
        query.status !== "inactive"
      ) {
        throw new AuthorizationError("validation", "status must be active or inactive");
      }

      if (
        query.kind !== undefined &&
        query.kind !== "user" &&
        query.kind !== "service"
      ) {
        throw new AuthorizationError("validation", "kind must be user or service");
      }

      const values: unknown[] = [organizationId];
      let where = "organization_id = $1";

      if (query.status) {
        values.push(query.status);
        where += " AND status = $" + values.length;
      }

      if (query.kind) {
        values.push(query.kind);
        where += " AND kind = $" + values.length;
      }

      const result = await pool.query(
        `SELECT
           id,
           organization_id,
           kind,
           display_name,
           external_ref,
           status,
           metadata,
           created_at,
           updated_at
         FROM principals
         WHERE ${where}
         ORDER BY display_name ASC, id ASC`,
        values,
      );

      return result.rows.map((row) => ({
        id: row.id,
        organizationId: row.organization_id,
        kind: row.kind,
        displayName: row.display_name,
        externalRef: row.external_ref,
        status: row.status,
        metadata: row.metadata ?? {},
        createdAt: (
          row.created_at instanceof Date
            ? row.created_at
            : new Date(row.created_at)
        ).toISOString(),
        updatedAt: (
          row.updated_at instanceof Date
            ? row.updated_at
            : new Date(row.updated_at)
        ).toISOString(),
      }));
    },
  );

  app.get(
    "/v1/organizations/:organizationId/authorizations",
    async (request) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };
      const query = request.query as {
        status?: string;
        resourceId?: string;
      };
      const allowed = new Set([
        "pending",
        "approved",
        "denied",
        "revoked",
        "expired",
      ]);

      if (
        query.status !== undefined &&
        !allowed.has(query.status)
      ) {
        throw new AuthorizationError(
          "validation",
          "status is invalid",
        );
      }

      const values: unknown[] = [organizationId];
      let where = "a.organization_id = $1";

      if (query.status) {
        values.push(query.status);
        where += " AND a.status = $" + values.length;
      }

      if (query.resourceId) {
        values.push(query.resourceId);
        where += " AND a.resource_id = $" + values.length;
      }

      const result = await pool.query(
        `SELECT
           a.*,
           COALESCE(d.approval_count, 0)::int AS approval_count,
           COALESCE(e.eligible_count, 0)::int AS eligible_approver_count
         FROM authorizations AS a
         LEFT JOIN (
           SELECT
             authorization_id,
             count(*) FILTER (
               WHERE decision = 'approve'
             ) AS approval_count
           FROM authorization_decisions
           GROUP BY authorization_id
         ) AS d
           ON d.authorization_id = a.id
         LEFT JOIN (
           SELECT
             authorization_id,
             count(*) AS eligible_count
           FROM authorization_eligible_approvers
           GROUP BY authorization_id
         ) AS e
           ON e.authorization_id = a.id
         WHERE ${where}
         ORDER BY a.requested_at DESC, a.id DESC`,
        values,
      );

      return result.rows.map((row) => ({
        id: row.id,
        organizationId: row.organization_id,
        resourceId: row.resource_id,
        authorizationType: row.authorization_type,
        status: row.status,
        requestedByPrincipalId:
          row.requested_by_principal_id,
        decidedByPrincipalId:
          row.decided_by_principal_id,
        requestedAt: (
          row.requested_at instanceof Date
            ? row.requested_at
            : new Date(row.requested_at)
        ).toISOString(),
        decidedAt:
          row.decided_at === null
            ? null
            : (
                row.decided_at instanceof Date
                  ? row.decided_at
                  : new Date(row.decided_at)
              ).toISOString(),
        validFrom:
          row.valid_from === null
            ? null
            : (
                row.valid_from instanceof Date
                  ? row.valid_from
                  : new Date(row.valid_from)
              ).toISOString(),
        validUntil:
          row.valid_until === null
            ? null
            : (
                row.valid_until instanceof Date
                  ? row.valid_until
                  : new Date(row.valid_until)
              ).toISOString(),
        scope: row.scope ?? {},
        conditions: row.conditions ?? {},
        approvalQuorum: Number(row.approval_quorum),
        approvalAuthority: row.approval_authority,
        emergency: Boolean(row.emergency),
        emergencyReviewDueAt:
          row.emergency_review_due_at === null
            ? null
            : (
                row.emergency_review_due_at instanceof Date
                  ? row.emergency_review_due_at
                  : new Date(row.emergency_review_due_at)
              ).toISOString(),
        emergencyReviewedAt:
          row.emergency_reviewed_at === null
            ? null
            : (
                row.emergency_reviewed_at instanceof Date
                  ? row.emergency_reviewed_at
                  : new Date(row.emergency_reviewed_at)
              ).toISOString(),
        approvalCount: Number(row.approval_count),
        eligibleApproverCount: Number(
          row.eligible_approver_count,
        ),
        metadata: row.metadata ?? {},
        createdAt: (
          row.created_at instanceof Date
            ? row.created_at
            : new Date(row.created_at)
        ).toISOString(),
        updatedAt: (
          row.updated_at instanceof Date
            ? row.updated_at
            : new Date(row.updated_at)
        ).toISOString(),
      }));
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

  app.post("/v1/exceptions", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    if (body.kind !== "exception" && body.kind !== "waiver") {
      throw new ExceptionError(
        "validation",
        "kind must be exception or waiver",
      );
    }

    const record = await exceptions.request({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceId: requiredString(body.resourceId, "resourceId"),
      ruleId: optionalNullableString(body.ruleId, "ruleId"),
      kind: body.kind,
      requestedByPrincipalId: requiredString(
        body.requestedByPrincipalId,
        "requestedByPrincipalId",
      ),
      justification: requiredString(
        body.justification,
        "justification",
      ),
      validFrom: optionalNullableString(body.validFrom, "validFrom"),
      validUntil: requiredString(body.validUntil, "validUntil"),
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
      metadata: optionalObject(body.metadata, "metadata"),
      correlationId: optionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send(record);
  });

  app.get("/v1/exceptions/:id", async (request) => {
    const { id } = request.params as { id: string };
    return exceptions.get(id);
  });

  app.get(
    "/v1/exceptions/:id/effectiveness",
    async (request) => {
      const { id } = request.params as { id: string };
      const query = request.query as { at?: string };

      if (query.at === undefined) {
        return exceptions.effectiveness(id);
      }

      const at = new Date(query.at);
      if (Number.isNaN(at.getTime())) {
        throw new ExceptionError(
          "validation",
          "at must be a valid date-time",
        );
      }

      return exceptions.effectiveness(id, at);
    },
  );

  app.post(
    "/v1/exceptions/:id/decisions",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      if (body.decision !== "approve" && body.decision !== "deny") {
        throw new ExceptionError(
          "validation",
          "decision must be approve or deny",
        );
      }

      return exceptions.recordDecision({
        exceptionId: id,
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
    "/v1/exceptions/:id/revoke",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return exceptions.revoke({
        exceptionId: id,
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

  app.post("/v1/evidence", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    const record = await evidence.create({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceId: requiredString(body.resourceId, "resourceId"),
      evidenceType: requiredString(
        body.evidenceType,
        "evidenceType",
      ),
      title: requiredString(body.title, "title"),
      submittedByPrincipalId: optionalNullableString(
        body.submittedByPrincipalId,
        "submittedByPrincipalId",
      ),
      source: optionalNullableString(body.source, "source"),
      uri: optionalNullableString(body.uri, "uri"),
      mediaType: optionalNullableString(
        body.mediaType,
        "mediaType",
      ),
      fileName: optionalNullableString(
        body.fileName,
        "fileName",
      ),
      checksumAlgorithm: optionalNullableString(
        body.checksumAlgorithm,
        "checksumAlgorithm",
      ),
      checksum: optionalNullableString(body.checksum, "checksum"),
      capturedAt: optionalNullableString(
        body.capturedAt,
        "capturedAt",
      ),
      validFrom: optionalNullableString(body.validFrom, "validFrom"),
      validUntil: optionalNullableString(
        body.validUntil,
        "validUntil",
      ),
      provenance: optionalObject(body.provenance, "provenance"),
      supersedesEvidenceId: optionalNullableString(
        body.supersedesEvidenceId,
        "supersedesEvidenceId",
      ),
      attributes: optionalObject(body.attributes, "attributes"),
      metadata: optionalObject(body.metadata, "metadata"),
      correlationId: optionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send(record);
  });

  app.get("/v1/evidence/:id", async (request) => {
    const { id } = request.params as { id: string };
    return evidence.get(id);
  });

  app.get(
    "/v1/organizations/:organizationId/resources/:resourceId/evidence",
    async (request) => {
      const { organizationId, resourceId } = request.params as {
        organizationId: string;
        resourceId: string;
      };
      return evidence.listForResource(
        organizationId,
        resourceId,
      );
    },
  );

  app.get(
    "/v1/organizations/:organizationId/resources/:resourceId/evidence-types",
    async (request) => {
      const { organizationId, resourceId } = request.params as {
        organizationId: string;
        resourceId: string;
      };
      const query = request.query as { at?: string };
      const at = query.at === undefined ? new Date() : new Date(query.at);

      if (Number.isNaN(at.getTime())) {
        throw new EvidenceError(
          "validation",
          "at must be a valid date-time",
        );
      }

      return {
        evidenceTypes: await evidence.validEvidenceTypes(
          organizationId,
          resourceId,
          at,
        ),
      };
    },
  );

  app.post(
    "/v1/evidence/:id/attestations",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return evidence.addAttestation({
        evidenceId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        attestationType: requiredString(
          body.attestationType,
          "attestationType",
        ),
        statement: requiredString(
          body.statement,
          "statement",
        ),
        claims: optionalObject(body.claims, "claims"),
        attestedAt: optionalString(body.attestedAt, "attestedAt"),
        validUntil: optionalNullableString(
          body.validUntil,
          "validUntil",
        ),
        metadata: optionalObject(body.metadata, "metadata"),
        correlationId: optionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post("/v1/evidence/:id/revoke", async (request) => {
    const { id } = request.params as { id: string };
    const body = (request.body ?? {}) as Record<string, unknown>;

    return evidence.revoke({
      evidenceId: id,
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
  });

  app.post(
    "/v1/evidence-attestations/:id/revoke",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return evidence.revokeAttestation({
        attestationId: id,
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

  app.post("/v1/deadlines", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    const record = await deadlines.create({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceId: deadlineOptionalNullableString(
        body.resourceId,
        "resourceId",
      ),
      subjectType: requiredString(
        body.subjectType,
        "subjectType",
      ),
      subjectId: requiredString(body.subjectId, "subjectId"),
      deadlineType: requiredString(
        body.deadlineType,
        "deadlineType",
      ),
      createdByPrincipalId: deadlineOptionalNullableString(
        body.createdByPrincipalId,
        "createdByPrincipalId",
      ),
      dueAt: deadlineOptionalString(body.dueAt, "dueAt"),
      anchorAt: deadlineOptionalString(
        body.anchorAt,
        "anchorAt",
      ),
      dueAfterSeconds: deadlineOptionalInteger(
        body.dueAfterSeconds,
        "dueAfterSeconds",
      ),
      warningWindowSeconds: deadlineOptionalInteger(
        body.warningWindowSeconds,
        "warningWindowSeconds",
      ),
      gracePeriodSeconds: deadlineOptionalInteger(
        body.gracePeriodSeconds,
        "gracePeriodSeconds",
      ),
      recurrenceIntervalSeconds:
        deadlineOptionalNullableInteger(
          body.recurrenceIntervalSeconds,
          "recurrenceIntervalSeconds",
        ),
      recurrenceEndAt: deadlineOptionalNullableString(
        body.recurrenceEndAt,
        "recurrenceEndAt",
      ),
      maxOccurrences: deadlineOptionalNullableInteger(
        body.maxOccurrences,
        "maxOccurrences",
      ),
      escalationAfterSeconds: deadlineOptionalNumberArray(
        body.escalationAfterSeconds,
        "escalationAfterSeconds",
      ),
      metadata: deadlineOptionalObject(
        body.metadata,
        "metadata",
      ),
      correlationId: deadlineOptionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send(record);
  });

  app.get("/v1/deadlines/:id", async (request) => {
    const { id } = request.params as { id: string };
    return deadlines.get(id);
  });

  app.get("/v1/deadlines/:id/status", async (request) => {
    const { id } = request.params as { id: string };
    const query = request.query as { at?: string };
    const at =
      query.at === undefined ? new Date() : new Date(query.at);

    if (Number.isNaN(at.getTime())) {
      throw new DeadlineError(
        "validation",
        "at must be a valid date-time",
      );
    }

    return deadlines.statusAt(id, at);
  });

  app.get(
    "/v1/organizations/:organizationId/subjects/:subjectType/:subjectId/deadlines",
    async (request) => {
      const {
        organizationId,
        subjectType,
        subjectId,
      } = request.params as {
        organizationId: string;
        subjectType: string;
        subjectId: string;
      };

      return deadlines.listBySubject(
        organizationId,
        subjectType,
        subjectId,
      );
    },
  );

  app.post(
    "/v1/deadlines/:id/satisfy",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return deadlines.satisfy({
        deadlineId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        satisfiedAt: deadlineOptionalString(
          body.satisfiedAt,
          "satisfiedAt",
        ),
        correlationId: deadlineOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/deadlines/:id/cancel",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return deadlines.cancel({
        deadlineId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: deadlineOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post("/v1/checks/run", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    const result = await evaluations.run({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceId: requiredString(body.resourceId, "resourceId"),
      ruleSet: evaluationOptionalObject(body.ruleSet, "ruleSet"),
      registeredRuleSetId:
        evaluationOptionalNullableString(
          body.registeredRuleSetId,
          "registeredRuleSetId",
        ),
      requestedByPrincipalId: evaluationOptionalNullableString(
        body.requestedByPrincipalId,
        "requestedByPrincipalId",
      ),
      facts: evaluationOptionalObject(body.facts, "facts"),
      evaluatedAt: evaluationOptionalString(
        body.evaluatedAt,
        "evaluatedAt",
      ),
      metadata: evaluationOptionalObject(
        body.metadata,
        "metadata",
      ),
      correlationId: evaluationOptionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send(result);
  });

  app.post("/v1/checks/event", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    const result = await evaluations.runEvent({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceId: requiredString(body.resourceId, "resourceId"),
      ruleSet: evaluationOptionalObject(body.ruleSet, "ruleSet"),
      registeredRuleSetId:
        evaluationOptionalNullableString(
          body.registeredRuleSetId,
          "registeredRuleSetId",
        ),
      requestedByPrincipalId: evaluationOptionalNullableString(
        body.requestedByPrincipalId,
        "requestedByPrincipalId",
      ),
      facts: evaluationOptionalObject(body.facts, "facts"),
      eventType: requiredString(body.eventType, "eventType"),
      event: evaluationRequiredObject(body.event, "event"),
      evaluatedAt: evaluationOptionalString(
        body.evaluatedAt,
        "evaluatedAt",
      ),
      metadata: evaluationOptionalObject(
        body.metadata,
        "metadata",
      ),
      correlationId: evaluationOptionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send(result);
  });

  app.post("/v1/checks/batch", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;

    const results = await evaluations.runBatch({
      organizationId: requiredString(
        body.organizationId,
        "organizationId",
      ),
      resourceIds: evaluationStringArray(
        body.resourceIds,
        "resourceIds",
      ),
      ruleSet: evaluationOptionalObject(body.ruleSet, "ruleSet"),
      registeredRuleSetId:
        evaluationOptionalNullableString(
          body.registeredRuleSetId,
          "registeredRuleSetId",
        ),
      requestedByPrincipalId: evaluationOptionalNullableString(
        body.requestedByPrincipalId,
        "requestedByPrincipalId",
      ),
      facts: evaluationOptionalObject(body.facts, "facts"),
      evaluatedAt: evaluationOptionalString(
        body.evaluatedAt,
        "evaluatedAt",
      ),
      metadata: evaluationOptionalObject(
        body.metadata,
        "metadata",
      ),
      correlationId: evaluationOptionalNullableString(
        body.correlationId,
        "correlationId",
      ),
    });

    return reply.code(201).send({ checks: results });
  });

  app.get("/v1/checks/:id", async (request) => {
    const { id } = request.params as { id: string };
    return evaluations.get(id);
  });

  app.get(
    "/v1/organizations/:organizationId/resources/:resourceId/checks",
    async (request) => {
      const { organizationId, resourceId } = request.params as {
        organizationId: string;
        resourceId: string;
      };
      return evaluations.listForResource(
        organizationId,
        resourceId,
      );
    },
  );

  app.post(
    "/v1/evaluation-schedules",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;

      const result = await evaluations.createSchedule({
        organizationId: requiredString(
          body.organizationId,
          "organizationId",
        ),
        resourceId: evaluationOptionalNullableString(
          body.resourceId,
          "resourceId",
        ),
        resourceType: evaluationOptionalNullableString(
          body.resourceType,
          "resourceType",
        ),
        ruleSet: evaluationOptionalObject(body.ruleSet, "ruleSet"),
      registeredRuleSetId:
        evaluationOptionalNullableString(
          body.registeredRuleSetId,
          "registeredRuleSetId",
        ),
        facts: evaluationOptionalObject(body.facts, "facts"),
        intervalSeconds: evaluationRequiredInteger(
          body.intervalSeconds,
          "intervalSeconds",
        ),
        nextRunAt: evaluationOptionalString(
          body.nextRunAt,
          "nextRunAt",
        ),
        createdByPrincipalId: evaluationOptionalNullableString(
          body.createdByPrincipalId,
          "createdByPrincipalId",
        ),
        metadata: evaluationOptionalObject(
          body.metadata,
          "metadata",
        ),
        correlationId: evaluationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });

      return reply.code(201).send(result);
    },
  );

  app.get(
    "/v1/evaluation-schedules/:id",
    async (request) => {
      const { id } = request.params as { id: string };
      return evaluations.getSchedule(id);
    },
  );

  app.post(
    "/v1/evaluation-schedules/:id/active",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      if (typeof body.active !== "boolean") {
        throw new EvaluationError(
          "validation",
          "active must be a boolean",
        );
      }

      return evaluations.setScheduleActive(
        id,
        body.active,
        requiredString(body.principalId, "principalId"),
        evaluationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      );
    },
  );

  app.post(
    "/v1/checks/:id/findings/sync",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return {
        findings: await findings.syncFailedCheck(
          id,
          findingOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
        ),
      };
    },
  );

  app.get("/v1/findings/:id", async (request) => {
    const { id } = request.params as { id: string };
    return findings.get(id);
  });

  app.get(
    "/v1/organizations/:organizationId/resources/:resourceId/findings",
    async (request) => {
      const { organizationId, resourceId } = request.params as {
        organizationId: string;
        resourceId: string;
      };
      const query = request.query as { status?: string };
      const allowed = new Set([
        "open",
        "acknowledged",
        "disputed",
        "remediating",
        "resolved",
        "closed",
      ]);

      if (
        query.status !== undefined &&
        !allowed.has(query.status)
      ) {
        throw new FindingError(
          "validation",
          "status is invalid",
        );
      }

      return findings.listForResource(
        organizationId,
        resourceId,
        query.status === undefined
          ? {}
          : {
              status: query.status as
                | "open"
                | "acknowledged"
                | "disputed"
                | "remediating"
                | "resolved"
                | "closed",
            },
      );
    },
  );

  app.post(
    "/v1/findings/:id/owner",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.assignOwner({
        findingId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        ownerPrincipalId: findingOptionalNullableString(
          body.ownerPrincipalId,
          "ownerPrincipalId",
        ) ?? null,
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/findings/:id/acknowledge",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.acknowledge({
        findingId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/findings/:id/dispute",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.dispute({
        findingId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/findings/:id/resolve-dispute",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      if (
        body.outcome !== "uphold" &&
        body.outcome !== "dismiss"
      ) {
        throw new FindingError(
          "validation",
          "outcome must be uphold or dismiss",
        );
      }

      return findings.resolveDispute({
        findingId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        outcome: body.outcome,
        rationale: requiredString(
          body.rationale,
          "rationale",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/findings/:id/remediations",
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      const result = await findings.createRemediation({
        findingId: id,
        createdByPrincipalId: requiredString(
          body.createdByPrincipalId,
          "createdByPrincipalId",
        ),
        ownerPrincipalId: findingOptionalNullableString(
          body.ownerPrincipalId,
          "ownerPrincipalId",
        ),
        plan: requiredString(body.plan, "plan"),
        dueAt: findingOptionalNullableString(
          body.dueAt,
          "dueAt",
        ),
        warningWindowSeconds: findingOptionalInteger(
          body.warningWindowSeconds,
          "warningWindowSeconds",
        ),
        gracePeriodSeconds: findingOptionalInteger(
          body.gracePeriodSeconds,
          "gracePeriodSeconds",
        ),
        escalationAfterSeconds: findingOptionalNumberArray(
          body.escalationAfterSeconds,
          "escalationAfterSeconds",
        ),
        metadata: findingOptionalObject(
          body.metadata,
          "metadata",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });

      return reply.code(201).send(result);
    },
  );

  app.post(
    "/v1/remediations/:id/start",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.startRemediation({
        remediationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/remediations/:id/submit",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.submitForVerification({
        remediationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/remediations/:id/verify",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.verifyRemediation({
        remediationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        note: findingOptionalNullableString(
          body.note,
          "note",
        ) ?? undefined,
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/remediations/:id/reject",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.rejectRemediation({
        remediationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/remediations/:id/cancel",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.cancelRemediation({
        remediationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/findings/:id/close",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.close({
        findingId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/findings/:id/reopen",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return findings.reopen({
        findingId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        correlationId: findingOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/certifications",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;

      const result = await certifications.issue({
        organizationId: requiredString(
          body.organizationId,
          "organizationId",
        ),
        resourceId: requiredString(
          body.resourceId,
          "resourceId",
        ),
        certificationType: requiredString(
          body.certificationType,
          "certificationType",
        ),
        supportingCheckId: requiredString(
          body.supportingCheckId,
          "supportingCheckId",
        ),
        issuedByPrincipalId: requiredString(
          body.issuedByPrincipalId,
          "issuedByPrincipalId",
        ),
        validFrom: certificationOptionalString(
          body.validFrom,
          "validFrom",
        ),
        validUntil: certificationOptionalString(
          body.validUntil,
          "validUntil",
        ),
        validitySeconds: certificationOptionalInteger(
          body.validitySeconds,
          "validitySeconds",
        ),
        criteria: certificationOptionalObject(
          body.criteria,
          "criteria",
        ),
        conditions: certificationOptionalObject(
          body.conditions,
          "conditions",
        ),
        metadata: certificationOptionalObject(
          body.metadata,
          "metadata",
        ),
        correlationId: certificationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });

      return reply.code(201).send(result);
    },
  );

  app.get(
    "/v1/certifications/:id",
    async (request) => {
      const { id } = request.params as { id: string };
      return certifications.get(id);
    },
  );

  app.get(
    "/v1/organizations/:organizationId/resources/:resourceId/certifications",
    async (request) => {
      const { organizationId, resourceId } = request.params as {
        organizationId: string;
        resourceId: string;
      };

      return certifications.listForResource(
        organizationId,
        resourceId,
      );
    },
  );

  app.post(
    "/v1/certifications/:id/renew",
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      const result = await certifications.renew({
        certificationId: id,
        supportingCheckId: requiredString(
          body.supportingCheckId,
          "supportingCheckId",
        ),
        issuedByPrincipalId: requiredString(
          body.issuedByPrincipalId,
          "issuedByPrincipalId",
        ),
        validFrom: certificationOptionalString(
          body.validFrom,
          "validFrom",
        ),
        validUntil: certificationOptionalString(
          body.validUntil,
          "validUntil",
        ),
        validitySeconds: certificationOptionalInteger(
          body.validitySeconds,
          "validitySeconds",
        ),
        criteria: certificationOptionalObject(
          body.criteria,
          "criteria",
        ),
        conditions: certificationOptionalObject(
          body.conditions,
          "conditions",
        ),
        metadata: certificationOptionalObject(
          body.metadata,
          "metadata",
        ),
        correlationId: certificationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });

      return reply.code(201).send(result);
    },
  );

  app.post(
    "/v1/certifications/:id/suspend",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return certifications.suspend({
        certificationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: certificationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/certifications/:id/reinstate",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return certifications.reinstate({
        certificationId: id,
        supportingCheckId: requiredString(
          body.supportingCheckId,
          "supportingCheckId",
        ),
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        rationale: requiredString(
          body.rationale,
          "rationale",
        ),
        correlationId: certificationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/certifications/:id/revoke",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return certifications.revoke({
        certificationId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(body.reason, "reason"),
        correlationId: certificationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/publications/preview",
    async (request) => {
      const body = (request.body ?? {}) as Record<string, unknown>;

      return publication.preview({
        organizationId: requiredString(
          body.organizationId,
          "organizationId",
        ),
        subjectType: requiredString(
          body.subjectType,
          "subjectType",
        ),
        subjectId: requiredString(
          body.subjectId,
          "subjectId",
        ),
        projectionType: requiredString(
          body.projectionType,
          "projectionType",
        ),
        asOf: publicationOptionalString(
          body.asOf,
          "asOf",
        ),
        policy: publicationOptionalObject(
          body.policy,
          "policy",
        ),
      });
    },
  );

  app.post(
    "/v1/publications/publish",
    async (request) => {
      const body = (request.body ?? {}) as Record<string, unknown>;

      return publication.publish({
        organizationId: requiredString(
          body.organizationId,
          "organizationId",
        ),
        subjectType: requiredString(
          body.subjectType,
          "subjectType",
        ),
        subjectId: requiredString(
          body.subjectId,
          "subjectId",
        ),
        projectionType: requiredString(
          body.projectionType,
          "projectionType",
        ),
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        asOf: publicationOptionalString(
          body.asOf,
          "asOf",
        ),
        policy: publicationOptionalObject(
          body.policy,
          "policy",
        ),
        correlationId:
          publicationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
      });
    },
  );

  app.post(
    "/v1/publications/unpublish",
    async (request) => {
      const body = (request.body ?? {}) as Record<string, unknown>;

      return publication.unpublish({
        organizationId: requiredString(
          body.organizationId,
          "organizationId",
        ),
        subjectType: requiredString(
          body.subjectType,
          "subjectType",
        ),
        subjectId: requiredString(
          body.subjectId,
          "subjectId",
        ),
        projectionType: requiredString(
          body.projectionType,
          "projectionType",
        ),
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason:
          publicationOptionalNullableString(
            body.reason,
            "reason",
          ),
        correlationId:
          publicationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
      });
    },
  );

  app.get(
    "/v1/publications/:id",
    async (request) => {
      const { id } = request.params as {
        id: string;
      };
      return publication.getById(id);
    },
  );

  app.get(
    "/v1/organizations/:organizationId/publications",
    async (request) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };
      const query = request.query as Record<string, unknown>;

      return publication.listControls(
        organizationId,
        {
          subjectType:
            publicationOptionalNullableString(
              query.subjectType,
              "subjectType",
            ),
          subjectId:
            publicationOptionalNullableString(
              query.subjectId,
              "subjectId",
            ),
          projectionType:
            publicationOptionalNullableString(
              query.projectionType,
              "projectionType",
            ),
        },
      );
    },
  );

  app.get(
    "/v1/public/publications/:id",
    async (request) => {
      const { id } = request.params as {
        id: string;
      };
      return publication.getPublicById(
        id,
      );
    },
  );

  app.get(
    "/v1/public/organizations/:organizationId/publications",
    async (request) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };
      const query = request.query as Record<string, unknown>;

      return publication.listPublic(
        organizationId,
        {
          subjectType:
            publicationOptionalNullableString(
              query.subjectType,
              "subjectType",
            ),
          subjectId:
            publicationOptionalNullableString(
              query.subjectId,
              "subjectId",
            ),
          projectionType:
            publicationOptionalNullableString(
              query.projectionType,
              "projectionType",
            ),
        },
      );
    },
  );

  app.get(
    "/v1/public/certifications/verify/:code",
    async (request) => {
      const { code } = request.params as { code: string };
      const query = request.query as { at?: string };
      const at =
        query.at === undefined
          ? new Date()
          : new Date(query.at);

      if (Number.isNaN(at.getTime())) {
        throw new CertificationError(
          "validation",
          "at must be a valid date-time",
        );
      }

      return certifications.verify(code, at);
    },
  );

  app.get(
    "/v1/reports/organizations/:organizationId/compliance",
    async (request, reply) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };
      const query = request.query as {
        format?: unknown;
        asOf?: unknown;
      };
      const format = reportFormat(query.format);
      const report = await reporting.generate({
        organizationId,
        asOf: reportOptionalString(
          query.asOf,
          "asOf",
        ),
      });

      if (format === "json") {
        return report;
      }

      const rendered = renderComplianceReport(
        report,
        format,
      );

      return reply
        .type(rendered.mediaType)
        .send(rendered.body);
    },
  );

  app.get(
    "/v1/reports/organizations/:organizationId/resources/:resourceId/compliance",
    async (request, reply) => {
      const { organizationId, resourceId } = request.params as {
        organizationId: string;
        resourceId: string;
      };
      const query = request.query as {
        format?: unknown;
        asOf?: unknown;
      };
      const format = reportFormat(query.format);
      const report = await reporting.generate({
        organizationId,
        resourceId,
        asOf: reportOptionalString(
          query.asOf,
          "asOf",
        ),
      });

      if (format === "json") {
        return report;
      }

      const rendered = renderComplianceReport(
        report,
        format,
      );

      return reply
        .type(rendered.mediaType)
        .send(rendered.body);
    },
  );

  app.post(
    "/v1/integration/service-accounts",
    async (request, reply) => {
      const body = (request.body ?? {}) as Record<string, unknown>;

      const result = await integrations.createServiceAccount({
        organizationId: requiredString(
          body.organizationId,
          "organizationId",
        ),
        displayName: requiredString(
          body.displayName,
          "displayName",
        ),
        credentialName: requiredString(
          body.credentialName,
          "credentialName",
        ),
        createdByPrincipalId: requiredString(
          body.createdByPrincipalId,
          "createdByPrincipalId",
        ),
        scopes: integrationStringArray(
          body.scopes,
          "scopes",
        ) as ServiceScope[],
        expiresAt: integrationOptionalNullableString(
          body.expiresAt,
          "expiresAt",
        ),
        externalRef: integrationOptionalNullableString(
          body.externalRef,
          "externalRef",
        ),
        metadata: integrationOptionalObject(
          body.metadata,
          "metadata",
        ),
        correlationId: integrationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });

      return reply.code(201).send(result);
    },
  );

  app.get(
    "/v1/integration/organizations/:organizationId/api-credentials",
    async (request) => {
      const { organizationId } = request.params as {
        organizationId: string;
      };

      return integrations.listCredentials(organizationId);
    },
  );

  app.post(
    "/v1/integration/api-credentials/:id/revoke",
    async (request) => {
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return integrations.revokeCredential({
        credentialId: id,
        principalId: requiredString(
          body.principalId,
          "principalId",
        ),
        reason: requiredString(
          body.reason,
          "reason",
        ),
        correlationId: integrationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      });
    },
  );

  app.post(
    "/v1/integration/resources",
    async (request, reply) => {
      const auth = await integrationAuth(
        request as any,
        ["resources:write"],
      );
      const body = (request.body ?? {}) as Record<string, unknown>;
      const result = await integrations.createResource(
        auth,
        integrationIdempotencyKey(
          request.headers["idempotency-key"],
        ),
        {
          resourceType: requiredString(
            body.resourceType,
            "resourceType",
          ),
          name: requiredString(body.name, "name"),
          externalRef: integrationOptionalNullableString(
            body.externalRef,
            "externalRef",
          ),
          status:
            body.status === "active" ||
            body.status === "inactive" ||
            body.status === "archived"
              ? body.status
              : undefined,
          attributes: integrationOptionalObject(
            body.attributes,
            "attributes",
          ),
          metadata: integrationOptionalObject(
            body.metadata,
            "metadata",
          ),
          correlationId: integrationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
        },
      );

      return reply
        .header(
          "Idempotency-Replayed",
          String(result.replayed),
        )
        .code(result.statusCode)
        .send(result.body);
    },
  );

  app.get(
    "/v1/integration/resources",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["resources:read"],
      );
      const query = request.query as Record<string, unknown>;

      return integrations.listResources(auth, {
        limit: integrationOptionalInteger(
          query.limit,
          "limit",
        ),
        cursor: integrationOptionalNullableString(
          query.cursor,
          "cursor",
        ),
        resourceType: integrationOptionalNullableString(
          query.resourceType,
          "resourceType",
        ),
        status:
          query.status === "active" ||
          query.status === "inactive" ||
          query.status === "archived"
            ? query.status
            : query.status === undefined
              ? null
              : query.status as any,
      });
    },
  );

  app.post(
    "/v1/integration/checks/run",
    async (request, reply) => {
      const auth = await integrationAuth(
        request as any,
        ["checks:run"],
      );
      const body = (request.body ?? {}) as Record<string, unknown>;
      const result = await integrations.runCheck(
        auth,
        integrationIdempotencyKey(
          request.headers["idempotency-key"],
        ),
        {
          resourceId: requiredString(
            body.resourceId,
            "resourceId",
          ),
          ruleSet: integrationOptionalObject(
            body.ruleSet,
            "ruleSet",
          ),
          registeredRuleSetId:
            integrationOptionalNullableString(
              body.registeredRuleSetId,
              "registeredRuleSetId",
            ),
          facts: integrationOptionalObject(
            body.facts,
            "facts",
          ),
          evaluatedAt: integrationOptionalString(
            body.evaluatedAt,
            "evaluatedAt",
          ),
          metadata: integrationOptionalObject(
            body.metadata,
            "metadata",
          ),
          correlationId: integrationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
        },
      );

      return reply
        .header(
          "Idempotency-Replayed",
          String(result.replayed),
        )
        .code(result.statusCode)
        .send(result.body);
    },
  );

  app.post(
    "/v1/integration/webhooks",
    async (request, reply) => {
      const auth = await integrationAuth(
        request as any,
        ["webhooks:write"],
      );
      const body = (request.body ?? {}) as Record<string, unknown>;

      const result = await integrations.createWebhookSubscription(
        auth,
        {
          name: requiredString(body.name, "name"),
          url: requiredString(body.url, "url"),
          eventTypes: integrationOptionalStringArray(
            body.eventTypes,
            "eventTypes",
          ),
          metadata: integrationOptionalObject(
            body.metadata,
            "metadata",
          ),
          correlationId: integrationOptionalNullableString(
            body.correlationId,
            "correlationId",
          ),
        },
      );

      return reply.code(201).send(result);
    },
  );

  app.get(
    "/v1/integration/webhooks",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["webhooks:read"],
      );

      return integrations.listWebhookSubscriptions(auth);
    },
  );

  app.post(
    "/v1/integration/webhooks/:id/active",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["webhooks:write"],
      );
      const { id } = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;

      return integrations.setWebhookActive(
        auth,
        id,
        integrationBoolean(
          body.active,
          "active",
        ),
        integrationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      );
    },
  );

  app.get(
    "/v1/integration/events",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["events:read"],
      );
      const query = request.query as Record<string, unknown>;

      return integrations.listEvents(auth, {
        limit: integrationOptionalInteger(
          query.limit,
          "limit",
        ),
        cursor: integrationOptionalNullableString(
          query.cursor,
          "cursor",
        ),
        eventType: integrationOptionalNullableString(
          query.eventType,
          "eventType",
        ),
      });
    },
  );

  app.post(
    "/v1/integration/import/resources",
    async (request, reply) => {
      const auth = await integrationAuth(
        request as any,
        ["imports:write"],
      );
      const body = (request.body ?? {}) as Record<string, unknown>;
      const result = await integrations.importResources(
        auth,
        integrationIdempotencyKey(
          request.headers["idempotency-key"],
        ),
        body as any,
        integrationOptionalNullableString(
          body.correlationId,
          "correlationId",
        ),
      );

      return reply
        .header(
          "Idempotency-Replayed",
          String(result.replayed),
        )
        .code(result.statusCode)
        .send(result.body);
    },
  );

  app.get(
    "/v1/integration/export/resources",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["exports:read"],
      );

      return integrations.exportResources(auth);
    },
  );

  app.get(
    "/v1/integration/resources/:resourceId/registry-projection",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["adapters:read"],
      );
      const { resourceId } = request.params as {
        resourceId: string;
      };

      return integrations.getRegistryProjection(
        auth,
        resourceId,
      );
    },
  );

  app.get(
    "/v1/integration/case-triggers",
    async (request) => {
      const auth = await integrationAuth(
        request as any,
        ["adapters:read"],
      );
      const query = request.query as Record<string, unknown>;

      return integrations.listCaseTriggers(
        auth,
        {
          limit: integrationOptionalInteger(
            query.limit,
            "limit",
          ),
          severity: integrationOptionalNullableString(
            query.severity,
            "severity",
          ),
        },
      );
    },
  );

  return app;
}
