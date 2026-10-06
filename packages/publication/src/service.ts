import {
  createHash,
  randomUUID,
} from "node:crypto";
import type {
  Pool,
  PoolClient,
} from "pg";
import type {
  JsonObject,
} from "@caiae/core";
import {
  appendAuditEventWithClient,
  canonicalJson,
} from "@caiae/db";
import {
  ReportingService,
} from "@caiae/reporting";
import {
  applyPublicationPolicy,
  normalizePublicationPolicy,
} from "./projection.js";
import {
  PublicationError,
  type PublicationListOptions,
  type PublicationPolicy,
  type PublicationPreview,
  type PublicationRecord,
  type PublicationServiceOptions,
  type PreviewPublicationInput,
  type PublicPublication,
  type PublicationProjectionBuilder,
  type PublishInput,
  type ResourceComplianceProjection,
  type UnpublishInput,
} from "./types.js";

export const BUILT_IN_PUBLICATION_PROJECTIONS = [
  "organization_summary",
  "organization_compliance",
  "resource_compliance",
  "finding_summary",
  "certification_summary",
] as const;

export class PublicationService {
  private readonly now: () => Date;
  private readonly reporting:
    ReportingService;
  private readonly builders:
    Map<
      string,
      PublicationProjectionBuilder
    >;

  constructor(
    private readonly pool: Pool,
    options: PublicationServiceOptions = {},
  ) {
    this.now =
      options.now ??
      (() => new Date());
    this.reporting =
      new ReportingService(pool);
    this.builders =
      new Map(
        Object.entries(
          this.builtInBuilders(),
        ),
      );

    for (
      const [key, builder] of
      Object.entries(
        options.projectionBuilders ??
          {},
      )
    ) {
      const normalized =
        requireIdentifier(
          key,
          "projection builder key",
        );
      this.builders.set(
        normalized,
        builder,
      );
    }
  }

  async preview(
    input: PreviewPublicationInput,
  ): Promise<PublicationPreview> {
    const normalized =
      normalizePreviewInput(
        input,
        this.now,
      );
    const builder =
      this.builders.get(
        normalized.projectionType,
      );

    if (!builder) {
      throw new PublicationError(
        "validation",
        `unsupported projectionType: ${normalized.projectionType}`,
      );
    }

    const baseProjection =
      await builder({
        organizationId:
          normalized.organizationId,
        subjectType:
          normalized.subjectType,
        subjectId:
          normalized.subjectId,
        projectionType:
          normalized.projectionType,
        asOf: normalized.asOf,
      });
    const policy =
      normalizePublicationPolicy(
        input.policy,
      );
    const projection =
      applyPublicationPolicy(
        baseProjection,
        policy,
      );
    const projectionHash =
      hashProjection(projection);

    return {
      schemaVersion: "1",
      organizationId:
        normalized.organizationId,
      subjectType:
        normalized.subjectType,
      subjectId:
        normalized.subjectId,
      projectionType:
        normalized.projectionType,
      asOf: normalized.asOf,
      policy,
      projectionHash,
      projection,
    };
  }

  async publish(
    input: PublishInput,
  ): Promise<PublicationRecord> {
    const preview =
      await this.preview(input);
    const principalId =
      requireUuid(
        input.principalId,
        "principalId",
      );
    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertActivePrincipal(
        client,
        preview.organizationId,
        principalId,
      );

      const existing =
        await client.query(
          `SELECT *
           FROM publication_controls
           WHERE organization_id = $1
             AND subject_type = $2
             AND subject_id = $3
             AND projection_type = $4
           FOR UPDATE`,
          [
            preview.organizationId,
            preview.subjectType,
            preview.subjectId,
            preview.projectionType,
          ],
        );

      const id =
        existing.rows[0]?.id ??
        randomUUID();
      const revision =
        Number(
          existing.rows[0]
            ?.revision ?? 0,
        ) + 1;
      const publishedAt =
        this.now().toISOString();

      if (existing.rows[0]) {
        await client.query(
          `UPDATE publication_controls
           SET state = 'published',
               revision = $2,
               projection = $3::jsonb,
               projection_hash = $4,
               policy = $5::jsonb,
               published_at = $6,
               published_by_principal_id = $7,
               unpublished_at = NULL,
               unpublished_by_principal_id = NULL,
               updated_at = now()
           WHERE id = $1`,
          [
            id,
            revision,
            JSON.stringify(
              preview.projection,
            ),
            preview.projectionHash,
            JSON.stringify(
              preview.policy,
            ),
            publishedAt,
            principalId,
          ],
        );
      } else {
        await client.query(
          `INSERT INTO publication_controls(
             id,
             organization_id,
             subject_type,
             subject_id,
             projection_type,
             state,
             revision,
             projection,
             projection_hash,
             policy,
             published_at,
             published_by_principal_id
           ) VALUES (
             $1, $2, $3, $4, $5,
             'published', $6,
             $7::jsonb, $8,
             $9::jsonb, $10, $11
           )`,
          [
            id,
            preview.organizationId,
            preview.subjectType,
            preview.subjectId,
            preview.projectionType,
            revision,
            JSON.stringify(
              preview.projection,
            ),
            preview.projectionHash,
            JSON.stringify(
              preview.policy,
            ),
            publishedAt,
            principalId,
          ],
        );
      }

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            preview.organizationId,
          aggregateType:
            "publication",
          aggregateId: id,
          eventType:
            "publication.published",
          actorPrincipalId:
            principalId,
          occurredAt: publishedAt,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            subjectType:
              preview.subjectType,
            subjectId:
              preview.subjectId,
            projectionType:
              preview.projectionType,
            revision,
            projectionHash:
              preview.projectionHash,
            asOf: preview.asOf,
            policy:
              preview.policy,
          },
        },
      );

      await client.query("COMMIT");
      return await this.getById(id);
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async unpublish(
    input: UnpublishInput,
  ): Promise<PublicationRecord> {
    const organizationId =
      requireUuid(
        input.organizationId,
        "organizationId",
      );
    const subjectType =
      requireIdentifier(
        input.subjectType,
        "subjectType",
      );
    const subjectId =
      requireUuid(
        input.subjectId,
        "subjectId",
      );
    const projectionType =
      requireIdentifier(
        input.projectionType,
        "projectionType",
      );
    const principalId =
      requireUuid(
        input.principalId,
        "principalId",
      );
    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertActivePrincipal(
        client,
        organizationId,
        principalId,
      );

      const result =
        await client.query(
          `SELECT *
           FROM publication_controls
           WHERE organization_id = $1
             AND subject_type = $2
             AND subject_id = $3
             AND projection_type = $4
           FOR UPDATE`,
          [
            organizationId,
            subjectType,
            subjectId,
            projectionType,
          ],
        );

      if (!result.rows[0]) {
        throw new PublicationError(
          "not_found",
          "publication control not found",
        );
      }

      const record =
        mapPublicationRecord(
          result.rows[0],
        );

      if (
        record.state !==
        "published"
      ) {
        throw new PublicationError(
          "invalid_state",
          "publication is already private",
        );
      }

      const unpublishedAt =
        this.now().toISOString();

      await client.query(
        `UPDATE publication_controls
         SET state = 'private',
             unpublished_at = $2,
             unpublished_by_principal_id = $3,
             updated_at = now()
         WHERE id = $1`,
        [
          record.id,
          unpublishedAt,
          principalId,
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId,
          aggregateType:
            "publication",
          aggregateId:
            record.id,
          eventType:
            "publication.unpublished",
          actorPrincipalId:
            principalId,
          occurredAt:
            unpublishedAt,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            subjectType,
            subjectId,
            projectionType,
            revision:
              record.revision,
            projectionHash:
              record.projectionHash,
            reason:
              normalizeNullableString(
                input.reason,
              ),
          },
        },
      );

      await client.query("COMMIT");
      return await this.getById(
        record.id,
      );
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async getById(
    publicationId: string,
  ): Promise<PublicationRecord> {
    const id =
      requireUuid(
        publicationId,
        "publicationId",
      );
    const result =
      await this.pool.query(
        `SELECT *
         FROM publication_controls
         WHERE id = $1`,
        [id],
      );

    if (!result.rows[0]) {
      throw new PublicationError(
        "not_found",
        "publication control not found",
      );
    }

    return mapPublicationRecord(
      result.rows[0],
    );
  }

  async listControls(
    organizationId: string,
    options:
      PublicationListOptions = {},
  ): Promise<PublicationRecord[]> {
    const organization =
      requireUuid(
        organizationId,
        "organizationId",
      );
    const values: unknown[] = [
      organization,
    ];
    const filters: string[] = [
      "organization_id = $1",
    ];

    addOptionalFilter(
      filters,
      values,
      "subject_type",
      options.subjectType,
      "subjectType",
    );
    addOptionalUuidFilter(
      filters,
      values,
      "subject_id",
      options.subjectId,
      "subjectId",
    );
    addOptionalFilter(
      filters,
      values,
      "projection_type",
      options.projectionType,
      "projectionType",
    );

    const result =
      await this.pool.query(
        `SELECT *
         FROM publication_controls
         WHERE ${filters.join(
           " AND ",
         )}
         ORDER BY
           subject_type ASC,
           subject_id ASC,
           projection_type ASC`,
        values,
      );

    return result.rows.map(
      mapPublicationRecord,
    );
  }

  async getPublicById(
    publicationId: string,
  ): Promise<PublicPublication> {
    const record =
      await this.getById(
        publicationId,
      );

    if (
      record.state !==
        "published" ||
      record.publishedAt === null
    ) {
      throw new PublicationError(
        "not_found",
        "public publication not found",
      );
    }

    return toPublicPublication(
      record,
    );
  }

  async listPublic(
    organizationId: string,
    options:
      PublicationListOptions = {},
  ): Promise<PublicPublication[]> {
    const controls =
      await this.listControls(
        organizationId,
        options,
      );

    return controls
      .filter(
        (record) =>
          record.state ===
            "published" &&
          record.publishedAt !==
            null,
      )
      .map(
        toPublicPublication,
      );
  }

  async buildResourceComplianceProjection(
    organizationId: string,
    resourceId: string,
    asOf = this.now().toISOString(),
  ): Promise<ResourceComplianceProjection> {
    return this.resourceComplianceProjection(
      requireUuid(
        organizationId,
        "organizationId",
      ),
      requireUuid(
        resourceId,
        "resourceId",
      ),
      normalizeDate(
        asOf,
        "asOf",
      ),
    );
  }

  private builtInBuilders():
    Record<
      string,
      PublicationProjectionBuilder
    > {
    return {
      organization_summary:
        async (context) =>
          this.organizationSummary(
            context,
          ),
      organization_compliance:
        async (context) =>
          this.organizationCompliance(
            context,
          ),
      resource_compliance:
        async (context) =>
          this.resourceCompliance(
            context,
          ),
      finding_summary:
        async (context) =>
          this.findingSummary(
            context,
          ),
      certification_summary:
        async (context) =>
          this.certificationSummary(
            context,
          ),
    };
  }

  private async organizationSummary(
    context: {
      organizationId: string;
      subjectType: string;
      subjectId: string;
    },
  ): Promise<JsonObject> {
    assertSubject(
      context,
      "organization",
    );

    if (
      context.subjectId !==
      context.organizationId
    ) {
      throw new PublicationError(
        "validation",
        "organization_summary subjectId must equal organizationId",
      );
    }

    const result =
      await this.pool.query(
        `SELECT id, name, slug, status
         FROM organizations
         WHERE id = $1`,
        [
          context.organizationId,
        ],
      );

    if (!result.rows[0]) {
      throw new PublicationError(
        "not_found",
        "organization not found",
      );
    }

    const row =
      result.rows[0];

    return {
      schemaVersion: "1",
      organization: {
        id: row.id,
        name: row.name,
        slug: row.slug,
        status: row.status,
      },
    };
  }

  private async organizationCompliance(
    context: {
      organizationId: string;
      subjectType: string;
      subjectId: string;
      asOf: string;
    },
  ): Promise<JsonObject> {
    assertSubject(
      context,
      "organization",
    );

    if (
      context.subjectId !==
      context.organizationId
    ) {
      throw new PublicationError(
        "validation",
        "organization_compliance subjectId must equal organizationId",
      );
    }

    const report =
      await this.reporting.generate({
        organizationId:
          context.organizationId,
        asOf: context.asOf,
      });

    return toJsonObject({
      schemaVersion: "1",
      organization:
        report.organization,
      asOf: report.asOf,
      summary:
        report.summary,
    });
  }

  private async resourceCompliance(
    context: {
      organizationId: string;
      subjectType: string;
      subjectId: string;
      asOf: string;
    },
  ): Promise<JsonObject> {
    assertSubject(
      context,
      "resource",
    );
    return toJsonObject(
      await this.resourceComplianceProjection(
        context.organizationId,
        context.subjectId,
        context.asOf,
      ),
    );
  }

  private async resourceComplianceProjection(
    organizationId: string,
    resourceId: string,
    asOf: string,
  ): Promise<ResourceComplianceProjection> {
    const resourceResult =
      await this.pool.query(
        `SELECT
           id,
           resource_type,
           name,
           external_ref,
           status
         FROM resources
         WHERE id = $1
           AND organization_id = $2`,
        [
          resourceId,
          organizationId,
        ],
      );

    if (!resourceResult.rows[0]) {
      throw new PublicationError(
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
        `SELECT
           id,
           status,
           evaluated_at,
           completed_at,
           created_at,
           rule_set_snapshot
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
          organizationId,
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
          organizationId,
          resourceId,
          asOf,
        ],
      ),
      this.pool.query(
        `SELECT
           count(*) FILTER (
             WHERE status NOT IN (
               'resolved',
               'closed'
             )
           )::int AS unresolved,
           count(*) FILTER (
             WHERE status NOT IN (
               'resolved',
               'closed'
             )
               AND severity IN (
                 'high',
                 'critical'
               )
           )::int AS unresolved_material
         FROM findings
         WHERE organization_id = $1
           AND resource_id = $2`,
        [
          organizationId,
          resourceId,
        ],
      ),
    ]);

    const resource =
      resourceResult.rows[0];
    const check =
      checkResult.rows[0];
    const ruleSet =
      objectOrEmpty(
        check?.rule_set_snapshot,
      );

    return {
      organizationId,
      resource: {
        id: resource.id,
        resourceType:
          resource.resource_type,
        name: resource.name,
        externalRef:
          resource.external_ref ??
          null,
        status:
          resource.status,
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
                .map(String)
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

  private async findingSummary(
    context: {
      organizationId: string;
      subjectType: string;
      subjectId: string;
    },
  ): Promise<JsonObject> {
    assertSubject(
      context,
      "finding",
    );

    const result =
      await this.pool.query(
        `SELECT
           id,
           organization_id,
           resource_id,
           rule_key,
           rule_set_key,
           rule_set_version,
           severity,
           status,
           title,
           opened_at,
           resolved_at,
           closed_at
         FROM findings
         WHERE id = $1
           AND organization_id = $2`,
        [
          context.subjectId,
          context.organizationId,
        ],
      );

    if (!result.rows[0]) {
      throw new PublicationError(
        "not_found",
        "finding not found",
      );
    }

    const row =
      result.rows[0];

    return {
      schemaVersion: "1",
      finding: {
        id: row.id,
        organizationId:
          row.organization_id,
        resourceId:
          row.resource_id,
        ruleKey:
          row.rule_key ??
          null,
        ruleSetKey:
          row.rule_set_key ??
          null,
        ruleSetVersion:
          row.rule_set_version ??
          null,
        severity:
          row.severity,
        status: row.status,
        title: row.title,
        openedAt:
          iso(row.opened_at),
        resolvedAt:
          nullableIso(
            row.resolved_at,
          ),
        closedAt:
          nullableIso(
            row.closed_at,
          ),
      },
    };
  }

  private async certificationSummary(
    context: {
      organizationId: string;
      subjectType: string;
      subjectId: string;
      asOf: string;
    },
  ): Promise<JsonObject> {
    assertSubject(
      context,
      "certification",
    );

    const result =
      await this.pool.query(
        `SELECT
           id,
           status,
           valid_from,
           valid_until,
           public_artifact
         FROM certifications
         WHERE id = $1
           AND organization_id = $2`,
        [
          context.subjectId,
          context.organizationId,
        ],
      );

    if (!result.rows[0]) {
      throw new PublicationError(
        "not_found",
        "certification not found",
      );
    }

    const row =
      result.rows[0];
    const effectiveStatus =
      effectiveCertificationStatus(
        row.status,
        row.valid_from,
        row.valid_until,
        context.asOf,
      );

    return {
      schemaVersion: "1",
      certification:
        objectOrEmpty(
          row.public_artifact,
        ),
      storedStatus:
        row.status,
      effectiveStatus,
      valid:
        effectiveStatus ===
        "active",
      asOf:
        context.asOf,
    };
  }
}

function normalizePreviewInput(
  input: PreviewPublicationInput,
  now: () => Date,
): {
  organizationId: string;
  subjectType: string;
  subjectId: string;
  projectionType: string;
  asOf: string;
} {
  return {
    organizationId:
      requireUuid(
        input.organizationId,
        "organizationId",
      ),
    subjectType:
      requireIdentifier(
        input.subjectType,
        "subjectType",
      ),
    subjectId:
      requireUuid(
        input.subjectId,
        "subjectId",
      ),
    projectionType:
      requireIdentifier(
        input.projectionType,
        "projectionType",
      ),
    asOf:
      input.asOf === undefined
        ? now().toISOString()
        : normalizeDate(
            input.asOf,
            "asOf",
          ),
  };
}

function assertSubject(
  context: {
    subjectType: string;
  },
  expected: string,
): void {
  if (
    context.subjectType !==
    expected
  ) {
    throw new PublicationError(
      "validation",
      `projection requires subjectType=${expected}`,
    );
  }
}

function hashProjection(
  projection: JsonObject,
): string {
  return createHash("sha256")
    .update(
      canonicalJson(projection),
      "utf8",
    )
    .digest("hex");
}

function mapPublicationRecord(
  row: any,
): PublicationRecord {
  const policy =
    normalizePublicationPolicy(
      objectOrEmpty(
        row.policy,
      ) as PublicationPolicy,
    );

  return {
    id: row.id,
    organizationId:
      row.organization_id,
    subjectType:
      row.subject_type,
    subjectId:
      row.subject_id,
    projectionType:
      row.projection_type,
    state: row.state,
    revision:
      Number(row.revision),
    projection:
      objectOrEmpty(
        row.projection,
      ),
    projectionHash:
      row.projection_hash,
    policy,
    publishedAt:
      nullableIso(
        row.published_at,
      ),
    publishedByPrincipalId:
      row.published_by_principal_id ??
      null,
    unpublishedAt:
      nullableIso(
        row.unpublished_at,
      ),
    unpublishedByPrincipalId:
      row.unpublished_by_principal_id ??
      null,
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function toPublicPublication(
  record: PublicationRecord,
): PublicPublication {
  if (
    record.publishedAt ===
    null
  ) {
    throw new PublicationError(
      "not_found",
      "public publication not found",
    );
  }

  return {
    id: record.id,
    organizationId:
      record.organizationId,
    subjectType:
      record.subjectType,
    subjectId:
      record.subjectId,
    projectionType:
      record.projectionType,
    revision:
      record.revision,
    projectionHash:
      record.projectionHash,
    publishedAt:
      record.publishedAt,
    projection:
      record.projection,
  };
}

async function assertActivePrincipal(
  client: PoolClient,
  organizationId: string,
  principalId: string,
): Promise<void> {
  const result =
    await client.query(
      `SELECT id
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
    throw new PublicationError(
      "validation",
      "principal must be active in the organization",
    );
  }
}

function addOptionalFilter(
  filters: string[],
  values: unknown[],
  column: string,
  value: string | null | undefined,
  field: string,
): void {
  if (
    value === undefined ||
    value === null
  ) {
    return;
  }

  const normalized =
    requireIdentifier(
      value,
      field,
    );
  values.push(normalized);
  filters.push(
    `${column} = $${values.length}`,
  );
}

function addOptionalUuidFilter(
  filters: string[],
  values: unknown[],
  column: string,
  value: string | null | undefined,
  field: string,
): void {
  if (
    value === undefined ||
    value === null
  ) {
    return;
  }

  const normalized =
    requireUuid(
      value,
      field,
    );
  values.push(normalized);
  filters.push(
    `${column} = $${values.length}`,
  );
}

function requireIdentifier(
  value: string,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.trim() === "" ||
    !/^[A-Za-z0-9_.:-]+$/.test(
      value.trim(),
    )
  ) {
    throw new PublicationError(
      "validation",
      `${field} must be a non-empty identifier`,
    );
  }
  return value.trim();
}

function requireUuid(
  value: string,
  field: string,
): string {
  const normalized =
    requireIdentifier(
      value,
      field,
    );

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      normalized,
    )
  ) {
    throw new PublicationError(
      "validation",
      `${field} must be a UUID`,
    );
  }

  return normalized;
}

function normalizeDate(
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
    throw new PublicationError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }

  return date.toISOString();
}

function normalizeNullableString(
  value: string | null | undefined,
): string | null {
  if (
    value === undefined ||
    value === null
  ) {
    return null;
  }

  const normalized =
    value.trim();

  return normalized === ""
    ? null
    : normalized;
}

function effectiveCertificationStatus(
  storedStatus: string,
  validFromRaw: unknown,
  validUntilRaw: unknown,
  asOf: string,
): string {
  if (
    storedStatus === "revoked" ||
    storedStatus === "superseded"
  ) {
    return storedStatus;
  }

  const at =
    new Date(asOf).getTime();
  const validFrom =
    new Date(
      String(validFromRaw),
    ).getTime();
  const validUntil =
    new Date(
      String(validUntilRaw),
    ).getTime();

  if (
    Number.isFinite(validUntil) &&
    at >= validUntil
  ) {
    return "expired";
  }

  if (
    storedStatus === "pending" &&
    Number.isFinite(validFrom) &&
    at >= validFrom
  ) {
    return "active";
  }

  return storedStatus;
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

function stringOrNull(
  value: unknown,
): string | null {
  return typeof value ===
    "string"
    ? value
    : null;
}

function nullableIso(
  value: unknown,
): string | null {
  return value === null ||
    value === undefined
    ? null
    : iso(value);
}

function iso(
  value: unknown,
): string {
  return (
    value instanceof Date
      ? value
      : new Date(
          String(value),
        )
  ).toISOString();
}

function toJsonObject(
  value: unknown,
): JsonObject {
  return JSON.parse(
    JSON.stringify(value),
  ) as JsonObject;
}

function normalizeError(
  error: unknown,
): Error {
  if (
    error instanceof
    PublicationError
  ) {
    return error;
  }

  return error instanceof Error
    ? error
    : new Error(
        String(error),
      );
}
