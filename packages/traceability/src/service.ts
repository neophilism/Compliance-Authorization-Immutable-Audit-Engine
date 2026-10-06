import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { JsonObject } from "@caiae/core";
import {
  appendAuditEventWithClient,
  canonicalJson,
} from "@caiae/db";
import {
  parseRuleSet,
  type DeclarativeRuleSet,
} from "@caiae/rules";
import {
  TraceabilityError,
  type ActivateRuleSetRevisionInput,
  type AuthoritySource,
  type CreateAuthoritySourceInput,
  type RegisterRuleSetRevisionInput,
  type RuleSetAuthorityLink,
  type RuleSetRevision,
  type SupersedeRuleSetRevisionInput,
} from "./types.js";

export class TraceabilityService {
  constructor(
    private readonly pool: Pool,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async createAuthoritySource(
    input: CreateAuthoritySourceInput,
  ): Promise<AuthoritySource> {
    const organizationId = requireUuid(
      input.organizationId,
      "organizationId",
    );
    const citation = requireString(
      input.citation,
      "citation",
    );
    const title = requireString(
      input.title,
      "title",
    );
    const sourceType = normalizeSourceType(
      input.sourceType,
    );
    const principalId =
      input.principalId == null
        ? null
        : requireUuid(
            input.principalId,
            "principalId",
          );
    const id = randomUUID();
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertOrganization(
        client,
        organizationId,
      );
      if (principalId) {
        await assertPrincipal(
          client,
          organizationId,
          principalId,
        );
      }

      await client.query(
        `INSERT INTO authority_sources(
           id,
           organization_id,
           source_type,
           jurisdiction,
           citation,
           title,
           uri,
           source_date,
           effective_from,
           effective_to,
           content_hash,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, $8, $9, $10, $11,
           $12::jsonb
         )`,
        [
          id,
          organizationId,
          sourceType,
          normalizeNullableString(
            input.jurisdiction,
          ),
          citation,
          title,
          normalizeNullableString(
            input.uri,
          ),
          normalizeOptionalDate(
            input.sourceDate,
            "sourceDate",
          ),
          normalizeOptionalDate(
            input.effectiveFrom,
            "effectiveFrom",
          ),
          normalizeOptionalDate(
            input.effectiveTo,
            "effectiveTo",
          ),
          normalizeOptionalHash(
            input.contentHash,
          ),
          JSON.stringify(
            input.metadata ?? {},
          ),
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId,
          aggregateType:
            "authority_source",
          aggregateId: id,
          eventType:
            "authority_source.created",
          actorPrincipalId:
            principalId,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            sourceType,
            citation,
            title,
          },
        },
      );

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }

    return this.getAuthoritySource(id);
  }

  async getAuthoritySource(
    id: string,
  ): Promise<AuthoritySource> {
    const result =
      await this.pool.query(
        `SELECT *
         FROM authority_sources
         WHERE id = $1`,
        [requireUuid(id, "id")],
      );
    if (!result.rows[0]) {
      throw new TraceabilityError(
        "not_found",
        "authority source not found",
      );
    }
    return mapAuthority(
      result.rows[0],
    );
  }

  async listAuthoritySources(
    organizationId: string,
  ): Promise<AuthoritySource[]> {
    const result =
      await this.pool.query(
        `SELECT *
         FROM authority_sources
         WHERE organization_id = $1
         ORDER BY citation ASC, id ASC`,
        [
          requireUuid(
            organizationId,
            "organizationId",
          ),
        ],
      );
    return result.rows.map(
      mapAuthority,
    );
  }

  async registerRuleSetRevision(
    input: RegisterRuleSetRevisionInput,
  ): Promise<RuleSetRevision> {
    const organizationId =
      requireUuid(
        input.organizationId,
        "organizationId",
      );
    const policyId =
      requireUuid(
        input.policyId,
        "policyId",
      );
    const principalId =
      input.principalId == null
        ? null
        : requireUuid(
            input.principalId,
            "principalId",
          );
    const ruleSet =
      parseRuleSet(input.ruleSet);
    const snapshot =
      toJsonObject(ruleSet);
    const contentHash =
      hashSnapshot(snapshot);
    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");
      await assertOrganization(
        client,
        organizationId,
      );
      await assertPolicy(
        client,
        organizationId,
        policyId,
      );
      if (principalId) {
        await assertPrincipal(
          client,
          organizationId,
          principalId,
        );
      }

      const existing =
        await client.query(
          `SELECT *
           FROM rule_sets
           WHERE organization_id = $1
             AND key = $2
             AND version = $3
           FOR UPDATE`,
          [
            organizationId,
            ruleSet.id,
            ruleSet.version,
          ],
        );

      let ruleSetId: string;

      if (existing.rows[0]) {
        const row = existing.rows[0];
        if (
          row.content_hash !==
          contentHash
        ) {
          throw new TraceabilityError(
            "conflict",
            "ruleset key/version is immutable and already exists with different content",
          );
        }
        ruleSetId = row.id;
      } else {
        ruleSetId = randomUUID();

        await client.query(
          `INSERT INTO rule_sets(
             id,
             organization_id,
             policy_id,
             key,
             version,
             status,
             effective_from,
             effective_to,
             metadata,
             declarative_snapshot,
             content_hash,
             created_by_principal_id
           ) VALUES (
             $1, $2, $3, $4, $5,
             'draft', $6, $7,
             $8::jsonb, $9::jsonb,
             $10, $11
           )`,
          [
            ruleSetId,
            organizationId,
            policyId,
            ruleSet.id,
            ruleSet.version,
            normalizeOptionalDate(
              input.effectiveFrom,
              "effectiveFrom",
            ),
            normalizeOptionalDate(
              input.effectiveTo,
              "effectiveTo",
            ),
            JSON.stringify(
              input.metadata ?? {},
            ),
            JSON.stringify(snapshot),
            contentHash,
            principalId,
          ],
        );

        for (const rule of ruleSet.rules) {
          await client.query(
            `INSERT INTO rules(
               id,
               organization_id,
               rule_set_id,
               key,
               title,
               description,
               severity,
               definition,
               enabled,
               metadata
             ) VALUES (
               $1, $2, $3, $4, $5,
               $6, $7, $8::jsonb,
               true, $9::jsonb
             )`,
            [
              randomUUID(),
              organizationId,
              ruleSetId,
              rule.id,
              rule.title,
              rule.description ?? "",
              rule.severity,
              JSON.stringify(
                toJsonObject(rule),
              ),
              JSON.stringify(
                rule.metadata ?? {},
              ),
            ],
          );
        }

        await appendAuditEventWithClient(
          client,
          {
            organizationId,
            aggregateType: "rule_set",
            aggregateId: ruleSetId,
            eventType:
              "rule_set.revision_registered",
            actorPrincipalId:
              principalId,
            correlationId:
              input.correlationId ??
              null,
            payload: {
              key: ruleSet.id,
              version:
                ruleSet.version,
              contentHash,
              policyId,
            },
          },
        );
      }

      for (
        const link of
        input.authorityLinks ?? []
      ) {
        await linkAuthority(
          client,
          organizationId,
          ruleSetId,
          link,
        );
      }

      await client.query("COMMIT");
      return await this.getRuleSetRevision(
        ruleSetId,
      );
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async getRuleSetRevision(
    ruleSetId: string,
  ): Promise<RuleSetRevision> {
    const id =
      requireUuid(
        ruleSetId,
        "ruleSetId",
      );
    const result =
      await this.pool.query(
        `SELECT *
         FROM rule_sets
         WHERE id = $1`,
        [id],
      );

    if (!result.rows[0]) {
      throw new TraceabilityError(
        "not_found",
        "ruleset revision not found",
      );
    }

    const links =
      await this.pool.query(
        `SELECT
           l.*,
           a.organization_id AS authority_organization_id,
           a.source_type,
           a.jurisdiction,
           a.citation,
           a.title,
           a.uri,
           a.source_date,
           a.effective_from AS authority_effective_from,
           a.effective_to AS authority_effective_to,
           a.content_hash AS authority_content_hash,
           a.metadata AS authority_metadata,
           a.created_at AS authority_created_at,
           a.updated_at AS authority_updated_at
         FROM rule_set_authority_links AS l
         INNER JOIN authority_sources AS a
           ON a.id = l.authority_source_id
         WHERE l.rule_set_id = $1
         ORDER BY a.citation ASC, l.id ASC`,
        [id],
      );

    return mapRevision(
      result.rows[0],
      links.rows,
    );
  }

  async listRuleSetRevisions(
    organizationId: string,
    key?: string,
  ): Promise<RuleSetRevision[]> {
    const values: unknown[] = [
      requireUuid(
        organizationId,
        "organizationId",
      ),
    ];
    let where =
      "organization_id = $1";
    if (
      key !== undefined &&
      key.trim() !== ""
    ) {
      values.push(key.trim());
      where +=
        ` AND key = $${values.length}`;
    }

    const result =
      await this.pool.query(
        `SELECT id
         FROM rule_sets
         WHERE ${where}
         ORDER BY key ASC, created_at ASC, id ASC`,
        values,
      );

    const output:
      RuleSetRevision[] = [];
    for (const row of result.rows) {
      output.push(
        await this.getRuleSetRevision(
          row.id,
        ),
      );
    }
    return output;
  }

  async activateRuleSetRevision(
    input: ActivateRuleSetRevisionInput,
  ): Promise<RuleSetRevision> {
    const client =
      await this.pool.connect();
    try {
      await client.query("BEGIN");
      const row =
        await lockRuleSet(
          client,
          input.ruleSetId,
        );
      if (
        row.status !== "draft"
      ) {
        throw new TraceabilityError(
          "invalid_state",
          "only draft ruleset revisions can be activated",
        );
      }

      const principalId =
        requireUuid(
          input.principalId,
          "principalId",
        );
      await assertPrincipal(
        client,
        row.organization_id,
        principalId,
      );
      const activatedAt =
        this.now().toISOString();
      const effectiveFrom =
        normalizeOptionalDate(
          input.effectiveFrom,
          "effectiveFrom",
        ) ??
        activatedAt;

      await client.query(
        `UPDATE rule_sets
         SET status = 'active',
             activated_at = $2,
             effective_from = COALESCE(
               effective_from,
               $3
             ),
             updated_at = now()
         WHERE id = $1`,
        [
          row.id,
          activatedAt,
          effectiveFrom,
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            row.organization_id,
          aggregateType: "rule_set",
          aggregateId: row.id,
          eventType:
            "rule_set.activated",
          actorPrincipalId:
            principalId,
          correlationId:
            input.correlationId ??
            null,
          occurredAt: activatedAt,
          payload: {
            key: row.key,
            version: row.version,
            contentHash:
              row.content_hash,
            effectiveFrom,
          },
        },
      );

      await client.query("COMMIT");
      return this.getRuleSetRevision(
        row.id,
      );
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async supersedeRuleSetRevision(
    input: SupersedeRuleSetRevisionInput,
  ): Promise<RuleSetRevision> {
    const client =
      await this.pool.connect();

    try {
      await client.query("BEGIN");
      const current =
        await lockRuleSet(
          client,
          input.ruleSetId,
        );
      const successor =
        await lockRuleSet(
          client,
          input.supersededByRuleSetId,
        );

      if (
        current.organization_id !==
          successor.organization_id ||
        current.key !== successor.key
      ) {
        throw new TraceabilityError(
          "validation",
          "successor must be another revision of the same ruleset in the same organization",
        );
      }
      if (
        current.status !== "active" ||
        successor.status !== "active"
      ) {
        throw new TraceabilityError(
          "invalid_state",
          "both current and successor revisions must be active before supersession",
        );
      }

      const principalId =
        requireUuid(
          input.principalId,
          "principalId",
        );
      await assertPrincipal(
        client,
        current.organization_id,
        principalId,
      );
      const effectiveTo =
        normalizeOptionalDate(
          input.effectiveTo,
          "effectiveTo",
        ) ??
        this.now().toISOString();

      await client.query(
        `UPDATE rule_sets
         SET status = 'superseded',
             effective_to = $2,
             superseded_by_rule_set_id = $3,
             updated_at = now()
         WHERE id = $1`,
        [
          current.id,
          effectiveTo,
          successor.id,
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            current.organization_id,
          aggregateType: "rule_set",
          aggregateId: current.id,
          eventType:
            "rule_set.superseded",
          actorPrincipalId:
            principalId,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            key: current.key,
            version:
              current.version,
            supersededByRuleSetId:
              successor.id,
            successorVersion:
              successor.version,
            effectiveTo,
          },
        },
      );

      await client.query("COMMIT");
      return this.getRuleSetRevision(
        current.id,
      );
    } catch (error) {
      await client.query("ROLLBACK");
      throw normalizeError(error);
    } finally {
      client.release();
    }
  }

  async assertRevisionMatches(
    organizationId: string,
    ruleSetId: string,
    ruleSet: DeclarativeRuleSet | unknown,
  ): Promise<RuleSetRevision> {
    const revision =
      await this.getRuleSetRevision(
        ruleSetId,
      );
    if (
      revision.organizationId !==
      requireUuid(
        organizationId,
        "organizationId",
      )
    ) {
      throw new TraceabilityError(
        "validation",
        "ruleset revision belongs to another organization",
      );
    }

    const parsed =
      parseRuleSet(ruleSet);
    const hash =
      hashSnapshot(
        toJsonObject(parsed),
      );
    if (
      hash !==
      revision.contentHash
    ) {
      throw new TraceabilityError(
        "conflict",
        "evaluation ruleset does not match the registered immutable revision",
      );
    }
    return revision;
  }
}

function hashSnapshot(
  snapshot: JsonObject,
): string {
  return createHash("sha256")
    .update(
      canonicalJson(snapshot),
      "utf8",
    )
    .digest("hex");
}

async function linkAuthority(
  client: PoolClient,
  organizationId: string,
  ruleSetId: string,
  input: {
    authoritySourceId: string;
    relation?: string;
    locator?: string | null;
    note?: string | null;
  },
): Promise<void> {
  const authoritySourceId =
    requireUuid(
      input.authoritySourceId,
      "authoritySourceId",
    );
  const source =
    await client.query(
      `SELECT id
       FROM authority_sources
       WHERE id = $1
         AND organization_id = $2`,
      [
        authoritySourceId,
        organizationId,
      ],
    );
  if (!source.rows[0]) {
    throw new TraceabilityError(
      "not_found",
      "authority source not found in organization",
    );
  }

  await client.query(
    `INSERT INTO rule_set_authority_links(
       id,
       rule_set_id,
       authority_source_id,
       relation,
       locator,
       note
     ) VALUES (
       $1, $2, $3, $4, $5, $6
     )
     ON CONFLICT (
       rule_set_id,
       authority_source_id,
       relation,
       locator_key
     ) DO NOTHING`,
    [
      randomUUID(),
      ruleSetId,
      authoritySourceId,
      normalizeRelation(
        input.relation,
      ),
      normalizeNullableString(
        input.locator,
      ),
      normalizeNullableString(
        input.note,
      ),
    ],
  );
}

async function lockRuleSet(
  client: PoolClient,
  id: string,
): Promise<any> {
  const result =
    await client.query(
      `SELECT *
       FROM rule_sets
       WHERE id = $1
       FOR UPDATE`,
      [
        requireUuid(
          id,
          "ruleSetId",
        ),
      ],
    );
  if (!result.rows[0]) {
    throw new TraceabilityError(
      "not_found",
      "ruleset revision not found",
    );
  }
  return result.rows[0];
}

async function assertOrganization(
  client: PoolClient,
  id: string,
): Promise<void> {
  const result =
    await client.query(
      `SELECT 1
       FROM organizations
       WHERE id = $1`,
      [id],
    );
  if (!result.rows[0]) {
    throw new TraceabilityError(
      "not_found",
      "organization not found",
    );
  }
}

async function assertPolicy(
  client: PoolClient,
  organizationId: string,
  policyId: string,
): Promise<void> {
  const result =
    await client.query(
      `SELECT 1
       FROM policies
       WHERE id = $1
         AND organization_id = $2`,
      [policyId, organizationId],
    );
  if (!result.rows[0]) {
    throw new TraceabilityError(
      "not_found",
      "policy not found in organization",
    );
  }
}

async function assertPrincipal(
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
    throw new TraceabilityError(
      "not_found",
      "active principal not found in organization",
    );
  }
}

function mapRevision(
  row: any,
  linkRows: any[],
): RuleSetRevision {
  const snapshot =
    parseRuleSet(
      row.declarative_snapshot,
    );
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    policyId: row.policy_id,
    key: row.key,
    version: row.version,
    status: row.status,
    effectiveFrom:
      nullableIso(
        row.effective_from,
      ),
    effectiveTo:
      nullableIso(
        row.effective_to,
      ),
    contentHash:
      row.content_hash,
    declarativeSnapshot:
      snapshot,
    createdByPrincipalId:
      row.created_by_principal_id ??
      null,
    activatedAt:
      nullableIso(
        row.activated_at,
      ),
    supersededByRuleSetId:
      row.superseded_by_rule_set_id ??
      null,
    metadata:
      objectOrEmpty(
        row.metadata,
      ),
    authorities:
      linkRows.map(
        (link) => ({
          link:
            mapAuthorityLink(
              link,
            ),
          source:
            mapAuthority({
              id:
                link.authority_source_id,
              organization_id:
                link.authority_organization_id,
              source_type:
                link.source_type,
              jurisdiction:
                link.jurisdiction,
              citation:
                link.citation,
              title:
                link.title,
              uri: link.uri,
              source_date:
                link.source_date,
              effective_from:
                link.authority_effective_from,
              effective_to:
                link.authority_effective_to,
              content_hash:
                link.authority_content_hash,
              metadata:
                link.authority_metadata,
              created_at:
                link.authority_created_at,
              updated_at:
                link.authority_updated_at,
            }),
        }),
      ),
    createdAt:
      iso(row.created_at),
    updatedAt:
      iso(row.updated_at),
  };
}

function mapAuthority(
  row: any,
): AuthoritySource {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    sourceType:
      row.source_type,
    jurisdiction:
      row.jurisdiction ??
      null,
    citation: row.citation,
    title: row.title,
    uri: row.uri ?? null,
    sourceDate:
      nullableIso(
        row.source_date,
      ),
    effectiveFrom:
      nullableIso(
        row.effective_from,
      ),
    effectiveTo:
      nullableIso(
        row.effective_to,
      ),
    contentHash:
      row.content_hash ??
      null,
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

function mapAuthorityLink(
  row: any,
): RuleSetAuthorityLink {
  return {
    id: row.id,
    ruleSetId:
      row.rule_set_id,
    authoritySourceId:
      row.authority_source_id,
    relation: row.relation,
    locator:
      row.locator ?? null,
    note:
      row.note ?? null,
    createdAt:
      iso(row.created_at),
  };
}

function normalizeSourceType(
  value: string,
): any {
  const allowed = new Set([
    "statute",
    "regulation",
    "order",
    "case",
    "contract",
    "policy",
    "standard",
    "guidance",
    "other",
  ]);
  if (
    !allowed.has(value)
  ) {
    throw new TraceabilityError(
      "validation",
      "sourceType is invalid",
    );
  }
  return value;
}

function normalizeRelation(
  value:
    | string
    | undefined,
): string {
  if (
    value === undefined ||
    value.trim() === ""
  ) {
    return "implements";
  }
  if (
    !/^[a-z][a-z0-9_.:-]*$/.test(
      value.trim(),
    )
  ) {
    throw new TraceabilityError(
      "validation",
      "relation is invalid",
    );
  }
  return value.trim();
}

function normalizeOptionalHash(
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
    value.trim().toLowerCase();
  if (
    !/^[0-9a-f]{64}$/.test(
      normalized,
    )
  ) {
    throw new TraceabilityError(
      "validation",
      "contentHash must be a SHA-256 hex digest",
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
    throw new TraceabilityError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
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

function requireString(
  value: string,
  field: string,
): string {
  if (
    typeof value !== "string" ||
    value.trim() === ""
  ) {
    throw new TraceabilityError(
      "validation",
      `${field} is required`,
    );
  }
  return value.trim();
}

function requireUuid(
  value: string,
  field: string,
): string {
  const normalized =
    requireString(
      value,
      field,
    );
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      normalized,
    )
  ) {
    throw new TraceabilityError(
      "validation",
      `${field} must be a UUID`,
    );
  }
  return normalized;
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

function toJsonObject(
  value: unknown,
): JsonObject {
  return JSON.parse(
    JSON.stringify(value),
  ) as JsonObject;
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
  return (
    value === null ||
    value === undefined
  )
    ? null
    : iso(value);
}

function normalizeError(
  error: unknown,
): Error {
  if (
    error instanceof
    TraceabilityError
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
    return new TraceabilityError(
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
