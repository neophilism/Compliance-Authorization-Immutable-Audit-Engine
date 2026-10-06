import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { JsonObject } from "@caiae/core";
import {
  parseRuleSet,
  type DeclarativeRuleSet,
} from "@caiae/rules";
import {
  appendAuditEventWithClient,
  canonicalJson,
} from "@caiae/db";
import {
  TraceabilityError,
  type ActivateRuleSetVersionInput,
  type AdHocRuleSetTraceabilityManifest,
  type AuthorityReference,
  type AuthorityReferenceInput,
  type ListRuleSetVersionsOptions,
  type RegisterRuleSetVersionInput,
  type RegisteredRuleSetVersion,
  type ResolveRuleSetInput,
  type RetireRuleSetVersionInput,
  type RuleSetAuthorityLink,
  type RuleSetTraceabilityManifest,
  type TraceabilityServiceOptions,
} from "./types.js";

export class TraceabilityService {
  private readonly now: () => Date;

  constructor(
    private readonly pool: Pool,
    options: TraceabilityServiceOptions = {},
  ) {
    this.now =
      options.now ??
      (() => new Date());
  }

  hashRuleSet(
    ruleSet: DeclarativeRuleSet | unknown,
  ): {
    ruleSet: DeclarativeRuleSet;
    definitionHash: string;
  } {
    let parsed: DeclarativeRuleSet;
    try {
      parsed = parseRuleSet(ruleSet);
    } catch (error) {
      throw new TraceabilityError(
        "validation",
        error instanceof Error
          ? error.message
          : "invalid ruleset",
      );
    }

    return {
      ruleSet: parsed,
      definitionHash:
        sha256(parsed),
    };
  }

  adHocManifest(
    ruleSet: DeclarativeRuleSet | unknown,
  ): AdHocRuleSetTraceabilityManifest {
    const normalized =
      this.hashRuleSet(ruleSet);

    return {
      schemaVersion: "1",
      registrationMode: "ad_hoc",
      registeredRuleSetId: null,
      key: normalized.ruleSet.id,
      version:
        normalized.ruleSet.version,
      definitionHash:
        normalized.definitionHash,
      authorities: [],
    };
  }

  async register(
    input: RegisterRuleSetVersionInput,
  ): Promise<RegisteredRuleSetVersion> {
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
    const key =
      requireKey(
        input.key,
        "key",
      );
    const normalized =
      this.hashRuleSet(
        input.ruleSet,
      );

    if (
      normalized.ruleSet.id !==
      key
    ) {
      throw new TraceabilityError(
        "validation",
        "ruleset.id must equal the registered key",
      );
    }

    const effectiveFrom =
      normalizeOptionalDate(
        input.effectiveFrom,
        "effectiveFrom",
      );
    const effectiveTo =
      normalizeOptionalDate(
        input.effectiveTo,
        "effectiveTo",
      );
    assertWindow(
      effectiveFrom,
      effectiveTo,
    );

    const supersedesRuleSetId =
      input.supersedesRuleSetId
        ? requireUuid(
            input.supersedesRuleSetId,
            "supersedesRuleSetId",
          )
        : null;
    const createdByPrincipalId =
      input.createdByPrincipalId
        ? requireUuid(
            input.createdByPrincipalId,
            "createdByPrincipalId",
          )
        : null;
    const client =
      await this.pool.connect();
    const id =
      randomUUID();

    try {
      await client.query("BEGIN");
      await assertPolicy(
        client,
        organizationId,
        policyId,
      );

      if (
        createdByPrincipalId
      ) {
        await assertPrincipal(
          client,
          organizationId,
          createdByPrincipalId,
        );
      }

      if (
        supersedesRuleSetId
      ) {
        const previous =
          await getRuleSetRow(
            client,
            supersedesRuleSetId,
          );
        if (
          previous.organization_id !==
            organizationId ||
          previous.key !== key
        ) {
          throw new TraceabilityError(
            "validation",
            "superseded ruleset must belong to the same organization and key lineage",
          );
        }
      }

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
           definition,
           definition_hash,
           title,
           description,
           supersedes_rule_set_id,
           created_by_principal_id,
           metadata
         ) VALUES (
           $1, $2, $3, $4, $5,
           'draft', $6, $7,
           $8::jsonb, $9, $10, $11,
           $12, $13, $14::jsonb
         )`,
        [
          id,
          organizationId,
          policyId,
          key,
          normalized.ruleSet.version,
          effectiveFrom,
          effectiveTo,
          JSON.stringify(
            normalized.ruleSet,
          ),
          normalized.definitionHash,
          normalized.ruleSet.title,
          normalized.ruleSet.description ??
            null,
          supersedesRuleSetId,
          createdByPrincipalId,
          JSON.stringify(
            input.metadata ?? {},
          ),
        ],
      );

      for (
        const authorityInput of
        input.authorities ?? []
      ) {
        const authority =
          await upsertAuthority(
            client,
            organizationId,
            authorityInput,
          );
        await client.query(
          `INSERT INTO rule_set_authorities(
             id,
             organization_id,
             rule_set_id,
             authority_reference_id,
             locator,
             metadata
           ) VALUES (
             $1, $2, $3, $4, $5,
             $6::jsonb
           )`,
          [
            randomUUID(),
            organizationId,
            id,
            authority.id,
            normalizeNullableString(
              authorityInput.locator,
            ),
            JSON.stringify(
              authorityInput.metadata ??
                {},
            ),
          ],
        );
      }

      await appendAuditEventWithClient(
        client,
        {
          organizationId,
          aggregateType:
            "rule_set",
          aggregateId: id,
          eventType:
            "rule_set.registered",
          actorPrincipalId:
            createdByPrincipalId,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            key,
            version:
              normalized.ruleSet.version,
            definitionHash:
              normalized.definitionHash,
            policyId,
            supersedesRuleSetId,
            effectiveFrom,
            effectiveTo,
            authorityCount:
              input.authorities
                ?.length ?? 0,
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

    return this.get(id);
  }

  async get(
    ruleSetId: string,
  ): Promise<RegisteredRuleSetVersion> {
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
        "registered ruleset not found",
      );
    }

    return mapRuleSet(
      result.rows[0],
    );
  }

  async list(
    organizationId: string,
    options:
      ListRuleSetVersionsOptions = {},
  ): Promise<RegisteredRuleSetVersion[]> {
    const org =
      requireUuid(
        organizationId,
        "organizationId",
      );
    const values: unknown[] = [org];
    const filters = [
      "organization_id = $1",
    ];

    if (
      options.key !== undefined &&
      options.key !== null
    ) {
      values.push(
        requireKey(
          options.key,
          "key",
        ),
      );
      filters.push(
        `key = $${values.length}`,
      );
    }

    if (
      options.status !== undefined &&
      options.status !== null
    ) {
      const status =
        normalizeStatus(
          options.status,
        );
      values.push(status);
      filters.push(
        `status = $${values.length}`,
      );
    }

    const result =
      await this.pool.query(
        `SELECT *
         FROM rule_sets
         WHERE ${filters.join(
           " AND ",
         )}
         ORDER BY
           key ASC,
           created_at ASC,
           id ASC`,
        values,
      );

    return result.rows.map(
      mapRuleSet,
    );
  }

  async traceability(
    ruleSetId: string,
  ): Promise<RuleSetTraceabilityManifest> {
    const ruleSet =
      await this.get(ruleSetId);
    const authorities =
      await this.authoritiesFor(
        ruleSet.id,
      );

    return {
      schemaVersion: "1",
      registrationMode:
        "registered",
      registeredRuleSetId:
        ruleSet.id,
      organizationId:
        ruleSet.organizationId,
      policyId:
        ruleSet.policyId,
      key: ruleSet.key,
      version:
        ruleSet.version,
      status: ruleSet.status,
      definitionHash:
        ruleSet.definitionHash,
      effectiveFrom:
        ruleSet.effectiveFrom,
      effectiveTo:
        ruleSet.effectiveTo,
      supersedesRuleSetId:
        ruleSet.supersedesRuleSetId,
      authorities,
    };
  }

  async resolve(
    input: ResolveRuleSetInput,
  ): Promise<RegisteredRuleSetVersion> {
    const organizationId =
      requireUuid(
        input.organizationId,
        "organizationId",
      );
    const key =
      requireKey(
        input.key,
        "key",
      );
    const at =
      input.at
        ? normalizeRequiredDate(
            input.at,
            "at",
          )
        : this.now().toISOString();

    const result =
      await this.pool.query(
        `SELECT *
         FROM rule_sets
         WHERE organization_id = $1
           AND key = $2
           AND status = 'active'
           AND (
             effective_from IS NULL
             OR effective_from <= $3
           )
           AND (
             effective_to IS NULL
             OR effective_to > $3
           )
         ORDER BY
           effective_from DESC NULLS LAST,
           activated_at DESC NULLS LAST,
           created_at DESC,
           id DESC
         LIMIT 2`,
        [
          organizationId,
          key,
          at,
        ],
      );

    if (
      result.rows.length === 0
    ) {
      throw new TraceabilityError(
        "not_found",
        "no active ruleset version is effective at the requested time",
      );
    }

    if (
      result.rows.length > 1
    ) {
      throw new TraceabilityError(
        "conflict",
        "multiple active ruleset versions overlap at the requested time",
      );
    }

    return mapRuleSet(
      result.rows[0],
    );
  }

  async loadForEvaluation(
    organizationId: string,
    ruleSetId: string,
    at: string,
  ): Promise<{
    ruleSet: DeclarativeRuleSet;
    manifest: RuleSetTraceabilityManifest;
  }> {
    const ruleSet =
      await this.get(ruleSetId);

    if (
      ruleSet.organizationId !==
      requireUuid(
        organizationId,
        "organizationId",
      )
    ) {
      throw new TraceabilityError(
        "not_found",
        "registered ruleset not found in organization",
      );
    }

    if (
      ruleSet.status !== "active"
    ) {
      throw new TraceabilityError(
        "invalid_state",
        "registered ruleset must be active for evaluation",
      );
    }

    const evaluationAt =
      normalizeRequiredDate(
        at,
        "at",
      );
    assertEffective(
      ruleSet,
      evaluationAt,
    );

    return {
      ruleSet:
        ruleSet.definition,
      manifest:
        await this.traceability(
          ruleSet.id,
        ),
    };
  }

  async activate(
    input: ActivateRuleSetVersionInput,
  ): Promise<RegisteredRuleSetVersion> {
    const ruleSetId =
      requireUuid(
        input.ruleSetId,
        "ruleSetId",
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
      const row =
        await getRuleSetRow(
          client,
          ruleSetId,
          true,
        );
      const current =
        mapRuleSet(row);

      if (
        current.status !==
        "draft"
      ) {
        throw new TraceabilityError(
          "invalid_state",
          "only draft ruleset versions can be activated",
        );
      }

      await assertPrincipal(
        client,
        current.organizationId,
        principalId,
      );

      const effectiveFrom =
        input.effectiveFrom ===
          undefined
          ? (
              current.effectiveFrom ??
              this.now().toISOString()
            )
          : normalizeOptionalDate(
              input.effectiveFrom,
              "effectiveFrom",
            );

      assertWindow(
        effectiveFrom,
        current.effectiveTo,
      );

      const overlap =
        await client.query(
          `SELECT id
           FROM rule_sets
           WHERE organization_id = $1
             AND key = $2
             AND status = 'active'
             AND id <> $3
             AND (
               effective_to IS NULL
               OR $4 IS NULL
               OR effective_to > $4
             )
             AND (
               $5::timestamptz IS NULL
               OR effective_from IS NULL
               OR effective_from < $5
             )
           LIMIT 1`,
          [
            current.organizationId,
            current.key,
            current.id,
            effectiveFrom,
            current.effectiveTo,
          ],
        );

      if (
        overlap.rows[0]
      ) {
        throw new TraceabilityError(
          "conflict",
          "active effective window overlaps another ruleset version",
        );
      }

      const activatedAt =
        this.now().toISOString();

      await client.query(
        `UPDATE rule_sets
         SET status = 'active',
             effective_from = $2,
             activated_at = $3,
             activated_by_principal_id = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          current.id,
          effectiveFrom,
          activatedAt,
          principalId,
        ],
      );

      if (
        current.supersedesRuleSetId
      ) {
        await client.query(
          `UPDATE rule_sets
           SET status = 'superseded',
               effective_to =
                 COALESCE(
                   effective_to,
                   $2
                 ),
               updated_at = now()
           WHERE id = $1
             AND status = 'active'`,
          [
            current.supersedesRuleSetId,
            effectiveFrom,
          ],
        );
      }

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            current.organizationId,
          aggregateType:
            "rule_set",
          aggregateId:
            current.id,
          eventType:
            "rule_set.activated",
          actorPrincipalId:
            principalId,
          occurredAt:
            activatedAt,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            key: current.key,
            version:
              current.version,
            definitionHash:
              current.definitionHash,
            effectiveFrom,
            supersedesRuleSetId:
              current.supersedesRuleSetId,
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

    return this.get(ruleSetId);
  }

  async retire(
    input: RetireRuleSetVersionInput,
  ): Promise<RegisteredRuleSetVersion> {
    const ruleSetId =
      requireUuid(
        input.ruleSetId,
        "ruleSetId",
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
      const row =
        await getRuleSetRow(
          client,
          ruleSetId,
          true,
        );
      const current =
        mapRuleSet(row);

      if (
        current.status ===
        "retired"
      ) {
        throw new TraceabilityError(
          "invalid_state",
          "ruleset version is already retired",
        );
      }

      await assertPrincipal(
        client,
        current.organizationId,
        principalId,
      );

      const retiredAt =
        this.now().toISOString();
      const effectiveTo =
        input.effectiveTo ===
          undefined
          ? retiredAt
          : normalizeOptionalDate(
              input.effectiveTo,
              "effectiveTo",
            );

      assertWindow(
        current.effectiveFrom,
        effectiveTo,
      );

      await client.query(
        `UPDATE rule_sets
         SET status = 'retired',
             effective_to = $2,
             retired_at = $3,
             retired_by_principal_id = $4,
             updated_at = now()
         WHERE id = $1`,
        [
          current.id,
          effectiveTo,
          retiredAt,
          principalId,
        ],
      );

      await appendAuditEventWithClient(
        client,
        {
          organizationId:
            current.organizationId,
          aggregateType:
            "rule_set",
          aggregateId:
            current.id,
          eventType:
            "rule_set.retired",
          actorPrincipalId:
            principalId,
          occurredAt:
            retiredAt,
          correlationId:
            input.correlationId ??
            null,
          payload: {
            key: current.key,
            version:
              current.version,
            definitionHash:
              current.definitionHash,
            effectiveTo,
            reason:
              normalizeNullableString(
                input.reason,
              ),
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

    return this.get(ruleSetId);
  }

  private async authoritiesFor(
    ruleSetId: string,
  ): Promise<RuleSetAuthorityLink[]> {
    const result =
      await this.pool.query(
        `SELECT
           a.*,
           l.locator,
           l.metadata AS link_metadata
         FROM rule_set_authorities AS l
         INNER JOIN authority_references AS a
           ON a.id =
             l.authority_reference_id
         WHERE l.rule_set_id = $1
         ORDER BY
           a.authority_type ASC,
           a.citation ASC,
           a.id ASC`,
        [ruleSetId],
      );

    return result.rows.map(
      (row) => ({
        authority:
          mapAuthority(row),
        locator:
          row.locator ?? null,
        metadata:
          objectOrEmpty(
            row.link_metadata,
          ),
      }),
    );
  }
}

async function upsertAuthority(
  client: PoolClient,
  organizationId: string,
  input: AuthorityReferenceInput,
): Promise<AuthorityReference> {
  const authorityType =
    requireKey(
      input.authorityType,
      "authorityType",
    );
  const citation =
    requireString(
      input.citation,
      "citation",
    );
  const title =
    normalizeNullableString(
      input.title,
    );
  const uri =
    normalizeNullableString(
      input.uri,
    );
  const jurisdiction =
    normalizeNullableString(
      input.jurisdiction,
    );
  const effectiveFrom =
    normalizeOptionalDate(
      input.effectiveFrom,
      "authority.effectiveFrom",
    );
  const effectiveTo =
    normalizeOptionalDate(
      input.effectiveTo,
      "authority.effectiveTo",
    );
  assertWindow(
    effectiveFrom,
    effectiveTo,
  );

  const canonical = {
    authorityType,
    citation,
    title,
    uri,
    jurisdiction,
    effectiveFrom,
    effectiveTo,
  };
  const referenceHash =
    sha256(canonical);
  const existing =
    await client.query(
      `SELECT *
       FROM authority_references
       WHERE organization_id = $1
         AND reference_hash = $2`,
      [
        organizationId,
        referenceHash,
      ],
    );

  if (
    existing.rows[0]
  ) {
    return mapAuthority(
      existing.rows[0],
    );
  }

  const id = randomUUID();
  const result =
    await client.query(
      `INSERT INTO authority_references(
         id,
         organization_id,
         authority_type,
         citation,
         title,
         uri,
         jurisdiction,
         effective_from,
         effective_to,
         reference_hash,
         metadata
       ) VALUES (
         $1, $2, $3, $4, $5,
         $6, $7, $8, $9, $10,
         $11::jsonb
       )
       RETURNING *`,
      [
        id,
        organizationId,
        authorityType,
        citation,
        title,
        uri,
        jurisdiction,
        effectiveFrom,
        effectiveTo,
        referenceHash,
        JSON.stringify(
          input.metadata ?? {},
        ),
      ],
    );

  return mapAuthority(
    result.rows[0],
  );
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
      [
        policyId,
        organizationId,
      ],
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

async function getRuleSetRow(
  client: PoolClient,
  ruleSetId: string,
  lock = false,
): Promise<any> {
  const result =
    await client.query(
      `SELECT *
       FROM rule_sets
       WHERE id = $1
       ${lock
         ? "FOR UPDATE"
         : ""}`,
      [ruleSetId],
    );

  if (!result.rows[0]) {
    throw new TraceabilityError(
      "not_found",
      "registered ruleset not found",
    );
  }

  return result.rows[0];
}

function mapRuleSet(
  row: any,
): RegisteredRuleSetVersion {
  let definition: DeclarativeRuleSet;
  try {
    definition =
      parseRuleSet(
        row.definition,
      );
  } catch {
    throw new TraceabilityError(
      "validation",
      "stored ruleset definition is invalid",
    );
  }

  return {
    id: row.id,
    organizationId:
      row.organization_id,
    policyId:
      row.policy_id,
    key: row.key,
    version:
      row.version,
    title:
      row.title ??
      definition.title,
    description:
      row.description ??
      definition.description ??
      null,
    status:
      normalizeStatus(
        row.status,
      ),
    effectiveFrom:
      nullableIso(
        row.effective_from,
      ),
    effectiveTo:
      nullableIso(
        row.effective_to,
      ),
    definition,
    definitionHash:
      row.definition_hash,
    supersedesRuleSetId:
      row.supersedes_rule_set_id ??
      null,
    activatedAt:
      nullableIso(
        row.activated_at,
      ),
    activatedByPrincipalId:
      row.activated_by_principal_id ??
      null,
    retiredAt:
      nullableIso(
        row.retired_at,
      ),
    retiredByPrincipalId:
      row.retired_by_principal_id ??
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

function mapAuthority(
  row: any,
): AuthorityReference {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    authorityType:
      row.authority_type,
    citation:
      row.citation,
    title:
      row.title ?? null,
    uri:
      row.uri ?? null,
    jurisdiction:
      row.jurisdiction ??
      null,
    effectiveFrom:
      nullableIso(
        row.effective_from,
      ),
    effectiveTo:
      nullableIso(
        row.effective_to,
      ),
    referenceHash:
      row.reference_hash,
    metadata:
      objectOrEmpty(
        row.metadata,
      ),
    createdAt:
      iso(row.created_at),
  };
}

function assertEffective(
  ruleSet: RegisteredRuleSetVersion,
  at: string,
): void {
  const time =
    new Date(at).getTime();
  const from =
    ruleSet.effectiveFrom === null
      ? Number.NEGATIVE_INFINITY
      : new Date(
          ruleSet.effectiveFrom,
        ).getTime();
  const to =
    ruleSet.effectiveTo === null
      ? Number.POSITIVE_INFINITY
      : new Date(
          ruleSet.effectiveTo,
        ).getTime();

  if (
    time < from ||
    time >= to
  ) {
    throw new TraceabilityError(
      "invalid_state",
      "registered ruleset is not effective at the evaluation time",
    );
  }
}

function assertWindow(
  from: string | null,
  to: string | null,
): void {
  if (
    from !== null &&
    to !== null &&
    new Date(from).getTime() >=
      new Date(to).getTime()
  ) {
    throw new TraceabilityError(
      "validation",
      "effectiveFrom must be earlier than effectiveTo",
    );
  }
}

function normalizeStatus(
  value: string,
): RegisteredRuleSetVersion["status"] {
  if (
    ![
      "draft",
      "active",
      "superseded",
      "retired",
    ].includes(value)
  ) {
    throw new TraceabilityError(
      "validation",
      "invalid ruleset status",
    );
  }
  return value as RegisteredRuleSetVersion["status"];
}

function requireKey(
  value: string,
  field: string,
): string {
  const normalized =
    requireString(
      value,
      field,
    );
  if (
    !/^[A-Za-z0-9_.:-]+$/.test(
      normalized,
    )
  ) {
    throw new TraceabilityError(
      "validation",
      `${field} must be an identifier`,
    );
  }
  return normalized;
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
    throw new TraceabilityError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }
  return date.toISOString();
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
  return normalizeRequiredDate(
    value,
    field,
  );
}

function normalizeNullableString(
  value:
    | string
    | null
    | undefined,
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

function sha256(
  value: unknown,
): string {
  return createHash("sha256")
    .update(
      canonicalJson(value),
      "utf8",
    )
    .digest("hex");
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
    error instanceof TraceabilityError
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
      "ruleset version or authority reference already exists",
    );
  }

  return error instanceof Error
    ? error
    : new Error(
        String(error),
      );
}
