import type { Pool } from "pg";
import type {
  AuditEvent,
  Deadline,
  JsonObject,
} from "@caiae/core";
import { verifyAuditChain } from "@caiae/db";
import { calculateDeadlineClock } from "@caiae/deadlines";
import {
  ReportingError,
  type AuditChainReport,
  type ComplianceReport,
  type ComplianceReportSummary,
  type CountMap,
  type GenerateReportInput,
  type ReportCertification,
  type ReportCheck,
  type ReportDeadline,
  type ReportException,
  type ReportFinding,
  type ReportRemediation,
  type ReportResource,
} from "./types.js";

export class ReportingService {
  constructor(private readonly pool: Pool) {}

  async generate(
    input: GenerateReportInput,
  ): Promise<ComplianceReport> {
    const organizationId =
      requiredString(
        input.organizationId,
        "organizationId",
      );
    const resourceId =
      normalizeNullableString(
        input.resourceId,
      );
    const generatedAt =
      new Date().toISOString();
    const asOfDate =
      input.asOf === undefined
        ? new Date(generatedAt)
        : parseDate(input.asOf, "asOf");
    const asOf = asOfDate.toISOString();

    const organizationResult =
      await this.pool.query(
        `SELECT id, name, slug, status
         FROM organizations
         WHERE id = $1`,
        [organizationId],
      );

    if (!organizationResult.rows[0]) {
      throw new ReportingError(
        "not_found",
        "organization not found",
      );
    }

    let scopedResource:
      | ReportResource
      | null = null;

    if (resourceId) {
      const resourceResult =
        await this.pool.query(
          `SELECT
             id,
             resource_type,
             name,
             status,
             external_ref
           FROM resources
           WHERE id = $1
             AND organization_id = $2`,
          [resourceId, organizationId],
        );

      if (!resourceResult.rows[0]) {
        throw new ReportingError(
          "not_found",
          "resource not found in organization",
        );
      }

      scopedResource =
        mapResource(
          resourceResult.rows[0],
        );
    }

    const scopeParams = [
      organizationId,
      resourceId,
    ];

    const [
      resourceRows,
      checkRows,
      exceptionRows,
      deadlineRows,
      findingRows,
      remediationRows,
      certificationRows,
      auditRows,
    ] = await Promise.all([
      this.pool.query(
        `SELECT
           id,
           resource_type,
           name,
           status,
           external_ref
         FROM resources
         WHERE organization_id = $1
           AND (
             $2::uuid IS NULL
             OR id = $2::uuid
           )
         ORDER BY resource_type, name, id`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT *
         FROM checks
         WHERE organization_id = $1
           AND (
             $2::uuid IS NULL
             OR resource_id = $2::uuid
           )
         ORDER BY
           COALESCE(
             completed_at,
             evaluated_at,
             created_at
           ) DESC,
           id DESC`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT *
         FROM exceptions
         WHERE organization_id = $1
           AND (
             $2::uuid IS NULL
             OR resource_id = $2::uuid
           )
         ORDER BY requested_at DESC, id DESC`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT *
         FROM deadlines
         WHERE organization_id = $1
           AND (
             $2::uuid IS NULL
             OR resource_id = $2::uuid
           )
         ORDER BY due_at ASC, id ASC`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT *
         FROM findings
         WHERE organization_id = $1
           AND (
             $2::uuid IS NULL
             OR resource_id = $2::uuid
           )
         ORDER BY
           opened_at DESC,
           id DESC`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT
           r.*,
           f.resource_id
         FROM remediations AS r
         INNER JOIN findings AS f
           ON f.id = r.finding_id
         WHERE r.organization_id = $1
           AND (
             $2::uuid IS NULL
             OR f.resource_id = $2::uuid
           )
         ORDER BY r.created_at DESC, r.id DESC`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT *
         FROM certifications
         WHERE organization_id = $1
           AND (
             $2::uuid IS NULL
             OR resource_id = $2::uuid
           )
         ORDER BY
           COALESCE(
             issued_at,
             created_at
           ) DESC,
           id DESC`,
        scopeParams,
      ),
      this.pool.query(
        `SELECT *
         FROM audit_events
         WHERE organization_id = $1
         ORDER BY
           aggregate_type ASC,
           aggregate_id ASC,
           sequence_number ASC`,
        [organizationId],
      ),
    ]);

    const resources =
      resourceRows.rows.map(mapResource);
    const checks =
      checkRows.rows.map(mapCheck);
    const exceptions =
      exceptionRows.rows.map((row) =>
        mapException(row, asOfDate),
      );
    const deadlines =
      deadlineRows.rows.map((row) =>
        mapDeadline(row, asOfDate),
      );
    const findings =
      findingRows.rows.map(mapFinding);
    const remediations =
      remediationRows.rows.map(
        mapRemediation,
      );
    const certifications =
      certificationRows.rows.map(
        (row) =>
          mapCertification(
            row,
            asOfDate,
          ),
      );

    const allAuditEvents =
      auditRows.rows.map(mapAuditEvent);
    const auditEvents =
      resourceId === null
        ? allAuditEvents
        : filterAuditForResource(
            allAuditEvents,
            resourceId,
            checks,
            exceptions,
            deadlines,
            findings,
            remediations,
            certifications,
          );
    const auditChains =
      buildAuditChainReports(
        auditEvents,
      );

    const summary =
      buildSummary(
        resources,
        checks,
        exceptions,
        deadlines,
        findings,
        remediations,
        certifications,
        auditEvents,
        auditChains,
        asOfDate,
      );

    const organization =
      organizationResult.rows[0];

    return {
      schemaVersion: "1",
      reportType: "compliance",
      generatedAt,
      asOf,
      scope: {
        organizationId,
        resourceId,
      },
      organization: {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        status: organization.status,
      },
      resource: scopedResource,
      summary,
      resources,
      checks,
      exceptions,
      deadlines,
      findings,
      remediations,
      certifications,
      auditChains,
      auditEvents,
    };
  }
}

function buildSummary(
  resources: ReportResource[],
  checks: ReportCheck[],
  exceptions: ReportException[],
  deadlines: ReportDeadline[],
  findings: ReportFinding[],
  remediations: ReportRemediation[],
  certifications: ReportCertification[],
  auditEvents: AuditEvent[],
  auditChains: AuditChainReport[],
  asOf: Date,
): ComplianceReportSummary {
  const unresolvedFindings =
    findings.filter(
      (finding) =>
        finding.status !== "resolved" &&
        finding.status !== "closed",
    );
  const deadlineById =
    new Map(
      deadlines.map((deadline) => [
        deadline.id,
        deadline,
      ]),
    );
  const overdueRemediations =
    remediations.filter(
      (remediation) => {
        if (
          remediation.status === "verified" ||
          remediation.status === "rejected" ||
          remediation.status === "cancelled"
        ) {
          return false;
        }

        if (remediation.deadlineId) {
          return (
            deadlineById.get(
              remediation.deadlineId,
            )?.effectiveStatus ===
            "overdue"
          );
        }

        return (
          remediation.dueAt !== null &&
          new Date(
            remediation.dueAt,
          ).getTime() <
            asOf.getTime()
        );
      },
    );

  return {
    resources: {
      total: resources.length,
      byStatus: countBy(
        resources.map(
          (resource) => resource.status,
        ),
      ),
    },
    checks: {
      total: checks.length,
      byStatus: countBy(
        checks.map(
          (check) => check.status,
        ),
      ),
      latestCompletedAt:
        latestDate(
          checks.map(
            (check) =>
              check.completedAt,
          ),
        ),
    },
    exceptions: {
      total: exceptions.length,
      active:
        exceptions.filter(
          (item) => item.active,
        ).length,
      byEffectiveStatus: countBy(
        exceptions.map(
          (item) =>
            item.effectiveStatus,
        ),
      ),
    },
    deadlines: {
      total: deadlines.length,
      overdue:
        deadlines.filter(
          (deadline) =>
            deadline.effectiveStatus ===
            "overdue",
        ).length,
      byEffectiveStatus: countBy(
        deadlines.map(
          (deadline) =>
            deadline.effectiveStatus,
        ),
      ),
    },
    findings: {
      total: findings.length,
      unresolved:
        unresolvedFindings.length,
      unresolvedHighCritical:
        unresolvedFindings.filter(
          (finding) =>
            finding.severity ===
              "high" ||
            finding.severity ===
              "critical",
        ).length,
      byStatus: countBy(
        findings.map(
          (finding) => finding.status,
        ),
      ),
      bySeverity: countBy(
        findings.map(
          (finding) =>
            finding.severity,
        ),
      ),
    },
    remediations: {
      total: remediations.length,
      overdue:
        overdueRemediations.length,
      byStatus: countBy(
        remediations.map(
          (remediation) =>
            remediation.status,
        ),
      ),
    },
    certifications: {
      total: certifications.length,
      valid:
        certifications.filter(
          (certification) =>
            certification.valid,
        ).length,
      byEffectiveStatus: countBy(
        certifications.map(
          (certification) =>
            certification.effectiveStatus,
        ),
      ),
    },
    audit: {
      eventCount: auditEvents.length,
      chainCount: auditChains.length,
      invalidChainCount:
        auditChains.filter(
          (chain) => !chain.valid,
        ).length,
      allChainsValid:
        auditChains.every(
          (chain) => chain.valid,
        ),
    },
  };
}

function mapResource(
  row: any,
): ReportResource {
  return {
    id: row.id,
    resourceType: row.resource_type,
    name: row.name,
    status: row.status,
    externalRef: row.external_ref,
  };
}

function mapCheck(
  row: any,
): ReportCheck {
  const ruleSetSnapshot =
    objectOrEmpty(
      row.rule_set_snapshot,
    );
  const result =
    objectOrEmpty(row.result);
  const counts =
    objectOrEmpty(result.counts);

  return {
    id: row.id,
    resourceId: row.resource_id,
    trigger: row.trigger ?? "manual",
    status: row.status,
    evaluatedAt:
      nullableIso(row.evaluated_at),
    completedAt:
      nullableIso(row.completed_at),
    ruleSetId:
      stringOrNull(
        ruleSetSnapshot.id,
      ),
    ruleSetVersion:
      stringOrNull(
        ruleSetSnapshot.version,
      ),
    counts:
      toJsonObject(counts),
    errorMessage:
      row.error_message ?? null,
  };
}

function mapException(
  row: any,
  asOf: Date,
): ReportException {
  const validFrom =
    nullableIso(row.valid_from);
  const validUntil =
    nullableIso(row.valid_until);
  const effectiveStatus =
    effectiveExceptionStatus(
      row.status,
      validUntil,
      asOf,
    );
  const fromTime =
    validFrom === null
      ? new Date(
          row.requested_at,
        ).getTime()
      : new Date(validFrom).getTime();
  const untilTime =
    validUntil === null
      ? Number.POSITIVE_INFINITY
      : new Date(validUntil).getTime();

  return {
    id: row.id,
    resourceId: row.resource_id,
    kind: row.kind ?? "exception",
    storedStatus: row.status,
    effectiveStatus,
    active:
      effectiveStatus ===
        "approved" &&
      asOf.getTime() >= fromTime &&
      asOf.getTime() < untilTime,
    justification: row.justification,
    validFrom,
    validUntil,
    requestedAt:
      iso(row.requested_at),
    decidedAt:
      nullableIso(row.decided_at),
    approvalAuthority:
      row.approval_authority ?? null,
  };
}

function mapDeadline(
  row: any,
  asOf: Date,
): ReportDeadline {
  const deadline =
    mapDeadlineEntity(row);
  const clock =
    deadline.status === "satisfied" ||
    deadline.status === "cancelled"
      ? null
      : calculateDeadlineClock(
          deadline,
          asOf,
        );

  return {
    id: deadline.id,
    resourceId:
      deadline.resourceId,
    subjectType:
      deadline.subjectType,
    subjectId:
      deadline.subjectId,
    deadlineType:
      deadline.deadlineType,
    storedStatus:
      deadline.status,
    effectiveStatus:
      clock?.status ??
      deadline.status,
    dueAt: deadline.dueAt,
    satisfiedAt:
      deadline.satisfiedAt,
    warningWindowSeconds:
      deadline.warningWindowSeconds,
    gracePeriodSeconds:
      deadline.gracePeriodSeconds,
    escalationLevel:
      clock?.escalationLevel ??
      deadline.escalationLevel,
    cycleNumber:
      deadline.cycleNumber,
  };
}

function mapDeadlineEntity(
  row: any,
): Deadline {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    resourceId:
      row.resource_id ?? null,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    deadlineType:
      row.deadline_type,
    status: row.status,
    createdByPrincipalId:
      row.created_by_principal_id ??
      null,
    anchorAt:
      nullableIso(row.anchor_at),
    dueOffsetSeconds:
      row.due_offset_seconds === null ||
      row.due_offset_seconds === undefined
        ? null
        : Number(
            row.due_offset_seconds,
          ),
    dueAt: iso(row.due_at),
    warningWindowSeconds:
      Number(
        row.warning_window_seconds ??
          0,
      ),
    gracePeriodSeconds:
      Number(
        row.grace_period_seconds ??
          0,
      ),
    recurrenceIntervalSeconds:
      row.recurrence_interval_seconds ===
        null ||
      row.recurrence_interval_seconds ===
        undefined
        ? null
        : Number(
            row.recurrence_interval_seconds,
          ),
    recurrenceEndAt:
      nullableIso(
        row.recurrence_end_at,
      ),
    maxOccurrences:
      row.max_occurrences === null ||
      row.max_occurrences === undefined
        ? null
        : Number(
            row.max_occurrences,
          ),
    cycleNumber:
      Number(row.cycle_number ?? 1),
    escalationAfterSeconds:
      Array.isArray(
        row.escalation_after_seconds,
      )
        ? row.escalation_after_seconds.map(
            (value: unknown) =>
              Number(value),
          )
        : [],
    escalationLevel:
      Number(
        row.escalation_level ?? 0,
      ),
    satisfiedAt:
      nullableIso(row.satisfied_at),
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

function mapFinding(
  row: any,
): ReportFinding {
  return {
    id: row.id,
    resourceId: row.resource_id,
    checkId: row.check_id ?? null,
    ruleKey: row.rule_key ?? null,
    ruleSetKey:
      row.rule_set_key ?? null,
    ruleSetVersion:
      row.rule_set_version ?? null,
    severity: row.severity,
    status: row.status,
    ownerPrincipalId:
      row.owner_principal_id ?? null,
    title: row.title,
    description: row.description,
    openedAt:
      iso(
        row.opened_at ??
          row.created_at,
      ),
    resolvedAt:
      nullableIso(row.resolved_at),
    closedAt:
      nullableIso(row.closed_at),
  };
}

function mapRemediation(
  row: any,
): ReportRemediation {
  return {
    id: row.id,
    findingId: row.finding_id,
    resourceId: row.resource_id,
    deadlineId:
      row.deadline_id ?? null,
    ownerPrincipalId:
      row.owner_principal_id ?? null,
    status: row.status,
    plan: row.plan,
    dueAt:
      nullableIso(row.due_at),
    startedAt:
      nullableIso(row.started_at),
    completedAt:
      nullableIso(row.completed_at),
    verifiedAt:
      nullableIso(row.verified_at),
  };
}

function mapCertification(
  row: any,
  asOf: Date,
): ReportCertification {
  const validFrom =
    nullableIso(row.valid_from);
  const validUntil =
    nullableIso(row.valid_until);
  const effectiveStatus =
    effectiveCertificationStatus(
      row.status,
      validFrom,
      validUntil,
      asOf,
    );

  return {
    id: row.id,
    resourceId: row.resource_id,
    certificationType:
      row.certification_type,
    certificateNumber:
      row.certificate_number ?? null,
    supportingCheckId:
      row.supporting_check_id ?? null,
    storedStatus: row.status,
    effectiveStatus,
    valid:
      effectiveStatus === "active",
    issuedAt:
      nullableIso(row.issued_at),
    validFrom,
    validUntil,
    suspensionReason:
      row.suspension_reason ?? null,
    revocationReason:
      row.revocation_reason ?? null,
  };
}

function mapAuditEvent(
  row: any,
): AuditEvent {
  return {
    id: row.id,
    organizationId:
      row.organization_id,
    aggregateType:
      row.aggregate_type,
    aggregateId:
      row.aggregate_id,
    sequenceNumber:
      Number(row.sequence_number),
    eventType: row.event_type,
    actorPrincipalId:
      row.actor_principal_id ?? null,
    occurredAt:
      iso(row.occurred_at),
    recordedAt:
      iso(row.recorded_at),
    correlationId:
      row.correlation_id ?? null,
    payload:
      objectOrEmpty(row.payload) as JsonObject,
    previousEventHash:
      row.previous_event_hash ?? null,
    eventHash: row.event_hash,
  };
}

function filterAuditForResource(
  events: AuditEvent[],
  resourceId: string,
  checks: ReportCheck[],
  exceptions: ReportException[],
  deadlines: ReportDeadline[],
  findings: ReportFinding[],
  remediations: ReportRemediation[],
  certifications: ReportCertification[],
): AuditEvent[] {
  const included =
    new Map<string, Set<string>>();

  addScopeId(
    included,
    "resource",
    resourceId,
  );

  for (const item of checks) {
    addScopeId(
      included,
      "check",
      item.id,
    );
  }

  for (const item of exceptions) {
    addScopeId(
      included,
      "exception",
      item.id,
    );
  }

  for (const item of deadlines) {
    addScopeId(
      included,
      "deadline",
      item.id,
    );
  }

  for (const item of findings) {
    addScopeId(
      included,
      "finding",
      item.id,
    );
  }

  for (const item of remediations) {
    addScopeId(
      included,
      "remediation",
      item.id,
    );
  }

  for (const item of certifications) {
    addScopeId(
      included,
      "certification",
      item.id,
    );
  }

  return events.filter((event) =>
    included
      .get(event.aggregateType)
      ?.has(event.aggregateId) ??
    false,
  );
}

function addScopeId(
  included: Map<
    string,
    Set<string>
  >,
  aggregateType: string,
  aggregateId: string,
): void {
  const ids =
    included.get(
      aggregateType,
    ) ?? new Set<string>();
  ids.add(aggregateId);
  included.set(
    aggregateType,
    ids,
  );
}

function buildAuditChainReports(
  events: AuditEvent[],
): AuditChainReport[] {
  const groups =
    new Map<
      string,
      AuditEvent[]
    >();

  for (const event of events) {
    const key =
      `${event.aggregateType}:${event.aggregateId}`;
    const current =
      groups.get(key) ?? [];
    current.push(event);
    groups.set(key, current);
  }

  return [...groups.entries()]
    .map(([key, chain]) => {
      const [aggregateType, ...idParts] =
        key.split(":");
      const aggregateId =
        idParts.join(":");
      const ordered =
        [...chain].sort(
          (left, right) =>
            left.sequenceNumber -
            right.sequenceNumber,
        );
      const verification =
        verifyAuditChain(ordered);

      return {
        aggregateType:
          aggregateType ?? "",
        aggregateId,
        eventCount:
          ordered.length,
        valid: verification.valid,
        failureReason:
          verification.valid
            ? null
            : verification.reason,
        failureSequenceNumber:
          verification.valid
            ? null
            : verification.sequenceNumber,
      };
    })
    .sort((left, right) =>
      `${left.aggregateType}:${left.aggregateId}`.localeCompare(
        `${right.aggregateType}:${right.aggregateId}`,
      ),
    );
}

function effectiveExceptionStatus(
  storedStatus: string,
  validUntil: string | null,
  asOf: Date,
): string {
  if (
    storedStatus === "denied" ||
    storedStatus === "revoked" ||
    storedStatus === "expired"
  ) {
    return storedStatus;
  }

  if (
    validUntil !== null &&
    asOf.getTime() >=
      new Date(
        validUntil,
      ).getTime()
  ) {
    return "expired";
  }

  return storedStatus;
}

function effectiveCertificationStatus(
  storedStatus: string,
  validFrom: string | null,
  validUntil: string | null,
  asOf: Date,
): string {
  if (
    storedStatus === "revoked" ||
    storedStatus === "expired" ||
    storedStatus === "superseded"
  ) {
    return storedStatus;
  }

  if (
    validUntil !== null &&
    asOf.getTime() >=
      new Date(
        validUntil,
      ).getTime()
  ) {
    return "expired";
  }

  if (
    validFrom !== null &&
    asOf.getTime() <
      new Date(
        validFrom,
      ).getTime()
  ) {
    return "pending";
  }

  if (
    storedStatus === "suspended"
  ) {
    return "suspended";
  }

  return "active";
}

function countBy(
  values: string[],
): CountMap {
  const counts =
    new Map<string, number>();

  for (const value of values) {
    counts.set(
      value,
      (counts.get(value) ?? 0) + 1,
    );
  }

  return Object.fromEntries(
    [...counts.entries()].sort(
      ([left], [right]) =>
        left.localeCompare(right),
    ),
  );
}

function latestDate(
  values: (
    | string
    | null
  )[],
): string | null {
  const dates =
    values.filter(
      (value): value is string =>
        value !== null,
    );

  if (dates.length === 0) {
    return null;
  }

  return dates
    .map((value) =>
      new Date(value),
    )
    .sort(
      (left, right) =>
        right.getTime() -
        left.getTime(),
    )[0]!
    .toISOString();
}

function requiredString(
  value: string,
  field: string,
): string {
  const normalized =
    value.trim();

  if (!normalized) {
    throw new ReportingError(
      "validation",
      `${field} is required`,
    );
  }

  return normalized;
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

function parseDate(
  value: string,
  field: string,
): Date {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new ReportingError(
      "validation",
      `${field} must be a valid date-time`,
    );
  }

  return date;
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
  return value === null ||
    value === undefined
    ? null
    : iso(value);
}
