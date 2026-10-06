import type {
  ComplianceReport,
  RenderedReport,
  ReportFormat,
} from "./types.js";

export function renderComplianceReport(
  report: ComplianceReport,
  format: ReportFormat,
): RenderedReport {
  switch (format) {
    case "json":
      return {
        format,
        mediaType: "application/json",
        body: renderJson(report),
      };
    case "csv":
      return {
        format,
        mediaType: "text/csv; charset=utf-8",
        body: renderCsv(report),
      };
    case "text":
      return {
        format,
        mediaType: "text/markdown; charset=utf-8",
        body: renderHumanReadable(report),
      };
  }
}

export function renderJson(
  report: ComplianceReport,
): string {
  return JSON.stringify(
    report,
    null,
    2,
  );
}

export function renderCsv(
  report: ComplianceReport,
): string {
  const header = [
    "section",
    "resource_id",
    "entity_type",
    "entity_id",
    "status",
    "effective_status",
    "severity",
    "key",
    "title",
    "occurred_at",
    "due_at",
    "valid_from",
    "valid_until",
    "details_json",
  ];

  const rows: string[][] = [];

  rows.push([
    "summary",
    report.scope.resourceId ?? "",
    "report",
    "",
    "",
    "",
    "",
    "",
    "Compliance report summary",
    report.asOf,
    "",
    "",
    "",
    JSON.stringify(report.summary),
  ]);

  for (const resource of report.resources) {
    rows.push([
      "resources",
      resource.id,
      "resource",
      resource.id,
      resource.status,
      resource.status,
      "",
      resource.resourceType,
      resource.name,
      "",
      "",
      "",
      "",
      JSON.stringify({
        externalRef:
          resource.externalRef,
      }),
    ]);
  }

  for (const check of report.checks) {
    rows.push([
      "checks",
      check.resourceId,
      "check",
      check.id,
      check.status,
      check.status,
      "",
      check.ruleSetId ?? "",
      check.ruleSetVersion
        ? `Ruleset ${check.ruleSetVersion}`
        : "Compliance check",
      check.evaluatedAt ?? "",
      "",
      "",
      "",
      JSON.stringify({
        trigger: check.trigger,
        counts: check.counts,
        errorMessage:
          check.errorMessage,
      }),
    ]);
  }

  for (const item of report.exceptions) {
    rows.push([
      "exceptions",
      item.resourceId,
      item.kind,
      item.id,
      item.storedStatus,
      item.effectiveStatus,
      "",
      item.kind,
      item.justification,
      item.decidedAt ??
        item.requestedAt,
      "",
      item.validFrom ?? "",
      item.validUntil ?? "",
      JSON.stringify({
        active: item.active,
        approvalAuthority:
          item.approvalAuthority,
      }),
    ]);
  }

  for (const deadline of report.deadlines) {
    rows.push([
      "deadlines",
      deadline.resourceId ?? "",
      "deadline",
      deadline.id,
      deadline.storedStatus,
      deadline.effectiveStatus,
      "",
      deadline.deadlineType,
      `${deadline.subjectType}:${deadline.subjectId}`,
      "",
      deadline.dueAt,
      "",
      "",
      JSON.stringify({
        cycleNumber:
          deadline.cycleNumber,
        escalationLevel:
          deadline.escalationLevel,
        satisfiedAt:
          deadline.satisfiedAt,
      }),
    ]);
  }

  for (const finding of report.findings) {
    rows.push([
      "findings",
      finding.resourceId,
      "finding",
      finding.id,
      finding.status,
      finding.status,
      finding.severity,
      finding.ruleKey ?? "",
      finding.title,
      finding.openedAt,
      "",
      "",
      "",
      JSON.stringify({
        checkId: finding.checkId,
        ruleSetKey:
          finding.ruleSetKey,
        ruleSetVersion:
          finding.ruleSetVersion,
        ownerPrincipalId:
          finding.ownerPrincipalId,
        resolvedAt:
          finding.resolvedAt,
        closedAt:
          finding.closedAt,
        description:
          finding.description,
      }),
    ]);
  }

  for (const remediation of report.remediations) {
    rows.push([
      "remediations",
      remediation.resourceId,
      "remediation",
      remediation.id,
      remediation.status,
      remediation.status,
      "",
      remediation.findingId,
      remediation.plan,
      remediation.startedAt ?? "",
      remediation.dueAt ?? "",
      "",
      "",
      JSON.stringify({
        findingId:
          remediation.findingId,
        deadlineId:
          remediation.deadlineId,
        ownerPrincipalId:
          remediation.ownerPrincipalId,
        completedAt:
          remediation.completedAt,
        verifiedAt:
          remediation.verifiedAt,
      }),
    ]);
  }

  for (const certification of report.certifications) {
    rows.push([
      "certifications",
      certification.resourceId,
      "certification",
      certification.id,
      certification.storedStatus,
      certification.effectiveStatus,
      "",
      certification.certificationType,
      certification.certificateNumber ??
        certification.certificationType,
      certification.issuedAt ?? "",
      "",
      certification.validFrom ?? "",
      certification.validUntil ?? "",
      JSON.stringify({
        valid:
          certification.valid,
        supportingCheckId:
          certification.supportingCheckId,
        suspensionReason:
          certification.suspensionReason,
        revocationReason:
          certification.revocationReason,
      }),
    ]);
  }

  for (const event of report.auditEvents) {
    rows.push([
      "audit",
      "",
      event.aggregateType,
      event.aggregateId,
      "",
      "",
      "",
      event.eventType,
      event.eventType,
      event.occurredAt,
      "",
      "",
      "",
      JSON.stringify({
        eventId: event.id,
        sequenceNumber:
          event.sequenceNumber,
        actorPrincipalId:
          event.actorPrincipalId,
        correlationId:
          event.correlationId,
        payload: event.payload,
        eventHash:
          event.eventHash,
      }),
    ]);
  }

  return [
    header,
    ...rows,
  ]
    .map((row) =>
      row
        .map(csvCell)
        .join(","),
    )
    .join("\n") + "\n";
}

export function renderHumanReadable(
  report: ComplianceReport,
): string {
  const lines: string[] = [];
  const scopeLabel =
    report.resource === null
      ? report.organization.name
      : `${report.organization.name} / ${report.resource.name}`;

  lines.push(
    "# Compliance Report",
    "",
    `**Scope:** ${scopeLabel}`,
    `**As of:** ${report.asOf}`,
    `**Generated:** ${report.generatedAt}`,
    "",
    "## Executive Summary",
    "",
    `- Resources: ${report.summary.resources.total}`,
    `- Checks: ${report.summary.checks.total} (${formatCountMap(report.summary.checks.byStatus)})`,
    `- Active exceptions/waivers: ${report.summary.exceptions.active} of ${report.summary.exceptions.total}`,
    `- Overdue deadlines: ${report.summary.deadlines.overdue} of ${report.summary.deadlines.total}`,
    `- Unresolved findings: ${report.summary.findings.unresolved} of ${report.summary.findings.total}`,
    `- Unresolved high/critical findings: ${report.summary.findings.unresolvedHighCritical}`,
    `- Overdue remediations: ${report.summary.remediations.overdue} of ${report.summary.remediations.total}`,
    `- Valid certifications: ${report.summary.certifications.valid} of ${report.summary.certifications.total}`,
    `- Audit integrity: ${report.summary.audit.allChainsValid ? "valid" : "INVALID"} across ${report.summary.audit.chainCount} chains / ${report.summary.audit.eventCount} events`,
  );

  if (report.checks.length > 0) {
    lines.push(
      "",
      "## Compliance Checks",
      "",
    );
    for (const check of report.checks) {
      lines.push(
        `- **${check.status.toUpperCase()}** — check ${check.id}; resource ${check.resourceId}; ruleset ${check.ruleSetId ?? "n/a"} ${check.ruleSetVersion ?? ""}; evaluated ${check.evaluatedAt ?? "n/a"}`,
      );
    }
  }

  if (report.exceptions.length > 0) {
    lines.push(
      "",
      "## Exceptions and Waivers",
      "",
    );
    for (const item of report.exceptions) {
      lines.push(
        `- **${item.effectiveStatus.toUpperCase()}** — ${item.kind} ${item.id}; resource ${item.resourceId}; valid through ${item.validUntil ?? "n/a"}; ${item.justification}`,
      );
    }
  }

  if (report.deadlines.length > 0) {
    lines.push(
      "",
      "## Deadlines",
      "",
    );
    for (const deadline of report.deadlines) {
      lines.push(
        `- **${deadline.effectiveStatus.toUpperCase()}** — ${deadline.deadlineType}; due ${deadline.dueAt}; subject ${deadline.subjectType}:${deadline.subjectId}; escalation level ${deadline.escalationLevel}`,
      );
    }
  }

  if (report.findings.length > 0) {
    lines.push(
      "",
      "## Findings",
      "",
    );
    for (const finding of report.findings) {
      lines.push(
        `- **${finding.severity.toUpperCase()} / ${finding.status.toUpperCase()}** — ${finding.title} (${finding.ruleKey ?? "unkeyed"}); opened ${finding.openedAt}`,
      );
    }
  }

  if (report.remediations.length > 0) {
    lines.push(
      "",
      "## Remediation",
      "",
    );
    for (const remediation of report.remediations) {
      lines.push(
        `- **${remediation.status.toUpperCase()}** — finding ${remediation.findingId}; due ${remediation.dueAt ?? "n/a"}; ${remediation.plan}`,
      );
    }
  }

  if (report.certifications.length > 0) {
    lines.push(
      "",
      "## Certifications",
      "",
    );
    for (const certification of report.certifications) {
      lines.push(
        `- **${certification.effectiveStatus.toUpperCase()}** — ${certification.certificationType}; certificate ${certification.certificateNumber ?? certification.id}; valid through ${certification.validUntil ?? "n/a"}`,
      );
    }
  }

  lines.push(
    "",
    "## Audit Integrity",
    "",
  );

  if (report.auditChains.length === 0) {
    lines.push(
      "No audit events are in scope.",
    );
  } else {
    for (const chain of report.auditChains) {
      lines.push(
        `- ${chain.valid ? "VALID" : "INVALID"} — ${chain.aggregateType}:${chain.aggregateId}; ${chain.eventCount} events${chain.failureReason ? `; failure ${chain.failureReason} at sequence ${chain.failureSequenceNumber}` : ""}`,
      );
    }
  }

  return lines.join("\n") + "\n";
}

function formatCountMap(
  counts: Record<string, number>,
): string {
  const entries =
    Object.entries(counts);

  if (entries.length === 0) {
    return "none";
  }

  return entries
    .map(
      ([key, value]) =>
        `${key}: ${value}`,
    )
    .join(", ");
}

function csvCell(
  value: string,
): string {
  if (
    value.includes(",") ||
    value.includes('"') ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    return `"${value.replaceAll('"', '""')}"`;
  }

  return value;
}
