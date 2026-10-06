"use client";

import {
  FormEvent,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  api,
  parseJsonObject,
  post,
} from "../lib/api";
import type {
  AuthorizationQueueItem,
  ComplianceReport,
  EvidenceItem,
  Principal,
  ReportCertification,
  ReportDeadline,
  ReportException,
  ReportFinding,
  ReportRemediation,
  ReportResource,
} from "../lib/types";

type Section =
  | "overview"
  | "resources"
  | "rules"
  | "authorizations"
  | "exceptions"
  | "deadlines"
  | "evidence"
  | "findings"
  | "certifications"
  | "audit";

const DEFAULT_RULESET = JSON.stringify(
  {
    schemaVersion: "1",
    id: "admin-console-draft",
    version: "1",
    title: "Admin Console Draft",
    rules: [
      {
        id: "resource-active",
        title: "Resource must be active",
        severity: "high",
        require: {
          field: "resource.status",
          operator: "equals",
          value: "active",
        },
      },
    ],
  },
  null,
  2,
);

const SECTIONS: Array<{
  id: Section;
  label: string;
}> = [
  { id: "overview", label: "Overview" },
  { id: "resources", label: "Resources" },
  { id: "rules", label: "Rules & Checks" },
  {
    id: "authorizations",
    label: "Authorizations",
  },
  { id: "exceptions", label: "Exceptions" },
  { id: "deadlines", label: "Deadlines" },
  { id: "evidence", label: "Evidence" },
  { id: "findings", label: "Findings" },
  {
    id: "certifications",
    label: "Certifications",
  },
  { id: "audit", label: "Audit & Reports" },
];

export function AdminConsole({
  initialOrganizationId,
}: {
  initialOrganizationId: string;
}) {
  const [organizationId, setOrganizationId] =
    useState(initialOrganizationId.trim());
  const [organizationDraft, setOrganizationDraft] =
    useState(initialOrganizationId.trim());
  const [section, setSection] =
    useState<Section>("overview");
  const [report, setReport] =
    useState<ComplianceReport | null>(null);
  const [principals, setPrincipals] = useState<
    Principal[]
  >([]);
  const [
    authorizations,
    setAuthorizations,
  ] = useState<AuthorizationQueueItem[]>([]);
  const [evidence, setEvidence] = useState<
    EvidenceItem[]
  >([]);
  const [actorId, setActorId] = useState("");
  const [
    selectedResourceId,
    setSelectedResourceId,
  ] = useState("");
  const [rulesetText, setRulesetText] =
    useState(DEFAULT_RULESET);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] =
    useState(false);
  const [message, setMessage] = useState<{
    tone: "success" | "error" | "info";
    text: string;
  } | null>(null);
  const [refreshToken, setRefreshToken] =
    useState(0);

  const loadCore = useCallback(async () => {
    if (!organizationId) {
      setReport(null);
      return;
    }

    setLoading(true);
    try {
      const [
        nextReport,
        nextPrincipals,
        nextAuthorizations,
      ] = await Promise.all([
        api<ComplianceReport>(
          `/v1/reports/organizations/${organizationId}/compliance`,
        ),
        api<Principal[]>(
          `/v1/organizations/${organizationId}/principals?status=active`,
        ),
        api<AuthorizationQueueItem[]>(
          `/v1/organizations/${organizationId}/authorizations`,
        ),
      ]);

      setReport(nextReport);
      setPrincipals(nextPrincipals);
      setAuthorizations(nextAuthorizations);

      setActorId((current) => {
        if (
          nextPrincipals.some(
            (principal) =>
              principal.id === current,
          )
        ) {
          return current;
        }

        return (
          nextPrincipals.find(
            (principal) =>
              principal.kind === "user",
          )?.id ??
          nextPrincipals[0]?.id ??
          ""
        );
      });

      setSelectedResourceId((current) => {
        if (
          nextReport.resources.some(
            (resource) =>
              resource.id === current,
          )
        ) {
          return current;
        }

        return (
          nextReport.resources[0]?.id ??
          ""
        );
      });

      setMessage(null);
    } catch (error) {
      setMessage({
        tone: "error",
        text: errorMessage(error),
      });
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    void loadCore();
  }, [loadCore, refreshToken]);

  useEffect(() => {
    if (
      !organizationId ||
      !selectedResourceId
    ) {
      setEvidence([]);
      return;
    }

    let cancelled = false;

    void api<EvidenceItem[]>(
      `/v1/organizations/${organizationId}/resources/${selectedResourceId}/evidence`,
    )
      .then((items) => {
        if (!cancelled) {
          setEvidence(items);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setMessage({
            tone: "error",
            text: errorMessage(error),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    organizationId,
    selectedResourceId,
    refreshToken,
  ]);

  const selectedResource = useMemo(
    () =>
      report?.resources.find(
        (resource) =>
          resource.id ===
          selectedResourceId,
      ) ?? null,
    [report, selectedResourceId],
  );

  const actor = useMemo(
    () =>
      principals.find(
        (principal) =>
          principal.id === actorId,
      ) ?? null,
    [principals, actorId],
  );

  async function mutate(
    label: string,
    action: () => Promise<unknown>,
  ) {
    if (busy) return;

    setBusy(true);
    setMessage({
      tone: "info",
      text: `${label}…`,
    });

    try {
      await action();
      setMessage({
        tone: "success",
        text: `${label} completed.`,
      });
      setRefreshToken(
        (value) => value + 1,
      );
    } catch (error) {
      setMessage({
        tone: "error",
        text: errorMessage(error),
      });
    } finally {
      setBusy(false);
    }
  }

  function requireActor(): string {
    if (!actorId) {
      throw new Error(
        "Select an active operator principal first.",
      );
    }
    return actorId;
  }

  function requireResource(): string {
    if (!selectedResourceId) {
      throw new Error(
        "Select a resource first.",
      );
    }
    return selectedResourceId;
  }

  function openOrganization(
    event: FormEvent,
  ) {
    event.preventDefault();
    const next =
      organizationDraft.trim();

    if (!next) return;

    setOrganizationId(next);
    window.history.replaceState(
      null,
      "",
      `/admin?organizationId=${encodeURIComponent(next)}`,
    );
  }

  const counts = useMemo(
    () => ({
      authorizations:
        authorizations.filter(
          (item) =>
            item.status ===
            "pending",
        ).length,
      exceptions:
        report?.exceptions.filter(
          (item) =>
            item.effectiveStatus ===
            "requested",
        ).length ?? 0,
      deadlines:
        report?.summary.deadlines
          .overdue ?? 0,
      findings:
        report?.summary.findings
          .unresolved ?? 0,
      certifications:
        report?.summary.certifications
          .valid ?? 0,
    }),
    [authorizations, report],
  );

  if (!organizationId) {
    return (
      <main className="landing">
        <form
          className="landing-enter"
          style={{
            width: "min(520px, 100%)",
            borderRadius: 16,
          }}
          onSubmit={openOrganization}
        >
          <h2>Open an organization</h2>
          <p>
            Enter the organization UUID to
            load its compliance workspace.
          </p>
          <input
            className="control"
            value={organizationDraft}
            onChange={(event) =>
              setOrganizationDraft(
                event.target.value,
              )
            }
            placeholder="Organization UUID"
          />
          <button
            className="button"
            type="submit"
          >
            Open console
          </button>
        </form>
      </main>
    );
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            CA
          </div>
          <div className="brand-copy">
            <strong>
              Compliance Administration
            </strong>
            <span>
              Reference operator console
            </span>
          </div>
        </div>

        <div className="nav-group">
          <div className="nav-label">
            Workspace
          </div>
          {SECTIONS.map((item) => (
            <button
              key={item.id}
              type="button"
              className={
                section === item.id
                  ? "nav-button active"
                  : "nav-button"
              }
              onClick={() =>
                setSection(item.id)
              }
            >
              <span>{item.label}</span>
              <span className="nav-count">
                {sectionCount(
                  item.id,
                  counts,
                  report,
                )}
              </span>
            </button>
          ))}
        </div>

        <div className="sidebar-note">
          This is a policy-neutral reference
          interface. Authentication and final
          operator RBAC hardening arrive in PR 16.
          Until then, the selected principal is
          passed explicitly to audited workflow
          endpoints.
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <form onSubmit={openOrganization}>
            <label>Organization</label>
            <input
              className="control mono"
              value={organizationDraft}
              onChange={(event) =>
                setOrganizationDraft(
                  event.target.value,
                )
              }
              aria-label="Organization ID"
            />
          </form>

          <div>
            <label>Acting principal</label>
            <select
              className="select"
              value={actorId}
              onChange={(event) =>
                setActorId(
                  event.target.value,
                )
              }
            >
              <option value="">
                Select operator
              </option>
              {principals.map(
                (principal) => (
                  <option
                    key={principal.id}
                    value={principal.id}
                  >
                    {principal.displayName}
                    {" — "}
                    {principal.kind}
                  </option>
                ),
              )}
            </select>
          </div>

          <button
            className="button secondary"
            type="button"
            onClick={() =>
              setRefreshToken(
                (value) => value + 1,
              )
            }
            disabled={loading}
          >
            {loading
              ? "Refreshing…"
              : "Refresh"}
          </button>
        </header>

        <div className="content">
          {message && (
            <div
              className={
                `notice ${message.tone}`
              }
            >
              {message.text}
            </div>
          )}

          {!report ? (
            <Panel title="Loading workspace">
              <div className="empty">
                {loading
                  ? "Loading compliance state…"
                  : "No report data is available."}
              </div>
            </Panel>
          ) : (
            <>
              <div className="page-heading">
                <div>
                  <h1>
                    {report.organization.name}
                  </h1>
                  <p>
                    {sectionDescription(
                      section,
                    )}
                  </p>
                </div>
                <div className="toolbar">
                  <select
                    className="select"
                    style={{
                      minWidth: 250,
                    }}
                    value={
                      selectedResourceId
                    }
                    onChange={(event) =>
                      setSelectedResourceId(
                        event.target.value,
                      )
                    }
                  >
                    <option value="">
                      All resources
                    </option>
                    {report.resources.map(
                      (resource) => (
                        <option
                          key={
                            resource.id
                          }
                          value={
                            resource.id
                          }
                        >
                          {resource.name}
                          {" — "}
                          {
                            resource.resourceType
                          }
                        </option>
                      ),
                    )}
                  </select>
                </div>
              </div>

              {section === "overview" && (
                <OverviewSection
                  report={report}
                  authorizations={
                    authorizations
                  }
                  selectedResource={
                    selectedResource
                  }
                />
              )}

              {section === "resources" && (
                <ResourcesSection
                  report={report}
                  organizationId={
                    organizationId
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                  setSelectedResourceId={
                    setSelectedResourceId
                  }
                  busy={busy}
                  mutate={mutate}
                />
              )}

              {section === "rules" && (
                <RulesSection
                  report={report}
                  selectedResourceId={
                    selectedResourceId
                  }
                  actorId={actorId}
                  rulesetText={rulesetText}
                  setRulesetText={
                    setRulesetText
                  }
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                  requireResource={
                    requireResource
                  }
                />
              )}

              {section ===
                "authorizations" && (
                <AuthorizationsSection
                  report={report}
                  items={authorizations}
                  actor={actor}
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                  organizationId={
                    organizationId
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                />
              )}

              {section === "exceptions" && (
                <ExceptionsSection
                  report={report}
                  actor={actor}
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                  organizationId={
                    organizationId
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                />
              )}

              {section === "deadlines" && (
                <DeadlinesSection
                  report={report}
                  actor={actor}
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                  organizationId={
                    organizationId
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                />
              )}

              {section === "evidence" && (
                <EvidenceSection
                  items={evidence}
                  selectedResource={
                    selectedResource
                  }
                  organizationId={
                    organizationId
                  }
                  actor={actor}
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                />
              )}

              {section === "findings" && (
                <FindingsSection
                  report={report}
                  actor={actor}
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                />
              )}

              {section ===
                "certifications" && (
                <CertificationsSection
                  report={report}
                  actor={actor}
                  busy={busy}
                  mutate={mutate}
                  requireActor={
                    requireActor
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                  organizationId={
                    organizationId
                  }
                />
              )}

              {section === "audit" && (
                <AuditSection
                  report={report}
                  organizationId={
                    organizationId
                  }
                  selectedResourceId={
                    selectedResourceId
                  }
                />
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function OverviewSection({
  report,
  authorizations,
  selectedResource,
}: {
  report: ComplianceReport;
  authorizations: AuthorizationQueueItem[];
  selectedResource: ReportResource | null;
}) {
  const pendingAuthorizations =
    authorizations.filter(
      (item) =>
        item.status === "pending",
    );
  const materialFindings =
    report.findings.filter(
      (finding) =>
        ![
          "resolved",
          "closed",
        ].includes(finding.status) &&
        [
          "high",
          "critical",
        ].includes(finding.severity),
    );
  const overdueDeadlines =
    report.deadlines.filter(
      (deadline) =>
        deadline.effectiveStatus ===
        "overdue",
    );

  return (
    <>
      <div className="stats">
        <Stat
          label="Resources"
          value={
            report.summary.resources.total
          }
        />
        <Stat
          label="Checks"
          value={report.summary.checks.total}
        />
        <Stat
          label="Pending authorizations"
          value={
            pendingAuthorizations.length
          }
        />
        <Stat
          label="Overdue deadlines"
          value={
            report.summary.deadlines
              .overdue
          }
        />
        <Stat
          label="Open high / critical"
          value={
            report.summary.findings
              .unresolvedHighCritical
          }
        />
        <Stat
          label="Valid certifications"
          value={
            report.summary.certifications
              .valid
          }
        />
      </div>

      <div className="grid">
        <Panel
          title="Attention required"
          className="span-7"
        >
          <div className="split-list">
            {overdueDeadlines
              .slice(0, 4)
              .map((deadline) => (
                <Alert
                  key={deadline.id}
                  title={
                    deadline.deadlineType
                  }
                  detail={`Overdue · due ${formatDate(deadline.dueAt)}`}
                  tone="danger"
                />
              ))}
            {materialFindings
              .slice(0, 4)
              .map((finding) => (
                <Alert
                  key={finding.id}
                  title={finding.title}
                  detail={`${finding.severity} finding · ${finding.status}`}
                  tone={
                    finding.severity ===
                    "critical"
                      ? "danger"
                      : "warn"
                  }
                />
              ))}
            {pendingAuthorizations
              .slice(0, 4)
              .map((authorization) => (
                <Alert
                  key={authorization.id}
                  title={
                    authorization.authorizationType
                  }
                  detail={`Authorization pending · ${authorization.approvalCount}/${authorization.approvalQuorum} approvals`}
                  tone="info"
                />
              ))}
            {overdueDeadlines.length ===
              0 &&
              materialFindings.length ===
                0 &&
              pendingAuthorizations.length ===
                0 && (
                <div className="empty">
                  No urgent workflow items.
                </div>
              )}
          </div>
        </Panel>

        <Panel
          title="Audit integrity"
          className="span-5"
        >
          <div
            style={{
              fontSize: 42,
              fontWeight: 800,
              letterSpacing: "-.04em",
            }}
          >
            {report.summary.audit
              .allChainsValid
              ? "Valid"
              : "Review"}
          </div>
          <p className="subtle">
            {
              report.summary.audit
                .chainCount
            }{" "}
            chains /{" "}
            {
              report.summary.audit
                .eventCount
            }{" "}
            events
          </p>
          <StatusBadge
            value={
              report.summary.audit
                .allChainsValid
                ? "all chains valid"
                : `${report.summary.audit.invalidChainCount} invalid chains`
            }
          />
        </Panel>

        <Panel
          title="Selected resource"
          className="span-12"
        >
          {selectedResource ? (
            <div className="grid">
              <div className="span-4">
                <div className="subtle">
                  Name
                </div>
                <div className="row-title">
                  {
                    selectedResource.name
                  }
                </div>
              </div>
              <div className="span-4">
                <div className="subtle">
                  Type
                </div>
                <div>
                  {
                    selectedResource.resourceType
                  }
                </div>
              </div>
              <div className="span-4">
                <div className="subtle">
                  Status
                </div>
                <StatusBadge
                  value={
                    selectedResource.status
                  }
                />
              </div>
            </div>
          ) : (
            <div className="empty">
              Select a resource from the
              toolbar to focus the workspace.
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

function ResourcesSection({
  report,
  organizationId,
  selectedResourceId,
  setSelectedResourceId,
  busy,
  mutate,
}: {
  report: ComplianceReport;
  organizationId: string;
  selectedResourceId: string;
  setSelectedResourceId: (
    id: string,
  ) => void;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
}) {
  async function createResource(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);

    await mutate(
      "Create resource",
      async () => {
        const created = await post<{
          id: string;
        }>("/v1/resources", {
          organizationId,
          resourceType: value(
            data,
            "resourceType",
          ),
          name: value(data, "name"),
          externalRef:
            optionalValue(
              data,
              "externalRef",
            ),
          attributes:
            parseJsonObject(
              value(
                data,
                "attributes",
                "{}",
              ),
              "Attributes",
            ),
        });

        setSelectedResourceId(
          created.id,
        );
        form.reset();
      },
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Resource inventory"
        className="span-8"
      >
        <Table>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Type</th>
              <th>Status</th>
              <th>External ref</th>
            </tr>
          </thead>
          <tbody>
            {report.resources.map(
              (resource) => (
                <tr
                  key={resource.id}
                  onClick={() =>
                    setSelectedResourceId(
                      resource.id,
                    )
                  }
                  style={{
                    cursor: "pointer",
                    background:
                      resource.id ===
                      selectedResourceId
                        ? "#f5f8ff"
                        : undefined,
                  }}
                >
                  <td>
                    <div className="row-title">
                      {resource.name}
                    </div>
                    <div className="mono subtle">
                      {resource.id}
                    </div>
                  </td>
                  <td>
                    {
                      resource.resourceType
                    }
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        resource.status
                      }
                    />
                  </td>
                  <td>
                    {resource.externalRef ??
                      "—"}
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="Add resource"
        className="span-4"
      >
        <form
          className="form-grid"
          onSubmit={createResource}
        >
          <Field
            label="Name"
            name="name"
            required
          />
          <Field
            label="Resource type"
            name="resourceType"
            required
            placeholder="information-system"
          />
          <Field
            label="External reference"
            name="externalRef"
            className="full"
          />
          <TextField
            label="Attributes JSON"
            name="attributes"
            defaultValue="{}"
            className="full"
          />
          <div className="form-actions">
            <button
              className="button"
              disabled={busy}
            >
              Create resource
            </button>
          </div>
        </form>
      </Panel>
    </div>
  );
}

function RulesSection({
  report,
  selectedResourceId,
  actorId,
  rulesetText,
  setRulesetText,
  busy,
  mutate,
  requireActor,
  requireResource,
}: {
  report: ComplianceReport;
  selectedResourceId: string;
  actorId: string;
  rulesetText: string;
  setRulesetText: (
    value: string,
  ) => void;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
  requireResource: () => string;
}) {
  const checks =
    selectedResourceId
      ? report.checks.filter(
          (check) =>
            check.resourceId ===
            selectedResourceId,
        )
      : report.checks;

  async function runCheck(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    await mutate(
      "Run compliance check",
      async () => {
        const parsed =
          JSON.parse(
            rulesetText,
          ) as Record<
            string,
            unknown
          >;

        await post(
          "/v1/checks/run",
          {
            organizationId:
              report.organization.id,
            resourceId:
              requireResource(),
            requestedByPrincipalId:
              requireActor(),
            ruleSet: parsed,
          },
        );
      },
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Declarative ruleset"
        className="span-5"
      >
        <form onSubmit={runCheck}>
          <div className="notice info">
            Rules remain configuration.
            Edit this JSON and run it
            against the selected resource;
            the engine snapshots the exact
            ruleset and context used.
          </div>
          <textarea
            className="textarea"
            style={{
              minHeight: 410,
            }}
            value={rulesetText}
            onChange={(event) =>
              setRulesetText(
                event.target.value,
              )
            }
          />
          <div
            className="form-actions"
            style={{
              marginTop: 12,
            }}
          >
            <button
              className="button"
              disabled={
                busy ||
                !selectedResourceId ||
                !actorId
              }
            >
              Run check
            </button>
          </div>
        </form>
      </Panel>

      <Panel
        title="Compliance checks"
        className="span-7"
      >
        <Table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Ruleset</th>
              <th>Trigger</th>
              <th>Evaluated</th>
            </tr>
          </thead>
          <tbody>
            {checks.map((check) => (
              <tr key={check.id}>
                <td>
                  <StatusBadge
                    value={check.status}
                  />
                  <div className="mono subtle">
                    {check.id}
                  </div>
                </td>
                <td>
                  {check.ruleSetId ??
                    "snapshot"}
                  {check.ruleSetVersion
                    ? ` · ${check.ruleSetVersion}`
                    : ""}
                </td>
                <td>{check.trigger}</td>
                <td>
                  {formatDate(
                    check.evaluatedAt ??
                      check.completedAt,
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>
    </div>
  );
}

function AuthorizationsSection({
  report,
  items,
  actor,
  busy,
  mutate,
  requireActor,
  organizationId,
  selectedResourceId,
}: {
  report: ComplianceReport;
  items: AuthorizationQueueItem[];
  actor: Principal | null;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
  organizationId: string;
  selectedResourceId: string;
}) {
  const shown =
    selectedResourceId
      ? items.filter(
          (item) =>
            item.resourceId ===
            selectedResourceId,
        )
      : items;

  async function requestAuthorization(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const emergency =
      data.get("emergency") ===
      "on";

    await mutate(
      "Request authorization",
      async () => {
        await post(
          "/v1/authorizations",
          {
            organizationId,
            resourceId: value(
              data,
              "resourceId",
            ),
            authorizationType:
              value(
                data,
                "authorizationType",
              ),
            requestedByPrincipalId:
              requireActor(),
            validUntil:
              isoInput(
                optionalValue(
                  data,
                  "validUntil",
                ),
              ),
            approvalQuorum:
              numberValue(
                data,
                "approvalQuorum",
                1,
              ),
            eligibleApproverPrincipalIds:
              csvValues(
                optionalValue(
                  data,
                  "eligibleApprovers",
                ),
              ),
            emergency,
            emergencyReviewDueAt:
              emergency
                ? isoInput(
                    optionalValue(
                      data,
                      "emergencyReviewDueAt",
                    ),
                  )
                : null,
          },
        );
        form.reset();
      },
    );
  }

  function decide(
    item: AuthorizationQueueItem,
    decision: "approve" | "deny",
  ) {
    const rationale =
      window.prompt(
        `${decision === "approve" ? "Approval" : "Denial"} rationale (optional)`,
        "",
      );

    if (rationale === null) return;

    void mutate(
      `${decision === "approve" ? "Approve" : "Deny"} authorization`,
      () =>
        post(
          `/v1/authorizations/${item.id}/decisions`,
          {
            principalId:
              requireActor(),
            decision,
            rationale,
          },
        ),
    );
  }

  function revoke(
    item: AuthorizationQueueItem,
  ) {
    const reason =
      window.prompt(
        "Revocation reason",
      );
    if (!reason) return;

    void mutate(
      "Revoke authorization",
      () =>
        post(
          `/v1/authorizations/${item.id}/revoke`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Authorization queue"
        className="span-8"
      >
        <Table>
          <thead>
            <tr>
              <th>Authorization</th>
              <th>Status</th>
              <th>Approvals</th>
              <th>Validity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="row-title">
                    {
                      item.authorizationType
                    }
                  </div>
                  <div className="subtle">
                    {
                      resourceName(
                        report,
                        item.resourceId,
                      )
                    }
                    {item.emergency
                      ? " · emergency"
                      : ""}
                  </div>
                  <div className="mono subtle">
                    {item.id}
                  </div>
                </td>
                <td>
                  <StatusBadge
                    value={item.status}
                  />
                </td>
                <td>
                  {item.approvalCount}/
                  {item.approvalQuorum}
                  {item.eligibleApproverCount >
                    0
                    ? ` · ${item.eligibleApproverCount} eligible`
                    : ""}
                </td>
                <td>
                  {formatDate(
                    item.validFrom,
                  )}
                  {" → "}
                  {formatDate(
                    item.validUntil,
                  )}
                </td>
                <td>
                  <div className="actions">
                    {(item.status ===
                      "pending" ||
                      (item.emergency &&
                        item.status ===
                          "approved" &&
                        !item.emergencyReviewedAt)) && (
                      <>
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            decide(
                              item,
                              "approve",
                            )
                          }
                        >
                          Approve
                        </button>
                        <button
                          className="button small danger"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            decide(
                              item,
                              "deny",
                            )
                          }
                        >
                          Deny
                        </button>
                      </>
                    )}
                    {item.status ===
                      "approved" && (
                      <button
                        className="button small secondary"
                        disabled={
                          busy ||
                          !actor
                        }
                        onClick={() =>
                          revoke(item)
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="New authorization"
        className="span-4"
      >
        <form
          className="form-grid"
          onSubmit={
            requestAuthorization
          }
        >
          <SelectField
            label="Resource"
            name="resourceId"
            defaultValue={
              selectedResourceId
            }
            options={report.resources.map(
              (resource) => ({
                value: resource.id,
                label: resource.name,
              }),
            )}
          />
          <Field
            label="Authorization type"
            name="authorizationType"
            placeholder="deployment-approval"
            required
          />
          <Field
            label="Approval quorum"
            name="approvalQuorum"
            type="number"
            defaultValue="1"
            min="1"
          />
          <Field
            label="Valid until"
            name="validUntil"
            type="datetime-local"
          />
          <Field
            label="Eligible approver IDs"
            name="eligibleApprovers"
            className="full"
            placeholder="uuid, uuid"
          />
          <label className="form-field full">
            <span
              style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
              }}
            >
              <input
                type="checkbox"
                name="emergency"
              />
              Emergency authorization
            </span>
          </label>
          <Field
            label="Emergency review due"
            name="emergencyReviewDueAt"
            type="datetime-local"
            className="full"
          />
          <div className="form-actions">
            <button
              className="button"
              disabled={
                busy || !actor
              }
            >
              Request
            </button>
          </div>
        </form>
      </Panel>
    </div>
  );
}

function ExceptionsSection({
  report,
  actor,
  busy,
  mutate,
  requireActor,
  organizationId,
  selectedResourceId,
}: {
  report: ComplianceReport;
  actor: Principal | null;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
  organizationId: string;
  selectedResourceId: string;
}) {
  const items =
    selectedResourceId
      ? report.exceptions.filter(
          (item) =>
            item.resourceId ===
            selectedResourceId,
        )
      : report.exceptions;

  async function requestException(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);

    await mutate(
      "Request exception",
      async () => {
        await post(
          "/v1/exceptions",
          {
            organizationId,
            resourceId: value(
              data,
              "resourceId",
            ),
            kind: value(
              data,
              "kind",
              "exception",
            ),
            requestedByPrincipalId:
              requireActor(),
            justification: value(
              data,
              "justification",
            ),
            validUntil:
              isoInput(
                value(
                  data,
                  "validUntil",
                ),
              ),
            approvalQuorum:
              numberValue(
                data,
                "approvalQuorum",
                1,
              ),
            eligibleApproverPrincipalIds:
              csvValues(
                optionalValue(
                  data,
                  "eligibleApprovers",
                ),
              ),
          },
        );
        form.reset();
      },
    );
  }

  function decide(
    item: ReportException,
    decision: "approve" | "deny",
  ) {
    const rationale =
      window.prompt(
        "Decision rationale (optional)",
        "",
      );
    if (rationale === null) return;

    void mutate(
      `${decision === "approve" ? "Approve" : "Deny"} ${item.kind}`,
      () =>
        post(
          `/v1/exceptions/${item.id}/decisions`,
          {
            principalId:
              requireActor(),
            decision,
            rationale,
          },
        ),
    );
  }

  function revoke(
    item: ReportException,
  ) {
    const reason =
      window.prompt(
        "Revocation reason",
      );
    if (!reason) return;

    void mutate(
      `Revoke ${item.kind}`,
      () =>
        post(
          `/v1/exceptions/${item.id}/revoke`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Exceptions & waivers"
        className="span-8"
      >
        <Table>
          <thead>
            <tr>
              <th>Request</th>
              <th>Status</th>
              <th>Validity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="row-title">
                    {item.kind}
                  </div>
                  <div className="subtle">
                    {
                      resourceName(
                        report,
                        item.resourceId,
                      )
                    }
                  </div>
                  <div className="subtle">
                    {
                      item.justification
                    }
                  </div>
                </td>
                <td>
                  <StatusBadge
                    value={
                      item.effectiveStatus
                    }
                  />
                </td>
                <td>
                  {formatDate(
                    item.validFrom,
                  )}
                  {" → "}
                  {formatDate(
                    item.validUntil,
                  )}
                </td>
                <td>
                  <div className="actions">
                    {item.effectiveStatus ===
                      "requested" && (
                      <>
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            decide(
                              item,
                              "approve",
                            )
                          }
                        >
                          Approve
                        </button>
                        <button
                          className="button small danger"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            decide(
                              item,
                              "deny",
                            )
                          }
                        >
                          Deny
                        </button>
                      </>
                    )}
                    {item.effectiveStatus ===
                      "approved" && (
                      <button
                        className="button small secondary"
                        disabled={
                          busy ||
                          !actor
                        }
                        onClick={() =>
                          revoke(item)
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="New exception / waiver"
        className="span-4"
      >
        <form
          className="form-grid"
          onSubmit={requestException}
        >
          <SelectField
            label="Resource"
            name="resourceId"
            defaultValue={
              selectedResourceId
            }
            options={report.resources.map(
              (resource) => ({
                value: resource.id,
                label: resource.name,
              }),
            )}
          />
          <SelectField
            label="Kind"
            name="kind"
            defaultValue="exception"
            options={[
              {
                value: "exception",
                label: "Exception",
              },
              {
                value: "waiver",
                label: "Waiver",
              },
            ]}
          />
          <Field
            label="Valid until"
            name="validUntil"
            type="datetime-local"
            required
          />
          <Field
            label="Approval quorum"
            name="approvalQuorum"
            type="number"
            min="1"
            defaultValue="1"
          />
          <Field
            label="Eligible approver IDs"
            name="eligibleApprovers"
            className="full"
            placeholder="uuid, uuid"
          />
          <TextField
            label="Justification"
            name="justification"
            className="full"
            required
          />
          <div className="form-actions">
            <button
              className="button"
              disabled={
                busy || !actor
              }
            >
              Submit request
            </button>
          </div>
        </form>
      </Panel>
    </div>
  );
}

function DeadlinesSection({
  report,
  actor,
  busy,
  mutate,
  requireActor,
  organizationId,
  selectedResourceId,
}: {
  report: ComplianceReport;
  actor: Principal | null;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
  organizationId: string;
  selectedResourceId: string;
}) {
  const items =
    selectedResourceId
      ? report.deadlines.filter(
          (item) =>
            item.resourceId ===
              selectedResourceId ||
            item.resourceId === null,
        )
      : report.deadlines;

  async function createDeadline(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);

    await mutate(
      "Create deadline",
      async () => {
        await post(
          "/v1/deadlines",
          {
            organizationId,
            resourceId:
              optionalValue(
                data,
                "resourceId",
              ) || null,
            subjectType: value(
              data,
              "subjectType",
            ),
            subjectId: value(
              data,
              "subjectId",
            ),
            deadlineType: value(
              data,
              "deadlineType",
            ),
            createdByPrincipalId:
              requireActor(),
            dueAt:
              isoInput(
                value(
                  data,
                  "dueAt",
                ),
              ),
            warningWindowSeconds:
              numberValue(
                data,
                "warningWindowSeconds",
                0,
              ),
            gracePeriodSeconds:
              numberValue(
                data,
                "gracePeriodSeconds",
                0,
              ),
          },
        );
        form.reset();
      },
    );
  }

  function satisfy(
    item: ReportDeadline,
  ) {
    void mutate(
      "Satisfy deadline",
      () =>
        post(
          `/v1/deadlines/${item.id}/satisfy`,
          {
            principalId:
              requireActor(),
          },
        ),
    );
  }

  function cancel(
    item: ReportDeadline,
  ) {
    const reason =
      window.prompt(
        "Cancellation reason",
      );
    if (!reason) return;

    void mutate(
      "Cancel deadline",
      () =>
        post(
          `/v1/deadlines/${item.id}/cancel`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Statutory & operational clocks"
        className="span-8"
      >
        <Table>
          <thead>
            <tr>
              <th>Deadline</th>
              <th>Status</th>
              <th>Due</th>
              <th>Escalation</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="row-title">
                    {
                      item.deadlineType
                    }
                  </div>
                  <div className="subtle">
                    {item.subjectType}:
                    {item.subjectId}
                  </div>
                </td>
                <td>
                  <StatusBadge
                    value={
                      item.effectiveStatus
                    }
                  />
                </td>
                <td>
                  {formatDate(
                    item.dueAt,
                  )}
                </td>
                <td>
                  Level{" "}
                  {
                    item.escalationLevel
                  }
                  {" · cycle "}
                  {item.cycleNumber}
                </td>
                <td>
                  <div className="actions">
                    {![
                      "satisfied",
                      "cancelled",
                    ].includes(
                      item.effectiveStatus,
                    ) && (
                      <>
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            satisfy(item)
                          }
                        >
                          Satisfy
                        </button>
                        <button
                          className="button small secondary"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            cancel(item)
                          }
                        >
                          Cancel
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="Create deadline"
        className="span-4"
      >
        <form
          className="form-grid"
          onSubmit={createDeadline}
        >
          <SelectField
            label="Resource"
            name="resourceId"
            defaultValue={
              selectedResourceId
            }
            allowEmpty
            options={report.resources.map(
              (resource) => ({
                value: resource.id,
                label: resource.name,
              }),
            )}
          />
          <Field
            label="Deadline type"
            name="deadlineType"
            required
            placeholder="statutory-response"
          />
          <Field
            label="Subject type"
            name="subjectType"
            required
            defaultValue="resource"
          />
          <Field
            label="Subject ID"
            name="subjectId"
            required
            defaultValue={
              selectedResourceId
            }
          />
          <Field
            label="Due at"
            name="dueAt"
            type="datetime-local"
            required
            className="full"
          />
          <Field
            label="Warning seconds"
            name="warningWindowSeconds"
            type="number"
            min="0"
            defaultValue="0"
          />
          <Field
            label="Grace seconds"
            name="gracePeriodSeconds"
            type="number"
            min="0"
            defaultValue="0"
          />
          <div className="form-actions">
            <button
              className="button"
              disabled={
                busy || !actor
              }
            >
              Create deadline
            </button>
          </div>
        </form>
      </Panel>
    </div>
  );
}

function EvidenceSection({
  items,
  selectedResource,
  organizationId,
  actor,
  busy,
  mutate,
  requireActor,
}: {
  items: EvidenceItem[];
  selectedResource: ReportResource | null;
  organizationId: string;
  actor: Principal | null;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
}) {
  async function createEvidence(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    if (!selectedResource) {
      throw new Error(
        "Select a resource first.",
      );
    }

    const form = event.currentTarget;
    const data = new FormData(form);

    await mutate(
      "Create evidence",
      async () => {
        await post("/v1/evidence", {
          organizationId,
          resourceId:
            selectedResource.id,
          evidenceType: value(
            data,
            "evidenceType",
          ),
          title: value(
            data,
            "title",
          ),
          submittedByPrincipalId:
            requireActor(),
          source:
            optionalValue(
              data,
              "source",
            ),
          uri:
            optionalValue(
              data,
              "uri",
            ),
          checksumAlgorithm:
            optionalValue(
              data,
              "checksumAlgorithm",
            ),
          checksum:
            optionalValue(
              data,
              "checksum",
            ),
          attributes:
            parseJsonObject(
              value(
                data,
                "attributes",
                "{}",
              ),
              "Evidence attributes",
            ),
        });
        form.reset();
      },
    );
  }

  function attest(
    item: EvidenceItem,
  ) {
    const attestationType =
      window.prompt(
        "Attestation type",
        "reviewed",
      );
    if (!attestationType) return;
    const statement =
      window.prompt(
        "Attestation statement",
      );
    if (!statement) return;

    void mutate(
      "Add evidence attestation",
      () =>
        post(
          `/v1/evidence/${item.id}/attestations`,
          {
            principalId:
              requireActor(),
            attestationType,
            statement,
          },
        ),
    );
  }

  function revoke(
    item: EvidenceItem,
  ) {
    const reason =
      window.prompt(
        "Evidence revocation reason",
      );
    if (!reason) return;

    void mutate(
      "Revoke evidence",
      () =>
        post(
          `/v1/evidence/${item.id}/revoke`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  if (!selectedResource) {
    return (
      <Panel title="Evidence">
        <div className="empty">
          Select a resource to manage
          evidence.
        </div>
      </Panel>
    );
  }

  return (
    <div className="grid">
      <Panel
        title={`Evidence · ${selectedResource.name}`}
        className="span-8"
      >
        <Table>
          <thead>
            <tr>
              <th>Evidence</th>
              <th>Type</th>
              <th>Status</th>
              <th>Validity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="row-title">
                    {item.title}
                  </div>
                  <div className="subtle">
                    {item.source ??
                      item.uri ??
                      "No external source"}
                  </div>
                </td>
                <td>
                  {item.evidenceType}
                </td>
                <td>
                  <StatusBadge
                    value={item.status}
                  />
                </td>
                <td>
                  {formatDate(
                    item.validFrom,
                  )}
                  {" → "}
                  {formatDate(
                    item.validUntil,
                  )}
                </td>
                <td>
                  <div className="actions">
                    {item.status ===
                      "active" && (
                      <>
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            attest(item)
                          }
                        >
                          Attest
                        </button>
                        <button
                          className="button small secondary"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            revoke(item)
                          }
                        >
                          Revoke
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="Add evidence"
        className="span-4"
      >
        <form
          className="form-grid"
          onSubmit={createEvidence}
        >
          <Field
            label="Evidence type"
            name="evidenceType"
            required
            placeholder="configuration-export"
          />
          <Field
            label="Title"
            name="title"
            required
          />
          <Field
            label="Source"
            name="source"
            className="full"
          />
          <Field
            label="URI"
            name="uri"
            className="full"
          />
          <Field
            label="Checksum algorithm"
            name="checksumAlgorithm"
            placeholder="sha256"
          />
          <Field
            label="Checksum"
            name="checksum"
          />
          <TextField
            label="Attributes JSON"
            name="attributes"
            defaultValue="{}"
            className="full"
          />
          <div className="form-actions">
            <button
              className="button"
              disabled={
                busy || !actor
              }
            >
              Add evidence
            </button>
          </div>
        </form>
      </Panel>
    </div>
  );
}

function FindingsSection({
  report,
  actor,
  busy,
  mutate,
  requireActor,
  selectedResourceId,
}: {
  report: ComplianceReport;
  actor: Principal | null;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
  selectedResourceId: string;
}) {
  const findings =
    selectedResourceId
      ? report.findings.filter(
          (item) =>
            item.resourceId ===
            selectedResourceId,
        )
      : report.findings;
  const findingIds =
    new Set(
      findings.map(
        (finding) => finding.id,
      ),
    );
  const remediations =
    report.remediations.filter(
      (item) =>
        findingIds.has(
          item.findingId,
        ),
    );

  function action(
    finding: ReportFinding,
    kind:
      | "acknowledge"
      | "reopen"
      | "close",
  ) {
    void mutate(
      `${kind} finding`,
      () =>
        post(
          `/v1/findings/${finding.id}/${kind}`,
          {
            principalId:
              requireActor(),
          },
        ),
    );
  }

  function dispute(
    finding: ReportFinding,
  ) {
    const reason =
      window.prompt(
        "Dispute reason",
      );
    if (!reason) return;

    void mutate(
      "Dispute finding",
      () =>
        post(
          `/v1/findings/${finding.id}/dispute`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  function resolveDispute(
    finding: ReportFinding,
    outcome: "uphold" | "dismiss",
  ) {
    const rationale =
      window.prompt(
        "Resolution rationale",
      );
    if (!rationale) return;

    void mutate(
      "Resolve finding dispute",
      () =>
        post(
          `/v1/findings/${finding.id}/resolve-dispute`,
          {
            principalId:
              requireActor(),
            outcome,
            rationale,
          },
        ),
    );
  }

  function createRemediation(
    finding: ReportFinding,
  ) {
    const plan =
      window.prompt(
        "Remediation plan",
      );
    if (!plan) return;

    const due =
      window.prompt(
        "Due date/time (ISO, optional)",
        "",
      );

    void mutate(
      "Create remediation",
      () =>
        post(
          `/v1/findings/${finding.id}/remediations`,
          {
            createdByPrincipalId:
              requireActor(),
            ownerPrincipalId:
              requireActor(),
            plan,
            dueAt:
              due?.trim()
                ? new Date(
                    due,
                  ).toISOString()
                : null,
          },
        ),
    );
  }

  function remediationAction(
    remediation: ReportRemediation,
    kind:
      | "start"
      | "submit"
      | "verify"
      | "reject"
      | "cancel",
  ) {
    let body:
      Record<string, unknown> = {
        principalId:
          requireActor(),
      };

    if (
      kind === "reject" ||
      kind === "cancel"
    ) {
      const reason =
        window.prompt(
          `${kind} reason`,
        );
      if (!reason) return;
      body = {
        ...body,
        reason,
      };
    }

    if (kind === "verify") {
      const note =
        window.prompt(
          "Verification note (optional)",
          "",
        );
      if (note === null) return;
      body = {
        ...body,
        note,
      };
    }

    void mutate(
      `${kind} remediation`,
      () =>
        post(
          `/v1/remediations/${remediation.id}/${kind}`,
          body,
        ),
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Findings"
        className="span-12"
      >
        <Table>
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Opened</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {findings.map(
              (finding) => (
                <tr key={finding.id}>
                  <td>
                    <div className="row-title">
                      {
                        finding.title
                      }
                    </div>
                    <div className="subtle">
                      {
                        finding.description
                      }
                    </div>
                    <div className="mono subtle">
                      {
                        finding.ruleKey ??
                        finding.id
                      }
                    </div>
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        finding.severity
                      }
                    />
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        finding.status
                      }
                    />
                  </td>
                  <td>
                    {formatDate(
                      finding.openedAt,
                    )}
                  </td>
                  <td>
                    <div className="actions">
                      {finding.status ===
                        "open" && (
                        <>
                          <button
                            className="button small"
                            disabled={
                              busy ||
                              !actor
                            }
                            onClick={() =>
                              action(
                                finding,
                                "acknowledge",
                              )
                            }
                          >
                            Acknowledge
                          </button>
                          <button
                            className="button small secondary"
                            disabled={
                              busy ||
                              !actor
                            }
                            onClick={() =>
                              dispute(
                                finding,
                              )
                            }
                          >
                            Dispute
                          </button>
                        </>
                      )}
                      {[
                        "open",
                        "acknowledged",
                        "remediating",
                      ].includes(
                        finding.status,
                      ) && (
                        <button
                          className="button small secondary"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            createRemediation(
                              finding,
                            )
                          }
                        >
                          Remediate
                        </button>
                      )}
                      {finding.status ===
                        "disputed" && (
                        <>
                          <button
                            className="button small"
                            disabled={
                              busy ||
                              !actor
                            }
                            onClick={() =>
                              resolveDispute(
                                finding,
                                "uphold",
                              )
                            }
                          >
                            Uphold
                          </button>
                          <button
                            className="button small secondary"
                            disabled={
                              busy ||
                              !actor
                            }
                            onClick={() =>
                              resolveDispute(
                                finding,
                                "dismiss",
                              )
                            }
                          >
                            Dismiss
                          </button>
                        </>
                      )}
                      {finding.status ===
                        "resolved" && (
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            action(
                              finding,
                              "close",
                            )
                          }
                        >
                          Close
                        </button>
                      )}
                      {[
                        "resolved",
                        "closed",
                      ].includes(
                        finding.status,
                      ) && (
                        <button
                          className="button small secondary"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            action(
                              finding,
                              "reopen",
                            )
                          }
                        >
                          Reopen
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="Remediation"
        className="span-12"
      >
        <Table>
          <thead>
            <tr>
              <th>Plan</th>
              <th>Status</th>
              <th>Due</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {remediations.map(
              (item) => (
                <tr key={item.id}>
                  <td>
                    <div className="row-title">
                      {item.plan}
                    </div>
                    <div className="mono subtle">
                      {item.id}
                    </div>
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        item.status
                      }
                    />
                  </td>
                  <td>
                    {formatDate(
                      item.dueAt,
                    )}
                  </td>
                  <td>
                    <div className="actions">
                      {item.status ===
                        "planned" && (
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            remediationAction(
                              item,
                              "start",
                            )
                          }
                        >
                          Start
                        </button>
                      )}
                      {item.status ===
                        "in_progress" && (
                        <button
                          className="button small"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            remediationAction(
                              item,
                              "submit",
                            )
                          }
                        >
                          Submit
                        </button>
                      )}
                      {item.status ===
                        "ready_for_verification" && (
                        <>
                          <button
                            className="button small"
                            disabled={
                              busy ||
                              !actor
                            }
                            onClick={() =>
                              remediationAction(
                                item,
                                "verify",
                              )
                            }
                          >
                            Verify
                          </button>
                          <button
                            className="button small danger"
                            disabled={
                              busy ||
                              !actor
                            }
                            onClick={() =>
                              remediationAction(
                                item,
                                "reject",
                              )
                            }
                          >
                            Reject
                          </button>
                        </>
                      )}
                      {[
                        "planned",
                        "in_progress",
                        "ready_for_verification",
                      ].includes(
                        item.status,
                      ) && (
                        <button
                          className="button small secondary"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            remediationAction(
                              item,
                              "cancel",
                            )
                          }
                        >
                          Cancel
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </Table>
      </Panel>
    </div>
  );
}

function CertificationsSection({
  report,
  actor,
  busy,
  mutate,
  requireActor,
  selectedResourceId,
  organizationId,
}: {
  report: ComplianceReport;
  actor: Principal | null;
  busy: boolean;
  mutate: (
    label: string,
    action: () => Promise<unknown>,
  ) => Promise<void>;
  requireActor: () => string;
  selectedResourceId: string;
  organizationId: string;
}) {
  const items =
    selectedResourceId
      ? report.certifications.filter(
          (item) =>
            item.resourceId ===
            selectedResourceId,
        )
      : report.certifications;
  const passedChecks =
    report.checks.filter(
      (check) =>
        check.status === "passed" &&
        (!selectedResourceId ||
          check.resourceId ===
            selectedResourceId),
    );

  async function issue(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);

    await mutate(
      "Issue certification",
      async () => {
        await post(
          "/v1/certifications",
          {
            organizationId,
            resourceId: value(
              data,
              "resourceId",
            ),
            certificationType:
              value(
                data,
                "certificationType",
              ),
            supportingCheckId:
              value(
                data,
                "supportingCheckId",
              ),
            issuedByPrincipalId:
              requireActor(),
            validitySeconds:
              numberValue(
                data,
                "validityDays",
                30,
              ) * 86_400,
            criteria:
              parseJsonObject(
                value(
                  data,
                  "criteria",
                  "{}",
                ),
                "Certification criteria",
              ),
          },
        );
        form.reset();
      },
    );
  }

  function suspend(
    item: ReportCertification,
  ) {
    const reason =
      window.prompt(
        "Suspension reason",
      );
    if (!reason) return;

    void mutate(
      "Suspend certification",
      () =>
        post(
          `/v1/certifications/${item.id}/suspend`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  function reinstate(
    item: ReportCertification,
  ) {
    const checkId =
      window.prompt(
        "Passed supporting check ID",
      );
    if (!checkId) return;

    const rationale =
      window.prompt(
        "Reinstatement rationale",
      );
    if (!rationale) return;

    void mutate(
      "Reinstate certification",
      () =>
        post(
          `/v1/certifications/${item.id}/reinstate`,
          {
            principalId:
              requireActor(),
            supportingCheckId:
              checkId,
            rationale,
          },
        ),
    );
  }

  function revoke(
    item: ReportCertification,
  ) {
    const reason =
      window.prompt(
        "Revocation reason",
      );
    if (!reason) return;

    void mutate(
      "Revoke certification",
      () =>
        post(
          `/v1/certifications/${item.id}/revoke`,
          {
            principalId:
              requireActor(),
            reason,
          },
        ),
    );
  }

  function renew(
    item: ReportCertification,
  ) {
    const checkId =
      window.prompt(
        "Passed supporting check ID",
        item.supportingCheckId ??
          "",
      );
    if (!checkId) return;

    const days =
      window.prompt(
        "Validity days",
        "30",
      );
    if (!days) return;

    void mutate(
      "Renew certification",
      () =>
        post(
          `/v1/certifications/${item.id}/renew`,
          {
            supportingCheckId:
              checkId,
            issuedByPrincipalId:
              requireActor(),
            validitySeconds:
              Number(days) *
              86_400,
          },
        ),
    );
  }

  return (
    <div className="grid">
      <Panel
        title="Certifications"
        className="span-8"
      >
        <Table>
          <thead>
            <tr>
              <th>Certificate</th>
              <th>Status</th>
              <th>Validity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="row-title">
                    {
                      item.certificationType
                    }
                  </div>
                  <div className="mono subtle">
                    {
                      item.certificateNumber ??
                      item.id
                    }
                  </div>
                </td>
                <td>
                  <StatusBadge
                    value={
                      item.effectiveStatus
                    }
                  />
                </td>
                <td>
                  {formatDate(
                    item.validFrom,
                  )}
                  {" → "}
                  {formatDate(
                    item.validUntil,
                  )}
                </td>
                <td>
                  <div className="actions">
                    {item.effectiveStatus ===
                      "active" && (
                      <button
                        className="button small secondary"
                        disabled={
                          busy ||
                          !actor
                        }
                        onClick={() =>
                          suspend(item)
                        }
                      >
                        Suspend
                      </button>
                    )}
                    {item.effectiveStatus ===
                      "suspended" && (
                      <button
                        className="button small"
                        disabled={
                          busy ||
                          !actor
                        }
                        onClick={() =>
                          reinstate(
                            item,
                          )
                        }
                      >
                        Reinstate
                      </button>
                    )}
                    {![
                      "revoked",
                      "superseded",
                    ].includes(
                      item.effectiveStatus,
                    ) && (
                      <>
                        <button
                          className="button small secondary"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            renew(item)
                          }
                        >
                          Renew
                        </button>
                        <button
                          className="button small danger"
                          disabled={
                            busy ||
                            !actor
                          }
                          onClick={() =>
                            revoke(item)
                          }
                        >
                          Revoke
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>

      <Panel
        title="Issue certification"
        className="span-4"
      >
        <form
          className="form-grid"
          onSubmit={issue}
        >
          <SelectField
            label="Resource"
            name="resourceId"
            defaultValue={
              selectedResourceId
            }
            options={report.resources.map(
              (resource) => ({
                value: resource.id,
                label: resource.name,
              }),
            )}
          />
          <Field
            label="Certification type"
            name="certificationType"
            required
            placeholder="baseline-compliance"
          />
          <SelectField
            label="Supporting passed check"
            name="supportingCheckId"
            className="full"
            options={passedChecks.map(
              (check) => ({
                value: check.id,
                label: `${check.ruleSetId ?? "ruleset"} · ${formatDate(check.evaluatedAt)}`,
              }),
            )}
          />
          <Field
            label="Validity days"
            name="validityDays"
            type="number"
            min="1"
            defaultValue="30"
          />
          <TextField
            label="Criteria JSON"
            name="criteria"
            defaultValue="{}"
            className="full"
          />
          <div className="form-actions">
            <button
              className="button"
              disabled={
                busy ||
                !actor ||
                passedChecks.length ===
                  0
              }
            >
              Issue certificate
            </button>
          </div>
        </form>
      </Panel>
    </div>
  );
}

function AuditSection({
  report,
  organizationId,
  selectedResourceId,
}: {
  report: ComplianceReport;
  organizationId: string;
  selectedResourceId: string;
}) {
  const base =
    selectedResourceId
      ? `/engine-api/v1/reports/organizations/${organizationId}/resources/${selectedResourceId}/compliance`
      : `/engine-api/v1/reports/organizations/${organizationId}/compliance`;

  return (
    <div className="grid">
      <Panel
        title="Report exports"
        className="span-4"
      >
        <p className="subtle">
          Export the same canonical
          compliance report as structured
          JSON, normalized CSV, or
          human-readable Markdown.
        </p>
        <div className="report-links">
          <a
            className="button"
            href={`${base}?format=json`}
            target="_blank"
          >
            JSON
          </a>
          <a
            className="button secondary"
            href={`${base}?format=csv`}
            target="_blank"
          >
            CSV
          </a>
          <a
            className="button secondary"
            href={`${base}?format=text`}
            target="_blank"
          >
            Markdown
          </a>
        </div>
      </Panel>

      <Panel
        title="Audit summary"
        className="span-8"
      >
        <div className="stats">
          <Stat
            label="Events"
            value={
              report.summary.audit
                .eventCount
            }
          />
          <Stat
            label="Chains"
            value={
              report.summary.audit
                .chainCount
            }
          />
          <Stat
            label="Invalid"
            value={
              report.summary.audit
                .invalidChainCount
            }
          />
        </div>
      </Panel>

      <Panel
        title="Tamper-evident chains"
        className="span-12"
      >
        <Table>
          <thead>
            <tr>
              <th>Aggregate</th>
              <th>Events</th>
              <th>Integrity</th>
              <th>Failure</th>
            </tr>
          </thead>
          <tbody>
            {report.auditChains.map(
              (chain) => (
                <tr
                  key={`${chain.aggregateType}:${chain.aggregateId}`}
                >
                  <td>
                    <div className="row-title">
                      {
                        chain.aggregateType
                      }
                    </div>
                    <div className="mono subtle">
                      {
                        chain.aggregateId
                      }
                    </div>
                  </td>
                  <td>
                    {chain.eventCount}
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        chain.valid
                          ? "valid"
                          : "invalid"
                      }
                    />
                  </td>
                  <td>
                    {chain.failureReason ??
                      "—"}
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </Table>
      </Panel>
    </div>
  );
}

function Panel({
  title,
  className = "span-12",
  children,
}: {
  title: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      className={`panel ${className}`}
    >
      <div className="panel-head">
        <h2>{title}</h2>
      </div>
      <div className="panel-body">
        {children}
      </div>
    </section>
  );
}

function Table({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <div className="table-wrap">
      <table>{children}</table>
    </div>
  );
}

function Stat({
  value,
  label,
}: {
  value: number | string;
  label: string;
}) {
  return (
    <div className="stat">
      <div className="value">
        {value}
      </div>
      <div className="label">
        {label}
      </div>
    </div>
  );
}

function StatusBadge({
  value,
}: {
  value: string;
}) {
  return (
    <span
      className={`badge ${tone(value)}`}
    >
      {value.replaceAll("_", " ")}
    </span>
  );
}

function Alert({
  title,
  detail,
  tone: alertTone,
}: {
  title: string;
  detail: string;
  tone: "danger" | "warn" | "info";
}) {
  return (
    <div className="alert-row">
      <div>
        <strong>{title}</strong>
        <div className="subtle">
          {detail}
        </div>
      </div>
      <span
        className={`badge ${alertTone}`}
      >
        attention
      </span>
    </div>
  );
}

function Field({
  label,
  name,
  className,
  ...props
}: {
  label: string;
  name: string;
  className?: string;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div
      className={`form-field ${className ?? ""}`}
    >
      <label htmlFor={name}>
        {label}
      </label>
      <input
        id={name}
        name={name}
        className="control"
        {...props}
      />
    </div>
  );
}

function TextField({
  label,
  name,
  className,
  ...props
}: {
  label: string;
  name: string;
  className?: string;
} & React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <div
      className={`form-field ${className ?? ""}`}
    >
      <label htmlFor={name}>
        {label}
      </label>
      <textarea
        id={name}
        name={name}
        className="textarea"
        {...props}
      />
    </div>
  );
}

function SelectField({
  label,
  name,
  options,
  className,
  allowEmpty = false,
  ...props
}: {
  label: string;
  name: string;
  options: Array<{
    value: string;
    label: string;
  }>;
  className?: string;
  allowEmpty?: boolean;
} & React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div
      className={`form-field ${className ?? ""}`}
    >
      <label htmlFor={name}>
        {label}
      </label>
      <select
        id={name}
        name={name}
        className="select"
        {...props}
      >
        {allowEmpty && (
          <option value="">
            None
          </option>
        )}
        {options.map((option) => (
          <option
            key={option.value}
            value={option.value}
          >
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function resourceName(
  report: ComplianceReport,
  resourceId: string,
): string {
  return (
    report.resources.find(
      (resource) =>
        resource.id === resourceId,
    )?.name ?? resourceId
  );
}

function sectionCount(
  section: Section,
  counts: {
    authorizations: number;
    exceptions: number;
    deadlines: number;
    findings: number;
    certifications: number;
  },
  report: ComplianceReport | null,
): string | number {
  switch (section) {
    case "resources":
      return (
        report?.resources.length ?? 0
      );
    case "rules":
      return report?.checks.length ?? 0;
    case "authorizations":
      return counts.authorizations;
    case "exceptions":
      return counts.exceptions;
    case "deadlines":
      return counts.deadlines;
    case "evidence":
      return "•";
    case "findings":
      return counts.findings;
    case "certifications":
      return counts.certifications;
    case "audit":
      return (
        report?.summary.audit
          .eventCount ?? 0
      );
    default:
      return "—";
  }
}

function sectionDescription(
  section: Section,
): string {
  switch (section) {
    case "overview":
      return "A live operating picture of compliance posture, urgent queues, certifications, and audit integrity.";
    case "resources":
      return "Register and select the domain-neutral resources that compliance rules, evidence, authorizations, and findings attach to.";
    case "rules":
      return "Run declarative rules against authoritative resource state and evidence, with exact ruleset snapshots retained for review.";
    case "authorizations":
      return "Request, review, approve, deny, and revoke scoped authorizations, including quorum and emergency-review workflows.";
    case "exceptions":
      return "Administer time-bound exceptions and waivers without changing the underlying compliance rules.";
    case "deadlines":
      return "Create and resolve statutory or operational clocks with warning, grace, recurrence, and escalation semantics.";
    case "evidence":
      return "Attach researchable evidence and attestations to the selected resource for later compliance evaluation.";
    case "findings":
      return "Move failed rules through acknowledgement, dispute, remediation, verification, closure, and reopening.";
    case "certifications":
      return "Issue check-backed credentials, then suspend, reinstate, renew, revoke, and verify their lifecycle.";
    case "audit":
      return "Inspect tamper-evident aggregate chains and export the canonical compliance report for external review.";
  }
}

function tone(value: string): string {
  const normalized =
    value.toLowerCase();

  if (
    [
      "active",
      "approved",
      "passed",
      "satisfied",
      "verified",
      "resolved",
      "closed",
      "valid",
      "all chains valid",
    ].includes(normalized)
  ) {
    return "success";
  }

  if (
    [
      "failed",
      "critical",
      "overdue",
      "revoked",
      "denied",
      "rejected",
      "invalid",
      "error",
    ].includes(normalized)
  ) {
    return "danger";
  }

  if (
    [
      "warning",
      "high",
      "open",
      "disputed",
      "suspended",
      "due",
    ].includes(normalized)
  ) {
    return "warn";
  }

  return "info";
}

function formatDate(
  value: string | null,
): string {
  if (!value) return "—";

  const date = new Date(value);
  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value;
  }

  return date.toLocaleString();
}

function errorMessage(
  error: unknown,
): string {
  return error instanceof Error
    ? error.message
    : "Unexpected error";
}

function value(
  data: FormData,
  key: string,
  fallback = "",
): string {
  const raw = data.get(key);
  if (
    typeof raw !== "string"
  ) {
    return fallback;
  }

  const trimmed = raw.trim();
  return trimmed || fallback;
}

function optionalValue(
  data: FormData,
  key: string,
): string | null {
  const raw = value(
    data,
    key,
  );
  return raw || null;
}

function numberValue(
  data: FormData,
  key: string,
  fallback: number,
): number {
  const raw =
    optionalValue(
      data,
      key,
    );

  if (raw === null) {
    return fallback;
  }

  const parsed = Number(raw);

  if (
    !Number.isFinite(parsed)
  ) {
    throw new Error(
      `${key} must be a number`,
    );
  }

  return parsed;
}

function csvValues(
  raw: string | null,
): string[] {
  if (!raw) return [];

  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function isoInput(
  raw: string | null,
): string | null {
  if (!raw) return null;

  const date = new Date(raw);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    throw new Error(
      "Date/time value is invalid.",
    );
  }

  return date.toISOString();
}
