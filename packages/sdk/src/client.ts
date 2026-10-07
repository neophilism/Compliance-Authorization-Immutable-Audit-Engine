import type {
  AssignFindingOwnerInput,
  AuthorizationEffectiveness,
  AuthorizationRecord,
  CancelDeadlineInput,
  CancelRemediationInput,
  Certification,
  AddEvidenceAttestationInput,
  CertificationActionInput,
  CertificationView,
  ComplianceReport,
  CreateDeadlineInput,
  CreateEvidenceInput,
  CreateRemediationInput,
  Deadline,
  DeadlineStatusSnapshot,
  DeadlineView,
  DisputeFindingInput,
  EngineHealth,
  Evidence,
  EvidenceTypesResult,
  EvidenceView,
  ExceptionEffectiveness,
  ExceptionRecordView,
  Finding,
  FindingActionInput,
  FindingListFilter,
  FindingView,
  IssueCertificationInput,
  Paginated,
  RecordAuthorizationDecisionInput,
  RecordExceptionDecisionInput,
  RegisteredRuleSetSummary,
  RegistryComplianceProjection,
  RequestAuthorizationInput,
  RequestExceptionInput,
  RevokeAuthorizationInput,
  RevokeExceptionInput,
  RevokeEvidenceAttestationInput,
  RevokeEvidenceInput,
  RejectRemediationInput,
  ReinstateCertificationInput,
  RemediationActionInput,
  RenewCertificationInput,
  ResolveDisputeInput,
  Resource,
  ResourceListOptions,
  RenderedComplianceFormat,
  RenderedComplianceReport,
  RunCheckInput,
  RunCheckResult,
  SdkClientOptions,
  SdkRequestOptions,
  SdkResponse,
  SatisfyDeadlineInput,
  SyncFindingsResult,
  UpdateResourceInput,
  VerifyRemediationInput,
} from "./types.js";
import { SdkError } from "./types.js";

export class ComplianceEngineClient {
  private readonly baseUrl: string;
  private readonly organizationId?: string;
  private readonly auth:
    SdkClientOptions["auth"];
  private readonly timeoutMs: number;
  private readonly fetchImpl:
    typeof fetch;
  private readonly defaultHeaders:
    Record<string, string>;

  constructor(
    options: SdkClientOptions,
  ) {
    this.baseUrl =
      normalizeBaseUrl(
        options.baseUrl,
      );
    this.organizationId =
      options.organizationId;
    this.auth =
      options.auth ?? {
        mode: "public",
      };
    this.timeoutMs =
      options.requestTimeoutMs ??
      30000;
    this.fetchImpl =
      options.transport
        ?.fetchImpl ??
      globalThis.fetch;
    this.defaultHeaders = {
      "content-type":
        "application/json",
      ...(
        options.transport
          ?.defaultHeaders ??
        {}
      ),
    };

    if (!this.fetchImpl) {
      throw new Error(
        "fetch implementation is required",
      );
    }

    validateAuth(this.auth);
  }

  async request<T>(
    path: string,
    options:
      SdkRequestOptions = {},
  ): Promise<SdkResponse<T>> {
    const url =
      buildUrl(
        this.baseUrl,
        path,
        options.query,
      );
    const controller =
      new AbortController();
    const timeout =
      setTimeout(
        () =>
          controller.abort(),
        this.timeoutMs,
      );
    const signal =
      options.signal ??
      controller.signal;

    try {
      const response =
        await this.fetchImpl(
          url,
          {
            method:
              options.method ??
              "GET",
            headers:
              this.headersFor(
                options,
              ),
            body:
              options.body ===
              undefined
                ? undefined
                : JSON.stringify(
                    options.body,
                  ),
            signal,
          },
        );

      const data =
        await decodeResponse(
          response,
        );

      if (!response.ok) {
        throw toSdkError(
          response,
          data,
        );
      }

      return {
        status:
          response.status,
        headers:
          response.headers,
        data:
          data as T,
      };
    } catch (error) {
      if (
        error instanceof
        SdkError
      ) {
        throw error;
      }
      if (
        error instanceof
          DOMException &&
        error.name ===
          "AbortError"
      ) {
        throw new SdkError(
          0,
          "timeout",
          "request timed out",
          null,
        );
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  async getHealth(): Promise<EngineHealth> {
    return (
      await this.request<
        EngineHealth
      >("/health")
    ).data;
  }

  async getOrganization(
    id =
      this.requireOrganizationId(),
  ) {
    return (
      await this.request<
        Record<string, unknown>
      >(
        `/v1/organizations/${encodeURIComponent(id)}`,
      )
    ).data;
  }

  async listResources(
    options:
      ResourceListOptions = {},
  ): Promise<Resource[]> {
    const organizationId =
      this.requireOrganizationId();
    return (
      await this.request<
        Resource[]
      >(
        `/v1/organizations/${organizationId}/resources`,
        {
          query: {
            resourceType:
              options.resourceType ??
              undefined,
          },
        },
      )
    ).data;
  }

  async createResource(
    input: {
      resourceType: string;
      name: string;
      externalRef?: string | null;
      status?: Resource["status"];
      attributes?: Record<string, unknown>;
      metadata?: Record<string, unknown>;
    },
  ): Promise<Resource> {
    return (
      await this.request<Resource>(
        "/v1/resources",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async getResource(
    resourceId: string,
  ): Promise<Resource> {
    return (
      await this.request<Resource>(
        `/v1/resources/${encodeURIComponent(resourceId)}`,
      )
    ).data;
  }

  async updateResource(
    resourceId: string,
    input: UpdateResourceInput,
  ): Promise<Resource> {
    return (
      await this.request<Resource>(
        `/v1/resources/${encodeURIComponent(resourceId)}`,
        {
          method: "PATCH",
          body: input,
        },
      )
    ).data;
  }

  async createEvidence(
    input: CreateEvidenceInput,
  ): Promise<EvidenceView> {
    return (
      await this.request<
        EvidenceView
      >(
        "/v1/evidence",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async getEvidence(
    evidenceId: string,
  ): Promise<EvidenceView> {
    return (
      await this.request<
        EvidenceView
      >(
        `/v1/evidence/${encodeURIComponent(evidenceId)}`,
      )
    ).data;
  }

  async listEvidenceForResource(
    resourceId: string,
  ): Promise<Evidence[]> {
    const organizationId =
      this.requireOrganizationId();

    return (
      await this.request<
        Evidence[]
      >(
        `/v1/organizations/${organizationId}/resources/${encodeURIComponent(resourceId)}/evidence`,
      )
    ).data;
  }

  async listValidEvidenceTypesForResource(
    resourceId: string,
    at?: string,
  ): Promise<string[]> {
    const organizationId =
      this.requireOrganizationId();
    const result =
      (
        await this.request<
          EvidenceTypesResult
        >(
          `/v1/organizations/${organizationId}/resources/${encodeURIComponent(resourceId)}/evidence-types`,
          {
            query: {
              at,
            },
          },
        )
      ).data;

    return result.evidenceTypes;
  }

  async addEvidenceAttestation(
    evidenceId: string,
    input: AddEvidenceAttestationInput,
  ): Promise<EvidenceView> {
    return (
      await this.request<
        EvidenceView
      >(
        `/v1/evidence/${encodeURIComponent(evidenceId)}/attestations`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async revokeEvidence(
    evidenceId: string,
    input: RevokeEvidenceInput,
  ): Promise<EvidenceView> {
    return (
      await this.request<
        EvidenceView
      >(
        `/v1/evidence/${encodeURIComponent(evidenceId)}/revoke`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async revokeEvidenceAttestation(
    attestationId: string,
    input: RevokeEvidenceAttestationInput,
  ): Promise<EvidenceView> {
    return (
      await this.request<
        EvidenceView
      >(
        `/v1/evidence-attestations/${encodeURIComponent(attestationId)}/revoke`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async requestAuthorization(
    input: RequestAuthorizationInput,
  ): Promise<AuthorizationRecord> {
    return (
      await this.request<
        AuthorizationRecord
      >(
        "/v1/authorizations",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async getAuthorization(
    authorizationId: string,
  ): Promise<AuthorizationRecord> {
    return (
      await this.request<
        AuthorizationRecord
      >(
        `/v1/authorizations/${encodeURIComponent(authorizationId)}`,
      )
    ).data;
  }

  async getAuthorizationEffectiveness(
    authorizationId: string,
    at?: string,
  ): Promise<AuthorizationEffectiveness> {
    return (
      await this.request<
        AuthorizationEffectiveness
      >(
        `/v1/authorizations/${encodeURIComponent(authorizationId)}/effectiveness`,
        {
          query: {
            at,
          },
        },
      )
    ).data;
  }

  async recordAuthorizationDecision(
    authorizationId: string,
    input:
      RecordAuthorizationDecisionInput,
  ): Promise<AuthorizationRecord> {
    return (
      await this.request<
        AuthorizationRecord
      >(
        `/v1/authorizations/${encodeURIComponent(authorizationId)}/decisions`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async revokeAuthorization(
    authorizationId: string,
    input: RevokeAuthorizationInput,
  ): Promise<AuthorizationRecord> {
    return (
      await this.request<
        AuthorizationRecord
      >(
        `/v1/authorizations/${encodeURIComponent(authorizationId)}/revoke`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async requestException(
    input: RequestExceptionInput,
  ): Promise<ExceptionRecordView> {
    return (
      await this.request<
        ExceptionRecordView
      >(
        "/v1/exceptions",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async getException(
    exceptionId: string,
  ): Promise<ExceptionRecordView> {
    return (
      await this.request<
        ExceptionRecordView
      >(
        `/v1/exceptions/${encodeURIComponent(exceptionId)}`,
      )
    ).data;
  }

  async getExceptionEffectiveness(
    exceptionId: string,
    at?: string,
  ): Promise<ExceptionEffectiveness> {
    return (
      await this.request<
        ExceptionEffectiveness
      >(
        `/v1/exceptions/${encodeURIComponent(exceptionId)}/effectiveness`,
        {
          query: {
            at,
          },
        },
      )
    ).data;
  }

  async recordExceptionDecision(
    exceptionId: string,
    input:
      RecordExceptionDecisionInput,
  ): Promise<ExceptionRecordView> {
    return (
      await this.request<
        ExceptionRecordView
      >(
        `/v1/exceptions/${encodeURIComponent(exceptionId)}/decisions`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async revokeException(
    exceptionId: string,
    input: RevokeExceptionInput,
  ): Promise<ExceptionRecordView> {
    return (
      await this.request<
        ExceptionRecordView
      >(
        `/v1/exceptions/${encodeURIComponent(exceptionId)}/revoke`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async createDeadline(
    input: CreateDeadlineInput,
  ): Promise<DeadlineView> {
    return (
      await this.request<
        DeadlineView
      >(
        "/v1/deadlines",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async getDeadline(
    deadlineId: string,
  ): Promise<DeadlineView> {
    return (
      await this.request<
        DeadlineView
      >(
        `/v1/deadlines/${encodeURIComponent(deadlineId)}`,
      )
    ).data;
  }

  async getDeadlineStatus(
    deadlineId: string,
    at?: string,
  ): Promise<DeadlineStatusSnapshot> {
    return (
      await this.request<
        DeadlineStatusSnapshot
      >(
        `/v1/deadlines/${encodeURIComponent(deadlineId)}/status`,
        {
          query: {
            at,
          },
        },
      )
    ).data;
  }

  async listDeadlinesBySubject(
    subjectType: string,
    subjectId: string,
  ): Promise<Deadline[]> {
    const organizationId =
      this.requireOrganizationId();
    return (
      await this.request<
        Deadline[]
      >(
        `/v1/organizations/${organizationId}/subjects/${encodeURIComponent(subjectType)}/${encodeURIComponent(subjectId)}/deadlines`,
      )
    ).data;
  }

  async satisfyDeadline(
    deadlineId: string,
    input: SatisfyDeadlineInput,
  ): Promise<DeadlineView> {
    return (
      await this.request<
        DeadlineView
      >(
        `/v1/deadlines/${encodeURIComponent(deadlineId)}/satisfy`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async cancelDeadline(
    deadlineId: string,
    input: CancelDeadlineInput,
  ): Promise<DeadlineView> {
    return (
      await this.request<
        DeadlineView
      >(
        `/v1/deadlines/${encodeURIComponent(deadlineId)}/cancel`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async syncFailedCheckFindings(
    checkId: string,
    correlationId?: string | null,
  ): Promise<SyncFindingsResult> {
    return (
      await this.request<
        SyncFindingsResult
      >(
        `/v1/checks/${encodeURIComponent(checkId)}/findings/sync`,
        {
          method: "POST",
          body: {
            correlationId:
              correlationId ?? null,
          },
        },
      )
    ).data;
  }

  async getFinding(
    findingId: string,
  ): Promise<FindingView> {
    return (
      await this.request<
        FindingView
      >(
        `/v1/findings/${encodeURIComponent(findingId)}`,
      )
    ).data;
  }

  async listFindingsForResource(
    resourceId: string,
    filter: FindingListFilter = {},
  ): Promise<Finding[]> {
    const organizationId =
      this.requireOrganizationId();
    return (
      await this.request<
        Finding[]
      >(
        `/v1/organizations/${organizationId}/resources/${encodeURIComponent(resourceId)}/findings`,
        {
          query: {
            status:
              filter.status,
          },
        },
      )
    ).data;
  }

  async assignFindingOwner(
    findingId: string,
    input: AssignFindingOwnerInput,
  ): Promise<FindingView> {
    return this.findingAction(
      findingId,
      "owner",
      input,
    );
  }

  async acknowledgeFinding(
    findingId: string,
    input: FindingActionInput,
  ): Promise<FindingView> {
    return this.findingAction(
      findingId,
      "acknowledge",
      input,
    );
  }

  async disputeFinding(
    findingId: string,
    input: DisputeFindingInput,
  ): Promise<FindingView> {
    return this.findingAction(
      findingId,
      "dispute",
      input,
    );
  }

  async resolveFindingDispute(
    findingId: string,
    input: ResolveDisputeInput,
  ): Promise<FindingView> {
    return this.findingAction(
      findingId,
      "resolve-dispute",
      input,
    );
  }

  async createRemediation(
    findingId: string,
    input: CreateRemediationInput,
  ): Promise<FindingView> {
    return (
      await this.request<
        FindingView
      >(
        `/v1/findings/${encodeURIComponent(findingId)}/remediations`,
        {
          method: "POST",
          body: input,
        },
      )
    ).data;
  }

  async startRemediation(
    remediationId: string,
    input: RemediationActionInput,
  ): Promise<FindingView> {
    return this.remediationAction(
      remediationId,
      "start",
      input,
    );
  }

  async submitRemediationForVerification(
    remediationId: string,
    input: RemediationActionInput,
  ): Promise<FindingView> {
    return this.remediationAction(
      remediationId,
      "submit",
      input,
    );
  }

  async verifyRemediation(
    remediationId: string,
    input: VerifyRemediationInput,
  ): Promise<FindingView> {
    return this.remediationAction(
      remediationId,
      "verify",
      input,
    );
  }

  async rejectRemediation(
    remediationId: string,
    input: RejectRemediationInput,
  ): Promise<FindingView> {
    return this.remediationAction(
      remediationId,
      "reject",
      input,
    );
  }

  async cancelRemediation(
    remediationId: string,
    input: CancelRemediationInput,
  ): Promise<FindingView> {
    return this.remediationAction(
      remediationId,
      "cancel",
      input,
    );
  }

  async closeFinding(
    findingId: string,
    input: FindingActionInput,
  ): Promise<FindingView> {
    return this.findingAction(
      findingId,
      "close",
      input,
    );
  }

  async reopenFinding(
    findingId: string,
    input: FindingActionInput,
  ): Promise<FindingView> {
    return this.findingAction(
      findingId,
      "reopen",
      input,
    );
  }

  async issueCertification(
    input: IssueCertificationInput,
  ): Promise<CertificationView> {
    return (
      await this.request<
        CertificationView
      >(
        "/v1/certifications",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async getCertification(
    certificationId: string,
  ): Promise<CertificationView> {
    return (
      await this.request<
        CertificationView
      >(
        `/v1/certifications/${encodeURIComponent(certificationId)}`,
      )
    ).data;
  }

  async listCertificationsForResource(
    resourceId: string,
  ): Promise<Certification[]> {
    const organizationId =
      this.requireOrganizationId();
    return (
      await this.request<
        Certification[]
      >(
        `/v1/organizations/${organizationId}/resources/${encodeURIComponent(resourceId)}/certifications`,
      )
    ).data;
  }

  async renewCertification(
    certificationId: string,
    input: RenewCertificationInput,
  ): Promise<CertificationView> {
    return this.certificationAction(
      certificationId,
      "renew",
      input,
    );
  }

  async suspendCertification(
    certificationId: string,
    input: CertificationActionInput,
  ): Promise<CertificationView> {
    return this.certificationAction(
      certificationId,
      "suspend",
      input,
    );
  }

  async reinstateCertification(
    certificationId: string,
    input: ReinstateCertificationInput,
  ): Promise<CertificationView> {
    return this.certificationAction(
      certificationId,
      "reinstate",
      input,
    );
  }

  async revokeCertification(
    certificationId: string,
    input: CertificationActionInput,
  ): Promise<CertificationView> {
    return this.certificationAction(
      certificationId,
      "revoke",
      input,
    );
  }

  async runCheck(
    input: RunCheckInput,
  ): Promise<RunCheckResult> {
    return (
      await this.request<
        RunCheckResult
      >(
        "/v1/checks/run",
        {
          method: "POST",
          body: {
            organizationId:
              this.requireOrganizationId(),
            ...input,
          },
        },
      )
    ).data;
  }

  async listRegisteredRuleSets(
    options: {
      key?: string;
      status?: string;
    } = {},
  ): Promise<
    RegisteredRuleSetSummary[]
  > {
    const organizationId =
      this.requireOrganizationId();
    return (
      await this.request<
        RegisteredRuleSetSummary[]
      >(
        `/v1/organizations/${organizationId}/rulesets`,
        {
          query: options,
        },
      )
    ).data;
  }

  async resolveRegisteredRuleSet(
    key: string,
    at?: string,
  ): Promise<
    RegisteredRuleSetSummary
  > {
    const organizationId =
      this.requireOrganizationId();
    return (
      await this.request<
        RegisteredRuleSetSummary
      >(
        `/v1/organizations/${organizationId}/rulesets/resolve/${encodeURIComponent(key)}`,
        {
          query: { at },
        },
      )
    ).data;
  }

  async getComplianceReport(
    resourceId?: string,
    asOf?: string,
  ): Promise<ComplianceReport> {
    const organizationId =
      this.requireOrganizationId();
    const path =
      resourceId
        ? `/v1/reports/organizations/${organizationId}/resources/${encodeURIComponent(resourceId)}/compliance`
        : `/v1/reports/organizations/${organizationId}/compliance`;

    return (
      await this.request<
        ComplianceReport
      >(
        path,
        {
          query: {
            asOf,
          },
        },
      )
    ).data;
  }

  async getRenderedComplianceReport(
    format: RenderedComplianceFormat,
    resourceId?: string,
    asOf?: string,
  ): Promise<RenderedComplianceReport> {
    const organizationId =
      this.requireOrganizationId();
    const path =
      resourceId
        ? `/v1/reports/organizations/${organizationId}/resources/${encodeURIComponent(resourceId)}/compliance`
        : `/v1/reports/organizations/${organizationId}/compliance`;
    const response =
      await this.request<string>(
        path,
        {
          query: {
            format,
            asOf,
          },
        },
      );

    return {
      format,
      mediaType:
        response.headers.get(
          "content-type",
        ) ??
        (format === "csv"
          ? "text/csv; charset=utf-8"
          : "text/plain; charset=utf-8"),
      body: response.data,
    };
  }

  async getRegistryProjection(
    resourceId: string,
  ): Promise<
    RegistryComplianceProjection
  > {
    return (
      await this.request<
        RegistryComplianceProjection
      >(
        `/v1/integration/resources/${encodeURIComponent(resourceId)}/registry-projection`,
      )
    ).data;
  }

  async listIntegrationResources(
    options:
      ResourceListOptions = {},
  ): Promise<
    Paginated<Resource>
  > {
    return (
      await this.request<
        Paginated<Resource>
      >(
        "/v1/integration/resources",
        {
          query: {
            limit:
              options.limit,
            cursor:
              options.cursor ??
              undefined,
            resourceType:
              options.resourceType ??
              undefined,
            status:
              options.status ??
              undefined,
          },
        },
      )
    ).data;
  }

  async publicVerifyCertification(
    code: string,
  ): Promise<
    Record<string, unknown>
  > {
    return (
      await this.request<
        Record<string, unknown>
      >(
        `/v1/public/certifications/verify/${encodeURIComponent(code)}`,
      )
    ).data;
  }

  async getPublishedProjection(
    publicationId: string,
  ): Promise<
    Record<string, unknown>
  > {
    return (
      await this.request<
        Record<string, unknown>
      >(
        `/v1/public/publications/${encodeURIComponent(publicationId)}`,
      )
    ).data;
  }

  private async findingAction(
    findingId: string,
    action: string,
    body: unknown,
  ): Promise<FindingView> {
    return (
      await this.request<
        FindingView
      >(
        `/v1/findings/${encodeURIComponent(findingId)}/${action}`,
        {
          method: "POST",
          body,
        },
      )
    ).data;
  }

  private async remediationAction(
    remediationId: string,
    action: string,
    body: unknown,
  ): Promise<FindingView> {
    return (
      await this.request<
        FindingView
      >(
        `/v1/remediations/${encodeURIComponent(remediationId)}/${action}`,
        {
          method: "POST",
          body,
        },
      )
    ).data;
  }

  private async certificationAction(
    certificationId: string,
    action: string,
    body: unknown,
  ): Promise<CertificationView> {
    return (
      await this.request<
        CertificationView
      >(
        `/v1/certifications/${encodeURIComponent(certificationId)}/${action}`,
        {
          method: "POST",
          body,
        },
      )
    ).data;
  }

  private headersFor(
    options: SdkRequestOptions,
  ): Record<string, string> {
    const headers = {
      ...this.defaultHeaders,
      ...(
        options.headers ??
        {}
      ),
    };

    if (
      this.auth?.mode ===
        "operator" ||
      this.auth?.mode ===
        "service"
    ) {
      headers.authorization =
        `Bearer ${this.auth.token}`;
    }

    if (
      options.idempotencyKey
    ) {
      headers[
        "idempotency-key"
      ] =
        options.idempotencyKey;
    }

    return headers;
  }

  private requireOrganizationId():
    string {
    if (!this.organizationId) {
      throw new Error(
        "organizationId is required for this operation",
      );
    }
    return this.organizationId;
  }
}

export function createPublicClient(
  options:
    Omit<
      SdkClientOptions,
      "auth"
    >,
): ComplianceEngineClient {
  return new ComplianceEngineClient({
    ...options,
    auth: {
      mode: "public",
    },
  });
}

export function createOperatorClient(
  options:
    Omit<
      SdkClientOptions,
      "auth"
    > & {
      token: string;
    },
): ComplianceEngineClient {
  return new ComplianceEngineClient({
    ...options,
    auth: {
      mode: "operator",
      token:
        options.token,
    },
  });
}

export function createServiceClient(
  options:
    Omit<
      SdkClientOptions,
      "auth"
    > & {
      token: string;
    },
): ComplianceEngineClient {
  return new ComplianceEngineClient({
    ...options,
    auth: {
      mode: "service",
      token:
        options.token,
    },
  });
}

function validateAuth(
  auth: NonNullable<
    SdkClientOptions["auth"]
  >,
): void {
  if (
    auth.mode === "public"
  ) {
    if (auth.token) {
      throw new Error(
        "public auth mode must not include a token",
      );
    }
    return;
  }

  if (
    !auth.token ||
    auth.token.trim() === ""
  ) {
    throw new Error(
      `${auth.mode} auth mode requires a token`,
    );
  }

  const expected =
    auth.mode === "operator"
      ? "caiau_"
      : "caiae_";

  if (
    !auth.token.startsWith(
      expected,
    )
  ) {
    throw new Error(
      `${auth.mode} token must begin with ${expected}`,
    );
  }
}

function normalizeBaseUrl(
  value: string,
): string {
  if (
    typeof value !==
      "string" ||
    value.trim() === ""
  ) {
    throw new Error(
      "baseUrl is required",
    );
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      "baseUrl must be an absolute URL",
    );
  }
  if (
    url.protocol !==
      "http:" &&
    url.protocol !==
      "https:"
  ) {
    throw new Error(
      "baseUrl must use http or https",
    );
  }
  return url
    .toString()
    .replace(/\/$/, "");
}

function buildUrl(
  baseUrl: string,
  path: string,
  query:
    SdkRequestOptions["query"],
): string {
  const url =
    new URL(
      path.startsWith("/")
        ? path
        : `/${path}`,
      `${baseUrl}/`,
    );

  for (
    const [key, value] of
    Object.entries(
      query ?? {},
    )
  ) {
    if (
      value === undefined ||
      value === null
    ) {
      continue;
    }
    url.searchParams.set(
      key,
      String(value),
    );
  }

  return url.toString();
}

async function decodeResponse(
  response: Response,
): Promise<unknown> {
  const contentType =
    response.headers.get(
      "content-type",
    ) ?? "";

  if (
    contentType.includes(
      "application/json",
    )
  ) {
    return response.json();
  }

  const text =
    await response.text();

  return text === ""
    ? null
    : text;
}

function toSdkError(
  response: Response,
  payload: unknown,
): SdkError {
  const body =
    (
      payload !== null &&
      typeof payload ===
        "object"
    )
      ? payload as Record<
          string,
          unknown
        >
      : {};

  const code =
    typeof body.error ===
      "string"
      ? body.error
      : `http_${response.status}`;
  const message =
    typeof body.message ===
      "string"
      ? body.message
      : typeof payload ===
        "string"
        ? payload
        : `request failed with HTTP ${response.status}`;

  return new SdkError(
    response.status,
    code,
    message,
    payload,
  );
}
