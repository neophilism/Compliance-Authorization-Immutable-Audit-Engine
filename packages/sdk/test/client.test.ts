import assert from "node:assert/strict";
import test from "node:test";
import {
  SdkError,
  createOperatorClient,
  createPublicClient,
  createServiceClient,
} from "../src/index.js";

const ORG =
  "11111111-1111-4111-8111-111111111111";

test("operator client sends bearer auth and organization-scoped requests", async () => {
  const calls:
    Array<{
      url: string;
      init?: RequestInit;
    }> = [];

  const client =
    createOperatorClient({
      baseUrl:
        "https://engine.example",
      organizationId: ORG,
      token:
        "caiau_operator_secret",
      fetchImpl: undefined,
      transport: {
        fetchImpl:
          async (
            input,
            init,
          ) => {
            calls.push({
              url:
                String(input),
              init,
            });
            return new Response(
              JSON.stringify([]),
              {
                status: 200,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    } as any);

  await client.listResources({
    resourceType:
      "generic",
  });

  assert.equal(
    calls.length,
    1,
  );
  assert.match(
    calls[0]!.url,
    new RegExp(
      `/v1/organizations/${ORG}/resources\\?resourceType=generic`,
    ),
  );
  const headers =
    calls[0]!.init
      ?.headers as Record<
        string,
        string
      >;
  assert.equal(
    headers.authorization,
    "Bearer caiau_operator_secret",
  );
});

test("service client propagates idempotency keys", async () => {
  let seenHeaders:
    Record<string, string> = {};

  const client =
    createServiceClient({
      baseUrl:
        "https://engine.example",
      token:
        "caiae_service_secret",
      transport: {
        fetchImpl:
          async (
            _input,
            init,
          ) => {
            seenHeaders =
              init?.headers as Record<
                string,
                string
              >;
            return new Response(
              JSON.stringify({
                ok: true,
              }),
              {
                status: 200,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    });

  const response =
    await client.request<{
      ok: boolean;
    }>(
      "/v1/integration/resources",
      {
        method: "POST",
        body: {
          resourceType:
            "generic",
          name: "Example",
        },
        idempotencyKey:
          "idem-123",
      },
    );

  assert.equal(
    response.data.ok,
    true,
  );
  assert.equal(
    seenHeaders.authorization,
    "Bearer caiae_service_secret",
  );
  assert.equal(
    seenHeaders[
      "idempotency-key"
    ],
    "idem-123",
  );
});

test("public client sends no bearer token and SDK errors preserve API payloads", async () => {
  let authorization:
    string | undefined;

  const client =
    createPublicClient({
      baseUrl:
        "https://engine.example",
      transport: {
        fetchImpl:
          async (
            _input,
            init,
          ) => {
            const headers =
              init?.headers as Record<
                string,
                string
              >;
            authorization =
              headers.authorization;
            return new Response(
              JSON.stringify({
                error:
                  "not_found",
                message:
                  "publication not found",
              }),
              {
                status: 404,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    });

  await assert.rejects(
    client.getPublishedProjection(
      "missing",
    ),
    (error: unknown) => {
      assert.ok(
        error instanceof
          SdkError,
      );
      assert.equal(
        error.status,
        404,
      );
      assert.equal(
        error.code,
        "not_found",
      );
      assert.equal(
        error.message,
        "publication not found",
      );
      return true;
    },
  );

  assert.equal(
    authorization,
    undefined,
  );
});

test("client rejects mixed token families", () => {
  assert.throws(
    () =>
      createOperatorClient({
        baseUrl:
          "https://engine.example",
        token:
          "caiae_service",
      }),
    /caiau_/,
  );

  assert.throws(
    () =>
      createServiceClient({
        baseUrl:
          "https://engine.example",
        token:
          "caiau_operator",
      }),
    /caiae_/,
  );
});


test("operator client gets and updates resources with optimistic concurrency", async () => {
  const calls:
    Array<{
      url: string;
      init?: RequestInit;
    }> = [];
  const resource = {
    id:
      "22222222-2222-4222-8222-222222222222",
    organizationId:
      ORG,
    resourceType:
      "generic",
    name:
      "Updated resource",
    externalRef:
      null,
    status:
      "active",
    attributes: {
      state:
        "updated",
    },
    metadata: {},
    createdAt:
      "2026-10-06T16:00:00.000Z",
    updatedAt:
      "2026-10-06T16:05:00.000Z",
  };

  const client =
    createOperatorClient({
      baseUrl:
        "https://engine.example",
      organizationId:
        ORG,
      token:
        "caiau_operator_secret",
      transport: {
        fetchImpl:
          async (
            input,
            init,
          ) => {
            calls.push({
              url:
                String(input),
              init,
            });
            return new Response(
              JSON.stringify(
                resource,
              ),
              {
                status: 200,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    });

  const fetched =
    await client.getResource(
      resource.id,
    );
  assert.equal(
    fetched.id,
    resource.id,
  );

  const updated =
    await client.updateResource(
      resource.id,
      {
        expectedUpdatedAt:
          "2026-10-06T16:00:00.000Z",
        name:
          "Updated resource",
        attributes: {
          state:
            "updated",
        },
        correlationId:
          "sdk-resource-update",
      },
    );

  assert.equal(
    updated.name,
    "Updated resource",
  );
  assert.equal(
    calls.length,
    2,
  );
  assert.match(
    calls[1]!.url,
    new RegExp(
      "/v1/resources/" +
        resource.id +
        "$",
    ),
  );
  assert.equal(
    calls[1]!.init?.method,
    "PATCH",
  );
  const body =
    JSON.parse(
      String(
        calls[1]!.init
          ?.body,
      ),
    );
  assert.equal(
    body.expectedUpdatedAt,
    "2026-10-06T16:00:00.000Z",
  );
  assert.equal(
    body.correlationId,
    "sdk-resource-update",
  );
});


test("operator client exposes typed exception lifecycle methods", async () => {
  const calls:
    Array<{
      url: string;
      init?: RequestInit;
    }> = [];
  const exceptionId =
    "33333333-3333-4333-8333-333333333333";
  const resourceId =
    "22222222-2222-4222-8222-222222222222";
  const requestedView = {
    exception: {
      id: exceptionId,
      organizationId:
        ORG,
      resourceId,
      ruleId:
        "fdea.s4.at-rest-encryption",
      kind:
        "waiver",
      status:
        "requested",
      requestedByPrincipalId:
        "requester-principal",
      decidedByPrincipalId:
        null,
      requestedAt:
        "2026-10-06T17:00:00.000Z",
      decidedAt:
        null,
      justification:
        "Temporary migration waiver",
      validFrom:
        null,
      validUntil:
        "2027-10-06T17:00:00.000Z",
      scope: {
        subsystem:
          "legacy-storage",
      },
      conditions: {
        compensatingControlsRequired:
          true,
      },
      approvalQuorum:
        2,
      approvalAuthority:
        "agency-cio",
      createdAt:
        "2026-10-06T17:00:00.000Z",
      updatedAt:
        "2026-10-06T17:00:00.000Z",
      metadata: {},
    },
    decisions: [],
    eligibleApproverPrincipalIds: [
      "approver-1",
      "approver-2",
    ],
    approvalCount:
      0,
  };

  const client =
    createOperatorClient({
      baseUrl:
        "https://engine.example",
      organizationId:
        ORG,
      token:
        "caiau_operator_secret",
      transport: {
        fetchImpl:
          async (
            input,
            init,
          ) => {
            const url =
              String(input);
            calls.push({
              url,
              init,
            });

            if (
              url.includes(
                "/effectiveness",
              )
            ) {
              return new Response(
                JSON.stringify({
                  effective:
                    true,
                  reason:
                    "approved",
                }),
                {
                  status:
                    200,
                  headers: {
                    "content-type":
                      "application/json",
                  },
                },
              );
            }

            return new Response(
              JSON.stringify(
                requestedView,
              ),
              {
                status:
                  init?.method ===
                    "POST" &&
                  url.endsWith(
                    "/v1/exceptions",
                  )
                    ? 201
                    : 200,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    });

  const requested =
    await client.requestException({
      resourceId,
      ruleId:
        "fdea.s4.at-rest-encryption",
      kind:
        "waiver",
      requestedByPrincipalId:
        "requester-principal",
      justification:
        "Temporary migration waiver",
      validUntil:
        "2027-10-06T17:00:00.000Z",
      scope: {
        subsystem:
          "legacy-storage",
      },
      conditions: {
        compensatingControlsRequired:
          true,
      },
      approvalQuorum:
        2,
      approvalAuthority:
        "agency-cio",
      eligibleApproverPrincipalIds: [
        "approver-1",
        "approver-2",
      ],
      correlationId:
        "sdk-exception-request",
    });

  assert.equal(
    requested.exception.id,
    exceptionId,
  );

  await client.getException(
    exceptionId,
  );
  const effectiveness =
    await client
      .getExceptionEffectiveness(
        exceptionId,
        "2026-10-07T17:00:00.000Z",
      );
  assert.equal(
    effectiveness.effective,
    true,
  );

  await client
    .recordExceptionDecision(
      exceptionId,
      {
        principalId:
          "approver-1",
        decision:
          "approve",
        rationale:
          "Controls are sufficient",
        correlationId:
          "sdk-exception-decision",
      },
    );

  await client.revokeException(
    exceptionId,
    {
      principalId:
        "approver-1",
      reason:
        "Migration completed",
      correlationId:
        "sdk-exception-revoke",
    },
  );

  assert.equal(
    calls.length,
    5,
  );

  const requestCall =
    calls[0]!;
  assert.equal(
    requestCall.init?.method,
    "POST",
  );
  const requestBody =
    JSON.parse(
      String(
        requestCall.init
          ?.body,
      ),
    );
  assert.equal(
    requestBody.organizationId,
    ORG,
  );
  assert.equal(
    requestBody.kind,
    "waiver",
  );
  assert.equal(
    requestBody.correlationId,
    "sdk-exception-request",
  );

  assert.match(
    calls[2]!.url,
    /\/effectiveness\?at=2026-10-07T17%3A00%3A00\.000Z$/,
  );
  assert.equal(
    calls[3]!.init?.method,
    "POST",
  );
  assert.match(
    calls[3]!.url,
    /\/decisions$/,
  );
  assert.equal(
    calls[4]!.init?.method,
    "POST",
  );
  assert.match(
    calls[4]!.url,
    /\/revoke$/,
  );
});


test("operator client exposes emergency authorization lifecycle methods", async () => {
  const calls:
    Array<{
      url: string;
      init?: RequestInit;
    }> = [];
  const authorizationId =
    "44444444-4444-4444-8444-444444444444";
  const resourceId =
    "22222222-2222-4222-8222-222222222222";
  const record = {
    authorization: {
      id:
        authorizationId,
      organizationId:
        ORG,
      resourceId,
      authorizationType:
        "fdea.emergency-communications",
      status:
        "approved",
      requestedByPrincipalId:
        "requester-principal",
      decidedByPrincipalId:
        null,
      requestedAt:
        "2026-10-06T17:00:00.000Z",
      decidedAt:
        null,
      validFrom:
        "2026-10-06T17:00:00.000Z",
      validUntil:
        "2026-10-06T21:00:00.000Z",
      scope: {},
      conditions: {},
      approvalQuorum:
        1,
      approvalAuthority:
        "agency-cio",
      emergency:
        true,
      emergencyReviewDueAt:
        "2026-10-06T19:00:00.000Z",
      emergencyReviewedAt:
        null,
      createdAt:
        "2026-10-06T17:00:00.000Z",
      updatedAt:
        "2026-10-06T17:00:00.000Z",
      metadata: {},
    },
    decisions: [],
    eligibleApproverPrincipalIds: [
      "approver-1",
    ],
    approvalCount:
      0,
  };

  const client =
    createOperatorClient({
      baseUrl:
        "https://engine.example",
      organizationId:
        ORG,
      token:
        "caiau_operator_secret",
      transport: {
        fetchImpl:
          async (
            input,
            init,
          ) => {
            const url =
              String(input);
            calls.push({
              url,
              init,
            });
            if (
              url.includes(
                "/effectiveness",
              )
            ) {
              return new Response(
                JSON.stringify({
                  effective:
                    true,
                  reason:
                    "approved",
                }),
                {
                  status:
                    200,
                  headers: {
                    "content-type":
                      "application/json",
                  },
                },
              );
            }
            return new Response(
              JSON.stringify(record),
              {
                status:
                  init?.method ===
                    "POST" &&
                  url.endsWith(
                    "/v1/authorizations",
                  )
                    ? 201
                    : 200,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    });

  await client.requestAuthorization({
    resourceId,
    authorizationType:
      "fdea.emergency-communications",
    requestedByPrincipalId:
      "requester-principal",
    validUntil:
      "2026-10-06T21:00:00.000Z",
    emergency:
      true,
    emergencyReviewDueAt:
      "2026-10-06T19:00:00.000Z",
    approvalAuthority:
      "agency-cio",
    eligibleApproverPrincipalIds: [
      "approver-1",
    ],
    correlationId:
      "sdk-emergency-request",
  });

  await client.getAuthorization(
    authorizationId,
  );
  const effectiveness =
    await client
      .getAuthorizationEffectiveness(
        authorizationId,
        "2026-10-06T18:00:00.000Z",
      );
  assert.equal(
    effectiveness.effective,
    true,
  );

  await client
    .recordAuthorizationDecision(
      authorizationId,
      {
        principalId:
          "approver-1",
        decision:
          "approve",
        rationale:
          "Emergency use reviewed",
      },
    );

  await client.revokeAuthorization(
    authorizationId,
    {
      principalId:
        "approver-1",
      reason:
        "Emergency ended",
    },
  );

  assert.equal(
    calls.length,
    5,
  );
  const requestBody =
    JSON.parse(
      String(
        calls[0]!.init
          ?.body,
      ),
    );
  assert.equal(
    requestBody.organizationId,
    ORG,
  );
  assert.equal(
    requestBody.emergency,
    true,
  );
  assert.equal(
    requestBody.emergencyReviewDueAt,
    "2026-10-06T19:00:00.000Z",
  );
  assert.match(
    calls[3]!.url,
    /\/decisions$/,
  );
  assert.match(
    calls[4]!.url,
    /\/revoke$/,
  );
});


test("operator client exposes typed deadline lifecycle methods", async () => {
  const calls:
    Array<{
      url: string;
      init?: RequestInit;
    }> = [];
  const deadlineId =
    "55555555-5555-4555-8555-555555555555";
  const resourceId =
    "22222222-2222-4222-8222-222222222222";
  const deadline = {
    id: deadlineId,
    organizationId: ORG,
    resourceId,
    subjectType:
      "statutory-obligation",
    subjectId:
      "agency/implementation",
    deadlineType:
      "implementation",
    status:
      "scheduled",
    createdByPrincipalId:
      "operator-principal",
    anchorAt:
      "2026-10-06T17:00:00.000Z",
    dueOffsetSeconds:
      15552000,
    dueAt:
      "2027-04-04T17:00:00.000Z",
    warningWindowSeconds:
      604800,
    gracePeriodSeconds:
      0,
    recurrenceIntervalSeconds:
      null,
    recurrenceEndAt:
      null,
    maxOccurrences:
      null,
    cycleNumber:
      1,
    escalationAfterSeconds: [
      86400,
    ],
    escalationLevel:
      0,
    satisfiedAt:
      null,
    createdAt:
      "2026-10-06T17:00:00.000Z",
    updatedAt:
      "2026-10-06T17:00:00.000Z",
    metadata: {},
  };
  const view = {
    deadline,
    clock: {
      status:
        "scheduled",
      escalationLevel:
        0,
      warningAt:
        "2027-03-28T17:00:00.000Z",
      dueAt:
        deadline.dueAt,
      overdueAt:
        deadline.dueAt,
    },
    occurrences: [],
  };

  const client =
    createOperatorClient({
      baseUrl:
        "https://engine.example",
      organizationId:
        ORG,
      token:
        "caiau_operator_secret",
      transport: {
        fetchImpl:
          async (
            input,
            init,
          ) => {
            const url =
              String(input);
            calls.push({
              url,
              init,
            });

            if (
              url.includes(
                "/status",
              )
            ) {
              return new Response(
                JSON.stringify({
                  status:
                    "scheduled",
                  escalationLevel:
                    0,
                  warningAt:
                    "2027-03-28T17:00:00.000Z",
                  dueAt:
                    deadline.dueAt,
                  overdueAt:
                    deadline.dueAt,
                }),
                {
                  status:
                    200,
                  headers: {
                    "content-type":
                      "application/json",
                  },
                },
              );
            }

            if (
              url.includes(
                "/subjects/",
              )
            ) {
              return new Response(
                JSON.stringify([
                  deadline,
                ]),
                {
                  status:
                    200,
                  headers: {
                    "content-type":
                      "application/json",
                  },
                },
              );
            }

            return new Response(
              JSON.stringify(view),
              {
                status:
                  init?.method ===
                    "POST" &&
                  url.endsWith(
                    "/v1/deadlines",
                  )
                    ? 201
                    : 200,
                headers: {
                  "content-type":
                    "application/json",
                },
              },
            );
          },
      },
    });

  const created =
    await client.createDeadline({
      resourceId,
      subjectType:
        "statutory-obligation",
      subjectId:
        "agency/implementation",
      deadlineType:
        "implementation",
      createdByPrincipalId:
        "operator-principal",
      anchorAt:
        "2026-10-06T17:00:00.000Z",
      dueAfterSeconds:
        15552000,
      warningWindowSeconds:
        604800,
      escalationAfterSeconds: [
        86400,
      ],
      correlationId:
        "sdk-deadline-create",
    });
  assert.equal(
    created.deadline.id,
    deadlineId,
  );

  await client.getDeadline(
    deadlineId,
  );

  const status =
    await client.getDeadlineStatus(
      deadlineId,
      "2027-03-01T12:00:00.000Z",
    );
  assert.equal(
    status.status,
    "scheduled",
  );

  const listed =
    await client.listDeadlinesBySubject(
      "statutory-obligation",
      "agency/implementation",
    );
  assert.equal(
    listed.length,
    1,
  );

  await client.satisfyDeadline(
    deadlineId,
    {
      principalId:
        "operator-principal",
      satisfiedAt:
        "2027-04-01T12:00:00.000Z",
      correlationId:
        "sdk-deadline-satisfy",
    },
  );

  await client.cancelDeadline(
    deadlineId,
    {
      principalId:
        "operator-principal",
      reason:
        "Superseded by corrected schedule",
      correlationId:
        "sdk-deadline-cancel",
    },
  );

  assert.equal(
    calls.length,
    6,
  );

  const createBody =
    JSON.parse(
      String(
        calls[0]!.init
          ?.body,
      ),
    );
  assert.equal(
    createBody.organizationId,
    ORG,
  );
  assert.equal(
    createBody.deadlineType,
    "implementation",
  );
  assert.equal(
    createBody.correlationId,
    "sdk-deadline-create",
  );

  assert.match(
    calls[2]!.url,
    /\/status\?at=2027-03-01T12%3A00%3A00\.000Z$/,
  );
  assert.match(
    calls[3]!.url,
    /\/subjects\/statutory-obligation\/agency%2Fimplementation\/deadlines$/,
  );
  assert.equal(
    calls[4]!.init?.method,
    "POST",
  );
  assert.match(
    calls[4]!.url,
    /\/satisfy$/,
  );
  assert.equal(
    calls[5]!.init?.method,
    "POST",
  );
  assert.match(
    calls[5]!.url,
    /\/cancel$/,
  );
});

test("operator client exposes typed publication lifecycle and public listing", async () => {
  const calls:
    Array<{
      url: string;
      init?: RequestInit;
    }> = [];
  const publicationId =
    "77777777-7777-4777-8777-777777777777";
  const subjectId =
    "22222222-2222-4222-8222-222222222222";
  const record = {
    id: publicationId,
    organizationId: ORG,
    subjectType: "resource",
    subjectId,
    projectionType:
      "resource_compliance",
    state: "published",
    revision: 1,
    projection: {
      resource: {
        id: subjectId,
      },
    },
    projectionHash:
      "abc123",
    policy: {
      omitPaths: [
        "resource.attributes.internal",
      ],
      replacements: {},
    },
    publishedAt:
      "2026-10-08T01:00:00.000Z",
    publishedByPrincipalId:
      "principal-1",
    unpublishedAt: null,
    unpublishedByPrincipalId:
      null,
    createdAt:
      "2026-10-08T01:00:00.000Z",
    updatedAt:
      "2026-10-08T01:00:00.000Z",
  };
  const preview = {
    schemaVersion: "1",
    organizationId: ORG,
    subjectType: "resource",
    subjectId,
    projectionType:
      "resource_compliance",
    asOf:
      "2026-10-08T01:00:00.000Z",
    policy: record.policy,
    projectionHash:
      record.projectionHash,
    projection:
      record.projection,
  };
  const publicRecord = {
    id: publicationId,
    organizationId: ORG,
    subjectType:
      record.subjectType,
    subjectId,
    projectionType:
      record.projectionType,
    revision: 1,
    projectionHash:
      record.projectionHash,
    publishedAt:
      record.publishedAt,
    projection:
      record.projection,
  };

  const client =
    createOperatorClient({
      baseUrl:
        "https://engine.example",
      organizationId: ORG,
      token:
        "caiau_operator_secret",
      transport: {
        fetchImpl:
          async (
            input,
            init,
          ) => {
            const url =
              String(input);
            calls.push({
              url,
              init,
            });

            if (
              url.endsWith(
                "/v1/publications/preview",
              )
            ) {
              return json(
                preview,
              );
            }
            if (
              url.includes(
                "/v1/public/organizations/",
              )
            ) {
              return json([
                publicRecord,
              ]);
            }
            if (
              url.includes(
                "/v1/public/publications/",
              )
            ) {
              return json(
                publicRecord,
              );
            }
            if (
              url.includes(
                "/v1/organizations/",
              )
            ) {
              return json([
                record,
              ]);
            }
            return json(record);
          },
      },
    });

  const previewed =
    await client.previewPublication({
      subjectType:
        "resource",
      subjectId,
      projectionType:
        "resource_compliance",
      policy: {
        omitPaths: [
          "resource.attributes.internal",
        ],
      },
    });
  assert.equal(
    previewed.projectionHash,
    "abc123",
  );

  const published =
    await client.publishPublication({
      subjectType:
        "resource",
      subjectId,
      projectionType:
        "resource_compliance",
      principalId:
        "principal-1",
      policy: {
        omitPaths: [
          "resource.attributes.internal",
        ],
      },
      correlationId:
        "sdk-publication-publish",
    });
  assert.equal(
    published.state,
    "published",
  );

  await client.getPublication(
    publicationId,
  );

  const listed =
    await client.listPublications({
      subjectType:
        "resource",
      subjectId,
      projectionType:
        "resource_compliance",
    });
  assert.equal(
    listed.length,
    1,
  );

  const publicProjection =
    await client.getPublishedProjection(
      publicationId,
    );
  assert.equal(
    publicProjection.revision,
    1,
  );

  const publicListed =
    await client.listPublishedProjections({
      subjectType:
        "resource",
    });
  assert.equal(
    publicListed.length,
    1,
  );

  await client.unpublishPublication({
    subjectType:
      "resource",
    subjectId,
    projectionType:
      "resource_compliance",
    principalId:
      "principal-1",
    reason:
      "Replace public projection",
  });

  assert.equal(
    calls.length,
    7,
  );

  const previewBody =
    JSON.parse(
      String(
        calls[0]!.init
          ?.body,
      ),
    );
  assert.equal(
    previewBody.organizationId,
    ORG,
  );

  const publishBody =
    JSON.parse(
      String(
        calls[1]!.init
          ?.body,
      ),
    );
  assert.equal(
    publishBody.organizationId,
    ORG,
  );
  assert.equal(
    publishBody.correlationId,
    "sdk-publication-publish",
  );

  assert.match(
    calls[3]!.url,
    new RegExp(
      "/v1/organizations/" +
        ORG +
        "/publications\\?subjectType=resource&subjectId=" +
        subjectId +
        "&projectionType=resource_compliance$",
    ),
  );
  assert.match(
    calls[5]!.url,
    new RegExp(
      "/v1/public/organizations/" +
        ORG +
        "/publications\\?subjectType=resource$",
    ),
  );

  const unpublishBody =
    JSON.parse(
      String(
        calls[6]!.init
          ?.body,
      ),
    );
  assert.equal(
    unpublishBody.reason,
    "Replace public projection",
  );
});

function json(
  value: unknown,
  status = 200,
): Response {
  return new Response(
    JSON.stringify(value),
    {
      status,
      headers: {
        "content-type":
          "application/json",
      },
    },
  );
}

