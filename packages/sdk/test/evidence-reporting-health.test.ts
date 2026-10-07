import assert from "node:assert/strict";
import test from "node:test";
import {
  createOperatorClient,
  createPublicClient,
} from "../src/index.js";

const ORG =
  "11111111-1111-4111-8111-111111111111";

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

test("public client exposes engine health without organization binding", async () => {
  let url = "";

  const client =
    createPublicClient({
      baseUrl:
        "https://engine.example",
      transport: {
        fetchImpl:
          async (input) => {
            url =
              String(input);
            return json({
              status: "ok",
              service: "api",
              release:
                "abc123",
              timestamp:
                "2026-10-07T16:00:00.000Z",
            });
          },
      },
    });

  const health =
    await client.getHealth();

  assert.equal(
    url,
    "https://engine.example/health",
  );
  assert.equal(
    health.status,
    "ok",
  );
  assert.equal(
    health.release,
    "abc123",
  );
});

test("operator client exposes evidence lifecycle through typed SDK methods", async () => {
  const calls: Array<{
    url: string;
    init?: RequestInit;
  }> = [];

  const evidenceView = {
    evidence: {
      id: "evidence-id",
      organizationId: ORG,
      resourceId:
        "resource/1",
      evidenceType:
        "generic-evidence",
      title:
        "Evidence record",
      status: "active",
      submittedByPrincipalId:
        "principal-1",
      source: "fixture",
      uri: null,
      mediaType: null,
      fileName: null,
      checksumAlgorithm:
        null,
      checksum: null,
      capturedAt:
        "2026-10-07T16:00:00.000Z",
      validFrom: null,
      validUntil: null,
      provenance: {},
      supersedesEvidenceId:
        null,
      supersededAt: null,
      attributes: {
        observed: true,
      },
      metadata: {},
      createdAt:
        "2026-10-07T16:00:00.000Z",
      updatedAt:
        "2026-10-07T16:00:00.000Z",
    },
    attestations: [],
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
              url.includes(
                "/evidence-types",
              )
            ) {
              return json({
                evidenceTypes: [
                  "generic-evidence",
                ],
              });
            }

            if (
              init?.method !==
                "POST" &&
              url.includes(
                "/resources/",
              ) &&
              url.endsWith(
                "/evidence",
              )
            ) {
              return json([
                evidenceView.evidence,
              ]);
            }

            return json(
              evidenceView,
              init?.method ===
                  "POST" &&
                url.endsWith(
                  "/v1/evidence",
                )
                ? 201
                : 200,
            );
          },
      },
    });

  await client.createEvidence({
    resourceId:
      "resource/1",
    evidenceType:
      "generic-evidence",
    title:
      "Evidence record",
    submittedByPrincipalId:
      "principal-1",
    source: "fixture",
    capturedAt:
      "2026-10-07T16:00:00.000Z",
    attributes: {
      observed: true,
    },
    correlationId:
      "evidence-create",
  });
  await client.getEvidence(
    "evidence/1",
  );
  await client
    .listEvidenceForResource(
      "resource/1",
    );
  const types =
    await client
      .listValidEvidenceTypesForResource(
        "resource/1",
        "2026-10-07T17:00:00.000Z",
      );
  await client
    .addEvidenceAttestation(
      "evidence/1",
      {
        principalId:
          "principal-2",
        attestationType:
          "review",
        statement:
          "Reviewed",
      },
    );
  await client.revokeEvidence(
    "evidence/1",
    {
      principalId:
        "principal-2",
      reason:
        "Superseded",
    },
  );
  await client
    .revokeEvidenceAttestation(
      "attestation/1",
      {
        principalId:
          "principal-2",
        reason:
          "Withdrawn",
      },
    );

  assert.deepEqual(
    types,
    [
      "generic-evidence",
    ],
  );
  assert.equal(
    calls.length,
    7,
  );

  const createBody =
    JSON.parse(
      String(
        calls[0]!.init?.body,
      ),
    );
  assert.equal(
    createBody.organizationId,
    ORG,
  );
  assert.equal(
    createBody.resourceId,
    "resource/1",
  );
  assert.equal(
    createBody.correlationId,
    "evidence-create",
  );

  assert.match(
    calls[1]!.url,
    /\/v1\/evidence\/evidence%2F1$/,
  );
  assert.match(
    calls[2]!.url,
    /\/v1\/organizations\/11111111-1111-4111-8111-111111111111\/resources\/resource%2F1\/evidence$/,
  );
  assert.match(
    calls[3]!.url,
    /\/evidence-types\?at=2026-10-07T17%3A00%3A00\.000Z$/,
  );
  assert.match(
    calls[4]!.url,
    /\/v1\/evidence\/evidence%2F1\/attestations$/,
  );
  assert.match(
    calls[5]!.url,
    /\/v1\/evidence\/evidence%2F1\/revoke$/,
  );
  assert.match(
    calls[6]!.url,
    /\/v1\/evidence-attestations\/attestation%2F1\/revoke$/,
  );
});

test("compliance report SDK supports as-of JSON and rendered text formats", async () => {
  const calls: Array<{
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
                "format=csv",
              )
            ) {
              return new Response(
                "resource,status\nA,passed\n",
                {
                  status: 200,
                  headers: {
                    "content-type":
                      "text/csv; charset=utf-8",
                  },
                },
              );
            }

            if (
              url.includes(
                "format=text",
              )
            ) {
              return new Response(
                "Compliance report",
                {
                  status: 200,
                  headers: {
                    "content-type":
                      "text/plain; charset=utf-8",
                  },
                },
              );
            }

            return json({
              schemaVersion: "1",
              reportType:
                "compliance",
              scope: {
                organizationId:
                  ORG,
                resourceId:
                  "resource/1",
              },
              organization: {
                id: ORG,
                name: "Org",
                slug: "org",
                status: "active",
              },
              resources: [],
              checks: [],
              findings: [],
              certifications: [],
            });
          },
      },
    });

  const report =
    await client
      .getComplianceReport(
        "resource/1",
        "2026-10-07T16:00:00.000Z",
      );
  const csv =
    await client
      .getRenderedComplianceReport(
        "csv",
        "resource/1",
        "2026-10-07T16:00:00.000Z",
      );
  const textReport =
    await client
      .getRenderedComplianceReport(
        "text",
      );

  assert.equal(
    report.scope.resourceId,
    "resource/1",
  );
  assert.equal(
    csv.format,
    "csv",
  );
  assert.equal(
    csv.mediaType,
    "text/csv; charset=utf-8",
  );
  assert.match(
    csv.body,
    /resource,status/,
  );
  assert.equal(
    textReport.body,
    "Compliance report",
  );

  assert.match(
    calls[0]!.url,
    /\/resources\/resource%2F1\/compliance\?asOf=2026-10-07T16%3A00%3A00\.000Z$/,
  );
  assert.match(
    calls[1]!.url,
    /format=csv/,
  );
  assert.match(
    calls[1]!.url,
    /asOf=2026-10-07T16%3A00%3A00\.000Z/,
  );
  assert.match(
    calls[2]!.url,
    /format=text/,
  );
});
