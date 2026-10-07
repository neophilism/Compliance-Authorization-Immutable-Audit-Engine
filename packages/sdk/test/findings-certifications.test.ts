import assert from "node:assert/strict";
import test from "node:test";
import {
  createOperatorClient,
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

test(
  "operator client exposes typed finding and remediation lifecycle",
  async () => {
    const calls: Array<{
      url: string;
      init?: RequestInit;
    }> = [];

    const findingView = {
      finding: {
        id: "finding-id",
      },
      remediations: [],
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
                  "/findings/sync",
                )
              ) {
                return json({
                  findings: [],
                });
              }

              if (
                init?.method !==
                  "POST" &&
                url.includes(
                  "/resources/",
                ) &&
                url.includes(
                  "/findings",
                )
              ) {
                return json([]);
              }

              return json(
                findingView,
                init?.method ===
                    "POST" &&
                  url.endsWith(
                    "/remediations",
                  )
                  ? 201
                  : 200,
              );
            },
        },
      });

    await client
      .syncFailedCheckFindings(
        "check/1",
        "sync-correlation",
      );
    await client.getFinding(
      "finding/1",
    );
    await client
      .listFindingsForResource(
        "resource/1",
        {
          status: "open",
        },
      );
    await client
      .assignFindingOwner(
        "finding/1",
        {
          principalId:
            "operator-principal",
          ownerPrincipalId:
            "owner-principal",
          correlationId:
            "owner-correlation",
        },
      );
    await client
      .acknowledgeFinding(
        "finding/1",
        {
          principalId:
            "operator-principal",
        },
      );
    await client.disputeFinding(
      "finding/1",
      {
        principalId:
          "operator-principal",
        reason:
          "Evidence is incomplete",
      },
    );
    await client
      .resolveFindingDispute(
        "finding/1",
        {
          principalId:
            "reviewer-principal",
          outcome: "uphold",
          rationale:
            "Failure is supported",
        },
      );
    await client
      .createRemediation(
        "finding/1",
        {
          createdByPrincipalId:
            "operator-principal",
          ownerPrincipalId:
            "owner-principal",
          plan:
            "Replace noncompliant configuration",
          dueAt:
            "2026-12-31T23:59:59.000Z",
          warningWindowSeconds:
            86400,
          gracePeriodSeconds: 0,
          escalationAfterSeconds: [
            3600,
          ],
          metadata: {
            source:
              "thin-app",
          },
        },
      );
    await client.startRemediation(
      "remediation/1",
      {
        principalId:
          "owner-principal",
      },
    );
    await client
      .submitRemediationForVerification(
        "remediation/1",
        {
          principalId:
            "owner-principal",
        },
      );
    await client.verifyRemediation(
      "remediation/1",
      {
        principalId:
          "reviewer-principal",
        note:
          "Evidence verified",
      },
    );
    await client.rejectRemediation(
      "remediation/2",
      {
        principalId:
          "reviewer-principal",
        reason:
          "Control still fails",
      },
    );
    await client.cancelRemediation(
      "remediation/3",
      {
        principalId:
          "operator-principal",
        reason:
          "Superseded",
      },
    );
    await client.closeFinding(
      "finding/1",
      {
        principalId:
          "reviewer-principal",
      },
    );
    await client.reopenFinding(
      "finding/1",
      {
        principalId:
          "reviewer-principal",
      },
    );

    assert.equal(
      calls.length,
      15,
    );
    assert.match(
      calls[0]!.url,
      /\/v1\/checks\/check%2F1\/findings\/sync$/,
    );
    assert.equal(
      calls[0]!.init?.method,
      "POST",
    );
    assert.deepEqual(
      JSON.parse(
        String(
          calls[0]!.init?.body,
        ),
      ),
      {
        correlationId:
          "sync-correlation",
      },
    );
    assert.match(
      calls[2]!.url,
      /\/v1\/organizations\/11111111-1111-4111-8111-111111111111\/resources\/resource%2F1\/findings\?status=open$/,
    );
    assert.match(
      calls[3]!.url,
      /\/v1\/findings\/finding%2F1\/owner$/,
    );
    assert.match(
      calls[7]!.url,
      /\/v1\/findings\/finding%2F1\/remediations$/,
    );
    assert.match(
      calls[8]!.url,
      /\/v1\/remediations\/remediation%2F1\/start$/,
    );
    assert.match(
      calls[9]!.url,
      /\/v1\/remediations\/remediation%2F1\/submit$/,
    );
    assert.match(
      calls[10]!.url,
      /\/v1\/remediations\/remediation%2F1\/verify$/,
    );
    assert.match(
      calls[13]!.url,
      /\/v1\/findings\/finding%2F1\/close$/,
    );
    assert.match(
      calls[14]!.url,
      /\/v1\/findings\/finding%2F1\/reopen$/,
    );
  },
);

test(
  "operator client exposes typed certification lifecycle",
  async () => {
    const calls: Array<{
      url: string;
      init?: RequestInit;
    }> = [];
    const certificationView = {
      certification: {
        id:
          "certification-id",
      },
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
                init?.method !==
                  "POST" &&
                url.includes(
                  "/resources/",
                ) &&
                url.endsWith(
                  "/certifications",
                )
              ) {
                return json([]);
              }

              return json(
                certificationView,
                init?.method ===
                  "POST"
                  ? 201
                  : 200,
              );
            },
        },
      });

    await client.issueCertification({
      resourceId:
        "agency/1",
      certificationType:
        "annual-compliance",
      supportingCheckId:
        "check/1",
      issuedByPrincipalId:
        "agency-head",
      validFrom:
        "2026-12-31T00:00:00.000Z",
      validUntil:
        "2027-12-31T00:00:00.000Z",
      criteria: {
        ruleSetId:
          "ruleset-id",
        blockingFindingSeverities: [
          "critical",
          "high",
        ],
      },
      metadata: {
        reportingYear: 2026,
      },
      correlationId:
        "issue-correlation",
    });
    await client.getCertification(
      "cert/1",
    );
    await client
      .listCertificationsForResource(
        "agency/1",
      );
    await client.renewCertification(
      "cert/1",
      {
        supportingCheckId:
          "check/2",
        issuedByPrincipalId:
          "agency-head",
        validitySeconds:
          31536000,
      },
    );
    await client.suspendCertification(
      "cert/1",
      {
        principalId:
          "oversight-principal",
        reason:
          "Material failure",
      },
    );
    await client
      .reinstateCertification(
        "cert/1",
        {
          supportingCheckId:
            "check/3",
          principalId:
            "oversight-principal",
          rationale:
            "Corrective check passed",
        },
      );
    await client.revokeCertification(
      "cert/1",
      {
        principalId:
          "oversight-principal",
        reason:
          "Certification withdrawn",
      },
    );

    assert.equal(
      calls.length,
      7,
    );
    assert.equal(
      calls[0]!.init?.method,
      "POST",
    );
    assert.match(
      calls[0]!.url,
      /\/v1\/certifications$/,
    );
    const issueBody =
      JSON.parse(
        String(
          calls[0]!.init?.body,
        ),
      );
    assert.equal(
      issueBody.organizationId,
      ORG,
    );
    assert.equal(
      issueBody.certificationType,
      "annual-compliance",
    );
    assert.match(
      calls[1]!.url,
      /\/v1\/certifications\/cert%2F1$/,
    );
    assert.match(
      calls[2]!.url,
      /\/v1\/organizations\/11111111-1111-4111-8111-111111111111\/resources\/agency%2F1\/certifications$/,
    );
    assert.match(
      calls[3]!.url,
      /\/v1\/certifications\/cert%2F1\/renew$/,
    );
    assert.match(
      calls[4]!.url,
      /\/v1\/certifications\/cert%2F1\/suspend$/,
    );
    assert.match(
      calls[5]!.url,
      /\/v1\/certifications\/cert%2F1\/reinstate$/,
    );
    assert.match(
      calls[6]!.url,
      /\/v1\/certifications\/cert%2F1\/revoke$/,
    );
  },
);
