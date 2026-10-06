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
