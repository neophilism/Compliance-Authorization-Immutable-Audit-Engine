import assert from "node:assert/strict";
import test from "node:test";
import {
  createThinAppRuntime,
  parseThinAppConfig,
  parseThinAppRuntimeConfig,
  toPublicThinAppConfig,
} from "../src/index.js";

const ORG =
  "11111111-1111-4111-8111-111111111111";

test("thin app configuration is normalized and runtime secrets stay separate", () => {
  const config =
    parseThinAppConfig({
      schemaVersion: "1",
      appId: "example.app",
      displayName:
        "Example Compliance App",
      engine: {
        apiBaseUrl:
          "https://engine.example.test/",
        organizationId: ORG,
      },
      features: {
        resources: true,
        checks: true,
        publication: false,
      },
      resourceTypes: {
        generic_system: {
          label:
            "Generic System",
        },
      },
      metadata: {
        downstream: true,
      },
    });

  assert.equal(
    config.engine.apiBaseUrl,
    "https://engine.example.test",
  );
  assert.equal(
    config.engine.requestTimeoutMs,
    30000,
  );
  assert.equal(
    config.resourceTypes
      ?.generic_system
      ?.label,
    "Generic System",
  );

  const runtime =
    parseThinAppRuntimeConfig({
      config,
      secrets: {
        operatorToken:
          "caiau_abc_secret",
        serviceToken:
          "caiae_xyz_secret",
      },
    });

  assert.equal(
    runtime.secrets
      ?.operatorToken,
    "caiau_abc_secret",
  );
  assert.deepEqual(
    toPublicThinAppConfig(
      runtime,
    ),
    config,
  );
  assert.equal(
    JSON.stringify(
      toPublicThinAppConfig(
        runtime,
      ),
    ).includes(
      "caiau_abc_secret",
    ),
    false,
  );
});

test("configuration rejects unsafe or ambiguous values", () => {
  assert.throws(
    () =>
      parseThinAppConfig({
        schemaVersion: "1",
        appId: "example",
        displayName:
          "Example",
        engine: {
          apiBaseUrl:
            "file:///tmp/engine",
        },
      }),
    /http or https/,
  );

  assert.throws(
    () =>
      parseThinAppConfig({
        schemaVersion: "1",
        appId: "example",
        displayName:
          "Example",
        engine: {
          apiBaseUrl:
            "https://engine.example",
        },
        features: {
          unknownFeature: true,
        },
      }),
    /not a recognized feature flag/,
  );

  assert.throws(
    () =>
      parseThinAppRuntimeConfig({
        config: {
          schemaVersion: "1",
          appId: "example",
          displayName:
            "Example",
          engine: {
            apiBaseUrl:
              "https://engine.example",
          },
        },
        secrets: {
          operatorToken:
            "caiae_wrong-family",
        },
      }),
    /caiau_/,
  );
});

test("runtime creates auth-specific clients without exposing tokens in config", () => {
  const runtime =
    createThinAppRuntime({
      config: {
        schemaVersion: "1",
        appId: "example",
        displayName:
          "Example",
        engine: {
          apiBaseUrl:
            "https://engine.example",
          organizationId: ORG,
        },
      },
      secrets: {
        operatorToken:
          "caiau_operator",
      },
    }, {
      fetchImpl:
        async () =>
          new Response(
            JSON.stringify({}),
            {
              status: 200,
              headers: {
                "content-type":
                  "application/json",
              },
            },
          ),
    });

  assert.ok(
    runtime.publicClient,
  );
  assert.ok(
    runtime.operatorClient,
  );
  assert.equal(
    runtime.serviceClient,
    null,
  );
  assert.equal(
    "secrets" in
      runtime.config,
    false,
  );
});
