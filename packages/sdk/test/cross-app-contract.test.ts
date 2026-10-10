import assert from "node:assert/strict";
import test from "node:test";
import { createThinAppRuntime, toPublicThinAppConfig } from "../src/index.js";

const FEDERAL_ORG = "11111111-1111-4111-8111-111111111111";
const ALGORITHM_ORG = "22222222-2222-4222-8222-222222222222";

test("two independent thin apps share one typed engine contract without sharing credentials or organization scope", async () => {
  const calls: Array<{ url: string; authorization: string | undefined }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    const headers = init?.headers as Record<string, string>;
    calls.push({ url, authorization: headers.authorization });
    const payload = url.endsWith("/health") ?
      { status: "ok", service: "api", release: "test", timestamp: new Date().toISOString() } :
      [];
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const federal = createThinAppRuntime({
    config: {
      schemaVersion: "1",
      appId: "federal-encryption",
      displayName: "Federal Encryption Compliance",
      engine: { apiBaseUrl: "https://engine.example", organizationId: FEDERAL_ORG },
      features: { resources: true, evidence: true, checks: true, reporting: true },
      resourceTypes: { cryptographicSystem: { label: "Cryptographic System" } },
    },
    secrets: { operatorToken: "caiau_federal_operator_token" },
  }, { fetchImpl });

  const algorithmic = createThinAppRuntime({
    config: {
      schemaVersion: "1",
      appId: "algorithmic-accountability",
      displayName: "Algorithmic Accountability",
      engine: { apiBaseUrl: "https://engine.example", organizationId: ALGORITHM_ORG },
      features: { resources: true, checks: true, reporting: true, publication: true },
      resourceTypes: { modelDeployment: { label: "Model Deployment" } },
    },
    secrets: { operatorToken: "caiau_algorithmic_operator_token" },
  }, { fetchImpl });

  assert.ok(federal.operatorClient);
  assert.ok(algorithmic.operatorClient);
  assert.equal(federal.serviceClient, null);
  assert.equal(algorithmic.serviceClient, null);

  await federal.operatorClient!.listResources();
  await algorithmic.operatorClient!.listResources();
  await federal.publicClient.getHealth();
  await algorithmic.publicClient.getHealth();

  assert.match(calls[0]!.url, new RegExp("/v1/organizations/" + FEDERAL_ORG + "/resources"));
  assert.match(calls[1]!.url, new RegExp("/v1/organizations/" + ALGORITHM_ORG + "/resources"));
  assert.equal(calls[0]!.authorization, "Bearer caiau_federal_operator_token");
  assert.equal(calls[1]!.authorization, "Bearer caiau_algorithmic_operator_token");
  assert.equal(calls[2]!.authorization, undefined);
  assert.equal(calls[3]!.authorization, undefined);

  const publicFederal = toPublicThinAppConfig(federal.config);
  const publicAlgorithm = toPublicThinAppConfig(algorithmic.config);
  assert.equal(publicFederal.appId, "federal-encryption");
  assert.equal(publicAlgorithm.appId, "algorithmic-accountability");
  assert.equal(JSON.stringify(publicFederal).includes("caiau_"), false);
  assert.equal(JSON.stringify(publicAlgorithm).includes("caiau_"), false);

  // Each app owns its own vocabulary, while the upstream engine uses generic resource semantics.
  assert.deepEqual(Object.keys(publicFederal.resourceTypes ?? {}), ["cryptographicSystem"]);
  assert.deepEqual(Object.keys(publicAlgorithm.resourceTypes ?? {}), ["modelDeployment"]);
});

test("thin app runtime rejects accidental cross-family operator and service credential use", () => {
  const config = {
    schemaVersion: "1", appId: "example", displayName: "Example",
    engine: { apiBaseUrl: "https://engine.example", organizationId: FEDERAL_ORG },
  };
  assert.throws(() => createThinAppRuntime({
    config, secrets: { operatorToken: "caiae_wrong_service_token" },
  }), /caiau_/);
  assert.throws(() => createThinAppRuntime({
    config, secrets: { serviceToken: "caiau_wrong_operator_token" },
  }), /caiae_/);
});
