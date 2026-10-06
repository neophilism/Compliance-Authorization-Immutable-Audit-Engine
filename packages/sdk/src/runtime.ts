import {
  parseThinAppRuntimeConfig,
} from "./config.js";
import {
  createOperatorClient,
  createPublicClient,
  createServiceClient,
  type ComplianceEngineClient,
} from "./client.js";
import type {
  ThinAppRuntimeConfig,
} from "./types.js";

export type ThinAppRuntime = {
  config:
    ThinAppRuntimeConfig["config"];
  publicClient:
    ComplianceEngineClient;
  operatorClient:
    ComplianceEngineClient | null;
  serviceClient:
    ComplianceEngineClient | null;
};

export function createThinAppRuntime(
  input: unknown,
  options: {
    fetchImpl?: typeof fetch;
  } = {},
): ThinAppRuntime {
  const runtime =
    parseThinAppRuntimeConfig(
      input,
    );
  const common = {
    baseUrl:
      runtime.config.engine
        .apiBaseUrl,
    organizationId:
      runtime.config.engine
        .organizationId,
    requestTimeoutMs:
      runtime.config.engine
        .requestTimeoutMs,
    transport: {
      fetchImpl:
        options.fetchImpl,
    },
  };

  return {
    config: runtime.config,
    publicClient:
      createPublicClient(
        common,
      ),
    operatorClient:
      runtime.secrets
        ?.operatorToken
        ? createOperatorClient({
            ...common,
            token:
              runtime.secrets
                .operatorToken,
          })
        : null,
    serviceClient:
      runtime.secrets
        ?.serviceToken
        ? createServiceClient({
            ...common,
            token:
              runtime.secrets
                .serviceToken,
          })
        : null,
  };
}
