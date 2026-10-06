import type {
  AuthenticatedService,
  CaseWorkflowTrigger,
  RegistryComplianceProjection,
} from "./types.js";

export interface RegistryIntegrationAdapter {
  getRegistryProjection(
    auth: AuthenticatedService,
    resourceId: string,
  ): Promise<RegistryComplianceProjection>;
}

export interface CaseWorkflowIntegrationAdapter {
  listCaseTriggers(
    auth: AuthenticatedService,
    options?: {
      limit?: number;
      severity?: string | null;
    },
  ): Promise<CaseWorkflowTrigger[]>;
}
