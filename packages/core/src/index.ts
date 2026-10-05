export type EntityId = string;

export type AuditActor = {
  id: EntityId;
  type: "user" | "service";
};

export type HealthStatus = {
  status: "ok";
  service: string;
  timestamp: string;
};
