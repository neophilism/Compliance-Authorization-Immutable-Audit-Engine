import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { JsonObject, Organization, Policy, Resource } from "@caiae/core";

type OrganizationInput = {
  name: string;
  slug: string;
  metadata?: JsonObject;
};

type PolicyInput = {
  organizationId: string;
  key: string;
  title: string;
  description?: string;
  status?: Policy["status"];
  metadata?: JsonObject;
};

type ResourceInput = {
  organizationId: string;
  resourceType: string;
  name: string;
  externalRef?: string | null;
  status?: Resource["status"];
  attributes?: JsonObject;
  metadata?: JsonObject;
};

export class DomainRepository {
  constructor(private readonly pool: Pool) {}

  async createOrganization(input: OrganizationInput): Promise<Organization> {
    const id = randomUUID();
    const result = await this.pool.query(
      `INSERT INTO organizations(id, name, slug, status, metadata)
       VALUES ($1, $2, $3, 'active', $4::jsonb)
       RETURNING *`,
      [id, input.name, input.slug, JSON.stringify(input.metadata ?? {})],
    );
    return mapOrganization(result.rows[0]);
  }

  async getOrganization(id: string): Promise<Organization | null> {
    const result = await this.pool.query("SELECT * FROM organizations WHERE id = $1", [id]);
    return result.rows[0] ? mapOrganization(result.rows[0]) : null;
  }

  async createPolicy(input: PolicyInput): Promise<Policy> {
    const id = randomUUID();
    const result = await this.pool.query(
      `INSERT INTO policies(id, organization_id, key, title, description, status, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING *`,
      [
        id,
        input.organizationId,
        input.key,
        input.title,
        input.description ?? "",
        input.status ?? "draft",
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapPolicy(result.rows[0]);
  }

  async getPolicy(id: string): Promise<Policy | null> {
    const result = await this.pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    return result.rows[0] ? mapPolicy(result.rows[0]) : null;
  }

  async createResource(input: ResourceInput): Promise<Resource> {
    const id = randomUUID();
    const result = await this.pool.query(
      `INSERT INTO resources(
         id, organization_id, resource_type, name, external_ref, status, attributes, metadata
       ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb)
       RETURNING *`,
      [
        id,
        input.organizationId,
        input.resourceType,
        input.name,
        input.externalRef ?? null,
        input.status ?? "active",
        JSON.stringify(input.attributes ?? {}),
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapResource(result.rows[0]);
  }

  async getResource(id: string): Promise<Resource | null> {
    const result = await this.pool.query("SELECT * FROM resources WHERE id = $1", [id]);
    return result.rows[0] ? mapResource(result.rows[0]) : null;
  }

  async listResources(organizationId: string, resourceType?: string): Promise<Resource[]> {
    const result = resourceType
      ? await this.pool.query(
          "SELECT * FROM resources WHERE organization_id = $1 AND resource_type = $2 ORDER BY created_at",
          [organizationId, resourceType],
        )
      : await this.pool.query(
          "SELECT * FROM resources WHERE organization_id = $1 ORDER BY created_at",
          [organizationId],
        );

    return result.rows.map(mapResource);
  }
}

function iso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function mapOrganization(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    status: row.status,
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapPolicy(row: any): Policy {
  return {
    id: row.id,
    organizationId: row.organization_id,
    key: row.key,
    title: row.title,
    description: row.description,
    status: row.status,
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function mapResource(row: any): Resource {
  return {
    id: row.id,
    organizationId: row.organization_id,
    resourceType: row.resource_type,
    name: row.name,
    externalRef: row.external_ref,
    status: row.status,
    attributes: row.attributes ?? {},
    metadata: row.metadata ?? {},
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}
