# ADR 0003: Core compliance domain model

**Status:** Accepted

The engine uses a small set of generic nouns shared across statutory and regulatory domains:

- Organization
- Principal
- Resource
- Policy
- RuleSet
- Rule
- Obligation
- Authorization
- Exception
- Evidence
- Check
- Finding
- Remediation
- Certification
- Deadline
- AuditEvent

Every regulated thing is modeled as a generic **Resource** with a stable `resourceType` and structured `attributes`. Policy-specific fields belong in downstream schemas/configuration rather than new upstream columns.

All domain records are scoped to an Organization. Cross-engine integrations use stable IDs and APIs rather than direct access to this engine's database.
