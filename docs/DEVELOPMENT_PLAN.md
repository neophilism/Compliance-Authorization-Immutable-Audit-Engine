# Compliance, Authorization & Immutable Audit Engine — recovered original development plan and independent-account handoff

**Historical source:** Original October 5 reusable 21-work-package plan. Numbered 21-milestone original roadmap recovered from the previous conversations and cross-checked with checked-in roadmap and technical documentation. This document preserves original scope and, where applicable, separates later extensions. Technical per-item acceptance language is an engineering elaboration rather than a purported verbatim transcript; a milestone ID is **not** a GitHub PR number.

## Product mandate and governing boundaries

Domain-neutral compliance and authorization infrastructure. Governing process: rule → authorization → action/event → evidence → deadline → review → finding → remediation → certification/report. Engine owns generic versioned rule evaluation, audit, persistence, APIs, policy execution and reporting. Federal Encryption Compliance and Algorithmic Accountability are thin downstream applications; no federal-only or algorithm-only rules in the shared engine.

## Original milestone sequence

### CA-01 — Foundation and architecture

- **Deliverable:** Create TypeScript monorepo, API, web/admin shell, worker, PostgreSQL/CI, provider-neutral adapters and ADRs.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-02 — Core compliance domain model

- **Deliverable:** Versioned organizations, resources, actors, controls, obligations, rules, authorizations, findings and evidence.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-03 — Tamper-evident audit ledger

- **Deliverable:** Append-only actor/time/subject event chain, hash checkpoints, independent verification and correction semantics.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-04 — Declarative rules engine

- **Deliverable:** Configuration DSL/policy bundles, typed predicates, deterministic evaluation and immutable input provenance.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-05 — Authorization lifecycle

- **Deliverable:** Request/review/approve/conditional/deny/expire/revoke, distinct decision rights and enforcement.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-06 — Exceptions and waivers

- **Deliverable:** Time-bounded justified exceptions with approver evidence, revocation, renewal and visible risk.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-07 — Evidence and attestations

- **Deliverable:** Versioned signed references, document policy, provenance, expiry and attestations linked to controls.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-08 — Deadlines and statutory clocks

- **Deliverable:** Jurisdiction-aware deadline rules, pauses/extensions/late escalations and business calendars as explicit policy.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-09 — Automated compliance evaluation

- **Deliverable:** Scheduler and event-triggered checks producing traceable pass/fail/unknown outcomes, not automatic approvals.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-10 — Findings and remediation

- **Deliverable:** Severity, owner, appeal/corrective actions, verification/reopening and linkage to authorizations.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-11 — Certification

- **Deliverable:** Rules-based attested decisions with validity, denial, renewal and revocation, no certification from missing proof.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-12 — Reporting

- **Deliverable:** Organization and reviewer dashboards, audit exports, compliance/filing reports and summary redaction.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-13 — API and integrations

- **Deliverable:** Scoped API/SDK, OpenAPI, idempotent webhooks, authenticated services, retry/replay controls.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-14 — Reference administration UI

- **Deliverable:** Tenant-scoped work queues, rules, evidence, waivers, deadlines, authorizations and findings.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-15 — Publication controls

- **Deliverable:** Separate private reviews from releasable reports with reasoned redactions/approvals.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-16 — Security and permissions

- **Deliverable:** RBAC/ABAC, tenant isolation, step-up privileged actions, secret protection and audit alarms.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-17 — Ruleset versioning and legal traceability

- **Deliverable:** Pin policy source, effective dates, signed versions and historical outcome reproducibility.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-18 — Configuration SDK

- **Deliverable:** Thin app policy bundles, legal-field schemas, typed client API and isolated theming.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-19 — Production readiness

- **Deliverable:** CI, performance, restore rehearsals, migrations, health, monitoring, security and acceptance gates.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-20 — Federal Encryption thin application

- **Deliverable:** Separate downstream policy and UI app proving reusable engine contracts, not federal logic added upstream.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

### CA-21 — Second application and abstraction test

- **Deliverable:** Independent Algorithmic Accountability app or another materially different consumer proving domain neutrality.
- **Acceptance:** Exercise correct transition/report/view, invalid data, permission denial, dependency failures and audit/provenance. Add deterministic unit/integration tests and document migrations, APIs and policy boundaries. Do not mark source/demo/SDK implementation as a live production integration.

## Dependencies and source-of-truth documents

- [docs/roadmap.md](../docs/roadmap.md)
- [docs/architecture.md](../docs/architecture.md)
- [docs/authorization-engine.md](../docs/authorization-engine.md)
- [docs/audit-ledger.md](../docs/audit-ledger.md)
- [docs/rules-engine.md](../docs/rules-engine.md)
- [docs/security-permissions.md](../docs/security-permissions.md)
- [docs/production-readiness.md](../docs/production-readiness.md)

A later implementation added milestones beyond the first 21 to handle real production verification, monitoring and downstream integration. Do not confuse original plan item numbers with GitHub PR numbers; Dependabot and maintenance PRs also occurred. Preserve the 21-item approved baseline and version additions.

## Execution / release / status rules

1. Read this plan plus the checked-in policy/data model, ADRs, current README and linked runbooks. Discover open and merged actual PRs, CI, image versions, migration versions, release tags, live Render/Neon state and dependent app contract versions; never trust outdated conversational status.
2. Create and maintain a mapping **roadmap ID → GitHub PR(s) → tests → release/deployment evidence**, preserving historical 2026 plan numbering and app-specific changes as separately versioned additions. Only verified merged functionality counts toward development; production evidence is independent.
3. Keep the engine reusable where applicable. Enforce documented negative paths, role/tenant leakage, audit integrity and source validity. Avoid unreviewed policy in upstream code, mock approval of legal obligations, and claims of real-world regulatory compliance from fictional cases.
4. Continue implementation in small chained PRs with required tests, migrations, review of security implications and rollback plan; stop when permissions, credentials, external provider/legal requirements or failing gates make it necessary. Consult the user only for material product and real credentials/authorization decisions.
5. Require real environment health/readiness, DB migrations, backup restoration, media/document storage and malware scanning where applicable, accessibility/security review and demonstrated end-to-end consumer flows before calling a production release complete.

## Recovery confidence

**The original 21 ordered milestones are recovered** and supported by the previous conversation and current repository docs. Current code/CI/live deployment evidence is not established by creating this document.
