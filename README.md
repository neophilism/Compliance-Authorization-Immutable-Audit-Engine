# Compliance, Authorization & Immutable Audit Engine

Reusable civic infrastructure for compliance rules, authorization decisions, tamper-evident audit history, evidence, deadlines, findings, remediation, certification, and reporting.

## Core lifecycle

`rule -> authorization -> action/event -> evidence -> deadline -> review -> finding -> remediation -> certification/report`

The upstream engine is intentionally domain-neutral. Bill-specific applications should contribute schemas, rules, terminology, workflows, and presentation without embedding their nouns into the core.

## Repository layout

- `apps/api` — Fastify API service.
- `apps/worker` — scheduled checks, deadlines, escalations, and background jobs.
- `apps/web` — Next.js reference administration interface.
- `packages/core` — shared TypeScript domain primitives.
- `docs/architecture.md` — architectural boundaries.
- `docs/adr` — architecture decision records.
- `docs/roadmap.md` — PR milestones.

## Local development

Requirements: Node.js 20+, npm, Docker.

```bash
cp .env.example .env
docker compose up -d
npm install
npm run typecheck
npm test
npm run build
npm run dev:api
```

In separate terminals:

```bash
npm run dev:web
npm run dev:worker
```

The API health endpoint is `GET http://localhost:4000/health`.

## Design commitments

1. Historical audit events are append-only; corrections are new events.
2. Domain rules are configuration, not hard-coded bill logic.
3. Cross-engine integration occurs through stable APIs/events, not shared database tables.
4. Every milestone must leave the repository buildable and testable.

See the development roadmap for the sequence from foundation through the first thin statutory applications.
