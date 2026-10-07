# Findings, remediation, and certification SDK boundary

The compliance engine already owns the generic lifecycle for findings,
remediations, and certifications. Thin applications should access that lifecycle
through `@caiae/sdk` rather than importing service or persistence packages
directly.

## Findings

The SDK exposes:

- synchronization of findings from a failed check;
- finding retrieval and resource-scoped listing;
- owner assignment;
- acknowledgement, dispute, dispute resolution, closure, and reopening.

The engine remains responsible for lifecycle validation and immutable audit
events. A downstream application supplies only its policy-specific meaning,
labels, evidence, and workflow decisions.

## Remediation

Remediation is part of the generic finding lifecycle. The SDK exposes:

- remediation plan creation;
- start;
- submission for verification;
- verification;
- rejection;
- cancellation.

If a remediation includes a due date, the existing findings service creates and
manages the generic remediation deadline. Verification satisfies that deadline;
rejection or cancellation handles its associated clock according to the existing
engine rules.

Thin applications must not recreate remediation state machines or deadline
persistence.

## Certifications

The SDK exposes:

- certification issuance;
- retrieval and resource-scoped listing;
- renewal;
- suspension;
- reinstatement;
- revocation.

The configured SDK organization is bound automatically when a certification is
issued. The underlying certification service remains responsible for supporting
check validation, blocking-finding criteria, validity windows, certificate
identifiers, immutable audit events, and lifecycle state transitions.

Public verification remains available through the existing
`publicVerifyCertification()` method.

## Policy neutrality

These SDK methods contain no Federal Encryption concepts and no statute-specific
criteria. A thin application may use generic metadata, criteria, conditions, and
certification types to express its policy-specific obligations while leaving the
lifecycle machinery upstream.

For example, an annual statutory certification can be represented downstream by
choosing a policy-specific `certificationType`, attaching the required report
metadata, and referencing the supporting compliance check. The engine does not
interpret the statute itself.
