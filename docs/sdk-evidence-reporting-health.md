# SDK evidence, reporting, and health boundary

Thin applications should not construct raw engine HTTP routes when the engine
already exposes a reusable generic lifecycle.

This SDK update completes three remaining access-layer gaps discovered while
finishing the first downstream thin application.

## Evidence

The SDK now exposes the generic evidence lifecycle:

- create evidence;
- get evidence with attestations;
- list evidence for a resource;
- list currently valid evidence types for a resource;
- add an attestation;
- revoke evidence;
- revoke an attestation.

The configured SDK organization is bound automatically on evidence creation and
resource-scoped listing.

The evidence service remains responsible for validity windows, supersession,
attestation rules, revocation, immutable audit events, and persistence.

## Compliance reports

`getComplianceReport(resourceId?, asOf?)` supports the engine's existing
point-in-time JSON report.

`getRenderedComplianceReport(format, resourceId?, asOf?)` exposes the
existing CSV and text renderers without making downstream applications
reconstruct report URLs or media types.

No reporting calculations or rendering logic are duplicated in the SDK.

## Health

`getHealth()` exposes the engine's public `/health` endpoint through the
same client boundary used for other public operations.

It does not require an organization binding.

## Policy neutrality

These methods contain no policy-specific evidence types, report sections,
statutory clocks, Federal terminology, or downstream presentation rules.

They are transport/access abstractions over capabilities already owned by the
master engine.
