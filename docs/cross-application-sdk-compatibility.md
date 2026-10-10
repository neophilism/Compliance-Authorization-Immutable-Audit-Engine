# Cross-application SDK acceptance

The reusable @caiae/sdk package must allow multiple policy-specific applications to coexist without duplicating engine persistence, service classes, or endpoint construction.

CI now tests two independent thin-app configurations: Federal Encryption Compliance and Algorithmic Accountability. Each has its own organization ID, operator credential, resource vocabulary, and enabled feature set while using the same typed API client classes. Public clients omit bearer authorization headers, and exposed configuration contains no runtime credentials.

The tests exercise transport and configuration invariants, not external deployments. The authoritative HTTP API must still enforce organization-scoped access control; a client-supplied organization identifier alone is not an authorization boundary. Separate end-to-end API security tests exercise that boundary in PR 33 and earlier PR 16.

Maintain these tests whenever the generic SDK or its configuration schema changes. Policy-specific rule definitions and screens remain in the downstream application repositories.
