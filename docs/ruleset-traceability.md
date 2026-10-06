# Ruleset versioning and legal traceability

PR 17 adds a canonical registry around the declarative rules already used by the compliance engine.

The existing evaluation guarantee remains unchanged: every check keeps the exact normalized ruleset snapshot, context snapshot, evidence trace, result, and evaluation time that produced the decision.

PR 17 adds a second, complementary guarantee: when a check uses a registered ruleset version, the engine can identify exactly which immutable registered version and source authorities the snapshot came from.

## Registered version model

A registered ruleset version has:

- an organization and policy;
- a stable ruleset key;
- a version identifier;
- immutable normalized definition content;
- a canonical SHA-256 definition hash;
- draft, active, superseded, or retired lifecycle state;
- an effective-from/effective-to window;
- optional supersession lineage;
- zero or more generic authority/source references.

Content and lineage fields are protected by a PostgreSQL trigger after registration. Lifecycle fields such as status and effective dates can change only through the normal lifecycle operations.

## Authority references

Authority references are deliberately domain-neutral. A downstream application can link a ruleset to any source by supplying fields such as:

```json
{
  "authorityType": "statute",
  "citation": "Example Code section 1",
  "title": "Example Authority",
  "uri": "https://example.invalid/source",
  "locator": "section 1(a)",
  "jurisdiction": "example"
}
```

The engine does not interpret the legal meaning of `authorityType`, `citation`, `locator`, or `jurisdiction`. Bill-specific citation conventions belong in downstream configuration.

Authority references receive their own canonical hashes, so identical source descriptions are deduplicated within an organization.

## Lifecycle

Registration always creates a draft immutable version.

Activation:

1. verifies the version is draft;
2. establishes its effective start;
3. rejects overlapping effective versions for the same organization/key lineage;
4. marks a declared predecessor superseded when appropriate;
5. closes the predecessor's effective window;
6. writes audit events for both activation and supersession.

Retirement closes a version's effective window and preserves the historical record.

Historical resolution considers active, superseded, and retired versions. A version that is no longer current can therefore still be resolved for a date when it was legally/effectively in force.

## Evaluation modes

Checks support exactly one of:

### Registered

```json
{
  "registeredRuleSetId": "..."
}
```

The engine verifies that the registered version is non-draft and effective at the evaluation time. The check then stores:

- `rule_set_id`;
- the exact ruleset snapshot;
- the canonical definition hash;
- a traceability manifest containing policy/version/effective-window/source information.

### Ad hoc

```json
{
  "ruleSet": {
    "schemaVersion": "1",
    "...": "..."
  }
}
```

Ad-hoc evaluation remains supported for experimentation, draft workflows, and downstream applications that do not need the registry. The check still receives a canonical SHA-256 hash and a provenance manifest explicitly marked `registrationMode: "ad_hoc"`.

Providing both inputs, or neither input, is rejected.

## Scheduled and integration checks

Evaluation schedules preserve the same registration mode, hash, and provenance manifest. A scheduled registered check revalidates the registered version against the scheduled evaluation time.

The PR 13 service integration endpoint also accepts either `ruleSet` or `registeredRuleSetId`, so machine-triggered evaluations can use the same canonical versions as human/operator workflows.

## Certifications and reports

Certification artifacts preserve the supporting check's registered ruleset ID, definition hash, and internal provenance summary. The public certification artifact exposes the registered ruleset ID and hash without exposing the full internal authority manifest.

Compliance reports add:

- registered ruleset ID;
- canonical ruleset hash;
- registration mode.

The Registry projection receives the same compact provenance fields.

## API

Registry lifecycle:

```
POST /v1/rulesets
GET  /v1/rulesets/:id
GET  /v1/rulesets/:id/traceability
POST /v1/rulesets/:id/activate
POST /v1/rulesets/:id/retire
GET  /v1/organizations/:organizationId/rulesets
GET  /v1/organizations/:organizationId/rulesets/resolve/:key
```

PR 16 protects these routes with the generic `rulesets.read` and `rulesets.write` permissions.

## Audit events

Ruleset lifecycle events are appended to the existing tamper-evident ledger:

- `rule_set.registered`;
- `rule_set.activated`;
- `rule_set.superseded`;
- `rule_set.retired`.

Check creation/completion events include the registered ruleset ID and canonical hash where applicable.
