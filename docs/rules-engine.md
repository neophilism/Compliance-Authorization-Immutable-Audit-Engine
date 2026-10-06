# Declarative rules engine

The rules engine evaluates policy configuration without executing user-provided code.

## Ruleset format

Rulesets may be supplied as JSON or YAML and use schema version `"1"`.

A ruleset identifies a stable ruleset ID and version and contains one or more rules. Each rule has:

- a stable rule ID;
- title and severity;
- optional applicability expression;
- required compliance expression;
- optional required evidence types;
- optional JSON metadata.

## Expressions

Version 1 supports:

- `all`
- `any`
- `not`
- `exists`
- `equals`
- `notEquals`
- `in`
- `contains`
- `greaterThan`
- `greaterThanOrEqual`
- `lessThan`
- `lessThanOrEqual`

Expressions access evaluation data using validated dot-separated field paths such as:

```yaml
field: resource.attributes.encryption.atRest.enabled
operator: equals
value: true
```

No JavaScript, shell commands, templates, dynamic imports, regular expressions, or arbitrary functions are accepted.

## Three-valued evaluation

Predicates return `true`, `false`, or `unknown`.

A missing value is generally `unknown`, rather than silently failing. The `exists` operator explicitly tests whether a field is present.

For `all`:

- any false child makes the result false;
- otherwise any unknown child makes it unknown;
- otherwise it is true.

For `any`:

- any true child makes the result true;
- otherwise any unknown child makes it unknown;
- otherwise it is false.

## Rule results

A rule produces one of:

- `pass`
- `fail`
- `unknown`
- `not_applicable`

If applicability is false, the rule is not applicable. If applicability cannot be determined, the result is unknown.

If the compliance expression is true but a declared required evidence type is absent, the result is unknown rather than pass. PR 7 will add richer evidence semantics; PR 4 only uses evidence-type presence.

## Ruleset result

A ruleset:

- fails if any applicable rule fails;
- is unknown if none fail but at least one is unknown;
- otherwise passes.

Not-applicable rules do not count as failures.

## CLI

Evaluate a ruleset against a JSON context without changing engine source code:

```bash
npm run rules:evaluate -- \
  examples/rules/baseline-system-security.yaml \
  examples/rules/baseline-system-security.context.json
```

Exit codes:

- `0`: pass
- `1`: fail
- `2`: invalid input or execution error
- `3`: unknown


## Registered versions and traceability

PR 17 adds an optional immutable registry around this ruleset format.

A ruleset can still be evaluated directly as an ad-hoc document. For governed workflows, the same normalized document can instead be registered under its stable `id`/version, linked to generic authority references, activated for an effective window, and evaluated by registered version ID.

Registration does not alter the declarative expression language. It adds provenance, lifecycle, canonical hashing, and historical effective-date resolution around the existing evaluator.

See `docs/ruleset-traceability.md`.
