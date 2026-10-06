# ADR 0004: Declarative rules instead of executable policy code

**Status:** Accepted

Compliance policy is represented as validated data, not executable user-provided code.

Version 1 rulesets are JSON/YAML documents with a fixed schema. They contain applicability expressions, required compliance expressions, severity, evidence-type requirements, and metadata.

The evaluator supports a bounded operator vocabulary and deterministic three-valued logic. Missing facts normally produce `unknown`, while the explicit `exists` operator tests presence.

The engine does not evaluate JavaScript, shell expressions, templates, dynamic imports, arbitrary functions, or regular expressions supplied by a ruleset.

This design provides:

- predictable and reproducible results;
- inspectable policy configuration;
- safer handling of untrusted or externally authored rules;
- straightforward versioning and historical reproduction;
- a stable path for thin statutory applications to change policy without forking engine logic.

Future rule-language extensions must remain deterministic and explicitly versioned.
