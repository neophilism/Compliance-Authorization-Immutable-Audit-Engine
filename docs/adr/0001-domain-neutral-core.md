# ADR 0001: Domain-neutral core

**Status:** Accepted

The upstream engine must not encode bill-specific nouns or statutory assumptions. Domain applications provide schemas, rules, labels, and workflows through configuration and extension points.

This prevents the reusable engine from becoming a disguised implementation of the first bill used to validate it.
