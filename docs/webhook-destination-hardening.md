# Webhook destination safety (PR 40)

Webhook subscriptions now require HTTPS DNS hostnames. HTTP, credentials embedded in URLs, IP literals (including IPv6 and alternate IPv4 spellings), localhost, .localhost, .local, .internal, URL fragments, and non-default ports are rejected.

Existing subscriptions are revalidated when a pending delivery is attempted; an old unsafe URL will be recorded as a delivery failure rather than fetched. Webhook HTTP requests disable redirects and have a 10-second abort timeout, bounding worker exposure to unreachable receivers.

Security boundary and residual risk: a hostname that is publicly resolvable during validation may later resolve to an internal IP due to DNS rebinding or poisoned DNS. The default Node fetch client does not pin and validate the resolved IP at connection time. Production must also enforce outbound network egress restrictions or use a hardened webhook egress proxy with connection-time DNS/IP validation. These safeguards reduce risk but do NOT establish absolute SSRF resistance.

Tests cover URL policy and the delivery request settings. The engine retains its existing HMAC signed webhook delivery lifecycle and retry/backoff semantics.
