# Fail closed when explicit proxy mode is unavailable

Status: accepted

## Decision

When an operator enables proxy mode, every supported discovery source and action must use a configured proxy. If none
is available, make no direct request and terminate with the sanitized `proxy-unavailable` reason.

One provider execution selects one proxy identity and keeps it for the owned request conversation. It must not silently
rotate or retry without a proxy.

## Why

Explicit proxy mode is an operator transport requirement. Falling back to a direct connection would violate that
requirement and could expose network identity without a visible failure.

## Consequences

Shared session construction rejects empty proxy configuration. The source runner selects and pins one concrete proxy
before it starts an adapter, keeps that identity through the complete source execution, and records the normalized
terminal outcome. Direct action owners use the same selection boundary; source adapters are not a separate transport
policy boundary. Tests cover one selection per execution and action, configured transport, and empty proxy
lists.
