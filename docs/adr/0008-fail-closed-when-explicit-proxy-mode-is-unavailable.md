# Fail closed when explicit proxy mode is unavailable

Status: superseded by ADR-0009

## Decision

When an operator enables proxy mode, every supported discovery source and action must use a configured proxy. If none
is available, make no direct request and terminate with the sanitized `proxy-unavailable` reason.

One provider execution selects one proxy identity and keeps it for the owned request conversation. It must not silently
rotate or retry without a proxy.

Sources and actions that require direct DNS are not supported in proxy mode and must be rejected before result
persistence. Proxying DNS is a separate transport feature, not an implicit exception to the operator requirement.

## Why

Explicit proxy mode is an operator transport requirement. Falling back to a direct connection would violate that
requirement and could expose network identity without a visible failure.

## Consequences

The run entry point rejects empty proxy configuration before initializing result persistence. The source runner keeps
the same guard for standalone callers, selects and pins one concrete proxy before it starts an adapter, and records the
normalized terminal outcome. Direct action owners use the same selection boundary; source adapters are not a separate
transport policy boundary. Tests cover immediate rejection, one selection per execution and action, and configured
transport. A configured proxy endpoint failure is recorded as `transport-error`.
