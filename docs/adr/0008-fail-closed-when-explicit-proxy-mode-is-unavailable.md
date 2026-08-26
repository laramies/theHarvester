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

Shared session construction rejects empty proxy configuration, the source runner records the normalized terminal
outcome, and direct adapter callers preserve the same reason. Tests cover configured selection and empty proxy lists.
