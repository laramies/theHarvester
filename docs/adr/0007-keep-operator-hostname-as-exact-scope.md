# Keep the operator hostname as the exact scope boundary

Status: accepted

## Decision

Treat the operator-supplied DNS name, after lowercase, trailing-dot, and IDNA canonicalization, as the exact authorization boundary. A leading `www.` label is part of that name and is never removed as an alias for the apex domain. Accepted hostname results must equal that boundary or be descendants of it.

A passive provider adapter may derive an apex-domain query only when its API contract requires one. That provider-specific query term does not widen result scope: every returned hostname still passes through the shared exact-boundary normalization before it becomes evidence.

## Why

Removing `www.` silently changes a request for one DNS subtree into a request for the broader registrable domain. DNS does not define `www.example.test` as equivalent to `example.test`, so treating it as an alias would expand operator scope without a decision.

Separating provider query construction from result-scope enforcement lets constrained passive APIs remain usable without letting their response shape redefine authorization.

## Consequences

Hostname normalization preserves a leading `www.` label, canonicalizes Unicode and IP values centrally, and rejects sibling or apex names outside the exact target boundary. Provider adapters can keep narrowly documented query transformations, but they cannot bypass shared result normalization. Legacy parsers that implement the old `www.` stripping rule are removed when they have no active callers.
