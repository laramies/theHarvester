# Pin takeover rule revisions and preserve evidence

The first reviewed rule revision bundles provider-gated evidence checks derived from can-i-take-over-xyz at `5bd4e128` and compound predicates from nuclei-templates at `9090ee10`. Bundling the reviewed revision keeps network failure or an upstream edit from silently changing evidence coverage between runs.

Persist evidence as UTF-8 JSON. The HTTP client can represent undecodable header bytes as lone surrogates, so redirect locations need a UTF-8-safe representation before persistence. An absent, oversized, or undecodable location must not prevent an otherwise valid check from retaining its outcome.
