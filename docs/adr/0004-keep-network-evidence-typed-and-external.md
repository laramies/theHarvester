# Keep network evidence typed and external to target scope

Status: accepted

## Decision

Represent routing evidence with a closed set of typed observations attached to a canonical network-prefix result: observed route origin, per-peer BGP route, and RPKI validation. Preserve the existing scalar ASN result alongside those observations.

Every prefix record is explicitly marked `external-relationship`. Routing evidence never implies registration, ownership, authorized target scope, or permission for active discovery. The model therefore has no generic relationship type and no `owns` or `registered_to` fields.

Persist the structured observations in the existing `results.details_json` column, advance the semantic database version to 9, and project the same nested records through JSONL and the API. No table alteration is needed. A normalized relationship table is deferred until a concrete cross-run query requires it.

## Why

Observed BGP origin, one peer's route view, and RPKI authorization answer different questions and have different timestamps and provenance. Flattening them into an ASN or a generic graph edge would erase those distinctions and could incorrectly turn third-party routing data into target-scope authority.

The existing result-details seam already preserves structured virtual-host evidence and can round-trip these prefix observations without a schema migration. That is the smallest durable foundation for a later provider action.

## Consequences

Provider actions must emit a canonical prefix result, its scalar origin ASN, matching prefix action provenance, and an observed-origin record before adding BGP-route or RPKI observations. Per-peer ASNs and AS-path members remain evidence fields rather than promoted results. A future provider integration can enrich known ASN or prefix evidence without joining passive source selection or expanding active scope.

One prefix may carry at most 10,000 observations and 8 MiB of serialized details. These persistence limits fit beneath the existing 10 MiB JSONL import envelope and are independent of provider-response transport budgets.
