# Persist ASN organization attribution as sourced evidence

Status: accepted

## Decision

Store each ASN organization attribution as a typed domain observation backed by a normalized SQLite relationship row linking the run, ASN result, related hostname or IP result, and source execution. Keep SQLAlchemy rows private to `ResultStore`, and project the observation through JSONL and the API instead of treating an organization label as a mutable property of an ASN.

## Why

Provider labels can be missing, change over time, or disagree across sources. A normalized relationship preserves those conflicts and supports cross-run queries without overloading `results.details_json`; the current unreleased schema remains version 8 and initialization creates the additional table when absent. Organization attribution is retained for operator review and never establishes ownership, authorization, or target scope. Its exact IP subject can select an automatic RouteViews pivot, but the organization label itself is not a filter.

## Consequences

Every attribution must reference a canonical ASN result, an exact hostname or IP subject, and the source or action that produced both. Import and persistence fail closed on missing, duplicate, or noncanonical relationships. Provider labels remain independently visible when they conflict and cannot authorize target-scope expansion.
