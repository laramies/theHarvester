# Persist ASN organization attribution as sourced evidence

Store each ASN organization attribution as a typed domain observation backed by a normalized SQLite relationship row linking the run, ASN result, related hostname or IP result, and source execution. Keep SQLAlchemy rows private to `ResultStore`, and project the observation through JSONL and the API instead of treating an organization label as a mutable property of an ASN.

Provider labels can be missing, change over time, or disagree across sources. A normalized relationship preserves those conflicts and supports cross-run queries without overloading `results.details_json`; the current unreleased schema remains version 8 and initialization creates the additional table when absent. Organization attribution is retained for operator review and does not filter RouteViews pivots or establish ownership, authorization, or target scope.
