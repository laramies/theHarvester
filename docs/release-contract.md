# Release contract

These rules govern the 5.0.0 development line on `dev`. [CONTEXT.md](../CONTEXT.md) defines the domain terms; the source catalog, type declarations, CLI help, and OpenAPI document define exact interfaces.

When changing a rule, update this contract, the affected code, regression coverage, and operator documentation in the same PR. Update the glossary when the meaning of a term changes. Record a new decision only when the trade-off is hard to reverse and would otherwise surprise a future contributor.

When the release is cut, update the package version in `theHarvester/__init__.py` and the release heading in `CHANGELOG.md` together.

## Product boundary

- theHarvester is a finite, one-shot enumerator. Each invocation or submitted run has an explicit target, selected sources or actions, limits, and a terminal outcome.
- The CLI, authenticated REST API, and HarvestView use the same normalized terminal evidence. HarvestView provides the local browser interface for submitting and reviewing runs.
- The local API owns durable run records, reusable schedules, and one isolated worker. Every scheduled target becomes an ordinary finite run record; schedule policy and dispatch state remain separate from terminal evidence.

## Authorization and scope

- Every provider, DNS, or direct action stays within the operator's explicit target and selected activity. P0, P1, and P2 describe observable network behavior, not confidence or importance.
- The authorized hostname boundary is the operator's exact DNS name after canonicalization. A leading `www.` label is part of that boundary and is never stripped as a convenience alias of the registrable domain.
- P0 sources query existing providers or datasets. P1 actions query DNS about authorized names or addresses. P2 actions contact a target endpoint or cause equivalent direct interaction.
- Scope-extension candidates and external relationships remain review evidence. An operator decision is the only path that promotes them into a later run's authorized scope.
- ASN labels, registry records, BGP origins, RPKI states, DNS answers, and endpoint responses remain time-bound evidence. None establishes ownership, legal control, reachability, or authorization by itself.

## Execution and lifecycle

- The source catalog is the authority for canonical source names, aliases, credentials, result capabilities, and activity class. Explicit source names and capability selectors form a union; `all` selects every cataloged P0 source once.
- A source adapter returns `None` for ordinary completion or an immutable `SourceExecutionReport` when it must preserve an explicit outcome or stop reason. The central source runner owns observation collection, result counting, no-result classification, exception handling, and final source status.
- A result limit of zero removes the shared local cap on results and pages. Adapters continue until the provider is exhausted, but source-owned quotas, protocol maxima, response limits, and runtime safety bounds still apply. A source that stops at one of those boundaries must report an explicit partial outcome and stop reason.
- Source execution statuses are `completed`, `partial`, `failed`, `rate-limited`, and `skipped`. Mutable adapter fields such as `execution_status` and `stop_reason` are outside this release contract and are rejected, including when an adapter raises or is cancelled.
- Explicit proxy mode is fail-closed for every supported discovery source and action. If no configured proxy is available, execution makes no direct request and terminates with the sanitized `proxy-unavailable` reason.
- Run lifecycle statuses are `queued`, `running`, `cancelling`, `cancelled`, `completed`, and `failed`. Terminal evidence status is independently `complete`, `partial`, or `failed`; retained evidence survives a later cancellation or process failure.
- Run schedules support one-time, hourly, daily, weekly, and monthly recurrence. Daily, weekly, and monthly occurrences preserve the selected local wall-clock time; a monthly day that does not exist falls on that month’s final day.
- Imported runs enter as completed run records and execute no source or action. Action-only runs create independent run records instead of mutating the evidence of the run that supplied their candidate.

## Evidence and portability

- A merged result is canonical by result kind and value. Source and action provenance, typed observations, execution outcomes, timestamps, and artifact metadata remain attached through deduplication and persistence.
- API run details derive source contributions from saved provenance. Each row counts hostnames reported by that source, hostnames unique to it, and hostnames shared with other sources, plus the hostnames with retained DNS answers. The counts measure contribution within the run and saved DNS evidence, not independent corroboration or service reachability.
- JSONL is the primary single-run interchange format: one summary record followed by sorted finding records. It retains terminal evidence status, producer outcomes, provenance, and supported structured observations.
- SQLite is the canonical local multi-run store. Portable SQLite export contains every finalized evidence record, preserves original run IDs and canonical structured evidence, and excludes queue, cancellation, worker-lease, and legacy-observation state. Screenshot metadata travels with evidence; screenshot files remain separately managed artifacts.
- Legacy JSON and XML remain supported grouped reports for existing consumers. They are presentation formats and do not replace JSONL or SQLite when lossless provenance and structured evidence are required.

## Release gates

- Routine tests and CI use mocked provider responses, local services, RFC-reserved domains, and TEST-NET addresses. Live provider or target checks remain explicit operator-run integration work.
- Every executable source has offline contract coverage for its declared lifecycle, and the catalog gate rejects missing, duplicate, or unknown coverage.
- Persistence and interchange changes prove canonical export and import round trips. HarvestView changes pass a separate real-browser gate covering the affected operator workflow.
- Release publication requires green Python, formatting, lint, typing, container, security, documentation, and HarvestView browser checks at the publication head.

## Deferred boundaries

- Read-only cross-run change projections over finalized evidence are part of the release contract. Alerts and automatic reactions remain deferred, and a scheduled occurrence only submits finite enumeration runs.
- Cross-run source ranking remains a reporting decision. One run's source-contribution summary does not automatically select, disable, or rank sources.
- Distributed workers, multi-host operation, PostgreSQL, and hosted multi-user authorization require measured demand and new decisions. The release remains SQLite-first and local-operator focused.
- Automatic scope expansion remains deferred. Evidence can suggest a later target, while the operator controls every scope change.
