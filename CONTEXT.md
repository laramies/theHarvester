# theHarvester release context

Status: accepted release baseline

Release: 5.0.0 development line on `dev`

Reconciled: 2026-08-16

This document is the semantic source of truth for the 5.0.0 release. It defines the product boundary, execution model, evidence contract, scope rules, and shared language used by code, tests, issues, pull requests, output, and operator documentation.

Version 5.0.0 is the accepted release target. The package version in `theHarvester/__init__.py` and the release heading in `CHANGELOG.md` are updated together when the release is cut. Exact flags, source names, result kinds, schemas, and routes remain authoritative in the executable catalog, type declarations, CLI help, and OpenAPI document. This file records the meanings and boundaries those interfaces must preserve.

When a change alters one of these boundaries, update this document and the nearest decision record in the same pull request. Completion means the implementation, focused regression coverage, operator documentation, and this context express the same contract.

## Release contract

### Product boundary

- theHarvester is a finite, one-shot enumerator. Each invocation or submitted run has an explicit target, selected sources or actions, limits, and a terminal outcome.
- The CLI, authenticated REST API, and HarvestView project the same normalized terminal evidence. HarvestView is the local browser workspace for submitting and reviewing runs; it is not a separate discovery engine.
- The local API owns durable run records, reusable schedules, and one isolated worker. Every scheduled target becomes an ordinary finite run record; schedule policy and dispatch state remain separate from terminal evidence.

### Authorization and scope

- Every provider, DNS, or direct action stays within the operator's explicit target and selected activity. P0, P1, and P2 describe observable network behavior, not confidence or importance.
- The authorized hostname boundary is the operator's exact DNS name after canonicalization. A leading `www.` label is part of that boundary and is never stripped as a convenience alias of the registrable domain.
- P0 sources query existing providers or datasets. P1 actions query DNS about authorized names or addresses. P2 actions contact a target endpoint or cause equivalent direct interaction.
- Scope-extension candidates and external relationships remain review evidence. An operator decision is the only path that promotes them into a later run's authorized scope.
- ASN labels, registry records, BGP origins, RPKI states, DNS answers, and endpoint responses remain time-bound evidence. None establishes ownership, legal control, reachability, or authorization by itself.

### Execution and lifecycle

- The source catalog is the authority for canonical source names, aliases, credentials, result capabilities, and activity class. Explicit source names and capability selectors form a union; `all` selects every cataloged P0 source once.
- A source adapter returns `None` for ordinary completion or an immutable `SourceExecutionReport` when it must preserve an explicit outcome or stop reason. The central source runner owns observation collection, result counting, no-result classification, exception handling, and final source status.
- A result limit of zero removes the shared local cap on results and pages. Adapters continue until the provider is exhausted, but source-owned quotas, protocol maxima, response limits, and runtime safety bounds still apply. A source that stops at one of those boundaries must report an explicit partial outcome and stop reason.
- Source execution statuses are `completed`, `partial`, `failed`, `rate-limited`, and `skipped`. Mutable adapter fields such as `execution_status` and `stop_reason` are outside this release contract and are rejected, including when an adapter raises or is cancelled.
- Explicit proxy mode is fail-closed for every supported discovery source and action. If no configured proxy is available, execution makes no direct request and terminates with the sanitized `proxy-unavailable` reason. Sources and actions that require direct DNS are rejected before result persistence; a configured proxy endpoint failure is recorded as `transport-error`.
- Run lifecycle statuses are `queued`, `running`, `cancelling`, `cancelled`, `completed`, and `failed`. Terminal evidence status is independently `complete`, `partial`, or `failed`; retained evidence survives a later cancellation or process failure.
- Run schedules support one-time, hourly, daily, weekly, and monthly recurrence. Daily, weekly, and monthly occurrences preserve the selected local wall-clock time; a monthly day that does not exist falls on that month’s final day.
- Imported runs enter as completed run records and execute no source or action. Action-only runs create independent run records instead of mutating the evidence of the run that supplied their candidate.

### Evidence and portability

- A merged result is canonical by result kind and value. Source and action provenance, typed observations, execution outcomes, timestamps, and artifact metadata remain attached through deduplication and persistence.
- API run details derive per-source hostname yields from persisted normalized provenance. The counts cover observed, unique, shared, DNS-resolved, and unique DNS-resolved hostnames. A hostname is unique when no other source in the run reported it. It is DNS-resolved when the run retained an A, AAAA, or CNAME answer. These counts measure marginal coverage and current DNS evidence, not independent corroboration or service reachability.
- JSONL is the primary single-run interchange format: one summary record followed by sorted finding records. It retains terminal evidence status, producer outcomes, provenance, and supported structured observations.
- SQLite is the canonical local multi-run store. Portable SQLite export contains every finalized evidence record, preserves original run IDs and canonical structured evidence, and excludes queue, cancellation, worker-lease, and legacy-observation state. Screenshot metadata travels with evidence; screenshot files remain separately managed artifacts.
- Legacy JSON and XML remain supported grouped reports for existing consumers. They are presentation formats and do not replace JSONL or SQLite when lossless provenance and structured evidence are required.

### Release gates

- Routine tests and CI use mocked provider responses, local services, RFC-reserved domains, and TEST-NET addresses. Live provider or target checks remain explicit operator-run integration work.
- Every executable source has offline contract coverage for its declared lifecycle, and the catalog gate rejects missing, duplicate, or unknown coverage.
- Persistence and interchange changes prove canonical export and import round trips. HarvestView changes pass a separate real-browser gate covering the affected operator workflow.
- Release publication requires green Python, formatting, lint, typing, container, security, documentation, and HarvestView browser checks at the publication head.

### Deferred boundaries

- Cross-run change detection, alerts, and automatic reactions remain separate future product decisions. A scheduled occurrence only submits finite enumeration runs.
- Cross-run source ranking remains a reporting decision. One run's hostname-yield summary does not automatically select, disable, or rank sources.
- Distributed workers, multi-host operation, PostgreSQL, and hosted multi-user authorization require measured demand and new decisions. The release remains SQLite-first and local-operator focused.
- Automatic scope expansion remains deferred. Evidence can suggest a later target, while the operator controls every scope change.

## Domain language

**Currently addressable subdomain**:
A normalized, in-scope subdomain with current resolver consensus evidence of an A or AAAA record, or a permitted CNAME chain ending in one, that is neither wildcard-indistinguishable nor resolver-disputed.
_Avoid_: Valid subdomain, live host, resolved host

**Secondary subdomain evidence**:
An in-scope DNS-existing, historical, dangling-alias, or indeterminate name observation retained for defensive and investigative use but excluded from the primary currently addressable yield count.
_Avoid_: Invalid subdomain, dead host, false positive

**Synthetic wildcard-control probe**:
An in-scope DNS query for a fresh, high-entropy nonce label that is overwhelmingly unlikely to be an exact node, used at an applicable closest-encloser depth to learn the wildcard response distribution. Its answer is validation evidence, never a discovered subdomain.
_Avoid_: Random wildcard control, random name, test subdomain

**Resolver consensus**:
The configured agreement among normalized answers from operator-approved resolver vantages within one validation window. It is evidence for current addressability, not proof that a service is reachable or useful.
_Avoid_: Resolved, DNS success, live

**Wildcard-indistinguishable**:
An in-scope candidate whose normalized DNS response cannot be distinguished from the learned wildcard response distribution at the applicable closest-encloser depth. It remains secondary subdomain evidence unless later observations distinguish it.
_Avoid_: Wildcard hit, false positive, invalid host

**Resolver-disputed**:
An in-scope candidate whose operator-approved resolver vantages do not reach resolver consensus sufficient to classify it as a currently addressable subdomain within one validation window. It remains secondary subdomain evidence until later observations resolve the disagreement.
_Avoid_: Invalid, dead, DNS failure

**In-scope candidate**:
A normalized name inside an explicitly authorized target boundary that has discovery evidence but has not yet met the currently addressable subdomain criteria. It remains secondary subdomain evidence until those criteria are met.
_Avoid_: Unverified host, maybe-valid subdomain

**Scope-extension candidate**:
An entity outside the current authorized boundary with evidence suggesting possible organizational relevance. It may be presented for operator review but cannot be actively queried, counted as a target result, or used for recursive discovery unless explicitly added to scope.
_Avoid_: Potentially in scope, related subdomain, unverified subdomain

**External relationship evidence**:
An out-of-scope entity referenced by an in-scope observation, such as an external CNAME target or shared service. It is retained as context rather than treated as a target result or discovery seed.
_Avoid_: Related subdomain, discovered asset

**Discovery observation**:
One source assertion about one normalized entity during one enumeration run. Several observations may support the same merged result, and deduplication never erases them.
_Avoid_: Result, duplicate, hit

**Merged result**:
A deduplicated operator-facing entity backed by one or more discovery observations and their retained provenance.
_Avoid_: Raw finding, source result

**Hostname result**:
One normalized DNS-name merged result. It can be the authorized target itself or a subordinate name and does not by itself imply current DNS addressability.
_Avoid_: Subdomain result, live host, resolved host

**Virtual-host observation**:
Structured differential endpoint evidence attached to a canonical hostname result. Several endpoint observations can enrich one hostname without creating another result or count.
_Avoid_: Virtual-host result, vhost result

**IP result**:
One canonical IPv4 or IPv6 address merged result.
_Avoid_: IP-address result, resolved host

**Network prefix result**:
One canonical IPv4 or IPv6 CIDR merged result retained as external relationship evidence. It is never promoted into the authorized target scope or used as an active-discovery seed without a separate scope decision.
_Avoid_: Owned netblock, in-scope range, registered network

**ASN organization attribution**:
One source's time-bound organization label for a canonical ASN, tied to the hostname or IP result that supplied the relationship. It is provider evidence rather than a canonical organization identity, ownership claim, or target-scope decision.
_Avoid_: ASN owner, owning organization, organization property

**Explicit network pivot**:
A canonical ASN, IP address, or CIDR supplied by the operator as the run target for passive routing enrichment. It authorizes provider-side lookup of that identifier only; related prefixes and origins remain external relationship evidence and do not expand engagement scope.
_Avoid_: Discovered network scope, owned ASN, target netblock

**Observed route origin**:
A provider's time-bound assertion that one ASN originates one network prefix. It records routing evidence, not registration, ownership, or authorization.
_Avoid_: Owned by, registered to, authorized origin

**BGP route observation**:
One collector and peer's time-bound view of a route, preserving its peer address, peer ASN, AS path, and communities as provider evidence attached to an observed route origin.
_Avoid_: Network ownership, authoritative route

**RPKI validation observation**:
A provider's time-bound validation state for one ASN-prefix route origin: valid, invalid, or not found. It reports route-origin authorization evidence, not registration, ownership, reachability, or target scope.
_Avoid_: Valid network, trusted ASN, owned prefix

**URL result**:
One normalized URL merged result. Source and action origins identify how it was found; provider-specific URL categories are not separate result kinds.
_Avoid_: Interesting URL, LinkedIn link, API endpoint result

**DNS validation observation**:
One resolver vantage's time-bound DNS evidence about one in-scope candidate. It supports classifying the candidate as currently addressable or wildcard-indistinguishable without replacing its discovery observations.
_Avoid_: DNS result, resolved host, validation status

**Enumeration run**:
One finite execution of theHarvester against an explicit target and selected options, identified independently from every other execution.
_Avoid_: Scan, monitoring cycle, session, job

**Run schedule**:
A durable local plan that combines an explicit authorized target inventory, one validated run template, recurrence timing, and an overlap policy. It creates enumeration runs but is never itself an enumeration run or evidence record.
_Avoid_: Scan schedule, cron job, monitoring run

**Scheduled occurrence**:
One due time in a run schedule. It produces at most one ordinary enumeration run per scheduled target and advances past missed recurrence times without replaying each one.
_Avoid_: Monitoring cycle, recurring run

**Dispatch reservation**:
The durable association between one scheduled occurrence, one target, and one preselected run ID that prevents duplicate run creation across retries or restarts.
_Avoid_: Queue item, scheduled result

**Overlap policy**:
The operator choice to skip a due occurrence while a prior scheduled batch is active or queue another finite batch behind it.
_Avoid_: Concurrency mode, retry policy

**Action-only run**:
An enumeration run with no discovery sources that performs an explicitly selected provider, DNS, or direct action against an explicitly authorized target. It creates its own run record and never mutates the evidence of a parent run.
_Avoid_: Result action, parent-run update, inline scan

**Run record**:
The durable operator-facing record that begins when an enumeration is submitted or evidence is imported and retains lifecycle, authorization, and available evidence under one stable identifier.
_Avoid_: Task, worker job, scan record

**HarvestView**:
The browser-based analysis workspace for creating schedules and run records and inspecting normalized evidence, source outcomes, and managed artifacts from theHarvester.
_Avoid_: Internal workflow names, operator app, console, dashboard

**Imported run**:
A run record created from an existing theHarvester result file. Import records evidence but never executes discovery or contacts a target.
_Avoid_: Uploaded scan, replayed run

**Finalized evidence record**:
A completed-result record with stable run ID, target, timestamps, normalized results, producer outcomes, provenance, typed observations, artifact metadata, and terminal evidence status. A partial or failed terminal evidence status can still be finalized and portable.
_Avoid_: Successful run, lifecycle row, complete-only result

**JSONL run interchange**:
One finalized evidence record encoded as a summary line followed by normalized finding lines. It is the primary streamable format for one-run automation and round trips.
_Avoid_: JSON report, event log, lifecycle export

**Portable SQLite export**:
A validated database containing finalized evidence records and their original run IDs without API lifecycle, cancellation, worker-lease, or legacy-observation state.
_Avoid_: Database backup, worker-state export, application clone

**Lifecycle status**:
The durable state of a run record: queued, running, cancelling, cancelled, completed, or failed. It describes control flow, not evidence quality.
_Avoid_: Run result, provider status

**Terminal evidence status**:
The completeness classification reported by a finished enumeration result: complete, partial, or failed. It does not describe queue or cancellation state.
_Avoid_: Lifecycle status, completion state

**Cancellation request**:
The operator's durable request that the run worker prevent queued work from starting or ask the running child process to stop. A request is not itself proof that execution has ended.
_Avoid_: Cancelled run, process killed

**Source execution**:
One attempt to run one canonical discovery source within an enumeration run, with an explicit completion status and summary counts.
_Avoid_: Source result, provider response

**Source hostname yield**:
One source's normalized hostname counts within one enumeration run: observed, unique, shared, DNS-resolved, and unique DNS-resolved. A hostname is unique when exactly one source reported it in that run. It is DNS-resolved when the run's resolution action retained an A, AAAA, or CNAME answer. The counts measure marginal coverage and current DNS evidence, not independent corroboration, ownership, or service reachability.
_Avoid_: Source quality score, authoritative result count, independent confirmation

**Source capability**:
A declared class of normalized result that a source can contribute to consolidated enumeration output, independent of whether one source execution yields any data.
_Avoid_: Guaranteed result, module return type, source category

**Capability selection**:
An operator request to run sources that declare one or more selected source capabilities. Multiple capabilities form a union, explicit source selection remains available, and capability selection does not filter fields returned by a selected source.
_Avoid_: Result filter, backend category, capability intersection

**Source family**:
A group of discovery sources whose observations depend on the same underlying dataset or collection mechanism. Family membership preserves source credit while preventing correlated observations from being treated as independent corroboration.
_Avoid_: Duplicate source, provider category

**Normalized evidence**:
Provider-independent evidence extracted into theHarvester's defined fields, such as the entity, source, collection time, and derivation, without retaining unrelated response content.
_Avoid_: Raw result, cleaned response

**Raw provider payload**:
The original unprocessed response returned by a discovery provider, which may contain unused, sensitive, or redistribution-restricted fields.
_Avoid_: Evidence record, JSONL result

**P0 passive collection**:
An activity that queries an existing provider or dataset without directing traffic toward the target.
_Avoid_: Passive scan

**P1 DNS interaction**:
An activity that queries DNS about the target or its authorized scope, including resolution, wildcard controls, brute force, PTR, and recursive DNS discovery.
_Avoid_: Passive collection, harmless lookup

**P2 direct interaction**:
An activity that contacts or scans the target directly or causes a provider to do so, including HTTP or TLS requests, screenshots, takeover checks, and port or endpoint scanning.
_Avoid_: Deep scan, comprehensive mode
