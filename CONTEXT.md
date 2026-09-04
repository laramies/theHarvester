# theHarvester domain language

Use these terms in code, tests, issues, and operator documentation. For product behavior, implementation rules, and release checks, read the [release contract](docs/release-contract.md).

## Targets and activity

**Enumeration target**:
The operator-supplied identifier that scopes one enumeration run. It is ordinarily a canonical hostname and may instead be a canonical IP address, ASN, or CIDR for supported routing activity, or an exact free-text company query for a source that accepts one.
_Avoid_: Domain, hostname when the target is not a DNS name, target alias

**In-scope candidate**:
A normalized name inside an explicitly authorized target boundary that has discovery evidence but has not yet met the currently addressable subdomain criteria. It remains secondary subdomain evidence until those criteria are met.
_Avoid_: Unverified host, maybe-valid subdomain

**Scope-extension candidate**:
An entity outside the current authorized boundary with evidence suggesting possible organizational relevance. It may be presented for operator review but cannot be actively queried, counted as a target result, or used for recursive discovery unless explicitly added to scope.
_Avoid_: Potentially in scope, related subdomain, unverified subdomain

**External relationship evidence**:
An out-of-scope entity referenced by an in-scope observation, such as an external CNAME target or shared service. It is retained as context rather than treated as a target result or discovery seed.
_Avoid_: Related subdomain, discovered asset

**Explicit network pivot**:
A canonical ASN, IP address, or CIDR supplied by the operator as the run target for passive routing enrichment. It authorizes provider-side lookup of that identifier only; related prefixes and origins remain external relationship evidence and do not expand engagement scope.
_Avoid_: Discovered network scope, owned ASN, target netblock

**P0 passive collection**:
An activity that queries an existing provider or dataset without directing traffic toward the target.
_Avoid_: Passive scan

**P1 DNS interaction**:
An activity that queries DNS about the target or its authorized scope, including resolution, wildcard controls, brute force, PTR, and recursive DNS discovery.
_Avoid_: Passive collection, harmless lookup

**P2 direct interaction**:
An activity that contacts or scans the target directly or causes a provider to do so, including HTTP or TLS requests, screenshots, takeover checks, and port or endpoint scanning.
_Avoid_: Deep scan, comprehensive mode


## Runs and schedules

**Enumeration run**:
One finite execution of theHarvester against an explicit target and selected options, identified independently from every other execution.
_Avoid_: Scan, monitoring cycle, session, job

**Run record**:
The durable operator-facing record that begins when an enumeration is submitted or evidence is imported and retains lifecycle, authorization, and available evidence under one stable identifier.
_Avoid_: Task, worker job, scan record

**HarvestView**:
The browser-based analysis workspace for creating schedules and run records and inspecting normalized evidence, source outcomes, and managed artifacts from theHarvester.
_Avoid_: Internal workflow names, operator app, console, dashboard

**Source execution**:
One attempt to run one canonical discovery source within an enumeration run, with an explicit completion status and summary counts.
_Avoid_: Source result, provider response

**Lifecycle status**:
The durable state of a run record: queued, running, cancelling, cancelled, completed, or failed. It describes control flow, not evidence quality.
_Avoid_: Run result, provider status

**Terminal evidence status**:
The completeness classification reported by a finished enumeration result: complete, partial, or failed. It does not describe queue or cancellation state.
_Avoid_: Lifecycle status, completion state

**Cancellation request**:
The operator's durable request that the run worker prevent queued work from starting or ask the running child process to stop. A request is not itself proof that execution has ended.
_Avoid_: Cancelled run, process killed

**Action-only run**:
An enumeration run with no discovery sources that performs an explicitly selected provider, DNS, or direct action against an explicitly authorized target. It creates its own run record and never mutates the evidence of a parent run.
_Avoid_: Result action, parent-run update, inline scan

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


## Results and provenance

**Discovery observation**:
One source assertion about one normalized entity during one enumeration run. Several observations may support the same merged result, and deduplication never erases them.
_Avoid_: Result, duplicate, hit

**Merged result**:
A deduplicated operator-facing entity backed by one or more discovery observations and their retained provenance.
_Avoid_: Raw finding, source result

**Hostname result**:
One normalized DNS-name merged result. It can be the authorized target itself or a subordinate name and does not by itself imply current DNS addressability.
_Avoid_: Subdomain result, live host, resolved host

**IP result**:
One canonical IPv4 or IPv6 address merged result.
_Avoid_: IP-address result, resolved host

**URL result**:
One normalized URL merged result. Source and action origins identify how it was found; provider-specific URL categories are not separate result kinds.
_Avoid_: Interesting URL, LinkedIn link, API endpoint result

**Virtual-host observation**:
Structured differential endpoint evidence attached to a canonical hostname result. Several endpoint observations can enrich one hostname without creating another result or count.
_Avoid_: Virtual-host result, vhost result

**Normalized evidence**:
Provider-independent evidence extracted into theHarvester's defined fields, such as the entity, source, collection time, and derivation, without retaining unrelated response content.
_Avoid_: Raw result, cleaned response

**Raw provider payload**:
The original unprocessed response returned by a discovery provider, which may contain unused, sensitive, or redistribution-restricted fields.
_Avoid_: Evidence record, JSONL result

**Source capability**:
A declared class of normalized result that a source can contribute to consolidated enumeration output, independent of whether one source execution yields any data.
_Avoid_: Guaranteed result, module return type, source category

**Capability selection**:
An operator request to run sources that declare one or more selected source capabilities. Multiple capabilities form a union, explicit source selection remains available, and capability selection does not filter fields returned by a selected source.
_Avoid_: Result filter, backend category, capability intersection

**Source family**:
A group of discovery sources whose observations depend on the same underlying dataset or collection mechanism. Family membership preserves source credit while preventing correlated observations from being treated as independent corroboration.
_Avoid_: Duplicate source, provider category


## DNS evidence

**Currently addressable subdomain**:
A normalized, in-scope subdomain with current resolver consensus evidence of an A or AAAA record, or a permitted CNAME chain ending in one, that is neither wildcard-indistinguishable nor resolver-disputed.
_Avoid_: Valid subdomain, live host, resolved host

**Secondary subdomain evidence**:
An in-scope DNS-existing, historical, dangling-alias, or indeterminate name observation retained for defensive and investigative use but excluded from the primary currently addressable count.
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

**DNS validation observation**:
One resolver vantage's time-bound DNS evidence about one in-scope candidate. It supports classifying the candidate as currently addressable or wildcard-indistinguishable without replacing its discovery observations.
_Avoid_: DNS result, resolved host, validation status

**Retained resolution evidence**:
What finalized evidence establishes about DNS resolution for one hostname in one run: a retained positive answer, no retained positive answer, or no recorded check. It remains separate from richer addressability classifications such as currently addressable, not currently addressable, resolver disputed, or wildcard indistinguishable.
_Avoid_: Boolean resolved state, live-host status, reachability


## Network relationships

**Network prefix result**:
One canonical IPv4 or IPv6 CIDR merged result retained as external relationship evidence. It is never promoted into the authorized target scope or used as an active-discovery seed without a separate scope decision.
_Avoid_: Owned netblock, in-scope range, registered network

**ASN organization attribution**:
One source's time-bound organization label for a canonical ASN, tied to the hostname or IP result that supplied the relationship. It is provider evidence rather than a canonical organization identity, ownership claim, or target-scope decision.
_Avoid_: ASN owner, owning organization, organization property

**Observed route origin**:
A provider's time-bound assertion that one ASN originates one network prefix. It records routing evidence, not registration, ownership, or authorization.
_Avoid_: Owned by, registered to, authorized origin

**BGP route observation**:
One collector and peer's time-bound view of a route, preserving its peer address, peer ASN, AS path, and communities as provider evidence attached to an observed route origin.
_Avoid_: Network ownership, authoritative route

**RPKI validation observation**:
A provider's time-bound validation state for one ASN-prefix route origin: valid, invalid, or not found. It reports route-origin authorization evidence, not registration, ownership, reachability, or target scope.
_Avoid_: Valid network, trusted ASN, owned prefix


## Saved evidence and reports

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

**Source contribution**:
One source's normalized result counts within a run: reported, unique to that source, and shared with other sources, with additional counts of hostnames that have retained DNS answers. The counts measure that source's contribution and saved DNS evidence; they do not establish independent corroboration, ownership, or service reachability.
_Avoid_: Source yield, source quality score, authoritative result count

**Source contribution report scope**:
The explicit finalized evidence records summarized by a source-contribution report: one enumeration run, selected runs for one canonical authorized target, or runs across every stored target only by deliberate operator choice.
_Avoid_: Implicit database aggregate, target alias

**One-source hostname**:
A hostname attributed to exactly one canonical source within one enumeration run. This is run-scoped and does not claim that no other source has ever observed the hostname.
_Avoid_: Source-exclusive hostname, globally unique hostname, proprietary hostname


## Hostname comparisons

**Compared source list**:
The canonical sources represented by source executions in one enumeration run, independent of their individual outcomes. Two runs are comparable only when this list is identical.
_Avoid_: Source cohort, successful sources, source results

**Comparable previous run**:
The latest earlier finalized enumeration run for the same canonical target and compared source list. Unhealthy source executions may retain evidence but cannot support a sound one-sided hostname claim.
_Avoid_: Baseline, similar run, matching run

**Hostname comparison**:
A read-only comparison between selected finalized runs and each run's comparable previous run. It is derived when requested, is not stored as new canonical evidence, and never initiates discovery or DNS activity.
_Avoid_: Hostname tracking, monitoring view, DNS refresh

**Hostname difference**:
A hostname is newly reported when reliably absent from the earlier run, still reported when retained in both, no longer reported when reliably absent from the later run, and uncertain when relevant source outcomes cannot support a comparison of a hostname found in only one run. These states describe saved evidence, not when a hostname came into existence or whether it currently exists or resolves.
_Avoid_: Added host, removed host, gone host

**Relevant source outcome**:
The outcome in the run where a hostname is absent for each source that reported it in the other run. All these sources must have completed successfully to classify the hostname as newly reported or no longer reported; otherwise the difference is uncertain, regardless of unrelated source failures.
_Avoid_: Run health, all-source success, provider reliability

**Uncertain hostname difference**:
A hostname retained on exactly one side when at least one source that contributed it there was partial, failed, rate limited, or skipped on the side where it was absent. The incomplete source outcomes and saved reasons explain the uncertainty; the comparison itself has not failed.
_Avoid_: Inconclusive result, missing hostname, comparison error
