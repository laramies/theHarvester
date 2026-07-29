# theHarvester discovery context

This glossary is the source of truth for discussing subdomain discovery across code, issues, pull requests, output, and documentation. It separates current addressability from historical, indirect, or unresolved evidence.

The definitions state intended semantics; they do not imply that every discovery adapter already produces every evidence class. Update this glossary when a change alters a term's meaning or boundary.

## Language

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

**DNS validation observation**:
One resolver vantage's time-bound DNS evidence about one in-scope candidate. It supports classifying the candidate as currently addressable or wildcard-indistinguishable without replacing its discovery observations.
_Avoid_: DNS result, resolved host, validation status

**Enumeration run**:
One finite execution of theHarvester against an explicit target and selected options, identified independently from every other execution.
_Avoid_: Scan, monitoring cycle, session

**Source execution**:
One attempt to run one canonical discovery source within an enumeration run, with an explicit completion status and summary counts.
_Avoid_: Source result, provider response

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
