# Operator workflows

Start with the smallest source set and least active behavior that can answer the engagement question. Replace `example.com` only with an authorized target.

Sources and explicit actions contribute different result routes and different levels of network activity. This map shows how they meet in one normalized evidence model:

![theHarvester discovery routes and enrichment](https://raw.githubusercontent.com/laramies/theHarvester/dev/docs/images/run-evidence-architecture.svg)

## Passive subdomain discovery

Network activity: provider-facing passive lookups.

```bash
uv run theHarvester -d example.com -b crtsh,certspotter,commoncrawl
```

Use the [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) to choose complementary sources. Adding every source usually increases noise, rate-limit failures, and runtime more than it improves a focused run.

## Save results for automation

Network activity: provider-facing discovery plus local report writes.

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

Use `report.jsonl` for automation, provenance, and run interchange. The same command also writes `report.json` and `report.xml` compatibility files. See [Results and Local Data](Results-and-Local-Data).

## DNS resolution

Network activity: provider-facing discovery followed by resolver-facing DNS queries.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -r
```

To control the resolvers used, create a resolver file with one IP address per line and pass its path:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r resolvers.txt
```

DNS requests disclose candidate names to each selected resolver. Candidates from all selected sources are normalized and deduplicated before one run-wide phase queries A, AAAA, and CNAME at most once per hostname and record type. The phase runs at most 20 hostname jobs concurrently with per-query resolver timeouts and no default query-count or phase-runtime ceiling.

## Reverse DNS

Network activity: provider-facing discovery followed by resolver-facing PTR queries.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester \
  -d "$AUTHORIZED_DOMAIN" \
  -b rapiddns \
  --dns-lookup \
  -f report
```

Reverse DNS uses the `/24` network containing each discovered IPv4 address. It deduplicates addresses across overlapping ranges and runs at most 20 PTR jobs concurrently with per-query resolver timeouts. It has no default request-count or phase-runtime ceiling.

## Shodan enrichment

Configure the Shodan key, then enrich resolved hosts:

Network activity: provider-facing discovery, resolver-facing DNS, and Shodan API requests.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r -s
```

Shodan host enrichment runs after discovery and is separate from the `shodan` source's subdomain results.

## DNS brute force

Use only an owned or explicitly authorized target:

Network activity: resolver-facing DNS queries for generated candidate names.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -c
```

DNS brute force actively tests candidate names. Do not run it against `example.com` or an unrelated third-party domain.

## Recursive DNS

Network activity: provider-facing discovery followed by resolver-facing DNS queries for descendant names.

Create `resolvers.txt` with exactly three distinct resolver IP addresses. Then set a depth and save the structured evidence:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester \
  -d "$AUTHORIZED_DOMAIN" \
  -b crtsh \
  --dns-resolvers resolvers.txt \
  --dns-recursive-depth 1 \
  -f report
```

Recursive DNS uses source results as seed names. Set the depth explicitly; query and runtime caps still apply. JSONL keeps the discovered hostnames and addresses along with recursive finding, classification, and summary records.

## Takeover checks

Network activity: provider-facing discovery followed by target-facing checks.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -t
```

Treat matches as leads requiring manual confirmation. Do not claim a takeover from a fingerprint match alone.

## RouteViews pivots

Network activity: provider-facing RouteViews requests.

Set an ASN that is part of the authorized assessment scope:

```bash
AUTHORIZED_ASN='replace-with-an-authorized-asn'
uv run theHarvester -d "$AUTHORIZED_ASN" --routeviews -f report
```

The target may also be an authorized IP or CIDR. The action writes external routing relationships and RPKI observations to `report.jsonl`. These records can guide analysis, but they do not establish ownership, authorization, or reachability. RouteViews is never enabled by `-b all`; see [Responsible Use and Scope](Responsible-Use-and-Scope#routeviews) for its fixed limits.

## Virtual host discovery

Network activity: provider-facing discovery followed by target-facing requests to harvested IP endpoints.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b rapiddns --vhost -f report
```

The action keeps only confirmed hostnames and records endpoint observations in JSONL. Read [Virtual Host Discovery](Virtual-Host-Discovery) before changing its endpoint, candidate, request, runtime, or TLS controls.

## Screenshots

Install Chromium first, then choose an output directory:

Network activity: provider-facing discovery, resolver-facing DNS, and target-facing browser requests.

```bash
uv run playwright install chromium
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r --screenshot screenshots
```

Screenshots actively open discovered web services and may retain sensitive page content.

## API-path scanning

Network activity: target-facing HTTP requests.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -a
```

Provide a custom path wordlist with `-w FILE`. This sends requests directly to the target and must be explicitly in scope.

## Diagnose one provider

When a combined run fails, rerun only the affected source with a conservative result limit:

Network activity: provider-facing lookup to the named source.

```bash
uv run theHarvester -d example.com -b source-name -l 10
```

Check the provider's current status, authentication requirements, rate limits, and terms before reporting a tool defect.
