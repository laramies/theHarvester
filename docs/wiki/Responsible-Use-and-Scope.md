# Responsible use and scope

Use theHarvester only on targets you own or are explicitly authorized to assess. The authorization should name the target, permitted techniques, time window, data-handling rules, and third-party restrictions.

## Passive does not mean invisible

Passive discovery sources query third-party services instead of directly probing every target host. Those services still receive the domain or organization name, may log requests, and enforce their own terms, quotas, and acceptable-use rules.

Select only the providers needed for the task. Do not treat a provider key, bug-bounty program, or publicly reachable host as blanket authorization.

## Features that add network activity

| Option | Network path | What it does |
| --- | --- | --- |
| `-r`, `--dns-resolve` | Resolver-facing | Resolves discovered names to A, AAAA, and CNAME records. |
| `-n`, `--dns-lookup` | Resolver-facing | Performs reverse DNS across discovered `/24` ranges. |
| `-c`, `--dns-brute` | Resolver-facing | Tries candidate subdomains against DNS. |
| `-t`, `--take-over` | Target-facing | Checks discovered hosts for takeover indicators. |
| `-s`, `--shodan` | Provider-facing | Enriches discovered hosts through Shodan. |
| `--routeviews` | Provider-facing | Queries RouteViews for external routing relationships. |
| `--vhost`, `--vhost-*` | Target-facing | Probes literal IP endpoints with candidate SNI and HTTP `Host` values. |
| `--screenshot DIR` | Target-facing | Opens discovered web services in a browser. |
| `-a`, `--api-scan` | Target-facing | Requests common API paths from the target. |

### DNS actions

Hostname resolution deduplicates discovered names, then queries A, AAAA, and CNAME once per name. One run can have up to 20 active hostname jobs. Queries have resolver timeouts, but the phase has no default query-count or runtime ceiling.

Reverse DNS deduplicates addresses across overlapping `/24` ranges. It uses a separate run-wide phase with up to 20 active PTR jobs and per-query timeouts, but no default request-count or runtime ceiling.

Use `--dns-resolvers IPS_OR_FILE` to select resolver addresses for DNS brute force, reverse lookup, or recursive DNS without enabling hostname resolution. `--dns-resolve [IPS_OR_FILE]` selects resolvers and enables hostname resolution.

### RouteViews

`--routeviews` is a separately selected P0 provider action. `-b all` never enables it, and `-l` does not change its fixed limit of 300 sequential requests or 300 seconds.

- Guest access runs at the documented rate of one request per second. A configured `routeviews.key` selects PeeringDB-verified authenticated access and the documented 10-request-per-second allowance.
- A domain run queries only harvested IPs backed by sourced IP-to-ASN attribution. Harvested IPs without that attribution are not sent, and bare ASN findings are not expanded into complete prefix inventories.
- An explicit run target may be an ASN, IP, or CIDR. IP lookups retain only the most-specific returned prefix, including every origin for a multi-origin prefix.
- Returned prefixes are not queried recursively or promoted into DNS or direct-action scope.

Treat cloud and CDN routes as relationship evidence. Route origins and RPKI states do not establish ownership, authorization, or reachability.

Use an owned or explicitly authorized domain for active examples. Do not substitute universities, public companies, bounty targets, or reserved example domains for recurring active scans.

## Protect collected data

Results may contain private infrastructure, employee addresses, account identifiers, or other sensitive context even when the source data is public.

- Keep reports, screenshots, and the SQLite database out of source control.
- Follow the engagement's retention and sharing rules.
- Redact credentials, private target data, account information, and unnecessary response content before filing an issue.
- Never publish raw provider responses merely to demonstrate a parsing or availability problem.

## API exposure

Every `/api/v1/*` route requires `THEHARVESTER_API_KEY`. HarvestView is restricted to a loopback browser origin and uses a derived HttpOnly cookie for those same routes. Provider credentials remain server-side.

Keep the service on localhost. If you require remote access, add network controls and TLS in front of the existing API authentication.
