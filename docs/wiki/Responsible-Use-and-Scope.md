# Responsible use and scope

Use theHarvester only on targets you own or are explicitly authorized to assess. The authorization should name the target, permitted techniques, time window, data-handling rules, and third-party restrictions.

## Passive does not mean invisible

Passive discovery sources query third-party services instead of directly probing every target host. Those services still receive the domain or organization name, may log requests, and enforce their own terms, quotas, and acceptable-use rules.

Select only the providers needed for the task. Do not treat a provider key, bug-bounty program, or publicly reachable host as blanket authorization.

## Features that add network activity

The following options require additional care:

| Option | Behavior |
| --- | --- |
| `-r`, `--dns-resolve` | Resolves discovered names through configured DNS resolvers. |
| `-n`, `--dns-lookup` | Performs reverse DNS lookup. |
| `-c`, `--dns-brute` | Tries candidate subdomains against DNS. |
| `-t`, `--take-over` | Checks discovered hosts for takeover indicators. |
| `-s`, `--shodan` | Enriches discovered hosts through Shodan. |
| `--routeviews` | Sends discovered public ASN identifiers, or an explicitly targeted IP/CIDR, to RouteViews and records external routing relationships. |
| `--vhost`, `--vhost-*` | Probes literal IP endpoints with candidate SNI and HTTP `Host` values. |
| `--screenshot DIR` | Opens discovered web services in a browser. |
| `-a`, `--api-scan` | Requests common API paths from the target. |

Use `--dns-resolvers IPS_OR_FILE` to select resolver addresses for DNS brute force, reverse lookup, or recursive DNS without also enabling hostname resolution. The compatible `--dns-resolve` value still selects resolvers and enables hostname resolution.

`--routeviews` is a separately selected P0 provider action. It is never enabled by `-b all` and ignores `-l`; one run is internally bounded to 300 sequential requests and 300 seconds at the guest rate. It does not send harvested IPs unless the IP/CIDR is the explicit run target, does not recursively query returned prefixes, and never promotes returned CIDRs into DNS or direct-action scope. Route origins and RPKI states can include anomalies or leaks and do not establish ownership or authorization.

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
