# Responsible use and scope

Use theHarvester only on targets you own or are explicitly authorized to assess. Authorization should identify the target, permitted techniques, time window, data handling rules, and any third-party restrictions.

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
| `--screenshot DIR` | Opens discovered web services in a browser. |
| `-a`, `--api-scan` | Requests common API paths from the target. |

Use an owned or explicitly authorized domain for active examples. Do not substitute universities, public companies, bounty targets, or reserved example domains for recurring active scans.

## Protect collected data

Results may contain private infrastructure, employee addresses, account identifiers, or other sensitive context even when the source data is public.

- Keep reports, screenshots, and the SQLite database out of source control.
- Follow the engagement's retention and sharing rules.
- Redact credentials, private target data, account information, and unnecessary response content before filing an issue.
- Never publish raw provider responses merely to demonstrate a parsing or availability problem.

## Service exposure

`restfulHarvest` core query routes are not authenticated. The optional `/additional/*` routes use `THEHARVESTER_API_KEY`, but that does not protect `/query`, `/sources`, or `/dnsbrute`. Keep the service on localhost or place it behind appropriate authentication, network controls, and TLS.
