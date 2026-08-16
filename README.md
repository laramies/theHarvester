# theHarvester

![theHarvester logo](theHarvester-logo.webp)

[![Python CI](https://github.com/laramies/theHarvester/actions/workflows/theHarvester.yml/badge.svg)](https://github.com/laramies/theHarvester/actions/workflows/theHarvester.yml)
[![Docker CI](https://github.com/laramies/theHarvester/actions/workflows/dockerci.yml/badge.svg)](https://github.com/laramies/theHarvester/actions/workflows/dockerci.yml)

theHarvester gathers open-source intelligence about a domain or organization from search engines, certificate transparency logs, DNS datasets, code repositories, threat-intelligence platforms, and other public sources.

It is built for the early reconnaissance stage of authorized security assessments. Use it only on targets you own or have explicit permission to test.

## What it does

theHarvester combines many public data sources in one run and normalizes their results. It can collect hostnames, email addresses, IP addresses, URLs, ASNs, people, and breach names. Optional actions cover DNS, RouteViews, Shodan, takeover checks, virtual hosts, API paths, and screenshots.

Use the CLI for one-off work or HarvestView for a local browser workflow. JSONL and SQLite retain structured evidence and provenance. JSON and XML remain available for existing integrations.

Providers control their own availability, quotas, and response formats, so individual sources may change independently of theHarvester.

## Package versions

[![Packaging status](https://repology.org/badge/vertical-allrepos/theharvester.svg)](https://repology.org/project/theharvester/versions)

## Architecture at a glance

### Discovery routes and enrichment

![theHarvester discovery routes and enrichment](docs/images/run-evidence-architecture.svg)

### HarvestView run desk

![HarvestView run desk architecture](docs/images/harvestview-architecture.svg)

## Quick start

theHarvester requires Python 3.12 or newer. From a source checkout:

```bash
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
uv sync
uv run theHarvester -d example.com -b crtsh,certspotter
```

See the [installation guide](docs/wiki/Installation.md) for platform-specific setup and packaged distributions.

## Common workflows

Query several passive sources:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter,commoncrawl
```

Three discovery sources run at once by default. Use `-j` or `--source-workers` to change the worker count. The REST API and HarvestView expose the same setting.

Run every source that can contribute subdomains:

```bash
uv run theHarvester -d example.com -b subdomains
```

Combine capability selectors, or mix them with explicit source names:

```bash
uv run theHarvester -d example.com -b emails,urls,certspotter
```

Capability selectors form a union and choose which sources run. They do not discard other result types returned by those sources. Available selectors are `subdomains`, `emails`, `ips`, `asns`, `urls`, `people`, and `breaches`. `-b all` runs every cataloged P0 passive source. P1 DNS and P2 direct sources require explicit selection.

Exclude hostname results while retaining other result types:

```bash
uv run theHarvester -d example.com -b emails,ips,urls --no-hosts -f non-host-results
```

`--no-hosts` skips hostname-only sources and omits hostname results while keeping other result types. It cannot be combined with actions that depend on hostnames. HarvestView and the REST API expose the same option as `no_hosts`.

Save a durable JSONL report:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

This writes `report.jsonl` for automation and interchange. The same command also writes legacy `report.json` and `report.xml` compatibility reports.

Resolve discovered hosts for an authorized domain with the default resolver list:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -r
```

List every option and its current behavior:

```bash
uv run theHarvester -h
```

## Activity and scope

Passive sources are P0. DNS resolution, brute force, recursive DNS, and reverse lookup are P1. HTTP, TLS, screenshot, takeover, virtual-host, port, and endpoint actions are P2. P1 and P2 activity runs only when you select it.

Common active options include DNS resolution (`-r`), DNS brute force (`-c`), reverse DNS (`-n`), recursive DNS (`--dns-recursive-depth`), takeover checks (`-t`), API path scanning (`-a`), and screenshots (`--screenshot`). A takeover indicator is evidence for review, not proof that a provider resource can be claimed.

Read [Responsible use and scope](docs/wiki/Responsible-Use-and-Scope.md) before active work. [Operator workflows](docs/wiki/Operator-Workflows.md) covers limits, resolvers, proxies, and action-specific behavior. Screenshot capture requires a Playwright-compatible browser.

## HarvestView and REST API

`harvestview` starts the local web application and API on `127.0.0.1:5000` by default:

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run harvestview
```

Open [HarvestView](http://127.0.0.1:5000/) to submit and inspect finite runs. The browser receives a derived HttpOnly session cookie and never stores the API key. See the [installation guide](docs/wiki/Installation.md) for local assets, screenshots, and isolated deployments.

Open [Swagger](http://127.0.0.1:5000/docs) or [ReDoc](http://127.0.0.1:5000/redoc) for the automation contract.

### Docker Compose

The Compose service runs as an unprivileged user, stores runs in a named volume, reads the operator key from a file secret, and publishes only to host loopback:

```bash
install -d -m 0700 .secrets
openssl rand -hex 32 > .secrets/operator-api-key
chmod 0444 .secrets/operator-api-key
docker compose up --build -d
docker compose ps
```

```bash
docker compose logs -f theharvester.svc.local
docker compose down
```

| Route | Purpose |
| --- | --- |
| `GET /api/v1/sources` | List registered discovery sources and capabilities. |
| `POST /api/v1/runs` | Submit a finite enumeration run. |
| `GET /api/v1/runs` | List durable run records. |
| `GET /api/v1/runs/{run_id}` | Retrieve lifecycle state, normalized results, and source outcomes. |
| `POST /api/v1/runs/{run_id}/cancel` | Cancel queued or running work. |
| `POST /api/v1/runs/import` | Import JSONL evidence without executing discovery. |
| `POST /api/v1/runs/import-database` | Import completed runs from a theHarvester SQLite database. |
| `GET /api/v1/runs/export-database` | Export all completed run evidence as a portable SQLite database. |
| `GET /api/v1/runs/{run_id}/export` | Export normalized evidence as JSONL. |

HarvestView can start screenshot and DNS brute-force runs from a hostname result. Each action creates its own run and leaves the original evidence unchanged.

API clients send `THEHARVESTER_API_KEY` in the `X-API-Key` header. Provider credentials stay in server-side configuration. Keep the service on localhost unless you add TLS and network access controls. The [REST API guide](docs/wiki/Rest-API.md) documents requests, imports, exports, and authentication.

## Discovery sources

Select sources by name or by any result route listed below. `-b all` runs the P0 sources. P1 and P2 sources require explicit selection. Credentials marked optional can provide additional access but are not required.

The `shodan` source contributes subdomains. Shodan host enrichment through `-s` or `--shodan` is a separate action and is not a source result route.

<details>
<summary><strong>View the source and result matrix</strong></summary>

| Source | Result routes | Activity | Credentials |
| --- | --- | :---: | :---: |
| `apis-guru` | subdomains, emails, urls | P0 | No |
| `arquivo` | subdomains | P0 | No |
| `baidu` | subdomains, emails | P0 | No |
| `bevigil` | subdomains, urls | P0 | Required |
| `bufferoverun` | subdomains, ips | P0 | Required |
| `builtwith` | subdomains, urls | P0 | Required |
| `brave` | subdomains, emails | P0 | Required |
| `censys` | subdomains, emails | P0 | Required |
| `certspotter` | subdomains | P0 | No |
| `commoncrawl` | subdomains | P0 | No |
| `criminalip` | subdomains, ips, asns | P2 | Required |
| `crt-name` | subdomains | P0 | No |
| `crtsh` | subdomains | P0 | No |
| `dehashed` | emails, ips | P0 | Required |
| `dnsdb` | subdomains | P0 | Required |
| `dnsdumpster` | subdomains, ips | P0 | Required |
| `duckduckgo` | subdomains, emails | P0 | No |
| `dymo` | subdomains | P0 | Required |
| `fofa` | subdomains, ips | P0 | Required |
| `fullhunt` | subdomains | P0 | Required |
| `github-code` | subdomains, emails | P0 | Required |
| `gitlab` | subdomains, emails, urls | P0 | No |
| `hackertarget` | subdomains, ips | P0 | Optional |
| `haveibeenpwned` | breaches | P0 | No |
| `hibpverified` | emails, breaches | P0 | Required |
| `hudsonrock` | subdomains, emails, ips | P0 | No |
| `hunter` | subdomains, emails | P0 | Required |
| `hunterhow` | subdomains | P0 | Required |
| `intelx` | subdomains, emails, urls | P0 | Required |
| `leakix` | subdomains | P0 | Required |
| `leaklookup` | emails, breaches | P0 | Required |
| `mojeek` | subdomains, emails | P0 | Optional |
| `netlas` | subdomains | P0 | Required |
| `onyphe` | subdomains, ips, asns | P0 | Required |
| `otx` | subdomains, ips | P0 | No |
| `pentesttools` | subdomains, ips | P1 | Required |
| `projectdiscovery` | subdomains | P0 | Required |
| `rapiddns` | subdomains, ips | P0 | No |
| `robtex` | ips | P0 | No |
| `rocketreach` | emails, urls | P0 | Required |
| `securityscorecard` | subdomains, ips | P0 | Required |
| `securityTrails` | subdomains, ips | P0 | Required |
| `sherlockeye` | subdomains, emails, ips | P0 | Required |
| `shodan` | subdomains | P1 | Required |
| `shodanInternetDB` | subdomains, ips | P1 | No |
| `shodanct` | subdomains | P0 | No |
| `sourcegraph` | subdomains | P0 | No |
| `subdomaincenter` | subdomains | P0 | No |
| `subdomainfinderc99` | subdomains | P1 | No |
| `thc` | subdomains | P0 | No |
| `tomba` | subdomains, emails | P0 | Required |
| `urlscan` | subdomains, ips, asns, urls | P0 | No |
| `virustotal` | subdomains | P0 | Required |
| `waybackarchive` | subdomains | P0 | No |
| `whoisxml` | subdomains | P0 | Required |
| `windvane` | subdomains, emails, ips | P0 | Optional |
| `yahoo` | subdomains, emails | P0 | No |
| `zoomeye` | subdomains, emails, ips, asns, urls | P0 | Required |

</details>

Provider plans and quotas change often, so this README does not list prices. See [Configuration and API keys](docs/wiki/Configuration-and-API-Keys.md) for credential names and setup. Contributors can add a provider through the [module guide](docs/wiki/How-to-add-a-new-module.md); the source catalog remains the executable inventory.

## Configuration

On first use, theHarvester creates default configuration files under `~/.theHarvester/`. It also reads system configuration from `/etc/theHarvester/` and `/usr/local/etc/theHarvester/`.

- `api-keys.yaml` stores provider credentials.
- `proxies.yaml` configures HTTP and SOCKS5 proxies used with `-p`.
- The `shodan` source and `-s` / `--shodan` enrichment use Shodan's Host REST API. When `-p` is enabled, both send those requests through `proxies.yaml`.
- `routeviews.key` is optional and enables authenticated RouteViews access for PeeringDB-verified users.

Never commit populated configuration files, API keys, account details, or provider responses.

## Output and local data

Terminal output is intended for interactive use. `-f NAME` also writes `NAME.jsonl`, `NAME.json`, and `NAME.xml`. Screenshots go to the directory passed to `--screenshot`, and completed runs are stored in `~/.local/share/theHarvester/stash.sqlite`.

Treat collected OSINT as potentially sensitive. Keep report files, screenshots, and the local database out of source control and share them only within the authorized engagement.

### JSONL

JSONL is the primary format for automation and one-run interchange. The first line describes the run. Each remaining line is one sorted, deduplicated finding with its source and action provenance.

```jsonl
{"action_executions":[],"artifacts":[],"completed_at":"2026-08-07T12:01:00Z","counts":{"hostname":1},"evidence_status":"complete","result_count":1,"run_id":"123e4567-e89b-12d3-a456-426614174000","source_executions":[],"started_at":"2026-08-07T12:00:00Z","target":"example.com","type":"summary"}
{"sources":[],"type":"hostname","value":"api.example.com"}
```

Extract common result types with `jq`:

```bash
jq -r 'select(.type == "hostname") | .value' report.jsonl
jq -r 'select(.type == "ip") | .value' report.jsonl
jq -r 'select(.type == "asn") | .value' report.jsonl
jq -r 'select(.type == "email") | .value' report.jsonl
jq -r 'select(.type == "url") | .value' report.jsonl
jq -c 'select(.type == "person") | .value | fromjson' report.jsonl
jq -r 'select(.type == "breach") | .value' report.jsonl
```

Some result types carry structured evidence. `person`, `infostealer`, and recursive DNS values contain JSON strings and need a second `fromjson` step. Shodan hosts use `details`; virtual hosts, network prefixes, and ASN attribution use native observations. Takeover results keep the hostname in `value` and their DNS, wildcard, HTTP, rule, status, and error evidence in `details`.

```bash
jq -c 'select(.type == "dns-recursive-finding") | .value | fromjson' report.jsonl
jq -c 'select(.type == "shodan-host") | {ip: .value, services: .details.services}' report.jsonl
jq -c 'select(.type == "hostname" and .observations) | {hostname: .value, observations}' report.jsonl
jq -c 'select(.type == "asn" and .observations) | {asn: .value, observations}' report.jsonl
```

List every finding as tab-separated type and value columns:

```bash
jq -r 'select(.type != "summary") | [.type, .value] | @tsv' report.jsonl
```

The `subdomains` capability produces `hostname` records because a result can be the target hostname itself. Read [Results and local data](docs/wiki/Results-and-Local-Data.md) for the complete JSONL and evidence contract.

### SQLite, JSON, and XML

CLI and API runs use the same SQLite evidence model. JSONL moves one run at a time. The API can import or export completed runs in bulk as a portable SQLite database while leaving queue and worker state behind. Screenshot files are managed separately from their metadata.

JSON and XML are compatibility reports grouped by result type. They do not include the full provenance, lifecycle outcomes, or structured action evidence available in JSONL, SQLite, the API, and HarvestView.

## Development and contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, required checks, testing expectations, and pull-request process.

## Support and credits

- Use [GitHub Issues](https://github.com/laramies/theHarvester/issues) for reproducible bugs and focused feature requests.
- Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md), not in public issues.
- [Christian Martorella (@laramies)](https://twitter.com/laramies) created theHarvester. Contact: [cmartorella@edge-security.com](mailto:cmartorella@edge-security.com).
- [Matt Brown (@NotoriousRebel1)](https://twitter.com/NotoriousRebel1) and [Jay "L1ghtn1ng" Townsend (@jay_townsend1)](https://twitter.com/jay_townsend1) maintain and develop the project.
- [Lee Baird (@discoverscripts)](https://twitter.com/discoverscripts) is a main contributor.
- Thanks to John Matherly for Shodan and Ahmed Aboul Ela for the bundled subdomain dictionaries.
