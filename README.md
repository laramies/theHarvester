# theHarvester

![theHarvester logo](theHarvester-logo.webp)

[![Python CI](https://github.com/laramies/theHarvester/actions/workflows/theHarvester.yml/badge.svg)](https://github.com/laramies/theHarvester/actions/workflows/theHarvester.yml)
[![Docker CI](https://github.com/laramies/theHarvester/actions/workflows/dockerci.yml/badge.svg)](https://github.com/laramies/theHarvester/actions/workflows/dockerci.yml)

theHarvester gathers open-source intelligence about a domain or organization from search engines, certificate transparency logs, DNS datasets, code repositories, threat-intelligence platforms, and other public sources.

It is built for the early reconnaissance stage of authorized security assessments. Use it only on targets you own or have explicit permission to test.

## Why theHarvester

- **Broad discovery coverage:** combine many independent sources in one run instead of querying each provider manually.
- **Useful result types:** collect hostnames, email addresses, IP addresses, URLs, ASNs, and people.
- **Enrichment after discovery:** optionally resolve DNS, query Shodan, check for subdomain takeovers, brute-force DNS names, scan common API paths, and capture screenshots.
- **CLI and browser-accessible API:** use the command line interactively or run the FastAPI service for automation and interactive Swagger/ReDoc documentation.
- **Repeatable output:** print results, write JSON and XML reports, and retain host, email, and IP findings in a local SQLite database.
- **Operational controls:** select individual sources, set result limits, use HTTP or SOCKS proxies, choose DNS resolvers, and suppress missing-key noise.

Source availability, quotas, and response formats are controlled by third parties and can change independently of theHarvester.

## Quick start

theHarvester requires Python 3.12 or newer and uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
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

Run every source that can contribute subdomains:

```bash
uv run theHarvester -d example.com -b subdomains
```

Combine capability selectors, or mix them with explicit source names:

```bash
uv run theHarvester -d example.com -b emails,urls,certspotter
```

Capability selectors form a union and choose which sources run. They do not discard other result types returned by those sources. Available selectors are `subdomains`, `emails`, `ips`, `asns`, `urls`, and `people`. `-b all` continues to run every registered source.

Save both JSON and XML reports:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

Resolve discovered hosts for an authorized domain with the default resolver list:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -r
```

List every option and its current behavior:

```bash
uv run theHarvester -h
```

### Active features

Options such as DNS brute force (`-c`), reverse DNS lookup (`-n`), takeover checks (`-t`), API endpoint scanning (`-a`), DNS resolution (`-r`), and screenshots (`--screenshot`) generate additional network activity. Use them only within an explicitly authorized scope.

Screenshot capture also requires a Playwright-compatible browser; see the installation guide for setup.

## Browser interface and REST API

`restfulHarvest` starts a FastAPI service on `127.0.0.1:5000` by default:

```bash
uv run restfulHarvest
```

Open [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs) for interactive Swagger documentation or [http://127.0.0.1:5000/redoc](http://127.0.0.1:5000/redoc) for ReDoc.

| Route | Purpose |
| --- | --- |
| `GET /sources` | List registered discovery sources. |
| `GET /query` | Return ASNs, interesting URLs, Twitter/LinkedIn fields, Trello URLs, IPs, emails, and hosts as JSON. |
| `GET /dnsbrute` | Run DNS brute force for a domain. |
| `POST /additional/breaches` | Return Have I Been Pwned breach data. |
| `POST /additional/leaks` | Return Leak-Lookup data. |
| `POST /additional/security-score` | Return SecurityScorecard data. |
| `POST /additional/tech-stack` | Return BuiltWith technology data. |
| `POST /additional/all` | Run all additional API lookups. |

The service rate limit defaults to five requests per minute and can be changed with `--rate-limit`. The `/additional/*` routes require `THEHARVESTER_API_KEY` on the server and the same value in the `X-API-Key` request header.

The core `/query`, `/sources`, and `/dnsbrute` routes do not require authentication. Keep the service bound to localhost. If you require remote access, add authentication, access controls, and TLS.

Docker Compose publishes port `5000` on every host interface unless you narrow the port mapping:

```bash
docker compose up --build
```

## Discovery sources

The table shows which result types each source can add to the JSON report. It covers the consolidated CLI report only. Some adapters parse fields that the report does not store.

The report groups findings by result type. It does not record which source found each item. Empty optional fields may be omitted.

A checkmark means the source can add that result type. The **Separate output** column lists REST endpoints and optional actions that return other data.

Read the **API key** column as follows:

- **✓**: credentials are required.
- **Optional**: a key can provide additional access.
- **No**: the source has no key setting.

<details>
<summary><strong>View the source and result matrix</strong></summary>

| Source | Subdomains | Emails | IPs | ASNs | URLs / links | People | Separate REST/action output (not consolidated report) | API key |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | --- | :---: |
| `baidu` | ✓ | ✓ | No | No | No | No | No | No |
| `bevigil` | ✓ | No | No | No | ✓ | No | No | ✓ |
| `bitbucket` | ✓ | ✓ | No | No | No | No | No | ✓ |
| `bufferoverun` | ✓ | No | ✓ | No | No | No | No | ✓ |
| `builtwith` | ✓ | No | No | No | ✓ | No | `POST /additional/tech-stack` response | ✓ |
| `brave` | ✓ | ✓ | No | No | No | No | No | ✓ |
| `censys` | ✓ | ✓ | No | No | No | No | No | ✓ |
| `certspotter` | ✓ | No | No | No | No | No | No | No |
| `chaos` | ✓ | No | No | No | No | No | No | ✓ |
| `commoncrawl` | ✓ | No | No | No | No | No | No | No |
| `criminalip` | ✓ | No | ✓ | ✓ | No | No | No | ✓ |
| `crtsh` | ✓ | No | No | No | No | No | No | No |
| `dehashed` | No | No | ✓ | No | No | No | No | ✓ |
| `dnsdb` | ✓ | No | No | No | No | No | No | ✓ |
| `dnsdumpster` | ✓ | No | ✓ | No | No | No | No | ✓ |
| `duckduckgo` | ✓ | ✓ | No | No | No | No | No | No |
| `dymo` | ✓ | No | No | No | No | No | No | ✓ |
| `fofa` | ✓ | No | ✓ | No | No | No | No | ✓ |
| `fullhunt` | ✓ | No | No | No | No | No | No | ✓ |
| `github-code` | ✓ | ✓ | No | No | No | No | No | ✓ |
| `gitlab` | ✓ | ✓ | No | No | No | No | No | No |
| `hackertarget` | ✓ | No | No | No | No | No | No | Optional |
| `haveibeenpwned` | No | No | No | No | No | No | `POST /additional/breaches` response | ✓ |
| `hudsonrock` | ✓ | ✓ | ✓ | No | No | No | No | No |
| `hunter` | ✓ | ✓ | No | No | No | No | No | ✓ |
| `hunterhow` | ✓ | No | No | No | No | No | No | ✓ |
| `intelx` | ✓ | ✓ | No | No | ✓ | No | No | ✓ |
| `leakix` | ✓ | ✓ | No | No | No | No | No | Optional |
| `leaklookup` | No | ✓ | No | No | No | No | `POST /additional/leaks` response | ✓ |
| `mojeek` | ✓ | ✓ | No | No | No | No | No | Optional |
| `netlas` | ✓ | No | No | No | No | No | No | ✓ |
| `onyphe` | ✓ | No | ✓ | ✓ | No | No | No | ✓ |
| `otx` | ✓ | No | ✓ | No | No | No | No | No |
| `pentesttools` | ✓ | No | No | No | No | No | No | ✓ |
| `projectdiscovery` | ✓ | No | No | No | No | No | No | ✓ |
| `rapiddns` | ✓ | No | ✓ | No | No | No | No | No |
| `robtex` | ✓ | No | ✓ | No | No | No | No | No |
| `rocketreach` | No | ✓ | No | No | ✓ | No | No | ✓ |
| `securityscorecard` | ✓ | No | ✓ | No | No | No | `POST /additional/security-score` response | ✓ |
| `securityTrails` | ✓ | No | ✓ | No | No | No | No | ✓ |
| `sherlockeye` | ✓ | ✓ | ✓ | No | No | No | No | ✓ |
| `shodan` | ✓ | No | No | No | No | No | `-s` / `--shodan` host-enrichment output | ✓ |
| `shodanInternetDB` | ✓ | No | ✓ | No | No | No | No | No |
| `subdomaincenter` | ✓ | No | No | No | No | No | No | No |
| `subdomainfinderc99` | ✓ | No | No | No | No | No | No | No |
| `thc` | ✓ | No | No | No | No | No | No | No |
| `threatcrowd` | ✓ | No | ✓ | No | No | No | No | No |
| `tomba` | ✓ | ✓ | No | No | No | No | No | ✓ |
| `urlscan` | ✓ | No | ✓ | ✓ | ✓ | No | No | No |
| `venacus` | No | ✓ | ✓ | No | ✓ | ✓ | No | ✓ |
| `virustotal` | ✓ | No | No | No | No | No | No | ✓ |
| `waybackarchive` | ✓ | No | No | No | No | No | No | No |
| `whoisxml` | ✓ | No | No | No | No | No | No | ✓ |
| `windvane` | ✓ | ✓ | ✓ | No | No | No | No | Optional |
| `yahoo` | ✓ | ✓ | No | No | No | No | No | No |
| `zoomeye` | ✓ | ✓ | ✓ | ✓ | ✓ | No | No | ✓ |

</details>

Provider pricing is intentionally omitted because plans and quotas change frequently. See [Configuration and API Keys](docs/wiki/Configuration-and-API-Keys.md) and each provider's current documentation.

The runtime registry also reports the legacy identifiers `linkedin`, `linkedin_links`, `netcraft`, `omnisint`, `sublist3r`, and `zoomeyeapi`. These identifiers have no active CLI handlers. The table does not present them as usable sources.

## Configuration

On first use, theHarvester creates default configuration files under `~/.theHarvester/`. It also reads system configuration from `/etc/theHarvester/` and `/usr/local/etc/theHarvester/`.

- `api-keys.yaml` stores provider credentials.
- `proxies.yaml` configures HTTP and SOCKS5 proxies used with `-p`.

Never commit populated configuration files, API keys, account details, or provider responses.

## Results and local data

- Terminal output shows consolidated findings. Separately selected actions, such as `-s` / `--shodan`, may print their own enrichment.
- `-f NAME` writes `NAME.json` and `NAME.xml`.
- Screenshots are written to the directory passed to `--screenshot`.
- Host, email, IP, and related scan records are stored in `~/.local/share/theHarvester/stash.sqlite`.
- REST queries return JSON.

Treat collected OSINT as potentially sensitive. Keep report files, screenshots, and the local database out of source control and share them only within the authorized engagement.

### Report formats

The JSON report is a single object and is the more complete format for automation. Host entries may be plain hostnames or `hostname:IP` pairs when DNS resolution is enabled.

| Field | Availability | Contents |
| --- | --- | --- |
| `cmd` | Always | Command-line arguments used for the run. |
| `hosts` | Always | Discovered hosts; an empty array when none are found. |
| `shodan` | Always | Shodan enrichment rows; an empty array when Shodan is not used. |
| `ips`, `emails`, `vhosts`, `asns` | When non-empty | Network and contact findings. |
| `interesting_urls`, `trello_urls`, `linkedin_links` | When non-empty | Discovered links and URLs. |
| `people`, `twitter_people`, `linkedin_people` | When non-empty | People and profile findings. |
| `takeover_results` | When non-empty | Optional takeover-check results. |

The XML report contains the command, emails, hosts, and virtual hosts. Use JSON when you need the additional result types above.

List discovered hosts with [`jq`](https://jqlang.org/):

```bash
jq -r '.hosts[]?' report.json
```

Count common result types while safely handling omitted fields:

```bash
jq '{
  hosts: (.hosts // [] | length),
  emails: (.emails // [] | length),
  ips: (.ips // [] | length),
  asns: (.asns // [] | length)
}' report.json
```

Export common findings as tab-separated values:

```bash
jq -r '(
  ["type", "value"],
  (.hosts[]? | ["host", .]),
  (.emails[]? | ["email", .]),
  (.ips[]? | ["ip", .]),
  (.asns[]? | ["asn", .])
) | @tsv' report.json > findings.tsv
```

## Development and contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, required checks, testing expectations, and pull-request process.

## Support and credits

- Use [GitHub Issues](https://github.com/laramies/theHarvester/issues) for reproducible bugs and focused feature requests.
- Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md), not in public issues.
- [Christian Martorella (@laramies)](https://twitter.com/laramies) created theHarvester No [cmartorella@edge-security.com](mailto:cmartorella@edge-security.com).
- [Matt Brown (@NotoriousRebel1)](https://twitter.com/NotoriousRebel1) and [Jay "L1ghtn1ng" Townsend (@jay_townsend1)](https://twitter.com/jay_townsend1) maintain and develop the project.
- [Lee Baird (@discoverscripts)](https://twitter.com/discoverscripts) is a main contributor.
- Thanks to John Matherly for Shodan and Ahmed Aboul Ela for the bundled subdomain dictionaries.
