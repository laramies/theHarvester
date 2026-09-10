# Moving from 4.11 to 5.0

Version 5.0 is still under development on `dev`. This guide compares the released [4.11.1 tag](https://github.com/laramies/theHarvester/tree/4.11.1) with the current development interfaces so you can update existing commands and REST automation before the release.

## Update the runtime first

Version 5.0 requires Python 3.14. A source checkout uses `uv` for the environment and commands:

```console
uv sync
uv run theHarvester --help
```

See [Installation](Installation) for platform steps and browser dependencies.

## Replace the REST launcher

Replace `uv run restfulHarvest` with `uv run harvestview` in service definitions and startup scripts. The installed `restfulHarvest` command and `python -m theHarvester.restfulHarvest` module are gone. For a module invocation, use `uv run python -m theHarvester.harvestview`.

```bash
export THEHARVESTER_API_KEY="$(openssl rand -hex 32)"
uv run harvestview --host 127.0.0.1 --port 5000
```

Configure the same operator key in the service and its clients. Every `/api/v1/*` request requires `X-API-Key`; provider credentials belong in server-side configuration, not the request body. See [Configuration and API Keys](Configuration-and-API-Keys).

`--host`, `--port`, `--log-level`, and `--reload` remain launcher options. Remove `--rate-limit` and `API_RATE_LIMIT`: the built-in request limiter has no replacement in HarvestView. If your deployment relied on it, enforce request limits outside the application. The default address remains `127.0.0.1:5000`; `/` now opens HarvestView, and `/docs`, `/redoc`, and `/openapi.json` describe the current API.

## Migrate REST requests and response parsing

The unversioned enumeration routes and `/additional/*` provider routes from 4.11.1 are removed. Use these replacements:

| Released 4.11.1 request | Current replacement |
| --- | --- |
| `GET /sources` | `GET /api/v1/sources`; source entries are objects, so read `.sources[].name` instead of `.sources[]`. Entries also describe capabilities, activity, and credentials. |
| `GET /query?domain=example.test&source=crtsh` | `POST /api/v1/runs` with `{"target":"example.test","sources":["crtsh"]}`. |
| `GET /dnsbrute?domain=example.test` | `POST /api/v1/runs` with `{"target":"example.test","sources":[],"dns_brute":true}`. This enables P1 DNS interaction. |
| `POST /additional/breaches` | Submit a run with `"sources":["haveibeenpwned"]`. For verified-domain email data, review `hibpverified` and its separate credential requirements. |
| `POST /additional/leaks` | Submit a run with `"sources":["leaklookup"]`. |
| `POST /additional/security-score` | `"sources":["securityscorecard"]` returns hostname/IP evidence. The old score, grades, issues, and recommendations payload has no current API equivalent. |
| `POST /additional/tech-stack` | Use `"sources":["builtwith"]`. Replace the grouped `tech_stack` parser with `.results[]` types `framework`, `language`, `server`, `cms`, and `analytics`; `interesting_urls` becomes `url`, alongside `hostname` findings. |
| `POST /additional/all` | No exact replacement. Select `haveibeenpwned`, `leaklookup`, `securityscorecard`, and `builtwith` for their current findings. The old route also resolved hosts and queried Shodan; review the separate `dns_resolve` and `shodan` actions if needed. Their results do not reproduce `shodan_data`. `"sources":["all"]` selects all P0 sources, a much broader request. |

For every provider replacement, include `target` and consume the current source's normalized findings. The old `{status, data}` provider response and its provider-specific fields are not preserved.

Move query parameters into the JSON body. Rename `domain` to `target` and `source` to the `sources` array. `limit`, `start`, `proxies`, `shodan`, `dns_brute`, `dns_lookup`, and `api_scan` keep their names. Other request changes are:

| Released request field | Current request field or action |
| --- | --- |
| `dns_server` or a resolver string in `dns_resolve` | `dns_resolvers`, an array of literal resolver IPs. `dns_resolve` is now a Boolean that enables hostname resolution. Server-side file paths are not accepted as resolver values. |
| `take_over` | `takeover`, a Boolean. |
| `wordlist` | `api_scan_paths`, an array of endpoint paths such as `["/api", "/health"]`; enable `api_scan` to use it. The API does not read a client-supplied wordlist file. |
| `filename` | Download `GET /api/v1/runs/{run_id}/export` and choose the local output filename. |
| `api_keys` in `/additional/*` bodies | Configure provider keys on the server; authenticate the request with the operator's `X-API-Key`. |

Unknown body fields are rejected. Use the [REST API guide](Rest-API) and the running service's OpenAPI document for exact request and response schemas.

For example, this replaces a `/query` call. `example.test` is a reserved placeholder; substitute an authorized target before executing. The local POST queues a run that contacts `crtsh`.

```bash
run_id="$(curl --fail-with-body -sS http://127.0.0.1:5000/api/v1/runs \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.test","sources":["crtsh"],"limit":100}' \
  | jq -er '.run_id')"

curl --fail-with-body -sS "http://127.0.0.1:5000/api/v1/runs/$run_id" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq '{status, evidence_status, results, source_executions}'
```

A successful POST returns HTTP 201 and a durable `run_id`, not completed findings. Poll the run's GET endpoint until `status` is `completed`, `failed`, or `cancelled`; `queued`, `running`, and `cancelling` are intermediate states. Read `evidence_status` and producer outcomes separately: a terminal run may retain partial evidence.

Replace old grouped response parsing such as `.hosts[]`, `.ips[]`, and `.emails[]` with normalized `.results[]` records. After the run is terminal, extract hostnames and download JSONL like this:

```bash
curl --fail-with-body -sS "http://127.0.0.1:5000/api/v1/runs/$run_id" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq -r '.results[] | select(.type == "hostname") | .value'

curl --fail-with-body -sS "http://127.0.0.1:5000/api/v1/runs/$run_id/export" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -o report.jsonl
```

Use result types `ip`, `email`, `asn`, `url`, or `person` for the corresponding records. Old social/provider-specific arrays have no guaranteed one-to-one replacement; consult each source's capabilities and the [result format](Results-and-Local-Data).

## Update CLI options and source selections

`-e` / `--dns-server` is removed. It was unused in 4.11.1. Use `--dns-resolvers IPS_OR_FILE` to select resolvers for enabled DNS actions without also enabling hostname resolution. Pass comma-separated literal IPs or a text file with one IP per line. `-r` / `--dns-resolve [IPS_OR_FILE]` still enables hostname resolution and can select resolvers; do not supply resolver values through both options.

This replacement for `-e` selects a resolver for DNS brute force. Both the target and resolver below are reserved placeholders; substitute your authorized domain and resolver before running this P1 command:

```console
uv run theHarvester -d example.test --dns-brute --dns-resolvers 192.0.2.53
```

Update explicit `-b` / `--source` lists and REST `sources` arrays against the [current source catalog](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources), also available through authenticated `GET /api/v1/sources`:

| Released identifier | Migration |
| --- | --- |
| `chaos` | Use `projectdiscovery`, the same dataset and credential. `chaos` is no longer an alias. |
| `zoomeyeapi` | Use the supported `zoomeye` source; the old identifier had no working dispatch. |
| `bitbucket` | Removed from domain discovery with no equivalent provider. Choose an appropriate current source, or use Bitbucket separately with an explicit workspace/repository scope. |
| `threatcrowd` | Removed. `otx` is a supported alternative with its own data and behavior, not an alias or identical dataset. |
| `venacus` | Removed with no direct replacement; choose current providers by the capabilities your workflow needs. |
| `linkedin`, `linkedin_links`, `netcraft`, `omnisint`, `sublist3r` | Removed legacy identifiers with no direct replacement. Select supported sources by capability; old names are not compatibility aliases. |

For example, change `-b chaos` to `-b projectdiscovery`, or `"sources":["chaos"]` to `"sources":["projectdiscovery"]`. Case-insensitive spellings of retained names still work; the catalog preserves canonical names such as `securityTrails` and `shodanInternetDB` in results.

Review `-b all` and capability selections before reuse. `all` now selects every P0 source and excludes P1/P2 sources; explicitly select other sources only when their activity is authorized. Capability selectors such as `emails` choose sources and retain all result types those sources return. For a fixed provider set, enumerate its names.

## Use the right result format

For new automation, use JSONL for one finalized run or SQLite for several runs.

- JSONL starts with a summary record, followed by normalized findings. It retains terminal evidence status, source and action outcomes, provenance, and supported structured observations.
- SQLite is the local multi-run store and the portable bulk import and export format. Portable exports omit queue, cancellation, and worker state.
- JSON and XML remain available as grouped compatibility reports, but they do not contain the full evidence model.

JSONL findings use the canonical result types `hostname`, `ip`, and `url`. Use each finding's `sources` and `actions` fields for attribution.

```console
jq -r 'select(.type == "hostname") | .value' report.jsonl
jq -r 'select(.type == "ip") | .value' report.jsonl
jq -r 'select(.type == "url") | .value' report.jsonl
```

Read [Results and Local Data](Results-and-Local-Data) for the complete evidence and portability contract.

## Report on saved runs

Use `harvest-report` to list targets, summarize source contributions, or compare hostnames:

```console
harvest-report targets
harvest-report contributions --target example.test
harvest-report hostname-changes --target example.test
```

Contribution reports are target-scoped by default. A database with several targets requires `--target`, `--run-id`, or an intentional `--all-targets` aggregate. Hostname comparisons use the latest earlier run with the same canonical target and exact source list.

The comparison labels describe saved evidence:

- `newly_reported`
- `still_reported`
- `no_longer_reported`
- `uncertain`

`no_longer_reported` does not prove that a hostname disappeared or stopped resolving. `uncertain` means a relevant source did not complete reliably on the side where the hostname was absent.

## Choose CLI, API, or HarvestView

The CLI, authenticated REST API, and HarvestView use the same normalized terminal evidence.

- Use the CLI for one finite run and shell automation.
- Use the [REST API](Rest-API) for durable local run records, imports, exports, cancellation, and schedules.
- Use HarvestView to submit and review those same runs in a local browser.

HarvestView uses the same engine as the CLI. A schedule submits finite runs for explicit targets, and its control state stays separate from portable evidence.

## Review network activity before running

Version 5.0 labels activities by observable network behavior:

- P0 queries an existing provider or dataset.
- P1 performs DNS interaction about an authorized name or address.
- P2 contacts a target endpoint or causes equivalent direct interaction.

These labels do not express importance or confidence. Check [Responsible Use and Scope](Responsible-Use-and-Scope) and confirm the target and selected activities before submitting a run.

## Migration checklist

- Install Python 3.14 and refresh the `uv` environment.
- Replace `restfulHarvest` with `harvestview`, configure the operator key, and remove obsolete rate-limit settings.
- Replace legacy REST routes and fields, then poll runs and parse normalized results.
- Replace `-e` / `--dns-server` and removed source names; review what `all` selects.
- Move new automation to JSONL, SQLite, or the authenticated API.
- Use `hostname`, `ip`, and `url` to filter JSONL findings.
- Use `harvest-report` for saved-run contributions and hostname comparisons.
- Treat hostname differences as saved evidence, not current network truth.
- Recheck P0, P1, and P2 activity before running an existing workflow.
